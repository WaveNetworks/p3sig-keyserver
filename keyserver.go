package main

// Key server: the fallback tier for apps on shared hosting (p3sig doc
// machine-identity-and-secret-delivery.md §4.4).
//
// An app's bundle is encrypted with a random bundle key; the bundle key is
// wrapped (wrap.go scheme 1, ecdh-p256-hkdf-aesgcm) to each key server's chip
// key. The host keeps only ciphertext. On a cold start the app sends the wrap
// for this key server, signed with its Ed25519 app key, plus a one-time X25519
// reply key. The key server checks the request, does the ECDH in its chip,
// and returns the bundle key sealed to the reply key. It never sees the
// secrets and keeps no per-app data beyond the allowlist in its config.
//
//	p3sig keyserver init   [--label keyserver]
//	p3sig keyserver serve  [--config ~/.p3sig/keyserver.json] [--listen 127.0.0.1:8787]
//	p3sig keyserver seal   --pub <b64 SEC1> [--pub ...] --in values.json --out cache.enc
//	p3sig keyserver stats  [--config FILE] [--days 14]
//
// Request (POST /v1/unwrap, JSON):
//
//	{"app","ts","wrap","reply","sig","why"}  sig = Ed25519 over
//	"p3sig-ks-v1|<app>|<ts>|<hex sha256(wrap bytes)>|<reply b64>"
//
// Response: {"sealed": b64 crypto_box_seal(bundle key, reply)}.
//
// "why" (optional, unsigned, telemetry only) is the app's reason for asking: "cold" (its
// memory copy was gone: a reboot or a first start — the real dependency on this server),
// "refresh" (routine, after refresh_after), "retry"; with "-cli" when a CLI/cron process
// asked. Every request for a known app is appended to events_file; `keyserver stats`
// counts them per app and day.

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/box"
)

const (
	ksSigContext   = "p3sig-ks-v1"
	ksBundleAAD    = "p3sig-bundle-v1"
	ksMaxBody      = 16 << 10
	ksClockSkew    = 60 * time.Second
	ksDefaultLabel = "keyserver"
	ksDefaultAddr  = "127.0.0.1:8787"
	ksRatePerMin   = 30
)

// ksConfig is the key server's allowlist. Apps are added by hand for now; a
// later version pulls them from p3sig.com.
type ksConfig struct {
	Label string `json:"label"`
	// ClientIPHeader names the header the local proxy (Tailscale Funnel,
	// Cloudflare Tunnel) puts the real client address in. Trusted only when the
	// connection itself comes from loopback.
	ClientIPHeader string `json:"client_ip_header"`
	// EventsFile, when set, gets one JSON line per request for a known app (unlocked or
	// refused). Requests naming no app (scanners) only go to the journal.
	EventsFile string           `json:"events_file"`
	Apps       map[string]ksApp `json:"apps"`
}

type ksApp struct {
	Key string   `json:"key"` // base64 Ed25519 public key
	IPs []string `json:"ips"` // allowed client addresses; empty = any (logged loudly)
}

func ksConfigPath(f map[string]string) (string, error) {
	if p := f["config"]; p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".p3sig", "keyserver.json"), nil
}

func loadKSConfig(path string) (*ksConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c ksConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.Label == "" {
		c.Label = ksDefaultLabel
	}
	for id, a := range c.Apps {
		if k, err := base64.StdEncoding.DecodeString(a.Key); err != nil || len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%s: app %q: key is not a base64 Ed25519 public key", path, id)
		}
		for _, ip := range a.IPs {
			if net.ParseIP(ip) == nil {
				return nil, fmt.Errorf("%s: app %q: %q is not an IP address", path, id, ip)
			}
		}
	}
	return &c, nil
}

func cmdKeyserver(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("keyserver needs a subcommand: init | serve | seal | stats")
	}
	f := parseFlags(args[1:])
	switch args[0] {
	case "init":
		return cmdKeyserverInit(f)
	case "serve":
		return cmdKeyserverServe(f)
	case "seal":
		return cmdKeyserverSeal(args[1:])
	case "stats":
		return cmdKeyserverStats(f)
	}
	return fmt.Errorf("unknown keyserver subcommand %q", args[0])
}

// init makes the chip key and prints its public point: that is what p3sig (or
// `keyserver seal`) wraps bundle keys to.
func cmdKeyserverInit(f map[string]string) error {
	label := f["label"]
	if label == "" {
		label = ksDefaultLabel
	}
	ks, err := openKeystore()
	if err != nil {
		return err
	}
	if _, err := ks.PublicKey(label); err != nil {
		if _, err := ks.Create(label); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "created chip key %q\n", label)
	}
	point, err := ks.CreateAgreementKey(label)
	if err != nil {
		return err
	}
	fmt.Println(base64.StdEncoding.EncodeToString(point))
	return nil
}

// ─── serve ──────────────────────────────────────────────────────────────────

type keyServer struct {
	cfgP  atomic.Pointer[ksConfig] // swapped on SIGHUP
	ks    Keystore
	mu    sync.Mutex
	seen  map[string]time.Time   // replay guard: sig hash -> expiry
	rate  map[string][]time.Time // app -> recent request times
	chip  sync.Mutex             // one TPM command at a time
	evMu  sync.Mutex             // serialises appends to events_file
	now   func() time.Time
	agree func(label string, peer []byte) ([]byte, error)
}

func cmdKeyserverServe(f map[string]string) error {
	path, err := ksConfigPath(f)
	if err != nil {
		return err
	}
	cfg, err := loadKSConfig(path)
	if err != nil {
		return err
	}
	ks, err := openKeystore()
	if err != nil {
		return err
	}
	if _, err := ks.CreateAgreementKey(cfg.Label); err != nil {
		return fmt.Errorf("chip key %q: %w (run: p3sig keyserver init)", cfg.Label, err)
	}
	addr := f["listen"]
	if addr == "" {
		addr = ksDefaultAddr
	}
	s := newKeyServer(cfg, ks)
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			next, err := loadKSConfig(path)
			if err != nil || next.Label != cfg.Label {
				log.Printf("keyserver: reload REFUSED, keeping the old config: %v (label changes need a restart)", err)
				continue
			}
			s.cfgP.Store(next)
			log.Printf("keyserver: reloaded, %d app(s)", len(next.Apps))
		}
	}()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/unwrap", s.handleUnwrap)
	mux.HandleFunc("/", http.NotFound)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	log.Printf("keyserver: %d app(s), chip key %q, listening on %s", len(cfg.Apps), cfg.Label, addr)
	return srv.ListenAndServe()
}

func newKeyServer(cfg *ksConfig, ks Keystore) *keyServer {
	s := &keyServer{
		ks:   ks,
		seen: map[string]time.Time{},
		rate: map[string][]time.Time{},
		now:  time.Now,
	}
	s.cfgP.Store(cfg)
	if ks != nil {
		s.agree = ks.Agree
	}
	return s
}

type ksRequest struct {
	App   string `json:"app"`
	TS    int64  `json:"ts"`
	Wrap  string `json:"wrap"`
	Reply string `json:"reply"`
	Sig   string `json:"sig"`
	Why   string `json:"why"`
}

func ksSigMessage(app string, ts int64, wrap []byte, reply string) []byte {
	h := sha256.Sum256(wrap)
	return []byte(ksSigContext + "|" + app + "|" + strconv.FormatInt(ts, 10) + "|" + hex.EncodeToString(h[:]) + "|" + reply)
}

func (s *keyServer) cfg() *ksConfig { return s.cfgP.Load() }

func (s *keyServer) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if h := s.cfg().ClientIPHeader; h != "" {
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			if v := strings.TrimSpace(strings.Split(r.Header.Get(h), ",")[0]); v != "" {
				return v
			}
		}
	}
	return host
}

func (s *keyServer) handleUnwrap(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	var req ksRequest
	refuse := func(code int, app, why string) {
		log.Printf("keyserver: REFUSED app=%q ip=%s: %s", app, ip, why)
		if _, known := s.cfg().Apps[app]; known {
			s.record(ksEvent{App: app, IP: ip, OK: false, Why: ksWhy(req.Why), Err: why})
		}
		http.Error(w, http.StatusText(code), code)
	}
	if r.Method != http.MethodPost {
		refuse(http.StatusMethodNotAllowed, "", "method "+r.Method)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, ksMaxBody+1))
	if err != nil || len(body) > ksMaxBody {
		refuse(http.StatusRequestEntityTooLarge, "", "body too large or unreadable")
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		refuse(http.StatusBadRequest, "", "bad json")
		return
	}
	sealed, err := s.unwrap(req, ip)
	if err != nil {
		var re ksRefusal
		if errors.As(err, &re) {
			refuse(re.code, req.App, re.why)
			return
		}
		log.Printf("keyserver: ERROR app=%q ip=%s: %v", req.App, ip, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	log.Printf("keyserver: unlocked app=%q ip=%s why=%s", req.App, ip, ksWhy(req.Why))
	s.record(ksEvent{App: req.App, IP: ip, OK: true, Why: ksWhy(req.Why)})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"sealed": base64.StdEncoding.EncodeToString(sealed)})
}

// ─── events: how often apps need this server ────────────────────────────────

type ksEvent struct {
	T   int64  `json:"t"`
	App string `json:"app"`
	IP  string `json:"ip"`
	OK  bool   `json:"ok"`
	Why string `json:"why,omitempty"`
	Err string `json:"err,omitempty"`
}

var ksWhyOK = regexp.MustCompile(`^[a-z][a-z-]{0,15}$`)

func ksWhy(w string) string {
	if ksWhyOK.MatchString(w) {
		return w
	}
	return "unknown"
}

func (s *keyServer) record(e ksEvent) {
	path := s.cfg().EventsFile
	if path == "" {
		return
	}
	e.T = s.now().Unix()
	line, _ := json.Marshal(e)
	s.evMu.Lock()
	defer s.evMu.Unlock()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		log.Printf("keyserver: cannot record event: %v", err)
		return
	}
	f.Write(append(line, '\n'))
	f.Close()
}

// stats: per app and UTC day — unlocks by reason, refusals — plus the last cold start.
func cmdKeyserverStats(f map[string]string) error {
	path, err := ksConfigPath(f)
	if err != nil {
		return err
	}
	cfg, err := loadKSConfig(path)
	if err != nil {
		return err
	}
	if cfg.EventsFile == "" {
		return fmt.Errorf("%s has no events_file; nothing is being recorded", path)
	}
	days := 14
	if d, err := strconv.Atoi(f["days"]); err == nil && d > 0 {
		days = d
	}
	b, err := os.ReadFile(cfg.EventsFile)
	if err != nil {
		return err
	}
	return ksPrintStats(os.Stdout, b, time.Now().UTC(), days)
}

func ksPrintStats(w io.Writer, b []byte, now time.Time, days int) error {
	type row struct{ cold, refresh, other, refused int }
	since := now.AddDate(0, 0, -days+1).Truncate(24 * time.Hour)
	per := map[string]map[string]*row{} // app -> day -> counts
	lastCold := map[string]time.Time{}
	refusedWhy := map[string]map[string]int{}
	for _, ln := range strings.Split(string(b), "\n") {
		var e ksEvent
		if ln == "" || json.Unmarshal([]byte(ln), &e) != nil {
			continue
		}
		t := time.Unix(e.T, 0).UTC()
		if strings.HasPrefix(e.Why, "cold") && e.OK && t.After(lastCold[e.App]) {
			lastCold[e.App] = t
		}
		if t.Before(since) {
			continue
		}
		day := t.Format("2006-01-02")
		if per[e.App] == nil {
			per[e.App] = map[string]*row{}
		}
		r := per[e.App][day]
		if r == nil {
			r = &row{}
			per[e.App][day] = r
		}
		switch {
		case !e.OK:
			r.refused++
			if refusedWhy[e.App] == nil {
				refusedWhy[e.App] = map[string]int{}
			}
			refusedWhy[e.App][e.Err]++
		case strings.HasPrefix(e.Why, "cold"):
			r.cold++
		case strings.HasPrefix(e.Why, "refresh"):
			r.refresh++
		default:
			r.other++
		}
	}
	if len(per) == 0 {
		fmt.Fprintf(w, "no requests in the last %d day(s)\n", days)
		return nil
	}
	apps := make([]string, 0, len(per))
	for a := range per {
		apps = append(apps, a)
	}
	sort.Strings(apps)
	for _, a := range apps {
		fmt.Fprintf(w, "%s  (last cold start: %s)\n", a, ksWhen(lastCold[a]))
		fmt.Fprintf(w, "  %-10s %5s %8s %6s %8s\n", "day (UTC)", "cold", "refresh", "other", "refused")
		dayKeys := make([]string, 0, len(per[a]))
		for d := range per[a] {
			dayKeys = append(dayKeys, d)
		}
		sort.Strings(dayKeys)
		for _, d := range dayKeys {
			r := per[a][d]
			fmt.Fprintf(w, "  %-10s %5d %8d %6d %8d\n", d, r.cold, r.refresh, r.other, r.refused)
		}
		for why, n := range refusedWhy[a] {
			fmt.Fprintf(w, "  refused %dx: %s\n", n, why)
		}
	}
	fmt.Fprintln(w, "cold = the app had lost its memory copy (reboot, first start): it could not run without this server.")
	fmt.Fprintln(w, "refresh = routine hourly re-check. other = older clients that don't say why.")
	return nil
}

func ksWhen(t time.Time) string {
	if t.IsZero() {
		return "none recorded"
	}
	return t.Format("2006-01-02 15:04 UTC")
}

type ksRefusal struct {
	code int
	why  string
}

func (e ksRefusal) Error() string { return e.why }

// unwrap runs every check before touching the chip, cheapest first.
func (s *keyServer) unwrap(req ksRequest, ip string) ([]byte, error) {
	app, ok := s.cfg().Apps[req.App]
	if !ok {
		return nil, ksRefusal{http.StatusForbidden, "unknown app"}
	}
	now := s.now()
	if d := now.Sub(time.Unix(req.TS, 0)); d > ksClockSkew || d < -ksClockSkew {
		return nil, ksRefusal{http.StatusForbidden, "timestamp outside ±60s"}
	}
	wrap, err1 := base64.StdEncoding.DecodeString(req.Wrap)
	reply, err2 := base64.StdEncoding.DecodeString(req.Reply)
	sig, err3 := base64.StdEncoding.DecodeString(req.Sig)
	if err1 != nil || err2 != nil || err3 != nil || len(reply) != 32 || len(sig) != ed25519.SignatureSize {
		return nil, ksRefusal{http.StatusBadRequest, "malformed fields"}
	}
	pub, _ := base64.StdEncoding.DecodeString(app.Key)
	if !ed25519.Verify(ed25519.PublicKey(pub), ksSigMessage(req.App, req.TS, wrap, req.Reply), sig) {
		return nil, ksRefusal{http.StatusForbidden, "bad signature"}
	}
	if len(app.IPs) > 0 && !ksIPAllowed(app.IPs, ip) {
		return nil, ksRefusal{http.StatusForbidden, "address not allowed for this app (stolen key?)"}
	}
	if len(app.IPs) == 0 {
		log.Printf("keyserver: WARNING app=%q has no address allowlist; accepted from %s", req.App, ip)
	}
	if err := s.admit(req.App, sig, now); err != nil {
		return nil, err
	}

	s.chip.Lock()
	bundleKey, err := UnwrapECDH(wrap, func(eph []byte) ([]byte, error) { return s.agree(s.cfg().Label, eph) })
	s.chip.Unlock()
	if err != nil {
		return nil, ksRefusal{http.StatusForbidden, "wrap does not open with this key server's chip: " + err.Error()}
	}
	defer zero(bundleKey)
	var rk [32]byte
	copy(rk[:], reply)
	return box.SealAnonymous(nil, bundleKey, &rk, rand.Reader)
}

func ksIPAllowed(allowed []string, ip string) bool {
	got := net.ParseIP(ip)
	for _, a := range allowed {
		if got != nil && got.Equal(net.ParseIP(a)) {
			return true
		}
	}
	return false
}

// admit applies the replay guard and the per-app rate limit.
func (s *keyServer) admit(app string, sig []byte, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, exp := range s.seen {
		if now.After(exp) {
			delete(s.seen, k)
		}
	}
	h := sha256.Sum256(sig)
	key := hex.EncodeToString(h[:])
	if _, dup := s.seen[key]; dup {
		return ksRefusal{http.StatusForbidden, "replayed request"}
	}
	recent := s.rate[app][:0]
	for _, t := range s.rate[app] {
		if now.Sub(t) < time.Minute {
			recent = append(recent, t)
		}
	}
	if len(recent) >= ksRatePerMin {
		s.rate[app] = recent
		return ksRefusal{http.StatusTooManyRequests, "rate limit"}
	}
	s.rate[app] = append(recent, now)
	s.seen[key] = now.Add(2 * ksClockSkew)
	return nil
}

// ─── seal: make a cache.enc (until the p3sig browser does this) ──────────────

// ksBundle is cache.enc. Values are encrypted with a random bundle key; the key
// is wrapped to every key server listed.
type ksBundle struct {
	V     int               `json:"v"`
	Wraps map[string]string `json:"wraps"` // key server id (b64 sha256 of its point, 16 chars) -> wrap
	Nonce string            `json:"nonce"`
	CT    string            `json:"ct"` // XChaCha20-Poly1305 over the values JSON, AAD ksBundleAAD
}

func ksServerID(point []byte) string {
	h := sha256.Sum256(point)
	return base64.RawURLEncoding.EncodeToString(h[:])[:16]
}

func sealKSBundle(values []byte, points [][]byte) (*ksBundle, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	defer zero(key)
	b := &ksBundle{V: 1, Wraps: map[string]string{}}
	for _, p := range points {
		pub, err := ecdh.P256().NewPublicKey(p)
		if err != nil {
			return nil, fmt.Errorf("key server point: %w", err)
		}
		w, err := WrapECDH(key, pub)
		if err != nil {
			return nil, err
		}
		b.Wraps[ksServerID(p)] = base64.StdEncoding.EncodeToString(w)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	b.Nonce = base64.StdEncoding.EncodeToString(nonce)
	b.CT = base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, values, []byte(ksBundleAAD)))
	return b, nil
}

func cmdKeyserverSeal(args []string) error {
	var points [][]byte
	var in, out string
	for i := 0; i < len(args); i++ {
		if i+1 >= len(args) {
			return fmt.Errorf("%s needs a value", args[i])
		}
		switch args[i] {
		case "--pub":
			p, err := base64.StdEncoding.DecodeString(args[i+1])
			if err != nil {
				return fmt.Errorf("--pub: %w", err)
			}
			points = append(points, p)
		case "--in":
			in = args[i+1]
		case "--out":
			out = args[i+1]
		default:
			return fmt.Errorf("unknown flag %s", args[i])
		}
		i++
	}
	if len(points) == 0 || in == "" || out == "" {
		return fmt.Errorf("usage: p3sig keyserver seal --pub <b64> [--pub <b64>] --in values.json --out cache.enc")
	}
	values, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	var check map[string]string
	if err := json.Unmarshal(values, &check); err != nil {
		return fmt.Errorf("%s must be a JSON object of NAME: value strings: %w", in, err)
	}
	b, err := sealKSBundle(values, points)
	if err != nil {
		return err
	}
	enc, _ := json.MarshalIndent(b, "", "  ")
	return os.WriteFile(out, append(enc, '\n'), 0o600)
}
