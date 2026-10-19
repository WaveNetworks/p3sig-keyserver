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
//
// Request (POST /v1/unwrap, JSON):
//
//	{"app","ts","wrap","reply","sig"}  sig = Ed25519 over
//	"p3sig-ks-v1|<app>|<ts>|<hex sha256(wrap bytes)>|<reply b64>"
//
// Response: {"sealed": b64 crypto_box_seal(bundle key, reply)}.

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
	ClientIPHeader string           `json:"client_ip_header"`
	Apps           map[string]ksApp `json:"apps"`
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
		return fmt.Errorf("keyserver needs a subcommand: init | serve | seal")
	}
	f := parseFlags(args[1:])
	switch args[0] {
	case "init":
		return cmdKeyserverInit(f)
	case "serve":
		return cmdKeyserverServe(f)
	case "seal":
		return cmdKeyserverSeal(args[1:])
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
	refuse := func(code int, app, why string) {
		log.Printf("keyserver: REFUSED app=%q ip=%s: %s", app, ip, why)
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
	var req ksRequest
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
	log.Printf("keyserver: unlocked app=%q ip=%s", req.App, ip)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"sealed": base64.StdEncoding.EncodeToString(sealed)})
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
