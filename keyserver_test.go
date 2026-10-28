package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/ssh"
)

// ksFixture: a key server whose "chip" is a software P-256 key, one app
// allowed from 203.0.113.7, and a sealed bundle for it.
type ksFixture struct {
	srv     *keyServer
	chip    *ecdh.PrivateKey
	appPriv ed25519.PrivateKey
	bundle  *ksBundle
	values  []byte
	now     time.Time
}

func newKSFixture(t *testing.T) *ksFixture {
	t.Helper()
	chip, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	appPub, appPriv, _ := ed25519.GenerateKey(rand.Reader)
	cfg := &ksConfig{Label: "keyserver", Apps: map[string]ksApp{
		"pilot": {Key: base64.StdEncoding.EncodeToString(appPub), IPs: []string{"203.0.113.7"}},
	}}
	s := newKeyServer(cfg, nil)
	f := &ksFixture{srv: s, chip: chip, appPriv: appPriv, now: time.Unix(1_800_000_000, 0)}
	s.now = func() time.Time { return f.now }
	s.agree = func(label string, peer []byte) ([]byte, error) {
		p, err := ecdh.P256().NewPublicKey(peer)
		if err != nil {
			return nil, err
		}
		return chip.ECDH(p)
	}
	f.values = []byte(`{"STRIPE_SECRET_KEY":"sk_test_123","SMTP_PASSWORD":"hunter2"}`)
	f.bundle, err = sealKSBundle(f.values, [][]byte{chip.PublicKey().Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// request builds a signed request the way the PHP side will.
func (f *ksFixture) request(t *testing.T, ts int64) (ksRequest, *[32]byte) {
	t.Helper()
	replyPub, replyPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var wrapB64 string
	for _, w := range f.bundle.Wraps {
		wrapB64 = w
	}
	wrap, _ := base64.StdEncoding.DecodeString(wrapB64)
	reply := base64.StdEncoding.EncodeToString(replyPub[:])
	sig := ed25519.Sign(f.appPriv, ksSigMessage("pilot", ts, wrap, reply))
	return ksRequest{App: "pilot", TS: ts, Wrap: wrapB64, Reply: reply, Sig: base64.StdEncoding.EncodeToString(sig)}, replyPriv
}

func (f *ksFixture) post(t *testing.T, req ksRequest, ip string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(req)
	r := httptest.NewRequest(http.MethodPost, "/v1/unwrap", bytes.NewReader(body))
	r.RemoteAddr = ip + ":40000"
	w := httptest.NewRecorder()
	f.srv.handleUnwrap(w, r)
	return w
}

func TestKeyserverRoundTrip(t *testing.T) {
	f := newKSFixture(t)
	req, replyPriv := f.request(t, f.now.Unix())
	w := f.post(t, req, "203.0.113.7")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	sealed, _ := base64.StdEncoding.DecodeString(resp["sealed"])

	// What the app does: open the reply, then the bundle.
	var replyPub [32]byte
	rp, _ := base64.StdEncoding.DecodeString(req.Reply)
	copy(replyPub[:], rp)
	key, ok := box.OpenAnonymous(nil, sealed, &replyPub, replyPriv)
	if !ok {
		t.Fatal("reply does not open with the reply key")
	}
	aead, _ := chacha20poly1305.NewX(key)
	nonce, _ := base64.StdEncoding.DecodeString(f.bundle.Nonce)
	ct, _ := base64.StdEncoding.DecodeString(f.bundle.CT)
	got, err := aead.Open(nil, nonce, ct, []byte(ksBundleAAD))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, f.values) {
		t.Fatalf("values = %s", got)
	}
}

func TestKeyserverRefusals(t *testing.T) {
	cases := []struct {
		name string
		mod  func(f *ksFixture, r *ksRequest)
		ip   string
		want int
	}{
		{"unknown app", func(f *ksFixture, r *ksRequest) { r.App = "other" }, "203.0.113.7", 403},
		{"old timestamp", func(f *ksFixture, r *ksRequest) { f.now = f.now.Add(2 * time.Minute) }, "203.0.113.7", 403},
		{"tampered wrap", func(f *ksFixture, r *ksRequest) { r.Wrap = base64.StdEncoding.EncodeToString([]byte("x")) }, "203.0.113.7", 403},
		{"wrong address", func(f *ksFixture, r *ksRequest) {}, "198.51.100.1", 403},
		{"bad signature", func(f *ksFixture, r *ksRequest) {
			_, other, _ := ed25519.GenerateKey(rand.Reader)
			wrap, _ := base64.StdEncoding.DecodeString(r.Wrap)
			r.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(other, ksSigMessage(r.App, r.TS, wrap, r.Reply)))
		}, "203.0.113.7", 403},
		{"short reply key", func(f *ksFixture, r *ksRequest) { r.Reply = "AAAA" }, "203.0.113.7", 400},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newKSFixture(t)
			req, _ := f.request(t, f.now.Unix())
			c.mod(f, &req)
			if w := f.post(t, req, c.ip); w.Code != c.want {
				t.Fatalf("status %d, want %d", w.Code, c.want)
			}
		})
	}
}

func TestKeyserverReplayAndRate(t *testing.T) {
	f := newKSFixture(t)
	req, _ := f.request(t, f.now.Unix())
	if w := f.post(t, req, "203.0.113.7"); w.Code != 200 {
		t.Fatalf("first: %d", w.Code)
	}
	if w := f.post(t, req, "203.0.113.7"); w.Code != 403 {
		t.Fatalf("replay: %d, want 403", w.Code)
	}
	for i := 1; i < ksRatePerMin; i++ {
		r, _ := f.request(t, f.now.Unix())
		if w := f.post(t, r, "203.0.113.7"); w.Code != 200 {
			t.Fatalf("request %d: %d", i, w.Code)
		}
	}
	r, _ := f.request(t, f.now.Unix())
	if w := f.post(t, r, "203.0.113.7"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("over the limit: %d, want 429", w.Code)
	}
}

func TestKeyserverClientIPHeader(t *testing.T) {
	f := newKSFixture(t)
	f.srv.cfg().ClientIPHeader = "X-Forwarded-For"
	req, _ := f.request(t, f.now.Unix())
	body, _ := json.Marshal(req)

	// From loopback (the local proxy) the header is believed.
	r := httptest.NewRequest(http.MethodPost, "/v1/unwrap", bytes.NewReader(body))
	r.RemoteAddr = "127.0.0.1:5000"
	r.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.1")
	w := httptest.NewRecorder()
	f.srv.handleUnwrap(w, r)
	if w.Code != 200 {
		t.Fatalf("via proxy: %d", w.Code)
	}

	// From anywhere else it is ignored.
	req2, _ := f.request(t, f.now.Unix())
	body, _ = json.Marshal(req2)
	r = httptest.NewRequest(http.MethodPost, "/v1/unwrap", bytes.NewReader(body))
	r.RemoteAddr = "198.51.100.1:5000"
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	w = httptest.NewRecorder()
	f.srv.handleUnwrap(w, r)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "Forbidden") {
		t.Fatalf("spoofed header from outside: %d", w.Code)
	}
}

func TestKeyserverEventsAndStats(t *testing.T) {
	f := newKSFixture(t)
	f.srv.cfg().EventsFile = t.TempDir() + "/events.jsonl"

	req, _ := f.request(t, f.now.Unix())
	req.Why = "cold"
	f.post(t, req, "203.0.113.7")
	req2, _ := f.request(t, f.now.Unix())
	req2.Why = "refresh"
	f.post(t, req2, "203.0.113.7")
	req3, _ := f.request(t, f.now.Unix()) // no "why": an older client
	f.post(t, req3, "203.0.113.7")
	bad, _ := f.request(t, f.now.Unix())
	bad.Why = "cold"
	f.post(t, bad, "198.51.100.1") // wrong address: refused, still recorded
	junk := ksRequest{App: ""}
	f.post(t, junk, "198.51.100.2") // no app: journal only

	b, err := os.ReadFile(f.srv.cfg().EventsFile)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(b), "\n"); n != 4 {
		t.Fatalf("recorded %d events, want 4 (the no-app request is not recorded):\n%s", n, b)
	}
	if strings.Contains(string(b), req.Wrap) || strings.Contains(string(b), req.Sig) {
		t.Fatal("events must not carry the wrap or signature")
	}
	var out bytes.Buffer
	if err := ksPrintStats(&out, b, f.now.UTC(), 14); err != nil {
		t.Fatal(err)
	}
	day := f.now.UTC().Format("2006-01-02")
	for _, want := range []string{
		"pilot  (last cold start: " + f.now.UTC().Format("2006-01-02 15:04 UTC") + ")",
		day + "     1        1      1        1",
		"refused 1x: address not allowed",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("stats missing %q:\n%s", want, out.String())
		}
	}
}

// ─── delegated-device request auth (task #2629) ──────────────────────────────

// fakeSK is a FIDO-style ssh.Signer built in software: it signs exactly what an
// sk-ecdsa / sk-ed25519 authenticator signs (sha256(app)||flags||counter||sha256(msg),
// OpenSSH PROTOCOL.u2f), so the server's verifier can be tested without a dongle.
type fakeSK struct {
	pub  ssh.PublicKey
	app  string
	sign func(data []byte) ([]byte, error)
}

func (k fakeSK) PublicKey() ssh.PublicKey { return k.pub }
func (k fakeSK) Sign(_ io.Reader, msg []byte) (*ssh.Signature, error) {
	rest := []byte{0x01, 0, 0, 0, 7} // user present, counter 7
	ah, mh := sha256.Sum256([]byte(k.app)), sha256.Sum256(msg)
	blob, err := k.sign(append(append(ah[:], rest...), mh[:]...))
	if err != nil {
		return nil, err
	}
	return &ssh.Signature{Format: k.pub.Type(), Blob: blob, Rest: rest}, nil
}

func newFakeSKECDSA(t *testing.T) ssh.Signer {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	q := elliptic.Marshal(elliptic.P256(), k.X, k.Y)
	pub, err := ssh.ParsePublicKey(ssh.Marshal(struct {
		T, C string
		Q    []byte
		A    string
	}{
		"sk-ecdsa-sha2-nistp256@openssh.com", "nistp256", q, "ssh:"}))
	if err != nil {
		t.Fatal(err)
	}
	return fakeSK{pub, "ssh:", func(d []byte) ([]byte, error) {
		h := sha256.Sum256(d)
		r, s, err := ecdsa.Sign(rand.Reader, k, h[:])
		if err != nil {
			return nil, err
		}
		return ssh.Marshal(struct{ R, S *big.Int }{r, s}), nil
	}}
}

func newFakeSKEd25519(t *testing.T) ssh.Signer {
	p, k, _ := ed25519.GenerateKey(rand.Reader)
	pub, err := ssh.ParsePublicKey(ssh.Marshal(struct {
		T string
		P []byte
		A string
	}{
		"sk-ssh-ed25519@openssh.com", p, "ssh:"}))
	if err != nil {
		t.Fatal(err)
	}
	return fakeSK{pub, "ssh:", func(d []byte) ([]byte, error) { return ed25519.Sign(k, d), nil }}
}

func deviceSigners(t *testing.T) map[string]ssh.Signer {
	_, ek, _ := ed25519.GenerateKey(rand.Reader)
	ed, _ := ssh.NewSignerFromKey(ek)
	pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	chip, _ := ssh.NewSignerFromKey(pk)
	return map[string]ssh.Signer{"ed25519": ed, "p256": chip, "sk_ecdsa": newFakeSKECDSA(t), "sk_ed25519": newFakeSKEd25519(t)}
}

func TestDeviceAuthForm(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for name, dev := range deviceSigners(t) {
		form, err := deviceAuthForm(dev, "policyPutBlob", now)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(form.Get("device_key")))
		if err != nil || ssh.FingerprintSHA256(pub) != ssh.FingerprintSHA256(dev.PublicKey()) {
			t.Fatalf("%s: device_key does not round-trip: %v", name, err)
		}
		raw, _ := base64.StdEncoding.DecodeString(form.Get("device_sig"))
		sig := new(ssh.Signature)
		if err := ssh.Unmarshal(raw, sig); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		msg := deviceAuthCtx + "policyPutBlob|" + ssh.FingerprintSHA256(pub) + "|1800000000"
		if form.Get("ts") != "1800000000" || pub.Verify([]byte(msg), sig) != nil {
			t.Fatalf("%s: signature is not over %q", name, msg)
		}
		if pub.Verify([]byte(deviceAuthCtx+"getPolicyStatus|"+ssh.FingerprintSHA256(pub)+"|1800000000"), sig) == nil {
			t.Fatalf("%s: auth for one action verifies for another", name)
		}
	}
}
