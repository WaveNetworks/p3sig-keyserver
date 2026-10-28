package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type policyFixture struct {
	root, chip, dongle ssh.Signer
	rootFP             string
	now                time.Time
	caKey              string
}

func newSigner(t *testing.T, ecdsaChip bool) ssh.Signer {
	t.Helper()
	var priv any
	if ecdsaChip { // stands in for a Secure Enclave / TPM P-256 key
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		priv = k
	} else {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		priv = k
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newPolicyFixture(t *testing.T) *policyFixture {
	f := &policyFixture{root: newSigner(t, false), chip: newSigner(t, true), dongle: newSigner(t, false), now: time.Now()}
	f.rootFP = ssh.FingerprintSHA256(f.root.PublicKey())
	f.caKey = authorizedKey(newSigner(t, false).PublicKey()) + " owner-ca"
	return f
}

// signed builds a getSignedPolicy response: both devices delegated, `by` signs.
func (f *policyFixture) signed(t *testing.T, by ssh.Signer, version int64, ca string, revoked ...ssh.Signer) *SignedPolicy {
	t.Helper()
	sp := &SignedPolicy{RootKey: authorizedKey(f.root.PublicKey()), Signer: authorizedKey(by.PublicKey())}
	for _, d := range []ssh.Signer{f.chip, f.dongle} {
		b, err := signDelegation(f.root, Delegation{Account: "7", DeviceKey: authorizedKey(d.PublicKey()), Issued: f.now.Unix()})
		if err != nil {
			t.Fatal(err)
		}
		sp.Chain = append(sp.Chain, b)
	}
	r := Revocations{Account: "7", Version: 1}
	for _, d := range revoked {
		r.Revoked = append(r.Revoked, ssh.FingerprintSHA256(d.PublicKey()))
	}
	rb, err := signRevocations(f.root, r)
	if err != nil {
		t.Fatal(err)
	}
	sp.Revocations = &rb
	p := Policy{Account: "7", Version: version, Issued: f.now.Unix(), KRLExpires: f.now.Add(24 * time.Hour).Unix(),
		CAKeys: []string{ca}, Grants: []PolicyGrant{{Principal: "ops", LoginUser: "root"}}, KRLSpec: "# none"}
	sp.Policy, err = signPolicy(by, p)
	if err != nil {
		t.Fatal(err)
	}
	return sp
}

func TestSignedPolicy_ChipSignedNoSafeAccepted(t *testing.T) {
	f := newPolicyFixture(t)
	for _, dev := range []ssh.Signer{f.chip, f.dongle} {
		p, err := verifySignedPolicy(f.signed(t, dev, 3, f.caKey), f.rootFP, policyState{}, f.now)
		if err != nil {
			t.Fatalf("%s: %v", dev.PublicKey().Type(), err)
		}
		if p.Version != 3 || p.CAKeys[0] != f.caKey {
			t.Fatalf("wrong policy %+v", p)
		}
	}
}

func TestSignedPolicy_TamperedCARejected(t *testing.T) {
	f := newPolicyFixture(t)
	sp := f.signed(t, f.chip, 3, f.caKey)
	raw, _ := base64.StdEncoding.DecodeString(sp.Policy.Payload)
	var p Policy
	_ = json.Unmarshal(raw, &p)
	p.CAKeys = append(p.CAKeys, authorizedKey(newSigner(t, false).PublicKey())+" attacker")
	raw, _ = json.Marshal(p)
	sp.Policy.Payload = base64.StdEncoding.EncodeToString(raw)
	if _, err := verifySignedPolicy(sp, f.rootFP, policyState{}, f.now); err == nil {
		t.Fatal("injected CA accepted")
	}
	// An attacker's own root + device: valid signatures, wrong root.
	evil := newPolicyFixture(t)
	if _, err := verifySignedPolicy(evil.signed(t, evil.chip, 99, "x"), f.rootFP, policyState{}, f.now); err == nil {
		t.Fatal("foreign root accepted")
	}
	// An undelegated device signing under our root.
	stranger := newSigner(t, false)
	if _, err := verifySignedPolicy(f.signed(t, stranger, 3, f.caKey), f.rootFP, policyState{}, f.now); err == nil {
		t.Fatal("undelegated device accepted")
	}
}

func TestSignedPolicy_ReplayRejected(t *testing.T) {
	f := newPolicyFixture(t)
	old := f.signed(t, f.chip, 4, f.caKey)
	if _, err := verifySignedPolicy(old, f.rootFP, policyState{Version: 5}, f.now); err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("older version accepted: %v", err)
	}
	if _, err := verifySignedPolicy(old, f.rootFP, policyState{Version: 1, RevocationsVersion: 2}, f.now); err == nil {
		t.Fatal("older revocation list accepted")
	}
	old.Revocations = nil
	if _, err := verifySignedPolicy(old, f.rootFP, policyState{RevocationsVersion: 1}, f.now); err == nil {
		t.Fatal("stripped revocation list accepted")
	}
}

func TestSignedPolicy_RevokedOrExpiredDeviceRejected(t *testing.T) {
	f := newPolicyFixture(t)
	if _, err := verifySignedPolicy(f.signed(t, f.dongle, 3, f.caKey, f.dongle), f.rootFP, policyState{}, f.now); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked device accepted: %v", err)
	}
	if _, err := verifySignedPolicy(f.signed(t, f.chip, 3, f.caKey, f.dongle), f.rootFP, policyState{}, f.now); err != nil {
		t.Fatalf("other device should still sign: %v", err)
	}
	sp := f.signed(t, f.chip, 3, f.caKey)
	b, _ := signDelegation(f.root, Delegation{Account: "7", DeviceKey: authorizedKey(f.chip.PublicKey()), Expires: f.now.Add(-time.Minute).Unix()})
	sp.Chain = []signedBlob{b}
	if _, err := verifySignedPolicy(sp, f.rootFP, policyState{}, f.now); err == nil {
		t.Fatal("expired delegation accepted")
	}
}

func TestSignedPolicy_StaleKRL(t *testing.T) {
	f := newPolicyFixture(t)
	sp := f.signed(t, f.chip, 3, f.caKey)
	if _, err := verifySignedPolicy(sp, f.rootFP, policyState{}, f.now.Add(25*time.Hour)); err != errStaleKRL {
		t.Fatalf("want errStaleKRL, got %v", err)
	}
}

// End to end through agentPullWith: a good pull lands, then an injected CA,
// a replay and an unsigned downgrade all leave the files untouched.
func TestAgentPull_SignedKeepsOldConfigOnFailure(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not installed")
	}
	f := newPolicyFixture(t)
	var serve any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("action") != "getSignedPolicy" {
			json.NewEncoder(w).Encode(map[string]any{"results": map[string]any{"trusted_user_ca_keys": "evil-unsigned", "grants": []any{}, "krl_spec": ""}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"results": serve})
	}))
	defer srv.Close()
	_, mk, _ := ed25519.GenerateKey(rand.Reader)
	out := t.TempDir()
	caFile := filepath.Join(out, "trusted_user_ca_keys")

	serve = f.signed(t, f.chip, 2, f.caKey)
	if err := agentPullWith(srv.URL, "m1", mk, out, f.rootFP, true); err != nil {
		t.Fatal(err)
	}
	good, _ := os.ReadFile(caFile)
	if !strings.Contains(string(good), "owner-ca") {
		t.Fatalf("CA not written: %q", good)
	}

	evilCA := authorizedKey(newSigner(t, false).PublicKey()) + " attacker"
	tampered := f.signed(t, f.chip, 3, f.caKey)
	tampered.Policy = f.signed(t, newSigner(t, true), 3, evilCA).Policy
	for name, resp := range map[string]any{
		"tampered": tampered,
		"replay":   f.signed(t, f.chip, 1, evilCA),
		"revoked":  f.signed(t, f.chip, 9, evilCA, f.chip),
		"unsigned": map[string]any{},
	} {
		serve = resp
		// rootFP "" + requireSigned false: the saved state alone must keep it mandatory.
		if err := agentPullWith(srv.URL, "m1", mk, out, "", false); err == nil {
			t.Fatalf("%s: pull succeeded", name)
		}
		if now, _ := os.ReadFile(caFile); string(now) != string(good) {
			t.Fatalf("%s: CA file changed to %q", name, now)
		}
	}
}

// A fresh install with --root pinned (no saved state, no --require-signed) must
// refuse a server that answers "no signed policy" instead of falling back to the
// unsigned CA — that fallback is exactly what a MITM would use.
func TestAgentPull_PinnedRootNeverFallsBackToUnsigned(t *testing.T) {
	f := newPolicyFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("action") == "getSignedPolicy" {
			json.NewEncoder(w).Encode(map[string]any{"results": map[string]any{}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"results": map[string]any{"trusted_user_ca_keys": "evil-unsigned", "grants": []any{}, "krl_spec": ""}})
	}))
	defer srv.Close()
	_, mk, _ := ed25519.GenerateKey(rand.Reader)
	out := t.TempDir()
	if err := agentPullWith(srv.URL, "m1", mk, out, f.rootFP, false); err == nil {
		t.Fatal("pull with a pinned root accepted an unsigned policy")
	}
	if _, err := os.Stat(filepath.Join(out, "trusted_user_ca_keys")); err == nil {
		t.Fatal("unsigned CA file was written despite the pinned root")
	}
}
