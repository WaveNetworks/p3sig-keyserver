package main

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func vaultFixture(t *testing.T, files map[string]string) (string, map[string][]byte, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	hashes := map[string]string{}
	served := map[string][]byte{}
	for p, body := range files {
		sum := sha512.Sum384([]byte(body))
		hashes[p] = "sha384-" + base64.StdEncoding.EncodeToString(sum[:])
		served[p] = []byte(body)
	}
	m, _ := json.Marshal(vaultRelease{V: 1, Kind: "p3sig-vault-release-v1", Commit: strings.Repeat("a", 40), BuiltAt: "2026-10-21T00:00:00Z", Files: hashes})
	env, _ := json.Marshal(map[string]string{"manifest": string(m), "sig": base64.StdEncoding.EncodeToString(ed25519.Sign(priv, m))})
	served["vault-release.json"] = env
	return base64.StdEncoding.EncodeToString(pub), served, priv
}

func getter(served map[string][]byte) func(string) ([]byte, error) {
	return func(p string) ([]byte, error) {
		if b, ok := served[p]; ok {
			return b, nil
		}
		return nil, errors.New("404")
	}
}

func TestVaultVerify(t *testing.T) {
	files := map[string]string{"assets/js/p3sig-crypto.js": "crypto", "assets/js/vendor/sodium.js": "sodium"}

	pub, served, _ := vaultFixture(t, files)
	if _, bad, err := verifyVaultRelease(getter(served), pub); err != nil || len(bad) != 0 {
		t.Fatalf("genuine release: err=%v bad=%v", err, bad)
	}

	// Server swaps a vault script: signature still fine, file flagged.
	served["assets/js/p3sig-crypto.js"] = []byte("exfiltrate()")
	if _, bad, err := verifyVaultRelease(getter(served), pub); err != nil || bad["assets/js/p3sig-crypto.js"] == "" {
		t.Fatalf("swapped file not flagged: err=%v bad=%v", err, bad)
	}

	// Server re-signs the manifest with its own key: refused outright.
	_, forged, _ := vaultFixture(t, map[string]string{"assets/js/p3sig-crypto.js": "exfiltrate()"})
	if _, _, err := verifyVaultRelease(getter(forged), pub); err == nil {
		t.Fatal("manifest signed by another key was accepted")
	}

	// Path outside assets/js is never fetched.
	pub2, served2, _ := vaultFixture(t, map[string]string{"../config/config.php": "x"})
	if _, bad, err := verifyVaultRelease(getter(served2), pub2); err != nil || bad["../config/config.php"] == "" {
		t.Fatalf("bad path not flagged: err=%v bad=%v", err, bad)
	}
}

func TestSiteBase(t *testing.T) {
	for in, want := range map[string]string{
		"https://p3sig.com/p3sig/api/index.php": "https://p3sig.com/p3sig",
		"https://p3sig.com/p3sig/api/":          "https://p3sig.com/p3sig",
		"https://p3sig.com/p3sig":               "https://p3sig.com/p3sig",
	} {
		if got := siteBase(in); got != want {
			t.Errorf("siteBase(%q) = %q, want %q", in, got, want)
		}
	}
}
