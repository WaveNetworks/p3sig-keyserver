//go:build darwin

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"os"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestSignRoundTrip exercises the full chip-key sign path against the real Secure
// Enclave, so it pops a Touch ID prompt and must be opted into:
//
//	P3SIG_TOUCHID_TEST=1 go test -run TestSignRoundTrip -v
//
// It assumes a key created by `p3sig setup --label test` (override with
// P3SIG_TOUCHID_LABEL). It signs a message and verifies the signature against the
// exported public key — proving Sign + the agent's DER normalization are correct.
func TestSignRoundTrip(t *testing.T) {
	if os.Getenv("P3SIG_TOUCHID_TEST") == "" {
		t.Skip("interactive (Touch ID) — set P3SIG_TOUCHID_TEST=1 to run")
	}
	label := os.Getenv("P3SIG_TOUCHID_LABEL")
	if label == "" {
		label = "test"
	}
	ks := secureEnclave{}

	line, err := ks.PublicKey(label)
	if err != nil {
		t.Fatalf("PublicKey(%q): %v", label, err)
	}
	sshPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	cryptoPub, ok := sshPub.(ssh.CryptoPublicKey)
	if !ok {
		t.Fatal("public key is not a CryptoPublicKey")
	}
	ecPub, ok := cryptoPub.CryptoPublicKey().(*ecdsa.PublicKey)
	if !ok || ecPub.Curve != elliptic.P256() {
		t.Fatalf("expected ECDSA P-256 public key, got %T", cryptoPub.CryptoPublicKey())
	}

	msg := []byte("p3sig chip-key sign round-trip")
	t.Log("approve the Touch ID prompt now...")
	raw, err := ks.Sign(label, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Same normalization the shared agent applies (Secure Enclave returns DER).
	r, s, err := normalizeECDSASig(raw)
	if err != nil {
		t.Fatalf("normalize signature: %v", err)
	}
	h := sha256.Sum256(msg)
	if !ecdsa.Verify(ecPub, h[:], r, s) {
		t.Fatalf("signature failed to verify (r=%s s=%s)", r, s)
	}
	t.Log("OK: Secure Enclave signature verified against the exported public key")
}
