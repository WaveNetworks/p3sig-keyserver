//go:build darwin

package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"os"
	"testing"

	"golang.org/x/crypto/ssh"
)

// sshPubToECDH turns an OpenSSH ECDSA P-256 public key line into an *ecdh.PublicKey,
// so a chip-exported SSH key can be used as the recipient of WrapECDH.
func sshPubToECDH(t *testing.T, line string) *ecdh.PublicKey {
	t.Helper()
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	cpk, ok := pk.(ssh.CryptoPublicKey)
	if !ok {
		t.Fatal("public key is not a CryptoPublicKey")
	}
	ecpub, ok := cpk.CryptoPublicKey().(*ecdsa.PublicKey)
	if !ok || ecpub.Curve != elliptic.P256() {
		t.Fatalf("expected ECDSA P-256 public key, got %T", cpk.CryptoPublicKey())
	}
	k, err := ecpub.ECDH()
	if err != nil {
		t.Fatalf("ecdsa->ecdh: %v", err)
	}
	return k
}

// TestSecureEnclave_AgreeRoundTrip wraps a secret to the chip's public key, then
// unwraps it through the real Enclave via Agree (ECDH) — proving T2's WrapECDH and
// T3's Agree agree on the same shared secret. It creates a throwaway SE key and
// pops Touch ID (create + agree), so it must be opted into:
//
//	P3SIG_HW_TEST=1 go test -run TestSecureEnclave_AgreeRoundTrip -v
func TestSecureEnclave_AgreeRoundTrip(t *testing.T) {
	if os.Getenv("P3SIG_HW_TEST") == "" {
		t.Skip("interactive (Touch ID) — set P3SIG_HW_TEST=1 to run")
	}
	ks := secureEnclave{}
	label := "p3sig-test-agree"
	defer ks.Delete(label)

	t.Log("approve the Touch ID prompt to create the throwaway key...")
	pub, err := ks.Create(label)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	chipPub := sshPubToECDH(t, pub)
	secret := bytes.Repeat([]byte{0x5a}, 32) // stands in for the vault key
	blob, err := WrapECDH(secret, chipPub)
	if err != nil {
		t.Fatalf("WrapECDH: %v", err)
	}

	t.Log("approve the Touch ID prompt to unwrap (ECDH)...")
	got, err := UnwrapECDH(blob, func(eph []byte) ([]byte, error) {
		return ks.Agree(label, eph)
	})
	if err != nil {
		t.Fatalf("UnwrapECDH: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("round-trip mismatch: got %x want %x", got, secret)
	}
	t.Log("OK: WrapECDH -> Enclave Agree -> UnwrapECDH recovered the secret")
}

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
