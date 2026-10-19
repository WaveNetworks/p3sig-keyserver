//go:build linux

package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"os"
	"testing"
)

// Runs against the real TPM; skipped where there is none (CI, the XPS).
// On nokemo2: P3SIG_TPM_TEST=1 go test -run TestLinuxTPM ./...
func TestLinuxTPMRoundTrip(t *testing.T) {
	if os.Getenv("P3SIG_TPM_TEST") != "1" {
		t.Skip("set P3SIG_TPM_TEST=1 on a machine with a TPM")
	}
	t.Setenv("P3SIG_TPM_DIR", t.TempDir())
	ks, err := openKeystore()
	if err != nil {
		t.Fatal(err)
	}
	const label = "p3sig-test"
	line, err := ks.Create(label)
	if err != nil {
		t.Fatal(err)
	}
	defer ks.Delete(label)
	if again, err := ks.PublicKey(label); err != nil || again != line {
		t.Fatalf("PublicKey = %q, %v; want %q", again, err, line)
	}
	if _, err := ks.Create(label); err == nil {
		t.Fatal("Create over an existing key should fail")
	}

	point, err := ks.CreateAgreementKey(label)
	if err != nil {
		t.Fatal(err)
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), point)
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

	msg := []byte("p3sig key server")
	sig, err := ks.Sign(label, msg)
	if err != nil {
		t.Fatal(err)
	}
	r, s, err := normalizeECDSASig(sig)
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(msg)
	if !ecdsa.Verify(pub, d[:], r, s) {
		t.Fatal("TPM signature does not verify with the key's public point")
	}

	peer, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpmShared, err := ks.Agree(label, peer.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	chipPub, err := ecdh.P256().NewPublicKey(point)
	if err != nil {
		t.Fatal(err)
	}
	swShared, err := peer.ECDH(chipPub)
	if err != nil {
		t.Fatal(err)
	}
	if new(big.Int).SetBytes(tpmShared).Cmp(new(big.Int).SetBytes(swShared)) != 0 {
		t.Fatalf("ECDH mismatch: tpm %x, software %x", tpmShared, swShared)
	}

	if err := ks.Delete(label); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.PublicKey(label); err == nil {
		t.Fatal("key still readable after Delete")
	}
}
