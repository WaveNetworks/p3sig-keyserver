package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Sign-then-seal (task #2598): a value sealed by anyone but a delegated device is
// rejected, and a genuine envelope can't be swapped, re-targeted or revoked-signed.
func TestSignedSecretBundles(t *testing.T) {
	f := newPolicyFixture(t)
	mPub, mPriv, _ := ed25519.GenerateKey(rand.Reader)
	mPubB64 := base64.StdEncoding.EncodeToString(mPub)
	me := machineKeyFP(mPub)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)

	good := SignedSecret{Account: "7", SecretID: "s1", Name: "DB_PASS", Value: "hunter2", Recipient: me, Issued: f.now.Unix()}
	trustFor := func(revoked ...ssh.Signer) *secretTrust {
		tr, err := newSecretTrust(f.signed(t, f.chip, 1, f.caKey, revoked...), f.rootFP)
		if err != nil {
			t.Fatal(err)
		}
		return tr
	}
	open := func(by ssh.Signer, s SignedSecret, id, name string, tr *secretTrust) (string, error) {
		ct, err := sealSignedSecret(by, s, mPubB64)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := openSealedBox(ct, mPriv)
		if err != nil {
			t.Fatal(err)
		}
		return openSecretValue(plain, id, name, me, tr, f.now)
	}

	if v, err := open(f.chip, good, "s1", "DB_PASS", trustFor()); err != nil || v != "hunter2" {
		t.Fatalf("chip-signed secret: %q %v", v, err)
	}
	if v, err := open(f.dongle, good, "s1", "DB_PASS", trustFor()); err != nil || v != "hunter2" {
		t.Fatalf("dongle-signed secret: %q %v", v, err)
	}

	reject := map[string]func() (string, error){
		"undelegated signer (server-forged)": func() (string, error) { return open(newSigner(t, false), good, "s1", "DB_PASS", trustFor()) },
		"revoked device":                     func() (string, error) { return open(f.dongle, good, "s1", "DB_PASS", trustFor(f.dongle)) },
		"served under another secret id":     func() (string, error) { return open(f.chip, good, "s2", "DB_PASS", trustFor()) },
		"served under another name":          func() (string, error) { return open(f.chip, good, "s1", "API_KEY", trustFor()) },
		"other account": func() (string, error) {
			s := good
			s.Account = "8"
			return open(f.chip, s, "s1", "DB_PASS", trustFor())
		},
		"re-sealed from another machine": func() (string, error) {
			s := good
			s.Recipient = machineKeyFP(otherPub)
			return open(f.chip, s, "s1", "DB_PASS", trustFor())
		},
		"signed but no root pinned": func() (string, error) { return open(f.chip, good, "s1", "DB_PASS", nil) },
	}
	for name, fn := range reject {
		if v, err := fn(); err == nil || errors.Is(err, errUnsignedSecret) || v != "" {
			t.Errorf("%s: accepted (%q, %v)", name, v, err)
		}
	}

	// Tampered envelope bytes never fall back to the raw plaintext.
	ct, _ := sealSignedSecret(f.chip, good, mPubB64)
	plain, _ := openSealedBox(ct, mPriv)
	if v, err := openSecretValue(strings.Replace(plain, "\"secret\"", "\"secret\" ", 1)+"x", "s1", "DB_PASS", me, trustFor(), f.now); err == nil || v != "" {
		t.Errorf("tampered envelope accepted: %q", v)
	}

	// Legacy plain values still open, flagged unsigned.
	if v, err := openSecretValue("plain-old", "s1", "DB_PASS", me, trustFor(), f.now); !errors.Is(err, errUnsignedSecret) || v != "plain-old" {
		t.Errorf("legacy value: %q %v", v, err)
	}

	// A wrong pinned root refuses the whole chain.
	if _, err := newSecretTrust(f.signed(t, f.chip, 1, f.caKey), "SHA256:wrong"); err == nil {
		t.Error("wrong root accepted")
	}
}
