package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
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

	// --require-signed: a legacy plain value is refused; a signed one still opens.
	if v, u, err := acceptSecretValue("plain-old", "s1", "DB_PASS", me, trustFor(), f.now, false); err != nil || !u || v != "plain-old" {
		t.Errorf("legacy value without --require-signed: %q %v %v", v, u, err)
	}
	if v, _, err := acceptSecretValue("plain-old", "s1", "DB_PASS", me, trustFor(), f.now, true); err == nil || v != "" {
		t.Errorf("legacy value accepted with --require-signed: %q", v)
	}
	if v, u, err := acceptSecretValue(plain, "s1", "DB_PASS", me, trustFor(), f.now, true); err != nil || u || v != "hunter2" {
		t.Errorf("signed value with --require-signed: %q %v %v", v, u, err)
	}

	// A wrong pinned root refuses the whole chain.
	if _, err := newSecretTrust(f.signed(t, f.chip, 1, f.caKey), "SHA256:wrong"); err == nil {
		t.Error("wrong root accepted")
	}
}

// `p3sig secret reseal` (task #2598): every machine copy is replaced by a signed
// envelope the agent verifies; a missing own-key copy is sealed plain; an
// undelegated device is refused before anything is uploaded.
func TestSecretResealSigns(t *testing.T) {
	f := newPolicyFixture(t)
	vPub, vPriv, _ := ed25519.GenerateKey(rand.Reader)
	v2Pub, v2Priv, _ := ed25519.GenerateKey(rand.Reader)
	mPub, mPriv, _ := ed25519.GenerateKey(rand.Reader)
	b64 := base64.StdEncoding.EncodeToString
	own, err := sealSecretFor("hunter2", secretMeta{Label: "DB_PASS"}, "KU1", b64(vPub))
	if err != nil {
		t.Fatal(err)
	}
	var saved []resealCopy
	fake := func(dev ssh.Signer) policyCall {
		return func(action string, extra url.Values, v any) error {
			var body string
			switch action {
			case "getPolicyStatus":
				body = `{"account":"7","delegations":[{"device_fp":"` + ssh.FingerprintSHA256(f.chip.PublicKey()) + `"}]}`
			case "getMyVaultKeys":
				body = `{"keys":[{"key_id":"KU1"},{"key_id":"KU2"}]}`
			case "getResealWork":
				if extra.Get("resign") != "1" {
					t.Errorf("getResealWork without resign=1")
				}
				w, _ := json.Marshal(map[string]any{"work": []any{map[string]any{
					"secret_id": "s1",
					"missing":   []any{map[string]string{"key_id": "KM1", "public_key": b64(mPub)}, map[string]string{"key_id": "KU2", "public_key": b64(v2Pub)}},
					"copies":    map[string]any{"KU1": map[string]string{"encrypted_data": own.Enc, "encrypted_meta": own.Meta}},
				}}})
				body = string(w)
			case "saveResealed":
				return json.Unmarshal([]byte(extra.Get("sealed_copies")), &saved)
			default:
				t.Fatalf("unexpected action %s", action)
			}
			return json.Unmarshal([]byte(body), v)
		}
	}

	if _, _, err := secretReseal(fake(f.dongle), vPriv, f.dongle, f.now); err == nil || saved != nil {
		t.Fatalf("undelegated device allowed to reseal (%v, %d uploaded)", err, len(saved))
	}
	signed, plain, err := secretReseal(fake(f.chip), vPriv, f.chip, f.now)
	if err != nil || signed != 1 || plain != 1 || len(saved) != 2 {
		t.Fatalf("reseal: signed=%d plain=%d uploaded=%d err=%v", signed, plain, len(saved), err)
	}
	trust, err := newSecretTrust(f.signed(t, f.chip, 1, f.caKey), f.rootFP)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range saved {
		switch c.KeyID {
		case "KM1":
			name, _ := openSecretName(c.Meta, mPriv)
			p, _ := openSealedBox(c.Enc, mPriv)
			if v, err := openSecretValue(p, c.SecretID, name.Label, machineKeyFP(mPub), trust, f.now); err != nil || v != "hunter2" {
				t.Errorf("machine copy does not verify: %q %v", v, err)
			}
		case "KU2":
			if p, _ := openSealedBox(c.Enc, v2Priv); p != "hunter2" {
				t.Errorf("own-key copy should be plain, got %q", p)
			}
		}
	}
}
