package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"testing"
	"time"
)

// TestAddVaultKey: the new key is added with a proof bound to it, every secret the
// old key opens is copied to the new key and opens there, and the re-check passes.
func TestAddVaultKey(t *testing.T) {
	_, old, _ := ed25519.GenerateKey(rand.Reader)
	_, nk, _ := ed25519.GenerateKey(rand.Reader)
	oldPub := base64.StdEncoding.EncodeToString(old.Public().(ed25519.PublicKey))
	newPub := base64.StdEncoding.EncodeToString(nk.Public().(ed25519.PublicKey))
	c, err := sealSecretFor("hunter2", secretMeta{Label: "db"}, "k-old", oldPub)
	if err != nil {
		t.Fatal(err)
	}
	stored := map[string]sealedCopy{}
	call := func(action string, extra url.Values, v any) error {
		switch action {
		case "addMyVaultKey":
			if extra.Get("new_public_key") != newPub {
				return errors.New("wrong new key")
			}
			sig, _ := base64.StdEncoding.DecodeString(extra.Get("add_sig"))
			if !ed25519.Verify(old.Public().(ed25519.PublicKey), []byte("p3sig-add-key|"+newPub+"|"+extra.Get("add_ts")), sig) {
				return errors.New("bad add_sig")
			}
			return json.Unmarshal([]byte(`{"key_id":"k-new"}`), v)
		case "getResealWork":
			work := []map[string]any{}
			if _, ok := stored["s1"]; !ok {
				work = append(work, map[string]any{"secret_id": "s1",
					"missing": []map[string]string{{"key_id": "k-new", "public_key": newPub}},
					"copies":  map[string]map[string]string{"k-old": {"encrypted_data": c.Enc, "encrypted_meta": c.Meta}}})
			}
			b, _ := json.Marshal(map[string]any{"work": work})
			return json.Unmarshal(b, v)
		case "saveResealed":
			var out []resealCopy
			if err := json.Unmarshal([]byte(extra.Get("sealed_copies")), &out); err != nil {
				return err
			}
			for _, o := range out {
				stored[o.SecretID] = o.sealedCopy
			}
			return nil
		}
		return errors.New("unexpected " + action)
	}
	n, err := addVaultKey(call, old, nk, "Vault USB", time.Now())
	if err != nil || n != 1 {
		t.Fatalf("addVaultKey = %d, %v", n, err)
	}
	got := stored["s1"]
	if got.KeyID != "k-new" {
		t.Fatalf("copy addressed to %q", got.KeyID)
	}
	if v, err := openSealedBox(got.Enc, nk); err != nil || v != "hunter2" {
		t.Fatalf("new key opens %q, %v", v, err)
	}
	if m, err := openSecretName(got.Meta, nk); err != nil || m.Label != "db" {
		t.Fatalf("new key name %+v, %v", m, err)
	}
}
