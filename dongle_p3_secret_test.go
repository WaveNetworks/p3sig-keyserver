package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

// The sealed-box opener fed by an X25519 shared secret matches box.OpenAnonymous.
func TestOpenSealedBoxShared(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ct, err := sealForKey("hunter2", base64.StdEncoding.EncodeToString(pub))
	if err != nil {
		t.Fatal(err)
	}
	xp, _ := ed25519PubToX25519(pub)
	xs := ed25519PrivToX25519(priv)
	unseal := func(e [32]byte) ([32]byte, error) {
		var o [32]byte
		s, err := curve25519.X25519(xs[:], e[:])
		copy(o[:], s)
		return o, err
	}
	got, err := openSealedBoxShared(ct, *xp, unseal)
	if err != nil || string(got) != "hunter2" {
		t.Fatalf("got %q, %v", got, err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	xo, _ := ed25519PubToX25519(other)
	if _, err := openSealedBoxShared(ct, *xo, unseal); err == nil {
		t.Fatal("opened with the wrong recipient key")
	}
}

// `p3sig secret get NAME --with dongle`: the request is signed on the dongle and
// the secret is unsealed there (firmware proto.c via dongle_sim); no vault key on
// the host, and without the phone's unlock share nothing opens.
func TestDongleP3SecretGet(t *testing.T) {
	d := startSim(t)
	dir := t.TempDir()
	t.Setenv("P3SIG_DONGLE_RECORD", dir+"/cfg/dongle-p3.json")
	t.Setenv("P3SIG_DONGLE_UNLOCK", "")
	p3OpenBLE = func(string) (DongleLink, io.Closer, error) {
		d.do('C', nil)
		return simLink{d, 'B'}, io.NopCloser(nil), nil
	}
	defer func() { p3OpenBLE = OpenDongleBLE }()
	p, err := p3Pair(simLink{d, 'U'}, "AA:BB:CC:DD:EE:FF", dir+"/phone/unlock.key", nil)
	if err != nil {
		t.Fatal(err)
	}
	vaultPub := base64.StdEncoding.EncodeToString(p.VaultEd)
	seal := func(s string) string {
		c, err := sealForKey(s, vaultPub)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	otherSeal, _ := sealForKey(`{"label":"db"}`, base64.StdEncoding.EncodeToString(other))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		ts, _ := strconv.ParseInt(r.Form.Get("ts"), 10, 64)
		sig, _ := base64.StdEncoding.DecodeString(r.Form.Get("signature"))
		if r.Form.Get("action") != "getMySecrets" || r.Form.Get("pubkey") != vaultPub ||
			time.Since(time.Unix(ts, 0)) > time.Minute ||
			!ed25519.Verify(p.VaultEd, []byte(vaultPub+"|"+r.Form.Get("ts")), sig) {
			http.Error(w, `{"error":"bad signature"}`, 401)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"results": map[string]any{"secrets": []map[string]string{
			{"encrypted_data": seal("not this"), "encrypted_meta": otherSeal},
			{"encrypted_data": seal("wrong"), "encrypted_meta": seal(`{"label":"api"}`)},
			{"encrypted_data": seal("s3cret-db"), "encrypted_meta": seal(`{"label":"db"}`)},
		}}})
	}))
	defer srv.Close()

	rec, err := loadP3Record()
	if err != nil {
		t.Fatal(err)
	}
	s, ed, x, c, err := openP3Session(rec)
	if err != nil {
		t.Fatal(err)
	}
	v, err := dongleSecretFetch(s, ed, x, srv.URL, "db")
	c.Close()
	if err != nil || v != "s3cret-db" {
		t.Fatalf("got %q, %v", v, err)
	}
	if _, err := os.Stat(dir + "/cfg/vault.key"); err == nil {
		t.Fatal("a vault key file appeared on the host")
	}
	// Without the phone's unlock share the dongle stays locked: no session.
	os.Remove(dir + "/phone/unlock.key")
	if _, _, _, _, err := openP3Session(rec); err == nil {
		t.Fatal("dongle opened without the unlock share")
	}
}
