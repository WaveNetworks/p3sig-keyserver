package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

// softDongle does what a CTAP2 authenticator does for getAssertion: sign
// authenticatorData (sha256(rp) || flags || counter) || clientDataHash, DER.
type softDongle struct {
	k       *ecdsa.PrivateKey
	counter uint32
}

func (d *softDongle) Info() DongleInfo      { return DongleInfo{Product: "soft", Serial: "T1"} }
func (d *softDongle) HasPIN() (bool, error) { return true, nil }
func (d *softDongle) SetPIN(string) error   { return nil }
func (d *softDongle) Credentials(app, _ string) ([]DongleCred, error) {
	return []DongleCred{{App: app, Q: pointQ(&d.k.PublicKey)}}, nil
}
func (d *softDongle) MakeCredential(app, _, _ string) (DongleCred, error) {
	return DongleCred{App: app, Q: pointQ(&d.k.PublicKey)}, nil
}
func (d *softDongle) Assert(c DongleCred, cdh [32]byte, _ string) (Assertion, error) {
	d.counter++
	rp := sha256.Sum256([]byte(c.App))
	ad := append(rp[:], 0x05, 0, 0, 0, 0) // UP|UV
	binary.BigEndian.PutUint32(ad[33:], d.counter)
	h := sha256.Sum256(append(ad, cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, d.k, h[:])
	return Assertion{Flags: 0x05, Counter: d.counter, DERSig: sig}, err
}

func newDongleTestSigner(t *testing.T) ssh.Signer {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	d := &softDongle{k: k}
	c, _ := d.MakeCredential(policyApp, "", "")
	s, err := newDongleSigner(d, c, func() (string, error) { return "1234", nil })
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The binary's own getAssertion encoding is accepted by verifySignedPolicy.
func TestDongleSignerSignedPolicyAccepted(t *testing.T) {
	f := newPolicyFixture(t)
	f.dongle = newDongleTestSigner(t)
	if f.dongle.PublicKey().Type() != skECDSAType {
		t.Fatalf("type %s", f.dongle.PublicKey().Type())
	}
	if _, err := verifySignedPolicy(f.signed(t, f.dongle, 4, f.caKey), f.rootFP, policyState{}, f.now); err != nil {
		t.Fatal(err)
	}
	// and the delegated-device request auth form signs with it too
	if _, err := deviceAuthForm(f.dongle, "getPolicyStatus", f.now); err != nil {
		t.Fatal(err)
	}
}

func TestDongleSignerWrongAppRejected(t *testing.T) {
	f := newPolicyFixture(t)
	s := newDongleTestSigner(t).(*dongleSigner)
	s.cred.App = "ssh:other" // signs for another rp than its public key names
	pub := s.pub
	s.pub, _ = skPublicKey(DongleCred{App: policyApp, Q: s.cred.Q})
	_ = pub
	f.dongle = s
	if _, err := verifySignedPolicy(f.signed(t, f.dongle, 4, f.caKey), f.rootFP, policyState{}, f.now); err == nil {
		t.Fatal("signature over another application accepted")
	}
}

var fastArgon = Argon2Params{MemKiB: 64, Time: 1, Par: 1}

func TestUSBStoreVerifyResumeClone(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	daily, safe := t.TempDir(), t.TempDir()
	os.Mkdir(filepath.Join(daily, "System Volume Information"), 0o755) // OS litter is fine
	if err := storeOnUSB(daily, key, []byte("daily pass"), fastArgon); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(usbKeyPath(daily))
	// resume: same key + passphrase → verified, file untouched
	if err := storeOnUSB(daily, key, []byte("daily pass"), fastArgon); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(usbKeyPath(daily))
	if string(before) != string(after) {
		t.Fatal("resume rewrote the key")
	}
	// a different key never replaces the one on the stick
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if err := storeOnUSB(daily, other, []byte("daily pass"), fastArgon); err == nil {
		t.Fatal("stick with a different key accepted")
	}
	if err := storeOnUSB(daily, key, []byte("wrong"), fastArgon); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	// clone under another passphrase unwraps to the same key
	if err := storeOnUSB(safe, key, []byte("safe pass"), fastArgon); err != nil {
		t.Fatal(err)
	}
	got, err := readUSBKey(safe, []byte("safe pass"))
	if err != nil || !got.Equal(key) {
		t.Fatalf("clone: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(safe, usbDir, usbPubFile)); len(b) == 0 {
		t.Fatal("no PUBLIC-KEY.txt")
	}
}

func TestUSBInterruptedAndUsedDrives(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	d := t.TempDir()
	// interrupted run: the dir and a .partial exist, the key does not
	os.MkdirAll(filepath.Join(d, usbDir), 0o700)
	os.WriteFile(usbKeyPath(d)+".partial", []byte("half"), 0o600)
	if err := storeOnUSB(d, key, []byte("p4ssword"), fastArgon); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(usbKeyPath(d) + ".partial"); err == nil {
		t.Fatal(".partial left behind")
	}
	used := t.TempDir()
	os.WriteFile(filepath.Join(used, "photos.zip"), []byte("x"), 0o644)
	if err := storeOnUSB(used, key, []byte("p4ssword"), fastArgon); err == nil {
		t.Fatal("non-empty drive accepted")
	}
	if _, err := os.Stat(usbKeyPath(used)); err == nil {
		t.Fatal("wrote to a used drive")
	}
}
