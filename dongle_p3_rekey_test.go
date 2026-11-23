package main

// `p3sig dongle rekey` against the firmware's own proto.c (dongle_sim, task #2829):
// the unlock key (and the host Noise key) rotate, the vault key does not.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"os"
	"strings"
	"testing"
)

func setupRekeySim(t *testing.T) (*simDongle, string, *DonglePairing) {
	d := startSim(t)
	dir := t.TempDir()
	t.Setenv("P3SIG_DONGLE_RECORD", dir+"/cfg/dongle-p3.json")
	t.Setenv("P3SIG_DONGLE_UNLOCK", "")
	p3OpenBLE = func(string) (DongleLink, io.Closer, error) {
		d.do('C', nil)
		return simLink{d, 'B'}, io.NopCloser(nil), nil
	}
	t.Cleanup(func() { p3OpenBLE = OpenDongleBLE })
	p, err := p3Pair(simLink{d, 'U'}, "AA:BB:CC:DD:EE:FF", dir+"/phone/unlock.key", nil)
	if err != nil {
		t.Fatal(err)
	}
	return d, dir, p
}

func press(d *simDongle) func(int) bool {
	return func(i int) bool { d.do('P', nil); return i == 0 }
}

func signsAsVault(t *testing.T, want ed25519.PublicKey) {
	t.Helper()
	s, err := loadDongleSigner("")
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("policy after rekey")
	sig, err := s.Sign(rand.Reader, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(want, msg, sig.Blob) {
		t.Fatal("signature is not by the paired vault key")
	}
}

func TestDongleP3Rekey(t *testing.T) {
	d, dir, p := setupRekeySim(t)
	oldKey, _ := os.ReadFile(dir + "/phone/unlock.key")
	_, flashBefore, _ := d.do('F', nil)

	// Without a press the dongle refuses and the host keeps the old key.
	if _, _, err := p3Rekey("", false, func(int) bool { return false }); err == nil ||
		!strings.Contains(err.Error(), "OLD unlock key") {
		t.Fatalf("rekey without a press: %v", err)
	}
	if cur, _ := os.ReadFile(dir + "/phone/unlock.key"); !bytes.Equal(cur, oldKey) {
		t.Fatal("refused rekey changed the unlock key file")
	}
	if _, err := os.Stat(dir + "/phone/unlock.key.new.unused"); err != nil {
		t.Fatal("the unused new key was not set aside:", err)
	}
	if rec, _ := loadP3Record(); rec.NextUnlockPath != "" {
		t.Fatal("pending rekey left in the record after a rollback")
	}
	signsAsVault(t, p.VaultEd)

	// With the press: same vault key, new unlock key in place, old one retired.
	ed, path, err := p3Rekey("", false, press(d))
	if err != nil {
		t.Fatal(err)
	}
	if !ed.Equal(p.VaultEd) || path != dir+"/phone/unlock.key" {
		t.Fatalf("rekey: vault key changed or wrong path %s", path)
	}
	newKey, _ := os.ReadFile(path)
	if bytes.Equal(newKey, oldKey) {
		t.Fatal("the unlock key file did not change")
	}
	if old, err := os.ReadFile(path + ".old"); err != nil || !bytes.Equal(old, oldKey) {
		t.Fatal("old key not kept as .old:", err)
	}
	signsAsVault(t, p.VaultEd)
	t.Setenv("P3SIG_DONGLE_UNLOCK", path+".old")
	if _, err := loadDongleSigner(""); err == nil || !p3IsStatus(err, p3StAuth) {
		t.Fatalf("old unlock key: want refused, got %v", err)
	}
	t.Setenv("P3SIG_DONGLE_UNLOCK", "")

	// The flash dump changed (new nonce + ciphertext) and still leaks nothing.
	_, flash, _ := d.do('F', nil)
	nk, _ := readUnlockKey(path)
	ok, _ := readUnlockKey(path + ".old")
	if bytes.Equal(flash, flashBefore) || bytes.Contains(flash, nk[:]) || bytes.Contains(flash, ok[:]) {
		t.Fatal("flash after rekey: unchanged, or holds an unlock key")
	}
	if _, staged, _ := d.do('G', nil); len(staged) != 0 {
		t.Fatal("staging slot not erased after rekey")
	}

	// --unlock-out next to the record is refused; elsewhere + a new host key works.
	if _, _, err := p3Rekey(dir+"/cfg/u.key", true, press(d)); err == nil {
		t.Fatal("unlock key next to the record accepted")
	}
	rec0, _ := loadP3Record()
	ed, path2, err := p3Rekey(dir+"/stick/unlock.key", true, press(d))
	if err != nil {
		t.Fatal(err)
	}
	rec1, _ := loadP3Record()
	if !ed.Equal(p.VaultEd) || path2 != dir+"/stick/unlock.key" || rec1.UnlockPath != path2 ||
		rec1.HostSK == rec0.HostSK || rec1.NextHostSK != "" {
		t.Fatalf("rekey --new-host-key: record %+v", rec1)
	}
	if _, err := os.Stat(path + ".old.2"); err != nil {
		t.Fatal("second rotation did not keep the previous key as .old.2:", err)
	}
	signsAsVault(t, p.VaultEd)
	oldHost, _ := b64to32(rec0.HostSK, "old host")
	static, _ := b64to32(rec0.DongleStatic, "static")
	d.do('C', nil)
	if _, err := OpenDongleSession(simLink{d, 'B'}, oldHost, static); err == nil {
		t.Fatal("old host key still completes the handshake")
	}

	// A reboot keeps it (the record is in the sim's flash).
	d.do('R', nil)
	signsAsVault(t, p.VaultEd)
}

// The dongle switched but the host crashed before retiring the old key:
// `dongle rekey` (and every session meanwhile) uses the pending new key.
func TestDongleP3RekeyInterrupted(t *testing.T) {
	d, dir, p := setupRekeySim(t)
	recPath, _ := p3RecordPath()
	rec, _ := loadP3Record()
	oldKey, _ := readUnlockKey(rec.UnlockPath)
	hostSK, _ := b64to32(rec.HostSK, "host")
	var newKey [32]byte
	rand.Read(newKey[:])
	newPath := dir + "/phone/unlock.key.new"
	writeSecretFile(newPath, []byte(base64.StdEncoding.EncodeToString(newKey[:])+"\n"))
	rec.NextUnlockPath, rec.NextUnlockFinal = newPath, rec.UnlockPath
	saveP3Record(recPath, rec)

	s, _, _, _, err := openP3SessionKeys(rec, hostSK, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Rekey(newKey, nil, press(d)); err != nil {
		t.Fatal(err)
	}
	// "Crash" here. The next signing session falls back to the pending key.
	signsAsVault(t, p.VaultEd)
	ed, path, err := p3Rekey("", false, press(d))
	if err != nil || !ed.Equal(p.VaultEd) || path != dir+"/phone/unlock.key" {
		t.Fatalf("settling the interrupted rekey: %v", err)
	}
	if got, _ := readUnlockKey(path); got != newKey {
		t.Fatal("the new key is not in place after settling")
	}
	if r, _ := loadP3Record(); r.NextUnlockPath != "" {
		t.Fatal("pending rekey not cleared")
	}
	signsAsVault(t, p.VaultEd)
}
