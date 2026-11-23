package main

import (
	"bufio"
	"crypto/aes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/xts"
)

// fat16Image builds a tiny FAT16 filesystem whose root holds a volume label, a
// deleted entry and fileName (long name + 8.3 alias) with content.
func fat16Image(t *testing.T, fileName string, content []byte) []byte {
	const sectors, spc, reserved, nfats, fatSz, rootEnt = 8192, 4, 1, 2, 8, 512
	img := make([]byte, sectors*512)
	b := img[:512]
	copy(b[3:], "MSDOS5.0")
	binary.LittleEndian.PutUint16(b[11:], 512)
	b[13] = spc
	binary.LittleEndian.PutUint16(b[14:], reserved)
	b[16] = nfats
	binary.LittleEndian.PutUint16(b[17:], rootEnt)
	binary.LittleEndian.PutUint16(b[19:], sectors)
	b[21] = 0xF8
	binary.LittleEndian.PutUint16(b[22:], fatSz)
	copy(b[54:], "FAT16   ")
	b[510], b[511] = 0x55, 0xAA
	for i := 0; i < nfats; i++ { // cluster 2 = end of chain
		fat := img[(reserved+i*fatSz)*512:]
		binary.LittleEndian.PutUint16(fat[0:], 0xFFF8)
		binary.LittleEndian.PutUint16(fat[2:], 0xFFFF)
		binary.LittleEndian.PutUint16(fat[4:], 0xFFFF)
	}
	root := img[(reserved+nfats*fatSz)*512:]
	ent := func(i int) []byte { return root[i*32 : i*32+32] }
	copy(ent(0), "P3SIG-DAILY")
	ent(0)[11] = 0x08 // volume label
	copy(ent(1), "\xE5OLD    TXT")
	// long name, last piece first
	u := []uint16{}
	for _, r := range fileName {
		u = append(u, uint16(r))
	}
	u = append(u, 0)
	for len(u)%13 != 0 {
		u = append(u, 0xFFFF)
	}
	pieces := len(u) / 13
	offs := []int{1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30}
	for p := pieces; p >= 1; p-- {
		e := ent(2 + pieces - p)
		e[0] = byte(p)
		if p == pieces {
			e[0] |= 0x40
		}
		e[11] = 0x0F
		for j, o := range offs {
			binary.LittleEndian.PutUint16(e[o:], u[(p-1)*13+j])
		}
	}
	e := ent(2 + pieces)
	copy(e, "P3SIG-~1KEY")
	e[11] = 0x20
	binary.LittleEndian.PutUint16(e[26:], 2)
	binary.LittleEndian.PutUint32(e[28:], uint32(len(content)))
	dataStart := (reserved + nfats*fatSz + rootEnt*32/512) * 512
	copy(img[dataStart:], content)
	return img
}

// veraCryptContainer wraps img the way VeraCrypt does for AES / SHA-512 / PIM 0.
func veraCryptContainer(t *testing.T, img []byte, pass string) []byte {
	const dataOff = 131072
	salt := make([]byte, 64)
	rand.Read(salt)
	mk := make([]byte, 64)
	rand.Read(mk)
	h := make([]byte, 448)
	copy(h, "VERA")
	binary.BigEndian.PutUint16(h[4:], 5)
	binary.BigEndian.PutUint16(h[6:], 0x010b)
	binary.BigEndian.PutUint64(h[36:], uint64(len(img)))
	binary.BigEndian.PutUint64(h[44:], dataOff)
	binary.BigEndian.PutUint64(h[52:], uint64(len(img)))
	binary.BigEndian.PutUint32(h[64:], 512)
	copy(h[192:], mk)
	binary.BigEndian.PutUint32(h[8:], crc32.ChecksumIEEE(h[192:448]))
	binary.BigEndian.PutUint32(h[188:], crc32.ChecksumIEEE(h[:188]))
	hc, _ := xts.NewCipher(aes.NewCipher, pbkdf2.Key([]byte(pass), salt, vcIterations, 64, sha512.New))
	out := make([]byte, dataOff+len(img))
	copy(out, salt)
	hc.Encrypt(out[64:512], h, 0)
	dc, _ := xts.NewCipher(aes.NewCipher, mk)
	for i := 0; i < len(img)/512; i++ {
		dc.Encrypt(out[dataOff+i*512:dataOff+(i+1)*512], img[i*512:(i+1)*512], uint64(dataOff/512+i))
	}
	return out
}

// legacyStick writes an old-format stick (container + PUBLIC-KEY.txt) for key.
func legacyStick(t *testing.T, dir string, key ed25519.PrivateKey, pass string) {
	os.MkdirAll(dir, 0o700)
	img := fat16Image(t, vcKeyName, []byte(base64.StdEncoding.EncodeToString(key)+"\n"))
	if err := os.WriteFile(filepath.Join(dir, vcContainerFile), veraCryptContainer(t, img, pass), 0o600); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, usbPubFile), []byte("p3sig vault + policy-root PUBLIC key (safe to share):\n"+
		pubB64(key)+"\n\nThe private key is inside p3sig-vault.hc (VeraCrypt).\n"), 0o644)
	if d := os.Getenv("P3SIG_VC_DUMP"); d != "" { // cross-check with cryptsetup tcryptDump --veracrypt
		os.WriteFile(d, veraCryptContainer(t, img, pass), 0o600)
	}
}

func TestReadVCKey(t *testing.T) {
	k := docKey(t)
	dir := filepath.Join(t.TempDir(), "P3SIG-DAILY")
	legacyStick(t, dir, k, "correct horse")
	got, err := readVCKey(filepath.Join(dir, vcContainerFile), []byte("correct horse"))
	if err != nil || !got.Equal(k) {
		t.Fatalf("readVCKey = %v", err)
	}
	if _, err := readVCKey(filepath.Join(dir, vcContainerFile), []byte("wrong")); !errors.Is(err, errVCPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
}

// TestUSBMigrate: the key comes out of the container, lands next to it in the
// usb: format on the same stick, unwraps to the same key; the .hc is untouched
// until --finish; a stick whose PUBLIC-KEY.txt disagrees is refused.
func TestUSBMigrate(t *testing.T) {
	k := docKey(t)
	root := t.TempDir()
	daily, safe := filepath.Join(root, "P3SIG-DAILY"), filepath.Join(root, "P3SIG-SAFE")
	legacyStick(t, daily, k, "vc-pass-123")
	legacyStick(t, safe, k, "vc-pass-123")
	hcBefore, _ := os.ReadFile(filepath.Join(daily, vcContainerFile))
	if _, err := usbState(daily); err == nil {
		t.Fatal("plain usbState must still refuse a used stick")
	}
	t.Setenv("P3SIG_PASSPHRASE", "vc-pass-123")
	in := bufio.NewReader(strings.NewReader(""))
	for _, d := range []string{daily, safe} {
		if err := cmdUSBMigrate(map[string]string{"drive": d}, in); err != nil {
			t.Fatalf("migrate %s: %v", d, err)
		}
		got, err := readUSBKey(d, []byte("vc-pass-123"))
		if err != nil || !got.Equal(k) {
			t.Fatalf("%s new format: %v", d, err)
		}
	}
	if hc, _ := os.ReadFile(filepath.Join(daily, vcContainerFile)); string(hc) != string(hcBefore) {
		t.Fatal("migrate changed the VeraCrypt container")
	}
	if err := cmdUSBMigrate(map[string]string{"drive": daily}, in); err != nil { // rerun = check only
		t.Fatalf("rerun: %v", err)
	}

	// doctor sees both sticks, migrated with the container still there
	st := findSticks(map[string]string{"drive": daily + "," + safe})
	if len(st) != 2 || st[0].Format != "usb" || !st[0].Legacy {
		t.Fatalf("doctor sticks %+v", st)
	}

	// mismatched PUBLIC-KEY.txt → refused, nothing written
	bad := filepath.Join(root, "P3SIG-OTHER")
	legacyStick(t, bad, k, "vc-pass-123")
	os.WriteFile(filepath.Join(bad, usbPubFile), []byte(pubB64(docKey(t))+"\n"), 0o644)
	if err := cmdUSBMigrate(map[string]string{"drive": bad}, in); err == nil || !strings.Contains(err.Error(), "not migrating") {
		t.Fatalf("mismatch: %v", err)
	}
	if _, err := os.Stat(usbKeyPath(bad)); err == nil {
		t.Fatal("a refused stick got a key file")
	}
}

func TestUSBMigrateFinishCheck(t *testing.T) {
	fx, _, k := healthy(t)
	root := t.TempDir()
	mk := func(name string) doctorStick {
		d := filepath.Join(root, name)
		os.MkdirAll(d, 0o700)
		os.WriteFile(filepath.Join(d, vcContainerFile), []byte("x"), 0o600)
		return doctorStick{Drive: d, Label: stickLabel(d), Format: "usb", FP: keyFPOf(k), Key: k, Legacy: true}
	}
	daily, safe := mk("P3SIG-DAILY"), mk("P3SIG-SAFE")
	hcs, _, err := usbMigrateFinishCheck([]doctorStick{daily, safe}, fx.call, time.Now())
	if err != nil || len(hcs) != 2 {
		t.Fatalf("finish = %v, %v", hcs, err)
	}
	if _, _, err := usbMigrateFinishCheck([]doctorStick{daily}, fx.call, time.Now()); err == nil || !strings.Contains(err.Error(), "BOTH") {
		t.Fatalf("one stick: %v", err)
	}
	old := safe
	old.Format = "veracrypt"
	if _, _, err := usbMigrateFinishCheck([]doctorStick{daily, old}, fx.call, time.Now()); err == nil || !strings.Contains(err.Error(), "not migrated") {
		t.Fatalf("unmigrated: %v", err)
	}
	fx.keys = []ed25519.PrivateKey{docKey(t)} // the account doesn't know the stick key
	if _, r, err := usbMigrateFinishCheck([]doctorStick{daily, safe}, fx.call, time.Now()); err == nil || r.SticksMatch {
		t.Fatalf("doctor gate: %v", err)
	}
}
