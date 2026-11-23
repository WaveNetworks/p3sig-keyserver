package main

// veracrypt.go — read the vault key out of an old VeraCrypt p3sig stick with no
// VeraCrypt, no mount and no root (task #2831).
//
// scripts/make-vault-usbs.sh (10-27) made each stick's p3sig-vault.hc with ONE
// fixed recipe: --encryption=AES --hash=SHA-512 --pim=0 --filesystem=FAT, and put
// the key at /p3sig-root.key inside it (base64 of the 64-byte Ed25519 key). That
// is enough to open it here in memory: a VeraCrypt standard volume header is
//
//	0    salt (64)
//	64   header, AES-XTS (data unit 0) under PBKDF2-HMAC-SHA512(passphrase, salt,
//	     500000 iterations — VeraCrypt's count for SHA-512 at PIM 0), 448 bytes:
//	       0 "VERA"  8 CRC32(master keys)  44 data offset  52 data size
//	       64 sector size  188 CRC32(bytes 0..187)  192 master keys (AES-XTS 2×32)
//
// and the data area is AES-XTS with 512-byte data units numbered from the start
// of the file (cryptsetup's iv_offset = data offset / 512). Inside is a plain FAT
// filesystem; only the root directory is read. Nothing is ever written to the .hc.
//
// Anything outside that recipe (another cipher or hash, a hidden volume, a PIM)
// fails with a clear message, and the owner can still open it with VeraCrypt and
// pass the key file (`p3sig usb migrate --key-file PATH`).

import (
	"crypto/aes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/xts"
)

const (
	vcIterations = 500000 // VeraCrypt, SHA-512, PIM 0, non-system volume
	vcKeyName    = "p3sig-root.key"
	vcUnit       = 512
)

var errVCPassphrase = errors.New("that passphrase does not open this VeraCrypt container")

type vcVolume struct {
	r       io.ReaderAt
	c       *xts.Cipher
	dataOff uint64
	size    uint64
	base    uint64 // data-unit number of the first data sector
}

// openVCHeader derives the header key and returns the decrypted volume.
func openVCHeader(r io.ReaderAt, pass []byte) (*vcVolume, error) {
	hdr := make([]byte, 512)
	if _, err := r.ReadAt(hdr, 0); err != nil {
		return nil, fmt.Errorf("reading the container header: %w", err)
	}
	dk := pbkdf2.Key(pass, hdr[:64], vcIterations, 64, sha512.New)
	defer wipeBytes(dk)
	hc, err := xts.NewCipher(aes.NewCipher, dk)
	if err != nil {
		return nil, err
	}
	dec := make([]byte, 448)
	defer wipeBytes(dec)
	hc.Decrypt(dec, hdr[64:], 0)
	if string(dec[:4]) != "VERA" ||
		crc32.ChecksumIEEE(dec[:188]) != binary.BigEndian.Uint32(dec[188:192]) ||
		crc32.ChecksumIEEE(dec[192:448]) != binary.BigEndian.Uint32(dec[8:12]) {
		return nil, errVCPassphrase
	}
	if ss := binary.BigEndian.Uint32(dec[64:68]); ss != 0 && ss != vcUnit {
		return nil, fmt.Errorf("unsupported VeraCrypt sector size %d", ss)
	}
	v := &vcVolume{r: r, dataOff: binary.BigEndian.Uint64(dec[44:52]), size: binary.BigEndian.Uint64(dec[52:60])}
	if v.dataOff%vcUnit != 0 || v.size == 0 {
		return nil, errors.New("unexpected VeraCrypt volume layout")
	}
	if v.c, err = xts.NewCipher(aes.NewCipher, dec[192:256]); err != nil {
		return nil, err
	}
	v.base = v.dataOff / vcUnit
	return v, nil
}

// readAt reads n decrypted bytes at off within the volume's data area.
func (v *vcVolume) readAt(off, n uint64) ([]byte, error) {
	if off+n > v.size {
		return nil, errors.New("read past the end of the VeraCrypt volume")
	}
	first, last := off/vcUnit, (off+n+vcUnit-1)/vcUnit
	buf := make([]byte, (last-first)*vcUnit)
	if _, err := v.r.ReadAt(buf, int64(v.dataOff+first*vcUnit)); err != nil {
		return nil, err
	}
	for i := uint64(0); i < last-first; i++ {
		s := buf[i*vcUnit : (i+1)*vcUnit]
		v.c.Decrypt(s, s, v.base+first+i)
	}
	return buf[off-first*vcUnit : off-first*vcUnit+n], nil
}

// readVCKey opens the container at path and returns the vault key inside it.
func readVCKey(path string, pass []byte) (ed25519.PrivateKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	v, err := openVCHeader(f, pass)
	if err != nil {
		return nil, err
	}
	boot, err := v.readAt(0, 512)
	if err != nil {
		return nil, err
	}
	if boot[510] != 0x55 || boot[511] != 0xAA {
		// Some tools number data units from the start of the data area instead.
		v.base = 0
		if boot, err = v.readAt(0, 512); err != nil || boot[510] != 0x55 || boot[511] != 0xAA {
			return nil, errors.New("the container opened, but holds no FAT filesystem")
		}
	}
	data, err := fatReadRootFile(v.readAt, boot, vcKeyName)
	if err != nil {
		return nil, err
	}
	defer wipeBytes(data)
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%s inside the container is not a p3sig vault key", vcKeyName)
	}
	return ed25519.PrivateKey(raw), nil
}

// fatReadRootFile finds name in the root directory of a FAT12/16/32 filesystem
// (long or 8.3 name) and returns its contents.
func fatReadRootFile(read func(off, n uint64) ([]byte, error), boot []byte, name string) ([]byte, error) {
	le16 := func(o int) uint64 { return uint64(binary.LittleEndian.Uint16(boot[o:])) }
	le32 := func(o int) uint64 { return uint64(binary.LittleEndian.Uint32(boot[o:])) }
	bps, spc := le16(11), uint64(boot[13])
	reserved, nfats, rootEnt := le16(14), uint64(boot[16]), le16(17)
	fatSz := le16(22)
	if fatSz == 0 {
		fatSz = le32(36)
	}
	if bps == 0 || bps%512 != 0 || spc == 0 || nfats == 0 || fatSz == 0 {
		return nil, errors.New("not a FAT filesystem")
	}
	clusBytes := bps * spc
	rootSecs := (rootEnt*32 + bps - 1) / bps
	firstData := (reserved + nfats*fatSz + rootSecs) * bps
	clusterOff := func(c uint64) uint64 { return firstData + (c-2)*clusBytes }

	var root []byte
	if rootEnt > 0 { // FAT12/16: fixed root directory
		var err error
		if root, err = read((reserved+nfats*fatSz)*bps, rootEnt*32); err != nil {
			return nil, err
		}
	} else { // FAT32: the root is a cluster chain
		for c, n := le32(44), 0; c >= 2 && c < 0x0FFFFFF8 && n < 64; n++ {
			b, err := read(clusterOff(c), clusBytes)
			if err != nil {
				return nil, err
			}
			root = append(root, b...)
			e, err := read(reserved*bps+c*4, 4)
			if err != nil {
				return nil, err
			}
			c = uint64(binary.LittleEndian.Uint32(e)) & 0x0FFFFFFF
		}
	}
	var lfn []uint16
	for i := 0; i+32 <= len(root); i += 32 {
		e := root[i : i+32]
		if e[0] == 0 {
			break
		}
		if e[0] == 0xE5 {
			lfn = nil
			continue
		}
		if e[11] == 0x0F { // long-name piece; pieces come last-first
			var part []uint16
			for _, o := range []int{1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30} {
				part = append(part, binary.LittleEndian.Uint16(e[o:]))
			}
			lfn = append(part, lfn...)
			continue
		}
		long := lfn
		lfn = nil
		if e[11]&0x18 != 0 { // directory or volume label
			continue
		}
		for j, ch := range long {
			if ch == 0 {
				long = long[:j]
				break
			}
		}
		short := strings.TrimRight(string(e[0:8]), " ")
		if ext := strings.TrimRight(string(e[8:11]), " "); ext != "" {
			short += "." + ext
		}
		if !strings.EqualFold(string(utf16.Decode(long)), name) && !strings.EqualFold(short, name) {
			continue
		}
		size := uint64(binary.LittleEndian.Uint32(e[28:]))
		clus := uint64(binary.LittleEndian.Uint16(e[26:])) | uint64(binary.LittleEndian.Uint16(e[20:]))<<16
		if size == 0 || size > clusBytes || clus < 2 {
			return nil, fmt.Errorf("%s inside the container has an unexpected size (%d bytes)", name, size)
		}
		return read(clusterOff(clus), size)
	}
	return nil, fmt.Errorf("no %s inside the container", name)
}
