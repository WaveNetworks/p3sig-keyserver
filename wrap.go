package main

// wrap.go — portable vault-key wrapping for device enrollment (Phase 1, task T2).
//
// Wraps an opaque secret (the Ed25519 vault private key, treated as []byte and
// never parsed) so only a device's chip (scheme ecdh-p256-hkdf-aesgcm) or a
// passphrase (scheme argon2id) can recover it. Pure Go, no cgo, no chip needed to
// *wrap*. Unwrapping scheme 1 calls an injected `agree` that performs the ECDH on
// the secure element (the biometric moment; implemented by T3/T4).
//
// Blob format (self-describing, versioned). AAD for AES-GCM = every byte before the
// ciphertext, so version, scheme, and all parameters are authenticated.
//
//	scheme 0x01 (ecdh-p256-hkdf-aesgcm):
//	  [0]=ver [1]=scheme [2:67]=eph P-256 pub SEC1 uncompressed(65)
//	  [67:79]=nonce(12) [79:]=AES-256-GCM ct‖tag        AAD=[0:79]
//	scheme 0x02 (argon2id):
//	  [0]=ver [1]=scheme [2:18]=salt(16) [18:22]=memKiB(u32be)
//	  [22:26]=time(u32be) [26]=par(u8) [27:39]=nonce(12) [39:]=ct‖tag  AAD=[0:39]
//
// See docs/device-enrollment-phase1-T2-wrap-spec.md for the full spec + vectors.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	wrapVersion  byte = 0x01
	schemeECDH   byte = 0x01
	schemeArgon2 byte = 0x02

	hkdfInfoECDH = "p3sig/device-wrap/v1/ecdh-p256-aesgcm"

	nonceLen       = 12
	ecdhPubLen     = 65 // SEC1 uncompressed P-256 point
	saltLen        = 16
	tagLen         = 16                                 // AES-GCM tag
	ecdhHeaderLen  = 2 + ecdhPubLen + nonceLen          // 79
	argonHeaderLen = 2 + saltLen + 4 + 4 + 1 + nonceLen // 39

	// Bounds on argon2 params read from an untrusted blob, so a corrupt/malicious
	// blob can't force absurd memory/time.
	maxArgonMemKiB uint32 = 2 * 1024 * 1024 // 2 GiB
	maxArgonTime   uint32 = 64
)

// Argon2Params configures the passphrase scheme. Stored per-blob so it can be tuned
// without breaking old blobs.
type Argon2Params struct {
	MemKiB uint32
	Time   uint32
	Par    uint8
}

// DefaultArgon2 exceeds OWASP-2024 minimums. Runs on every passphrase-tier read.
var DefaultArgon2 = Argon2Params{MemKiB: 65536, Time: 3, Par: 4}

var (
	ErrBadFormat         = errors.New("wrap: malformed blob")
	ErrUnsupportedScheme = errors.New("wrap: unsupported scheme")
	ErrVersion           = errors.New("wrap: unsupported version")
	// ErrUnwrap covers wrong key / wrong passphrase / tampered blob alike —
	// deliberately indistinguishable (no oracle).
	ErrUnwrap = errors.New("wrap: unwrap failed")
)

// zero best-effort wipes a scratch buffer. (Go may have copied it; still worth doing.)
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func hkdfKey(shared []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, shared, nil, []byte(hkdfInfoECDH))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

func gcmSeal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block) // 12-byte nonce, 16-byte tag
	if err != nil {
		return nil, err
	}
	return g.Seal(nil, nonce, plaintext, aad), nil
}

func gcmOpen(key, nonce, ct, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	pt, err := g.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, ErrUnwrap
	}
	return pt, nil
}

// SchemeOf reports the scheme id of a blob without touching key material.
func SchemeOf(blob []byte) (byte, error) {
	if len(blob) < 2 {
		return 0, ErrBadFormat
	}
	if blob[0] != wrapVersion {
		return 0, ErrVersion
	}
	switch blob[1] {
	case schemeECDH, schemeArgon2:
		return blob[1], nil
	default:
		return 0, ErrUnsupportedScheme
	}
}

// --- scheme 1: ecdh-p256-hkdf-aesgcm -----------------------------------------

// WrapECDH wraps secret to a device chip's P-256 public key. Pure Go; no chip or
// biometric needed to wrap.
func WrapECDH(secret []byte, chipPub *ecdh.PublicKey) ([]byte, error) {
	ephPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return wrapECDHWith(secret, chipPub, ephPriv, nonce)
}

// wrapECDHWith is the deterministic core (test hook: fixed ephemeral key + nonce).
func wrapECDHWith(secret []byte, chipPub *ecdh.PublicKey, ephPriv *ecdh.PrivateKey, nonce []byte) ([]byte, error) {
	shared, err := ephPriv.ECDH(chipPub)
	if err != nil {
		return nil, err
	}
	defer zero(shared)
	aesKey, err := hkdfKey(shared)
	if err != nil {
		return nil, err
	}
	defer zero(aesKey)

	header := make([]byte, 0, ecdhHeaderLen)
	header = append(header, wrapVersion, schemeECDH)
	header = append(header, ephPriv.PublicKey().Bytes()...) // 65-byte uncompressed
	header = append(header, nonce...)

	ct, err := gcmSeal(aesKey, nonce, secret, header)
	if err != nil {
		return nil, err
	}
	return append(header, ct...), nil // header is at cap → append allocates, leaving AAD intact
}

// UnwrapECDH recovers secret. agree performs ECDH(chipPriv, ephPub) on the secure
// element and returns the 32-byte big-endian X (the biometric moment).
func UnwrapECDH(blob []byte, agree func(ephPubSEC1 []byte) (shared []byte, err error)) ([]byte, error) {
	if len(blob) < 2 {
		return nil, ErrBadFormat
	}
	if blob[0] != wrapVersion {
		return nil, ErrVersion
	}
	if blob[1] != schemeECDH {
		return nil, ErrUnsupportedScheme
	}
	if len(blob) < ecdhHeaderLen+tagLen {
		return nil, ErrBadFormat
	}
	ephPub := append([]byte(nil), blob[2:2+ecdhPubLen]...) // copy; agree may retain it
	nonce := blob[2+ecdhPubLen : ecdhHeaderLen]
	ct := blob[ecdhHeaderLen:]
	aad := blob[:ecdhHeaderLen]

	shared, err := agree(ephPub)
	if err != nil {
		return nil, err
	}
	defer zero(shared)
	if len(shared) != 32 {
		return nil, ErrUnwrap
	}
	aesKey, err := hkdfKey(shared)
	if err != nil {
		return nil, err
	}
	defer zero(aesKey)
	return gcmOpen(aesKey, nonce, ct, aad)
}

// --- scheme 2: argon2id ------------------------------------------------------

// WrapPassphrase wraps secret under a passphrase. Zero-value params → DefaultArgon2.
func WrapPassphrase(secret, passphrase []byte, p Argon2Params) ([]byte, error) {
	if p == (Argon2Params{}) {
		p = DefaultArgon2
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	aesKey := argon2.IDKey(passphrase, salt, p.Time, p.MemKiB, p.Par, 32)
	defer zero(aesKey)
	return assembleArgon2(secret, aesKey, salt, nonce, p)
}

// assembleArgon2 builds the scheme-2 blob from a precomputed key (test hook: fixed
// key exercises the format+GCM layer without running argon2).
func assembleArgon2(secret, aesKey, salt, nonce []byte, p Argon2Params) ([]byte, error) {
	header := make([]byte, 0, argonHeaderLen)
	header = append(header, wrapVersion, schemeArgon2)
	header = append(header, salt...)
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], p.MemKiB)
	header = append(header, b4[:]...)
	binary.BigEndian.PutUint32(b4[:], p.Time)
	header = append(header, b4[:]...)
	header = append(header, p.Par)
	header = append(header, nonce...)

	ct, err := gcmSeal(aesKey, nonce, secret, header)
	if err != nil {
		return nil, err
	}
	return append(header, ct...), nil
}

// UnwrapPassphrase recovers secret using params stored in the blob.
func UnwrapPassphrase(blob, passphrase []byte) ([]byte, error) {
	if len(blob) < 2 {
		return nil, ErrBadFormat
	}
	if blob[0] != wrapVersion {
		return nil, ErrVersion
	}
	if blob[1] != schemeArgon2 {
		return nil, ErrUnsupportedScheme
	}
	if len(blob) < argonHeaderLen+tagLen {
		return nil, ErrBadFormat
	}
	salt := blob[2 : 2+saltLen]
	memKiB := binary.BigEndian.Uint32(blob[18:22])
	t := binary.BigEndian.Uint32(blob[22:26])
	par := blob[26]
	nonce := blob[27:argonHeaderLen]
	ct := blob[argonHeaderLen:]
	aad := blob[:argonHeaderLen]

	if memKiB == 0 || memKiB > maxArgonMemKiB || t == 0 || t > maxArgonTime || par == 0 {
		return nil, ErrBadFormat
	}
	aesKey := argon2.IDKey(passphrase, salt, t, memKiB, par, 32)
	defer zero(aesKey)
	return gcmOpen(aesKey, nonce, ct, aad)
}
