package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

func rep(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// A. HKDF correctness — RFC 5869 Test Case 1 (authoritative anchor).
func TestHKDF_RFC5869_TC1(t *testing.T) {
	ikm := rep(0x0b, 22)
	salt := hx(t, "000102030405060708090a0b0c")
	info := hx(t, "f0f1f2f3f4f5f6f7f8f9")
	r := hkdf.New(sha256.New, ikm, salt, info)
	okm := make([]byte, 42)
	if _, err := io.ReadFull(r, okm); err != nil {
		t.Fatal(err)
	}
	want := "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
	if got := hex.EncodeToString(okm); got != want {
		t.Fatalf("OKM\n got %s\nwant %s", got, want)
	}
}

// B. Scheme-1 HKDF derivation with our info string (shared = 0x02*32).
func TestHKDFKey_Vector(t *testing.T) {
	key, err := hkdfKey(rep(0x02, 32))
	if err != nil {
		t.Fatal(err)
	}
	want := "cf1a2d74ae72450a325c39c60bcbf304beb7900e19a180b6a3d315fd1f355541"
	if got := hex.EncodeToString(key); got != want {
		t.Fatalf("aesKey\n got %s\nwant %s", got, want)
	}
}

// C. Scheme-1 full ECDH KAT — deterministic (fixed scalars + nonce). Cross-checks
// Go's crypto/ecdh against the vectors generated with a separate library.
func TestWrapECDH_KAT(t *testing.T) {
	chipPriv, err := ecdh.P256().NewPrivateKey(rep(0x11, 32))
	if err != nil {
		t.Fatal(err)
	}
	ephPriv, err := ecdh.P256().NewPrivateKey(rep(0x22, 32))
	if err != nil {
		t.Fatal(err)
	}

	// Cross-implementation checks against the frozen vectors.
	if got := hex.EncodeToString(chipPriv.PublicKey().Bytes()); got != "040217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794" {
		t.Fatalf("chip pub mismatch: %s", got)
	}
	if got := hex.EncodeToString(ephPriv.PublicKey().Bytes()); got != "04d65a93977caa3d1b081852ff57a79e465f1660577304baead505dd3a48589cf350185e895372df6221ea3a137557e473fddb6755f05bd507c3c533fce9c91285" {
		t.Fatalf("eph pub mismatch: %s", got)
	}
	shared, err := ephPriv.ECDH(chipPriv.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(shared); got != "ccfc261f58193c98ca4ad4a53bbac6f0ee29bc4d48438090446908622ca79af6" {
		t.Fatalf("shared mismatch: %s", got)
	}

	nonce := hx(t, "0102030405060708090a0b0c")
	vault := rep(0xaa, 32)
	blob, err := wrapECDHWith(vault, chipPriv.PublicKey(), ephPriv, nonce)
	if err != nil {
		t.Fatal(err)
	}
	wantBlob := "010104d65a93977caa3d1b081852ff57a79e465f1660577304baead505dd3a48589cf350185e895372df6221ea3a137557e473fddb6755f05bd507c3c533fce9c912850102030405060708090a0b0c8a4581a7100ba5437bfc15b173ff971e30520c908680b0a61595d1c6b27e7b948023e7db6ecebca07b3e7b95424e66df"
	if got := hex.EncodeToString(blob); got != wantBlob {
		t.Fatalf("blob\n got %s\nwant %s", got, wantBlob)
	}

	// Unwrap: agree = ECDH(chipPriv, ephPub) — the software stand-in for the chip.
	agree := func(ephPubSEC1 []byte) ([]byte, error) {
		pub, err := ecdh.P256().NewPublicKey(ephPubSEC1)
		if err != nil {
			return nil, err
		}
		return chipPriv.ECDH(pub)
	}
	got, err := UnwrapECDH(blob, agree)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, vault) {
		t.Fatalf("unwrap mismatch: %x", got)
	}
}

func TestWrapECDH_RoundTrip(t *testing.T) {
	chipPriv, _ := ecdh.P256().NewPrivateKey(rep(0x11, 32))
	agree := func(ephPubSEC1 []byte) ([]byte, error) {
		pub, err := ecdh.P256().NewPublicKey(ephPubSEC1)
		if err != nil {
			return nil, err
		}
		return chipPriv.ECDH(pub)
	}
	for _, n := range []int{1, 32, 33, 64, 200} {
		secret := rep(0x5a, n)
		blob, err := WrapECDH(secret, chipPriv.PublicKey())
		if err != nil {
			t.Fatalf("wrap len=%d: %v", n, err)
		}
		got, err := UnwrapECDH(blob, agree)
		if err != nil {
			t.Fatalf("unwrap len=%d: %v", n, err)
		}
		if !bytes.Equal(got, secret) {
			t.Fatalf("len=%d roundtrip mismatch", n)
		}
	}
}

// D. Scheme-2 GCM-layer KAT — fixed key (tests format+GCM without running argon2).
func TestAssembleArgon2_KAT(t *testing.T) {
	key := rep(0x33, 32)
	salt := hx(t, "00112233445566778899aabbccddeeff")
	nonce := hx(t, "0102030405060708090a0b0c")
	vault := rep(0xaa, 32)
	blob, err := assembleArgon2(vault, key, salt, nonce, Argon2Params{MemKiB: 65536, Time: 3, Par: 4})
	if err != nil {
		t.Fatal(err)
	}
	want := "010200112233445566778899aabbccddeeff0001000000000003040102030405060708090a0b0ca0bc38ce0666026de82e60676c9c5a6159abd649259bd0cde6fa0edf859dcd9d28d7e4a736619f4a7bc3709a4f228e9d"
	if got := hex.EncodeToString(blob); got != want {
		t.Fatalf("blob\n got %s\nwant %s", got, want)
	}
}

func TestPassphrase_RoundTrip(t *testing.T) {
	// Fast params for test speed; roundtrip works for any params (stored in blob).
	fast := Argon2Params{MemKiB: 1024, Time: 1, Par: 1}
	secret := rep(0xa5, 32)
	pw := []byte("hunter2-correct-horse")
	blob, err := WrapPassphrase(secret, pw, fast)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapPassphrase(blob, pw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("roundtrip mismatch")
	}
}

// E. Argon2id KDF vector — frozen with the spec's default params.
func TestArgon2id_Vector(t *testing.T) {
	salt := hx(t, "00112233445566778899aabbccddeeff")
	key := argon2.IDKey([]byte("correct horse battery staple"), salt, 3, 65536, 4, 32)
	want := "aeb08a81bdb9da07c32f8f9d2c87cfba3313c0fdc7468179e494c56680f0ae8d"
	if got := hex.EncodeToString(key); got != want {
		t.Fatalf("argon2id\n got %s\nwant %s", got, want)
	}
}

func TestTamper_ECDH(t *testing.T) {
	chipPriv, _ := ecdh.P256().NewPrivateKey(rep(0x11, 32))
	agree := func(p []byte) ([]byte, error) {
		pub, err := ecdh.P256().NewPublicKey(p)
		if err != nil {
			return nil, err
		}
		return chipPriv.ECDH(pub)
	}
	base, _ := WrapECDH(rep(0x01, 32), chipPriv.PublicKey())
	// Flip a byte in: eph-pub region (header/AAD+agree), nonce, and ciphertext.
	for _, idx := range []int{5, ecdhHeaderLen - 1, len(base) - 1} {
		blob := append([]byte(nil), base...)
		blob[idx] ^= 0xff
		if _, err := UnwrapECDH(blob, agree); !errors.Is(err, ErrUnwrap) {
			// A corrupted eph-pub may fail inside agree (invalid point) → also acceptable non-nil error.
			if err == nil {
				t.Fatalf("tamper at %d: expected failure, got success", idx)
			}
		}
	}
}

func TestTamper_Passphrase(t *testing.T) {
	pw := []byte("pw")
	base, _ := WrapPassphrase(rep(0x01, 32), pw, Argon2Params{MemKiB: 1024, Time: 1, Par: 1})
	for _, idx := range []int{5, argonHeaderLen - 1, len(base) - 1} {
		blob := append([]byte(nil), base...)
		blob[idx] ^= 0xff
		if _, err := UnwrapPassphrase(blob, pw); err == nil {
			t.Fatalf("tamper at %d: expected failure", idx)
		}
	}
}

func TestWrongPassphrase(t *testing.T) {
	fast := Argon2Params{MemKiB: 1024, Time: 1, Par: 1}
	blob, _ := WrapPassphrase(rep(0x01, 32), []byte("right"), fast)
	if _, err := UnwrapPassphrase(blob, []byte("wrong")); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("want ErrUnwrap, got %v", err)
	}
}

func TestCrossScheme(t *testing.T) {
	chipPriv, _ := ecdh.P256().NewPrivateKey(rep(0x11, 32))
	ecdhBlob, _ := WrapECDH(rep(0x01, 32), chipPriv.PublicKey())
	passBlob, _ := WrapPassphrase(rep(0x01, 32), []byte("pw"), Argon2Params{MemKiB: 1024, Time: 1, Par: 1})

	if _, err := UnwrapPassphrase(ecdhBlob, []byte("pw")); !errors.Is(err, ErrUnsupportedScheme) {
		t.Fatalf("ecdh->passphrase: want ErrUnsupportedScheme, got %v", err)
	}
	if _, err := UnwrapECDH(passBlob, func([]byte) ([]byte, error) { return rep(0, 32), nil }); !errors.Is(err, ErrUnsupportedScheme) {
		t.Fatalf("passphrase->ecdh: want ErrUnsupportedScheme, got %v", err)
	}
}

func TestBadVersionAndTruncation(t *testing.T) {
	chipPriv, _ := ecdh.P256().NewPrivateKey(rep(0x11, 32))
	blob, _ := WrapECDH(rep(0x01, 32), chipPriv.PublicKey())

	bad := append([]byte(nil), blob...)
	bad[0] = 0x02
	if _, err := UnwrapECDH(bad, func([]byte) ([]byte, error) { return rep(0, 32), nil }); !errors.Is(err, ErrVersion) {
		t.Fatalf("want ErrVersion, got %v", err)
	}
	for _, short := range [][]byte{{}, {0x01}, blob[:ecdhHeaderLen]} {
		if _, err := UnwrapECDH(short, func([]byte) ([]byte, error) { return rep(0, 32), nil }); err == nil {
			t.Fatalf("truncated blob len=%d: expected error", len(short))
		}
	}
}

func TestSchemeOf(t *testing.T) {
	chipPriv, _ := ecdh.P256().NewPrivateKey(rep(0x11, 32))
	ecdhBlob, _ := WrapECDH(rep(0x01, 32), chipPriv.PublicKey())
	passBlob, _ := WrapPassphrase(rep(0x01, 32), []byte("pw"), Argon2Params{MemKiB: 1024, Time: 1, Par: 1})

	if s, err := SchemeOf(ecdhBlob); err != nil || s != schemeECDH {
		t.Fatalf("ecdh scheme: %v %v", s, err)
	}
	if s, err := SchemeOf(passBlob); err != nil || s != schemeArgon2 {
		t.Fatalf("argon scheme: %v %v", s, err)
	}
	if _, err := SchemeOf([]byte{0x01}); !errors.Is(err, ErrBadFormat) {
		t.Fatalf("short: want ErrBadFormat, got %v", err)
	}
}
