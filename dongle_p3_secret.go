package main

// `p3sig secret get NAME --with dongle`: the account request is signed and every
// sealed box is opened ON the dongle (design §9.1). The host only ever sees the
// per-item X25519 shared secret the dongle's UNSEAL returns, never the vault key.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/salsa20/salsa"
)

// openSealedBoxShared opens a libsodium crypto_box_seal ciphertext
// (epk[32] || box) given only the recipient's X25519 public key and a function
// that returns X25519(recipient secret, epk) — what the dongle's UNSEAL gives.
// Same result as box.OpenAnonymous, without the private key on the host.
func openSealedBoxShared(encB64 string, recipX [32]byte, unseal func([32]byte) ([32]byte, error)) ([]byte, error) {
	ct, err := base64.StdEncoding.DecodeString(encB64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}
	if len(ct) < 32+box.Overhead {
		return nil, errors.New("sealed box too short")
	}
	var epk [32]byte
	copy(epk[:], ct[:32])
	shared, err := unseal(epk)
	if err != nil {
		return nil, err
	}
	// crypto_box_beforenm: HSalsa20(shared, 0).
	var zero [16]byte
	var k [32]byte
	salsa.HSalsa20(&k, &zero, &shared, &salsa.Sigma)
	wipeBytes(shared[:])
	// crypto_box_seal nonce: BLAKE2b-192(epk || recipient pk).
	h, _ := blake2b.New(24, nil)
	h.Write(epk[:])
	h.Write(recipX[:])
	var nonce [24]byte
	copy(nonce[:], h.Sum(nil))
	plain, ok := box.OpenAfterPrecomputation(nil, ct[32:], &nonce, &k)
	wipeBytes(k[:])
	if !ok {
		return nil, errors.New("decryption failed — not sealed to the dongle's vault key, or corrupted")
	}
	return plain, nil
}

// dongleSecretGet is cmdSecretGetUser with the vault key on our dongle.
func dongleSecretGet(apiBase, name string) error {
	rec, err := loadP3Record()
	if err != nil {
		return fmt.Errorf("--with dongle: no pairing record (run `p3sig dongle pair`): %w", err)
	}
	s, ed, x, c, err := openP3Session(rec)
	if err != nil {
		return err
	}
	if c != nil {
		defer c.Close() // the dongle wipes its unlocked key on disconnect
	}
	val, err := dongleSecretFetch(s, ed, x, apiBase, name)
	if err != nil {
		return err
	}
	fmt.Println(val)
	return nil
}

func dongleSecretFetch(s *DongleSession, ed ed25519.PublicKey, x [32]byte, apiBase, name string) (string, error) {
	pub := base64.StdEncoding.EncodeToString(ed)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig, err := s.Sign([]byte(pub + "|" + ts))
	if err != nil {
		return "", err
	}
	if !ed25519.Verify(ed, []byte(pub+"|"+ts), sig) {
		return "", errors.New("dongle: request signature does not verify under the paired vault key")
	}
	form := url.Values{}
	form.Set("action", "getMySecrets")
	form.Set("pubkey", pub)
	form.Set("ts", ts)
	form.Set("signature", base64.StdEncoding.EncodeToString(sig))
	var res struct {
		Secrets []struct {
			Enc  string `json:"encrypted_data"`
			Meta string `json:"encrypted_meta"`
		} `json:"secrets"`
	}
	if err := postForm(apiBase, form, &res); err != nil {
		return "", err
	}
	for _, it := range res.Secrets {
		if it.Meta == "" {
			continue
		}
		j, err := openSealedBoxShared(it.Meta, x, s.Unseal)
		if err != nil {
			continue
		}
		var m secretMeta
		if json.Unmarshal(j, &m) != nil || m.Label != name {
			continue
		}
		v, err := openSealedBoxShared(it.Enc, x, s.Unseal)
		if err != nil {
			return "", fmt.Errorf("unseal %q on the dongle: %w", name, err)
		}
		return string(v), nil
	}
	return "", fmt.Errorf("no secret named %q on this account", name)
}

// withDongle: `--with dongle` on a command that can use it.
func withDongle(f map[string]string) bool { return f["with"] == "dongle" }
