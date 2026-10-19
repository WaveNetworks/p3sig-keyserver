package main

// org.go — Org Vault client crypto (platform-independent, cgo-free).
//
// The Go twin of the browser reference `window.P3Crypto` (p3sig/assets/js/
// p3sig-crypto.js) and PHP `p3sig_vault_seal_for_key` (crypto.php). Keeps org-secret
// plaintext AND the org private key off the server: every seal / open / wrap / rotate
// happens here; the server only ever holds ciphertext (sealed copies + wrapped org
// keys). See docs/ORG-VAULT-CONTEXT.md.
//
// Seal format = libsodium crypto_box_seal to an Ed25519 public key converted to
// X25519 — byte-for-byte compatible with the browser (`crypto_box_seal`) and PHP
// (`sodium_crypto_box_seal`). All base64 is StdEncoding (PHP base64_encode / libsodium
// base64_variants.ORIGINAL). A vault private key is a 64-byte Ed25519 secret key,
// sealed as raw bytes (NOT a UTF-8 string) — hence the raw variants below.
//
// These ops are pure Go and build on every platform; the only platform-specific step
// in the whole feature is unlocking the *personal* key (USB / chip via keystore.Agree),
// which happens before any of this.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/nacl/box"
)

// ─── raw seal / open (the byte-level primitives the string versions build on) ──

// sealForKeyRaw seals raw bytes to a base64 Ed25519 public key, producing a base64
// libsodium sealed box (crypto_box_seal). The raw form is needed to wrap a vault
// private key (64 raw bytes, not UTF-8). sealForKey is the string wrapper.
func sealForKeyRaw(plaintext []byte, edPubB64 string) (string, error) {
	edPub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(edPubB64))
	if err != nil || len(edPub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid recipient public key")
	}
	xPub, err := ed25519PubToX25519(ed25519.PublicKey(edPub))
	if err != nil {
		return "", err
	}
	sealed, err := box.SealAnonymous(nil, plaintext, xPub, rand.Reader)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// openSealedBoxRaw opens a base64 crypto_box_seal ciphertext with an Ed25519 private
// key (converted to X25519), returning raw plaintext bytes. openSealedBox is the
// string wrapper. Used to recover a wrapped org private key (raw 64 bytes).
func openSealedBoxRaw(encryptedB64 string, edPriv ed25519.PrivateKey) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedB64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}
	edPub := edPriv.Public().(ed25519.PublicKey)
	xPub, err := ed25519PubToX25519(edPub)
	if err != nil {
		return nil, fmt.Errorf("public key conversion: %w", err)
	}
	xPriv := ed25519PrivToX25519(edPriv)
	plaintext, ok := box.OpenAnonymous(nil, ciphertext, xPub, xPriv)
	if !ok {
		return nil, fmt.Errorf("decryption failed — wrong key or corrupted ciphertext")
	}
	return plaintext, nil
}

// ─── org vault operations (mirror P3Crypto) ────────────────────────────────────

// createOrgVault generates a fresh org Ed25519 keypair, wraps its private key to the
// creating owner's personal public key, and returns the org public key (b64), the
// wrapped-for-owner private key (b64, → p3sig_org_key_wraps), and the org private key
// so the owner can immediately seal secrets / wrap to others. Mirrors
// P3Crypto.createOrgVaultFor.
func createOrgVault(ownerPubB64 string) (orgPubB64, wrappedForOwnerB64 string, orgPriv ed25519.PrivateKey, err error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", "", nil, err
	}
	wrapped, err := sealForKeyRaw(priv, ownerPubB64)
	if err != nil {
		return "", "", nil, err
	}
	return base64.StdEncoding.EncodeToString(pub), wrapped, priv, nil
}

// unwrapOrgKey opens the org private key (a copy sealed to the personal key) and
// returns it. Mirrors P3Crypto.unwrapOrgKey.
func unwrapOrgKey(wrappedB64 string, personalPriv ed25519.PrivateKey) (ed25519.PrivateKey, error) {
	raw, err := openSealedBoxRaw(wrappedB64, personalPriv)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("unwrapped org key is %d bytes, want %d", len(raw), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(raw), nil
}

// openOrgSecret opens an org secret (sealed to the org vault key) with the org private
// key. Mirrors P3Crypto.openOrgSecret.
func openOrgSecret(ctB64 string, orgPriv ed25519.PrivateKey) (string, error) {
	raw, err := openSealedBoxRaw(ctB64, orgPriv)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// wrapOrgKeyFor seals the org private key to a member's personal public key, producing
// a p3sig_org_key_wraps.wrapped_org_key value. Mirrors P3Crypto.wrapOrgKeyFor.
func wrapOrgKeyFor(orgPriv ed25519.PrivateKey, memberPubB64 string) (string, error) {
	return sealForKeyRaw(orgPriv, memberPubB64)
}

// ─── rotation ───────────────────────────────────────────────────────────────

// OrgMemberKey is a remaining member's personal recipient key (rotate re-wraps to it).
type OrgMemberKey struct {
	UserID string `json:"user_id"`
	KeyID  string `json:"key_id"`
	Pub    string `json:"public_key"`
}

// OrgSecretCopy is a secret's copy sealed to the OLD org key (rotate re-seals it):
// the value and its sealed name.
type OrgSecretCopy struct {
	SecretID string `json:"secret_id"`
	Enc      string `json:"encrypted_data"`
	Meta     string `json:"encrypted_meta"`
}

// SealedSecret is a secret re-sealed to the NEW org key. Carries no key_id — the new
// org key's id is assigned server-side after its public key is registered.
type SealedSecret struct {
	SecretID string `json:"secret_id"`
	Enc      string `json:"encrypted_data"`
	Meta     string `json:"encrypted_meta"`
}

// MemberWrap is the org private key re-wrapped to one remaining member.
type MemberWrap struct {
	MemberUserID string `json:"member_user_id"`
	MemberKeyID  string `json:"member_key_id"`
	Wrapped      string `json:"wrapped_org_key"`
}

// RotateResult is the payload for rotateOrgVault plus the newly-adopted org key.
type RotateResult struct {
	NewOrgPub  string             `json:"new_org_public_key"`
	Sealed     []SealedSecret     `json:"sealed"`
	Wraps      []MemberWrap       `json:"wraps"`
	NewOrgPriv ed25519.PrivateKey `json:"-"` // held locally; never serialized
}

// rotateOrgVault rotates the org vault: decrypts every secret with the CURRENT org key,
// generates a new org keypair, re-seals every secret to it, and re-wraps the new
// private key to each remaining member. Precondition: orgPriv is the CURRENT key (so
// old ciphertext opens). Mirrors P3Crypto.rotate. The caller uploads NewOrgPub / Sealed
// / Wraps via rotateOrgVault; the old key is revoked server-side.
func rotateOrgVault(orgPriv ed25519.PrivateKey, members []OrgMemberKey, secrets []OrgSecretCopy) (*RotateResult, error) {
	// Decrypt all current secrets (value + name) with the OLD org key first.
	type kv struct{ id, val, meta string }
	plain := make([]kv, 0, len(secrets))
	for _, s := range secrets {
		v, err := openOrgSecret(s.Enc, orgPriv)
		if err != nil {
			return nil, fmt.Errorf("open secret %s under current org key: %w", s.SecretID, err)
		}
		m, err := openOrgSecret(s.Meta, orgPriv)
		if err != nil {
			return nil, fmt.Errorf("open the name of secret %s under current org key: %w", s.SecretID, err)
		}
		plain = append(plain, kv{s.SecretID, v, m})
	}

	newPub, newPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	newPubB64 := base64.StdEncoding.EncodeToString(newPub)

	sealed := make([]SealedSecret, 0, len(plain))
	for _, p := range plain {
		enc, err := sealForKeyRaw([]byte(p.val), newPubB64)
		if err != nil {
			return nil, err
		}
		meta, err := sealForKeyRaw([]byte(p.meta), newPubB64)
		if err != nil {
			return nil, err
		}
		sealed = append(sealed, SealedSecret{SecretID: p.id, Enc: enc, Meta: meta})
	}

	wraps := make([]MemberWrap, 0, len(members))
	for _, m := range members {
		w, err := sealForKeyRaw(newPriv, m.Pub)
		if err != nil {
			return nil, err
		}
		wraps = append(wraps, MemberWrap{MemberUserID: m.UserID, MemberKeyID: m.KeyID, Wrapped: w})
	}

	return &RotateResult{NewOrgPub: newPubB64, Sealed: sealed, Wraps: wraps, NewOrgPriv: newPriv}, nil
}
