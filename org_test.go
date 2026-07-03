package main

// org_test.go — round-trip + wire-shape tests for the Org Vault crypto core (org.go).
// Pure Go, no chip, no server: proves the crown-jewels sealing/wrapping/rotation is
// self-consistent and that the refactored string wrappers match the raw primitives.
// Cross-client wire-compat with PHP/libsodium is guaranteed by construction (identical
// crypto_box_seal over the same Ed25519→X25519 conversion, already proven for personal
// secrets); these tests lock the org-specific assembly.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

// newKey returns a fresh Ed25519 keypair as (base64 public, private).
func newKey(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return base64.StdEncoding.EncodeToString(pub), priv
}

func TestSealForKeyRaw_RoundTrip(t *testing.T) {
	pubB64, priv := newKey(t)
	msg := []byte{0x00, 0x01, 0xff, 0x5a, 0x00} // includes non-UTF8 / NUL bytes
	ct, err := sealForKeyRaw(msg, pubB64)
	if err != nil {
		t.Fatalf("sealForKeyRaw: %v", err)
	}
	got, err := openSealedBoxRaw(ct, priv)
	if err != nil {
		t.Fatalf("openSealedBoxRaw: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("round-trip mismatch: got %x want %x", got, msg)
	}
}

// The refactored string wrappers must be exactly the raw primitives over []byte.
func TestStringWrappers_MatchRaw(t *testing.T) {
	pubB64, priv := newKey(t)
	const value = "hunter2 🔐 unicode"

	ct, err := sealForKey(value, pubB64)
	if err != nil {
		t.Fatalf("sealForKey: %v", err)
	}
	// openSealedBox (string) and openSealedBoxRaw agree.
	s, err := openSealedBox(ct, priv)
	if err != nil {
		t.Fatalf("openSealedBox: %v", err)
	}
	raw, err := openSealedBoxRaw(ct, priv)
	if err != nil {
		t.Fatalf("openSealedBoxRaw: %v", err)
	}
	if s != value || string(raw) != value {
		t.Fatalf("wrapper mismatch: string=%q raw=%q want %q", s, string(raw), value)
	}
}

// The full owner+member lifecycle: create a vault, seal a secret, open it as the
// owner, wrap the org key to a member, and open the same secret as that member.
func TestOrgVault_Lifecycle(t *testing.T) {
	ownerPub, ownerPriv := newKey(t)
	memberPub, memberPriv := newKey(t)
	const secret = "s3cr3t-value"

	orgPubB64, wrappedForOwner, orgPriv, err := createOrgVault(ownerPub)
	if err != nil {
		t.Fatalf("createOrgVault: %v", err)
	}

	// Seal a secret to the org vault key (this is the org-key copy the server stores).
	enc, err := sealForKey(secret, orgPubB64)
	if err != nil {
		t.Fatalf("seal secret to org key: %v", err)
	}

	// Owner opens it directly with the just-created org key.
	if got, err := openOrgSecret(enc, orgPriv); err != nil || got != secret {
		t.Fatalf("owner openOrgSecret = %q, %v; want %q", got, err, secret)
	}

	// Owner re-derives the org key from the wrap sealed to their personal key.
	ownerOrgPriv, err := unwrapOrgKey(wrappedForOwner, ownerPriv)
	if err != nil {
		t.Fatalf("owner unwrapOrgKey: %v", err)
	}
	if !bytes.Equal(ownerOrgPriv, orgPriv) {
		t.Fatal("owner-unwrapped org key differs from the created org key")
	}

	// Admit a member: wrap the org key to their personal public key.
	wrappedForMember, err := wrapOrgKeyFor(orgPriv, memberPub)
	if err != nil {
		t.Fatalf("wrapOrgKeyFor: %v", err)
	}
	memberOrgPriv, err := unwrapOrgKey(wrappedForMember, memberPriv)
	if err != nil {
		t.Fatalf("member unwrapOrgKey: %v", err)
	}
	if got, err := openOrgSecret(enc, memberOrgPriv); err != nil || got != secret {
		t.Fatalf("member openOrgSecret = %q, %v; want %q", got, err, secret)
	}
}

// Unwrapping the org key with the wrong personal key must fail (no oracle).
func TestUnwrapOrgKey_WrongKey(t *testing.T) {
	ownerPub, _ := newKey(t)
	_, wrongPriv := newKey(t)
	_, wrapped, _, err := createOrgVault(ownerPub)
	if err != nil {
		t.Fatalf("createOrgVault: %v", err)
	}
	if _, err := unwrapOrgKey(wrapped, wrongPriv); err == nil {
		t.Fatal("expected unwrap with wrong personal key to fail")
	}
}

// Rotation re-seals every secret to a new org key and re-wraps remaining members;
// the old ciphertext must no longer open under the new key, values are preserved,
// and a remaining member opens everything under the new key.
func TestRotateOrgVault(t *testing.T) {
	ownerPub, _ := newKey(t)
	memberPub, memberPriv := newKey(t)

	orgPubB64, _, orgPriv, err := createOrgVault(ownerPub)
	if err != nil {
		t.Fatalf("createOrgVault: %v", err)
	}

	// Two secrets sealed to the current org key.
	secrets := map[string]string{"API_KEY": "abc123", "DB_URL": "postgres://x"}
	var copies []OrgSecretCopy
	for id, val := range secrets {
		enc, err := sealForKey(val, orgPubB64)
		if err != nil {
			t.Fatalf("seal %s: %v", id, err)
		}
		copies = append(copies, OrgSecretCopy{SecretID: id, Enc: enc})
	}

	members := []OrgMemberKey{{UserID: "u-member", KeyID: "k1", Pub: memberPub}}

	res, err := rotateOrgVault(orgPriv, members, copies)
	if err != nil {
		t.Fatalf("rotateOrgVault: %v", err)
	}
	if res.NewOrgPub == orgPubB64 {
		t.Fatal("rotation produced the same org public key")
	}
	if len(res.Sealed) != len(copies) || len(res.Wraps) != 1 {
		t.Fatalf("rotate shape: %d sealed, %d wraps", len(res.Sealed), len(res.Wraps))
	}

	// Every re-sealed secret opens under the NEW org key and preserves its value.
	for _, s := range res.Sealed {
		got, err := openOrgSecret(s.Enc, res.NewOrgPriv)
		if err != nil {
			t.Fatalf("open re-sealed %s: %v", s.SecretID, err)
		}
		if got != secrets[s.SecretID] {
			t.Fatalf("re-sealed %s = %q, want %q", s.SecretID, got, secrets[s.SecretID])
		}
		// The OLD ciphertext must not open under the NEW key.
		for _, old := range copies {
			if old.SecretID == s.SecretID {
				if _, err := openOrgSecret(old.Enc, res.NewOrgPriv); err == nil {
					t.Fatalf("old ciphertext for %s still opens under the rotated key", s.SecretID)
				}
			}
		}
	}

	// The remaining member re-derives the NEW org key from their wrap and opens a secret.
	memberOrgPriv, err := unwrapOrgKey(res.Wraps[0].Wrapped, memberPriv)
	if err != nil {
		t.Fatalf("member unwrap after rotate: %v", err)
	}
	if !bytes.Equal(memberOrgPriv, res.NewOrgPriv) {
		t.Fatal("member-unwrapped rotated key differs from the new org key")
	}
}
