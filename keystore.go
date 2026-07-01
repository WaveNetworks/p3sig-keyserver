package main

// Keystore is a chip-backed SSH client identity: a non-extractable key held in
// the platform secure hardware (Apple Secure Enclave / a TPM) and gated by the
// platform biometric (Touch ID / Windows Hello). Implemented per-platform behind
// build tags; see docs/TODO-macos.md and docs/TODO-windows.md.
//
// Keys are ECDSA P-256 (what the Secure Enclave and most TPM/Hello keys support),
// encoded as OpenSSH "ecdsa-sha2-nistp256 ..." public keys.
type Keystore interface {
	// Create makes a new non-extractable key gated by biometric and returns its
	// OpenSSH public key line.
	Create(label string) (sshPublicKey string, err error)
	// PublicKey returns the OpenSSH public key line for an existing key.
	PublicKey(label string) (sshPublicKey string, err error)
	// Sign signs data with the chip key, prompting the biometric. macOS returns
	// a DER ECDSA signature; Windows returns r||s — the ssh-agent normalizes both.
	Sign(label string, data []byte) (signature []byte, err error)
	// Agree performs ECDH between the chip's P-256 private key and peerPubSEC1 — a
	// peer public key as an uncompressed SEC1 point (0x04‖X‖Y, 65 bytes) — prompting
	// the biometric. It returns the 32-byte big-endian X coordinate of the shared
	// point: the raw ECDH secret that wrap.go feeds to HKDF in the
	// ecdh-p256-hkdf-aesgcm scheme. This is the unwrap-time "unlock" for an
	// enclave-held vault key (see docs/device-enrollment-phase1-T2-wrap-spec.md).
	// Note: Windows/NCrypt yields the shared secret little-endian, so that backend
	// must reverse it to big-endian before returning.
	Agree(label string, peerPubSEC1 []byte) (shared []byte, err error)
	// Delete removes the key from the keystore.
	Delete(label string) error
}

// openKeystore returns the platform implementation. Defined in the build-tagged
// files: keystore_darwin.go, keystore_windows.go, keystore_stub.go.
