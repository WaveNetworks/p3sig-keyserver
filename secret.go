package main

// Sign-then-seal for secret bundles (task #2598, threat 3 of #2568).
//
// crypto_box_seal hides a secret from everyone but the recipient machine, but it
// carries no sender: anyone who knows the machine's public key — including a
// compromised p3sig.com — can seal a value of its own choosing and serve it. So
// the sealed plaintext may now be a SIGNED ENVELOPE:
//
//	"p3sig-signed-secret-v1\n" + JSON{signer, secret: signedBlob(SignedSecret)}
//
// signed by a DEVICE key that holds a live root delegation (the same chain the
// signed policy uses), and binding the secret id, its name and the recipient key
// so a valid envelope can't be replayed under another secret or re-sealed to
// another machine. The agent verifies it before any value reaches the process
// environment. Plain (legacy) values still open, with a warning when a root is
// pinned; making signatures mandatory for enrolled agents is a later flag.

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	ctxSecret          = "p3sig-secret-v1\n"
	signedSecretPrefix = "p3sig-signed-secret-v1\n"
)

// SignedSecret is what a device signs before sealing it to one machine.
type SignedSecret struct {
	Account   string `json:"account"`
	SecretID  string `json:"secret_id"`
	Name      string `json:"name"`
	Value     string `json:"value"`
	Recipient string `json:"recipient"` // SHA256:… of the machine key it is sealed to
	Issued    int64  `json:"issued"`
}

type signedSecretEnvelope struct {
	Signer string     `json:"signer"` // device key, authorized_keys line
	Secret signedBlob `json:"secret"`
}

// secretTrust is the root + delegation chain + revocations, checked once per pull.
type secretTrust struct {
	root    ssh.PublicKey
	chain   []signedBlob
	revoked map[string]bool
}

func machineKeyFP(pub ed25519.PublicKey) string {
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(sp)
}

// newSecretTrust checks the signed-policy root against the pinned fingerprint and
// opens its revocation list.
func newSecretTrust(sp *SignedPolicy, rootFP string) (*secretTrust, error) {
	root, err := parseKey(sp.RootKey)
	if err != nil {
		return nil, fmt.Errorf("root key: %w", err)
	}
	if got := ssh.FingerprintSHA256(root); got != rootFP {
		return nil, fmt.Errorf("root key %s is not the pinned root %s", got, rootFP)
	}
	t := &secretTrust{root: root, chain: sp.Chain, revoked: map[string]bool{}}
	if sp.Revocations != nil {
		var r Revocations
		if err := openSignedBlob(root, ctxRevocations, *sp.Revocations, &r); err != nil {
			return nil, fmt.Errorf("revocations: %w", err)
		}
		for _, fp := range r.Revoked {
			t.revoked[fp] = true
		}
	}
	return t, nil
}

// delegatedAccounts: accounts for which signerFP holds a live root delegation.
func (t *secretTrust) delegatedAccounts(signerFP string, now time.Time) (map[string]bool, error) {
	if t.revoked[signerFP] {
		return nil, fmt.Errorf("signing device %s has been revoked", signerFP)
	}
	accounts := map[string]bool{}
	for i, b := range t.chain {
		var d Delegation
		if err := openSignedBlob(t.root, ctxDelegation, b, &d); err != nil {
			return nil, fmt.Errorf("delegation %d: %w", i, err)
		}
		dk, err := parseKey(d.DeviceKey)
		if err != nil || ssh.FingerprintSHA256(dk) != signerFP {
			continue
		}
		if d.Expires != 0 && now.Unix() >= d.Expires {
			continue
		}
		accounts[d.Account] = true
	}
	if len(accounts) == 0 {
		return nil, fmt.Errorf("signing device %s has no live delegation from the root", signerFP)
	}
	return accounts, nil
}

// sealSignedSecret signs s with a delegated device key and seals the envelope to
// the recipient machine's Ed25519 public key (base64).
func sealSignedSecret(device ssh.Signer, s SignedSecret, recipientPubB64 string) (string, error) {
	blob, err := signBlob(device, ctxSecret, s)
	if err != nil {
		return "", err
	}
	env, err := json.Marshal(signedSecretEnvelope{Signer: authorizedKey(device.PublicKey()), Secret: blob})
	if err != nil {
		return "", err
	}
	return sealForKeyRaw(append([]byte(signedSecretPrefix), env...), recipientPubB64)
}

var errUnsignedSecret = errors.New("secret is not signed")

// openSecretValue turns an opened sealed plaintext into the value to use. A signed
// envelope must verify against trust and match secretID, name and this machine's
// key; anything that fails is an error, never a fallback to the raw bytes. A
// legacy plain value is returned with errUnsignedSecret so the caller can warn.
func openSecretValue(plain, secretID, name, recipientFP string, trust *secretTrust, now time.Time) (string, error) {
	if !strings.HasPrefix(plain, signedSecretPrefix) {
		return plain, errUnsignedSecret
	}
	if trust == nil {
		return "", errors.New("signed secret but no root pinned to verify it (--root SHA256:… / P3SIG_ROOT)")
	}
	var env signedSecretEnvelope
	dec := json.NewDecoder(strings.NewReader(plain[len(signedSecretPrefix):]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return "", fmt.Errorf("signed secret envelope: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return "", errors.New("signed secret envelope: trailing data")
	}
	signer, err := parseKey(env.Signer)
	if err != nil {
		return "", fmt.Errorf("signer key: %w", err)
	}
	accounts, err := trust.delegatedAccounts(ssh.FingerprintSHA256(signer), now)
	if err != nil {
		return "", err
	}
	var s SignedSecret
	if err := openSignedBlob(signer, ctxSecret, env.Secret, &s); err != nil {
		return "", err
	}
	switch {
	case !accounts[s.Account]:
		return "", fmt.Errorf("signer is not delegated for account %q", s.Account)
	case s.SecretID != secretID:
		return "", fmt.Errorf("signed for secret %s, served as %s (swapped)", s.SecretID, secretID)
	case s.Name != name:
		return "", fmt.Errorf("signed for name %q, served as %q (swapped)", s.Name, name)
	case s.Recipient != recipientFP:
		return "", fmt.Errorf("signed for machine %s, not this one (%s)", s.Recipient, recipientFP)
	}
	return s.Value, nil
}

// loadSecretTrust fetches the signed policy chain when a root is pinned. No root →
// nil trust (legacy). A pinned root whose chain fails is a hard error.
func loadSecretTrust(apiBase, machine string, key ed25519.PrivateKey, rootFP string) (*secretTrust, error) {
	if rootFP == "" {
		return nil, nil
	}
	var sp SignedPolicy
	if err := pullInto(apiBase, "getSignedPolicy", machine, key, nil, &sp); err != nil {
		return nil, fmt.Errorf("getSignedPolicy: %w", err)
	}
	if sp.RootKey == "" {
		return nil, errors.New("server returned no signing chain for a pinned root")
	}
	return newSecretTrust(&sp, rootFP)
}

func warnUnsignedSecrets(n int, rootPinned bool) {
	if n == 0 {
		return
	}
	hint := "Pin a root (P3SIG_ROOT=SHA256:…) and re-seal them signed."
	if rootPinned {
		hint = "Re-seal them signed with a delegated device key."
	}
	fmt.Fprintf(os.Stderr, "WARNING: %d secret(s) are not signed; only encryption protects them, not who sealed them. %s\n", n, hint)
}
