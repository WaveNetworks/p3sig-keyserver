package main

// Signed policy (task #2568): the agent no longer trusts p3sig.com's TLS alone
// for what it writes into sshd's trust files.
//
//	ROOT    — the vault key in the safe. Signs only DELEGATIONS ("device key X may
//	          sign policy for account Y", optional expiry) and the list of revoked
//	          delegations. Needed only to enrol or revoke a signing device.
//	DEVICE  — the daily dongle or a device-chip key (Secure Enclave / TPM). Signs
//	          every policy: CA list, principals, KRL, with a monotonic version.
//	SERVER  — stores the signed blobs + chain and holds no signing key.
//	AGENT   — pins the root FINGERPRINT, verifies chain → revocations → policy
//	          signature → version ≥ last seen → KRL freshness, and only then writes.
//
// Every key is an OpenSSH public key and every signature an OpenSSH signature,
// so ed25519 files, sk-ssh-ed25519 dongles and ecdsa-p256 chips all verify the
// same way. Each signed payload carries a domain-separation prefix so a
// signature over one kind can never be replayed as another.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	ctxDelegation  = "p3sig-delegation-v1\n"
	ctxRevocations = "p3sig-revocations-v1\n"
	ctxPolicy      = "p3sig-policy-v1\n"

	policyStateFile = ".p3sig-policy-state.json"
)

// Delegation: the root lets one device key sign policy for one account.
type Delegation struct {
	Account   string `json:"account"`
	DeviceKey string `json:"device_key"` // authorized_keys line
	Label     string `json:"label,omitempty"`
	Issued    int64  `json:"issued"`
	Expires   int64  `json:"expires,omitempty"` // unix; 0 = no expiry
}

// Revocations: root-signed list of device-key fingerprints that may no longer
// sign. Versioned so an attacker can't serve an older, shorter list.
type Revocations struct {
	Account string   `json:"account"`
	Version int64    `json:"version"`
	Revoked []string `json:"revoked"` // SHA256:… fingerprints
}

type PolicyGrant struct {
	Principal string `json:"principal"`
	LoginUser string `json:"login_user"`
}

// Policy: everything the agent writes into sshd's files.
type Policy struct {
	Account    string        `json:"account"`
	Version    int64         `json:"version"`
	Issued     int64         `json:"issued"`
	KRLExpires int64         `json:"krl_expires"` // a fresh signed KRL must arrive before this
	CAKeys     []string      `json:"trusted_user_ca_keys"`
	Grants     []PolicyGrant `json:"grants"`
	KRLSpec    string        `json:"krl_spec"`
}

// signedBlob: base64 payload + base64 ssh.Marshal(*ssh.Signature).
type signedBlob struct {
	Payload string `json:"payload"`
	Sig     string `json:"sig"`
}

// SignedPolicy is what getSignedPolicy returns.
type SignedPolicy struct {
	RootKey     string       `json:"root_key"` // checked against the pinned fingerprint
	Chain       []signedBlob `json:"chain"`
	Revocations *signedBlob  `json:"revocations,omitempty"`
	Policy      signedBlob   `json:"policy"`
	Signer      string       `json:"signer"` // device key that signed Policy
}

type policyState struct {
	RootFP             string `json:"root_fp"`
	Version            int64  `json:"version"`
	RevocationsVersion int64  `json:"revocations_version"`
	KRLExpires         int64  `json:"krl_expires"`
}

var errStaleKRL = errors.New("signed KRL has expired — keeping the last good config")

// ─── signing (root + device side) ───────────────────────────────────────────

func signBlob(s ssh.Signer, ctx string, v any) (signedBlob, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return signedBlob{}, err
	}
	sig, err := s.Sign(nil, append([]byte(ctx), payload...))
	if err != nil {
		return signedBlob{}, err
	}
	return signedBlob{
		Payload: base64.StdEncoding.EncodeToString(payload),
		Sig:     base64.StdEncoding.EncodeToString(ssh.Marshal(sig)),
	}, nil
}

func signDelegation(root ssh.Signer, d Delegation) (signedBlob, error) {
	return signBlob(root, ctxDelegation, d)
}

func signRevocations(root ssh.Signer, r Revocations) (signedBlob, error) {
	return signBlob(root, ctxRevocations, r)
}

func signPolicy(device ssh.Signer, p Policy) (signedBlob, error) {
	return signBlob(device, ctxPolicy, p)
}

func authorizedKey(pub ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}

// ─── verification (agent side) ──────────────────────────────────────────────

func openSignedBlob(pub ssh.PublicKey, ctx string, b signedBlob, v any) error {
	payload, err := base64.StdEncoding.DecodeString(b.Payload)
	if err != nil {
		return fmt.Errorf("payload encoding: %w", err)
	}
	rawSig, err := base64.StdEncoding.DecodeString(b.Sig)
	if err != nil {
		return fmt.Errorf("signature encoding: %w", err)
	}
	sig := new(ssh.Signature)
	if err := ssh.Unmarshal(rawSig, sig); err != nil {
		return fmt.Errorf("signature format: %w", err)
	}
	if err := pub.Verify(append([]byte(ctx), payload...), sig); err != nil {
		return fmt.Errorf("bad signature: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func parseKey(line string) (ssh.PublicKey, error) {
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	return k, err
}

// verifySignedPolicy checks sp against the pinned root fingerprint and the last
// state this agent accepted. It returns the policy only when every check passes.
func verifySignedPolicy(sp *SignedPolicy, rootFP string, st policyState, now time.Time) (*Policy, error) {
	if rootFP == "" {
		return nil, errors.New("no root fingerprint pinned (p3sig agent pull --root SHA256:…)")
	}
	root, err := parseKey(sp.RootKey)
	if err != nil {
		return nil, fmt.Errorf("root key: %w", err)
	}
	if got := ssh.FingerprintSHA256(root); got != rootFP {
		return nil, fmt.Errorf("root key %s is not the pinned root %s", got, rootFP)
	}

	revoked := map[string]bool{}
	if sp.Revocations != nil {
		var r Revocations
		if err := openSignedBlob(root, ctxRevocations, *sp.Revocations, &r); err != nil {
			return nil, fmt.Errorf("revocations: %w", err)
		}
		if r.Version < st.RevocationsVersion {
			return nil, fmt.Errorf("revocation list v%d is older than v%d already seen (replay)", r.Version, st.RevocationsVersion)
		}
		for _, fp := range r.Revoked {
			revoked[fp] = true
		}
	} else if st.RevocationsVersion > 0 {
		return nil, errors.New("revocation list missing after one was seen (stripped)")
	}

	signer, err := parseKey(sp.Signer)
	if err != nil {
		return nil, fmt.Errorf("signer key: %w", err)
	}
	signerFP := ssh.FingerprintSHA256(signer)
	if revoked[signerFP] {
		return nil, fmt.Errorf("signing device %s has been revoked", signerFP)
	}

	// The signer must hold a live root delegation; collect the accounts it covers.
	accounts := map[string]bool{}
	for i, b := range sp.Chain {
		var d Delegation
		if err := openSignedBlob(root, ctxDelegation, b, &d); err != nil {
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

	var p Policy
	if err := openSignedBlob(signer, ctxPolicy, sp.Policy, &p); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if !accounts[p.Account] {
		return nil, fmt.Errorf("device %s is not delegated for account %q", signerFP, p.Account)
	}
	if p.Version < st.Version {
		return nil, fmt.Errorf("policy v%d is older than v%d already applied (replay)", p.Version, st.Version)
	}
	if p.KRLExpires == 0 || now.Unix() >= p.KRLExpires {
		return &p, errStaleKRL
	}
	for _, k := range p.CAKeys {
		if _, err := parseKey(k); err != nil {
			return nil, fmt.Errorf("policy CA key is not an OpenSSH public key: %w", err)
		}
	}
	return &p, nil
}

// nextState is the state to persist after p (and its revocation list) was applied.
func nextState(sp *SignedPolicy, rootFP string, p *Policy, prev policyState) policyState {
	st := policyState{RootFP: rootFP, Version: p.Version, KRLExpires: p.KRLExpires, RevocationsVersion: prev.RevocationsVersion}
	if sp.Revocations != nil {
		var r Revocations
		if b, err := base64.StdEncoding.DecodeString(sp.Revocations.Payload); err == nil && json.Unmarshal(b, &r) == nil {
			st.RevocationsVersion = r.Version
		}
	}
	return st
}

func loadPolicyState(outDir string) policyState {
	var st policyState
	if b, err := os.ReadFile(filepath.Join(outDir, policyStateFile)); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	return st
}

func savePolicyState(outDir string, st policyState) error {
	b, _ := json.MarshalIndent(st, "", "  ")
	return writeFileAtomic(filepath.Join(outDir, policyStateFile), append(b, '\n'), 0o600)
}

// writeFileAtomic replaces path in one rename, so sshd never reads a half file.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
