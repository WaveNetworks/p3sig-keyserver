package main

// Account-wide signed policy + freshness key (task #2631, TUF targets/timestamp split).
//
//	ACCOUNT POLICY — ONE device signature (one PIN + touch) lists every machine's
//	                 grants (machine_id → CAs/principals) plus one account KRL.
//	                 Each agent applies only the entry under its own machine_id.
//	                 Optional named groups (prod/lab…) are separate account
//	                 policies, each with its own monotonic version. The device
//	                 signature carries an initial expiry.
//	FRESHNESS KEY  — a low-privilege key the root delegates with its own context
//	                 (p3sig-freshness-delegation-v1), so it can never sign policy.
//	                 It signs only {account, group, policy hash, version, issued,
//	                 expires}: it extends how long one exact policy stays valid and
//	                 cannot change a byte of it. Compromise = the withholding attack
//	                 only (no worse than before). Revoked like any device, through
//	                 the root-signed revocation list.
//
// The agent accepts an account policy if the device chain verifies AND either the
// policy's own expiry or a valid freshness statement for its exact hash is live.
// Otherwise it keeps the last good sshd files (errStaleKRL) and reports it.
// Versions are shared with the per-machine format, so a switch can't go back.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	ctxAccountPolicy       = "p3sig-account-policy-v1\n"
	ctxFreshness           = "p3sig-freshness-v1\n"
	ctxFreshnessDelegation = "p3sig-freshness-delegation-v1\n"
	formatAccount          = "account"
	maxFreshnessWindow     = 7 * 24 * time.Hour // a freshness statement never vouches further than this
	maxFreshnessClockSkew  = 5 * time.Minute
)

// MachinePolicy is one machine's slice of an account policy.
type MachinePolicy struct {
	CAKeys []string      `json:"trusted_user_ca_keys"`
	Grants []PolicyGrant `json:"grants"`
}

// AccountPolicy: everything every machine in the account (or group) writes into sshd.
type AccountPolicy struct {
	Account  string                   `json:"account"`
	Group    string                   `json:"group,omitempty"` // "" = the whole account
	Version  int64                    `json:"version"`
	Issued   int64                    `json:"issued"`
	Expires  int64                    `json:"expires"` // initial validity; freshness statements extend it
	KRLSpec  string                   `json:"krl_spec"`
	Machines map[string]MachinePolicy `json:"machines"`
}

// FreshnessDelegation: the root lets one key vouch for freshness of one account's policies.
type FreshnessDelegation struct {
	Account string `json:"account"`
	Key     string `json:"key"` // authorized_keys line
	Label   string `json:"label,omitempty"`
	Issued  int64  `json:"issued"`
	Expires int64  `json:"expires,omitempty"`
}

// Freshness: "the policy with this hash is still current until Expires".
type Freshness struct {
	Account    string `json:"account"`
	Group      string `json:"group,omitempty"`
	PolicyHash string `json:"policy_hash"`
	Version    int64  `json:"version"`
	Issued     int64  `json:"issued"`
	Expires    int64  `json:"expires"`
}

func signAccountPolicy(device ssh.Signer, p AccountPolicy) (signedBlob, error) {
	return signBlob(device, ctxAccountPolicy, p)
}

func signFreshnessDelegation(root ssh.Signer, d FreshnessDelegation) (signedBlob, error) {
	return signBlob(root, ctxFreshnessDelegation, d)
}

func signFreshness(key ssh.Signer, f Freshness) (signedBlob, error) {
	return signBlob(key, ctxFreshness, f)
}

// accountPolicyHash binds a freshness statement to the exact signed bytes.
func accountPolicyHash(b signedBlob) (string, error) {
	payload, err := base64.StdEncoding.DecodeString(b.Payload)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(append([]byte(ctxAccountPolicy), payload...))
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

// verifyPolicyAny picks the format: the account policy is preferred when served;
// once one was applied, a per-machine policy is refused (no downgrade replay).
func verifyPolicyAny(sp *SignedPolicy, rootFP, machine string, st policyState, now time.Time) (*Policy, error) {
	if sp.AccountPolicy != nil && sp.AccountPolicy.Payload != "" {
		return verifyAccountPolicy(sp, rootFP, machine, st, now)
	}
	if st.Format == formatAccount {
		return nil, errors.New("per-machine policy served after an account policy was applied (format downgrade refused)")
	}
	return verifySignedPolicy(sp, rootFP, st, now)
}

// verifyAccountPolicy verifies sp.AccountPolicy and returns this machine's entry
// projected onto Policy (KRLExpires = the effective expiry), so the apply path is shared.
func verifyAccountPolicy(sp *SignedPolicy, rootFP, machine string, st policyState, now time.Time) (*Policy, error) {
	root, revoked, err := verifyRootAndRevocations(sp, rootFP, st)
	if err != nil {
		return nil, err
	}
	signer, err := parseKey(sp.Signer)
	if err != nil {
		return nil, fmt.Errorf("signer key: %w", err)
	}
	signerFP := ssh.FingerprintSHA256(signer)
	if revoked[signerFP] {
		return nil, fmt.Errorf("signing device %s has been revoked", signerFP)
	}
	accounts, err := liveDelegations(root, sp.Chain, signerFP, now)
	if err != nil {
		return nil, err
	}

	var ap AccountPolicy
	if err := openSignedBlob(signer, ctxAccountPolicy, *sp.AccountPolicy, &ap); err != nil {
		return nil, fmt.Errorf("account policy: %w", err)
	}
	if !accounts[ap.Account] {
		return nil, fmt.Errorf("device %s is not delegated for account %q", signerFP, ap.Account)
	}
	if ap.Version < st.Version {
		return nil, fmt.Errorf("account policy v%d is older than v%d already applied (replay)", ap.Version, st.Version)
	}
	mine, ok := ap.Machines[machine]
	if !ok {
		return nil, fmt.Errorf("account policy v%d has no entry for machine %q", ap.Version, machine)
	}
	for _, k := range mine.CAKeys {
		if _, err := parseKey(k); err != nil {
			return nil, fmt.Errorf("policy CA key is not an OpenSSH public key: %w", err)
		}
	}
	p := &Policy{Account: ap.Account, Version: ap.Version, Issued: ap.Issued, KRLExpires: ap.Expires,
		CAKeys: mine.CAKeys, Grants: mine.Grants, KRLSpec: ap.KRLSpec}

	var why error
	if sp.Freshness != nil {
		exp, ferr := verifyFreshness(sp, root, revoked, &ap, now)
		if ferr != nil {
			why = ferr
		} else if exp > p.KRLExpires {
			p.KRLExpires = exp
		}
	}
	if p.KRLExpires == 0 || now.Unix() >= p.KRLExpires {
		if why != nil {
			return p, fmt.Errorf("%w (freshness refused: %v)", errStaleKRL, why)
		}
		return p, errStaleKRL
	}
	return p, nil
}

// verifyFreshness returns the expiry a valid freshness statement grants ap.
func verifyFreshness(sp *SignedPolicy, root ssh.PublicKey, revoked map[string]bool, ap *AccountPolicy, now time.Time) (int64, error) {
	key, err := parseKey(sp.FreshnessSigner)
	if err != nil {
		return 0, fmt.Errorf("freshness key: %w", err)
	}
	fp := ssh.FingerprintSHA256(key)
	if revoked[fp] {
		return 0, fmt.Errorf("freshness key %s has been revoked", fp)
	}
	delegated := false
	for i, b := range sp.FreshnessChain {
		var d FreshnessDelegation
		if err := openSignedBlob(root, ctxFreshnessDelegation, b, &d); err != nil {
			return 0, fmt.Errorf("freshness delegation %d: %w", i, err)
		}
		k, err := parseKey(d.Key)
		if err != nil || ssh.FingerprintSHA256(k) != fp || d.Account != ap.Account {
			continue
		}
		if d.Expires != 0 && now.Unix() >= d.Expires {
			continue
		}
		delegated = true
	}
	if !delegated {
		return 0, fmt.Errorf("freshness key %s has no live delegation from the root for account %q", fp, ap.Account)
	}
	var f Freshness
	if err := openSignedBlob(key, ctxFreshness, *sp.Freshness, &f); err != nil {
		return 0, fmt.Errorf("freshness statement: %w", err)
	}
	want, err := accountPolicyHash(*sp.AccountPolicy)
	if err != nil {
		return 0, err
	}
	if f.PolicyHash != want || f.Account != ap.Account || f.Group != ap.Group || f.Version != ap.Version {
		return 0, errors.New("freshness statement is for a different policy")
	}
	if f.Issued > now.Add(maxFreshnessClockSkew).Unix() {
		return 0, errors.New("freshness statement is issued in the future")
	}
	exp := f.Expires
	if cap := f.Issued + int64(maxFreshnessWindow/time.Second); exp > cap {
		exp = cap
	}
	if now.Unix() >= exp {
		return 0, fmt.Errorf("freshness statement expired %s", time.Unix(exp, 0).UTC().Format(time.RFC3339))
	}
	return exp, nil
}

// verifyRootAndRevocations checks the pinned root and the root-signed revocation list.
func verifyRootAndRevocations(sp *SignedPolicy, rootFP string, st policyState) (ssh.PublicKey, map[string]bool, error) {
	if rootFP == "" {
		return nil, nil, errors.New("no root fingerprint pinned (p3sig agent pull --root SHA256:…)")
	}
	root, err := parseKey(sp.RootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("root key: %w", err)
	}
	if got := ssh.FingerprintSHA256(root); got != rootFP {
		return nil, nil, fmt.Errorf("root key %s is not the pinned root %s", got, rootFP)
	}
	revoked := map[string]bool{}
	if sp.Revocations != nil {
		var r Revocations
		if err := openSignedBlob(root, ctxRevocations, *sp.Revocations, &r); err != nil {
			return nil, nil, fmt.Errorf("revocations: %w", err)
		}
		if r.Version < st.RevocationsVersion {
			return nil, nil, fmt.Errorf("revocation list v%d is older than v%d already seen (replay)", r.Version, st.RevocationsVersion)
		}
		for _, fp := range r.Revoked {
			revoked[fp] = true
		}
	} else if st.RevocationsVersion > 0 {
		return nil, nil, errors.New("revocation list missing after one was seen (stripped)")
	}
	return root, revoked, nil
}

// liveDelegations returns the accounts the root currently lets signerFP sign for.
func liveDelegations(root ssh.PublicKey, chain []signedBlob, signerFP string, now time.Time) (map[string]bool, error) {
	accounts := map[string]bool{}
	for i, b := range chain {
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
	return accounts, nil
}
