package main

// Owner + refresher side of the account-wide policy and freshness key (task #2631).
//
//	p3sig policy sign [--group G] [--expires-hours 72]   ONE device signature for every machine
//	p3sig policy freshness-delegate --root-key K --freshness-key PUB [--label L] [--expires 365d]
//	p3sig policy refresh --freshness-key K --account user:N --root SHA256:… [--group G] [--window 36h]
//
// `refresh` is the timestamp role, run on a timer on the key server (nokemo2 TPM),
// never on p3sig.com. It needs no vault key: every request is signed by the
// freshness key itself. It VERIFIES the device-signed policy against the pinned
// root before vouching for it, and keeps a version floor, so a server that names
// an older policy can't get it re-freshened.

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const freshnessAuthCtx = "p3sig-freshness-auth-v1\n"

// accountDiff mirrors p3sig_account_policy_diff (server) — shown before signing.
type accountDiff struct {
	SinceVersion    int64    `json:"since_version"`
	MachinesAdded   []string `json:"machines_added"`
	MachinesRemoved []string `json:"machines_removed"`
	Changed         map[string]struct {
		CAAdded       []string `json:"ca_added"`
		CARemoved     []string `json:"ca_removed"`
		GrantsAdded   []string `json:"grants_added"`
		GrantsRemoved []string `json:"grants_removed"`
	} `json:"changed"`
	KRLAdded   []string `json:"krl_added"`
	KRLRemoved []string `json:"krl_removed"`
}

// policySignAccount fetches the account (or group) draft, shows it with the diff
// since the last signed version, and signs exactly what was reviewed: one
// signature for every machine. Returns 0 when declined.
func policySignAccount(call policyCall, dev ssh.Signer, group string, hours int, review func(AccountPolicy, accountDiff) bool) (int64, error) {
	var d struct {
		Policy json.RawMessage `json:"policy"`
		Diff   json.RawMessage `json:"diff"`
	}
	if err := call("getAccountPolicyDraft", url.Values{"group": {group}, "expires_hours": {strconv.Itoa(hours)}}, &d); err != nil {
		return 0, err
	}
	var p AccountPolicy
	dec := json.NewDecoder(bytes.NewReader(d.Policy))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return 0, fmt.Errorf("draft account policy: %w", err)
	}
	if p.Group != group {
		return 0, fmt.Errorf("draft is for group %q, asked for %q", p.Group, group)
	}
	if len(p.Machines) == 0 {
		return 0, errors.New("draft lists no machines")
	}
	for mid, m := range p.Machines {
		for _, k := range m.CAKeys {
			if _, err := parseKey(k); err != nil {
				return 0, fmt.Errorf("machine %s: draft CA key is not an OpenSSH public key: %w", mid, err)
			}
		}
	}
	var diff accountDiff
	if len(d.Diff) > 0 {
		_ = json.Unmarshal(d.Diff, &diff) // display only; the signature covers p, not the diff
	}
	if !review(p, diff) {
		fmt.Println("not signed.")
		return 0, nil
	}
	b, err := signAccountPolicy(dev, p)
	if err != nil {
		return 0, err
	}
	return p.Version, call("accountPolicyPut", url.Values{"kind": {"account_policy"}, "payload": {b.Payload}, "sig": {b.Sig},
		"signer": {authorizedKey(dev.PublicKey())}}, nil)
}

// describeAccountPolicy: what the owner reviews before the ONE signature.
func describeAccountPolicy(p AccountPolicy, d accountDiff) string {
	var sb strings.Builder
	name := firstNonEmpty(p.Group, "whole account")
	fmt.Fprintf(&sb, "\naccount policy v%d for %s (%s) — %d machine(s), one signature\n", p.Version, p.Account, name, len(p.Machines))
	if d.SinceVersion == 0 {
		sb.WriteString("  first account policy — everything below is new\n")
	} else {
		fmt.Fprintf(&sb, "  changes since v%d:\n", d.SinceVersion)
		n := 0
		line := func(f string, a ...any) { fmt.Fprintf(&sb, "    "+f+"\n", a...); n++ }
		for _, m := range d.MachinesAdded {
			line("+ machine %s", m)
		}
		for _, m := range d.MachinesRemoved {
			line("- machine %s", m)
		}
		for m, c := range d.Changed {
			for _, k := range c.CAAdded {
				line("%s + CA %s", m, keyFP(k))
			}
			for _, k := range c.CARemoved {
				line("%s - CA %s", m, keyFP(k))
			}
			for _, g := range c.GrantsAdded {
				line("%s + %s", m, g)
			}
			for _, g := range c.GrantsRemoved {
				line("%s - %s", m, g)
			}
		}
		for _, k := range d.KRLAdded {
			line("+ revoke %s", k)
		}
		for _, k := range d.KRLRemoved {
			line("- un-revoke %s", k)
		}
		if n == 0 {
			sb.WriteString("    (none — re-signing the same content)\n")
		}
	}
	for mid, m := range p.Machines {
		fmt.Fprintf(&sb, "  %s:", mid)
		for _, k := range m.CAKeys {
			fmt.Fprintf(&sb, " CA %s", keyFP(k))
		}
		for _, g := range m.Grants {
			fmt.Fprintf(&sb, " · %s → %s", g.Principal, g.LoginUser)
		}
		sb.WriteString("\n")
	}
	krl := 0
	if s := strings.TrimSpace(p.KRLSpec); s != "" {
		krl = strings.Count(s, "\n") + 1
	}
	fmt.Fprintf(&sb, "  KRL: %d revoked entr(ies); valid until %s unless the freshness key extends it\n",
		krl, time.Unix(p.Expires, 0).UTC().Format("2006-01-02 15:04Z"))
	return sb.String()
}

func keyFP(line string) string {
	if pk, err := parseKey(line); err == nil {
		return ssh.FingerprintSHA256(pk)
	}
	return "?"
}

// policyFreshnessDelegate: the root lets key vouch for freshness of this account's policies.
func policyFreshnessDelegate(call policyCall, root ssh.Signer, keyLine, label string, expires int64, now time.Time) (string, error) {
	st, err := rootStatus(call, root)
	if err != nil {
		return "", err
	}
	k, err := parseKey(keyLine)
	if err != nil {
		return "", fmt.Errorf("freshness key: %w", err)
	}
	b, err := signFreshnessDelegation(root, FreshnessDelegation{Account: st.Account, Key: authorizedKey(k), Label: label, Issued: now.Unix(), Expires: expires})
	if err != nil {
		return "", err
	}
	return ssh.FingerprintSHA256(k), call("accountPolicyPut", url.Values{"kind": {"freshness_delegation"}, "payload": {b.Payload}, "sig": {b.Sig}}, nil)
}

// refreshState: what the refresher has already vouched for (its own floor).
type refreshState struct {
	Version            int64 `json:"version"`
	RevocationsVersion int64 `json:"revocations_version"`
	Issued             int64 `json:"issued"`
}

// defaultFreshnessWindow is used when neither --window nor the account's
// settings (SSH Access › Freshness settings) give one.
const defaultFreshnessWindow = 36 * time.Hour

// freshnessRefresh is one timer tick: fetch, verify, vouch, upload. post is
// postForm(apiBase, …) in the CLI and a fake in tests. window 0 = the
// account's window from freshnessGetCurrent; a larger --window is cut down to
// it, because freshnessPut refuses statements longer than the account window.
func freshnessRefresh(post func(url.Values, any) error, key ssh.Signer, account, group, rootFP string, window time.Duration, st *refreshState, now time.Time) (int64, error) {
	if window < 0 || window > maxFreshnessWindow {
		return 0, fmt.Errorf("--window must be between 1m and %s", maxFreshnessWindow)
	}
	fp := ssh.FingerprintSHA256(key.PublicKey())
	ts := strconv.FormatInt(now.Unix(), 10)
	asig, err := key.Sign(nil, []byte(freshnessAuthCtx+"freshnessGetCurrent|"+fp+"|"+ts))
	if err != nil {
		return 0, fmt.Errorf("freshness key %s did not sign: %w", fp, err)
	}
	var cur struct {
		SignedPolicy
		PolicyHash string `json:"policy_hash"`
		Settings   struct {
			WindowHours int `json:"window_hours"`
		} `json:"settings"`
	}
	if err := post(url.Values{"action": {"freshnessGetCurrent"}, "account": {account}, "group": {group}, "key": {authorizedKey(key.PublicKey())},
		"ts": {ts}, "auth_sig": {base64.StdEncoding.EncodeToString(ssh.Marshal(asig))}}, &cur); err != nil {
		return 0, err
	}
	sp := &cur.SignedPolicy
	if sp.AccountPolicy == nil || sp.AccountPolicy.Payload == "" {
		return 0, errors.New("server returned no account policy")
	}
	root, revoked, err := verifyRootAndRevocations(sp, rootFP, policyState{RevocationsVersion: st.RevocationsVersion})
	if err != nil {
		return 0, err
	}
	if revoked[fp] {
		return 0, fmt.Errorf("this freshness key %s has been revoked by the root", fp)
	}
	signer, err := parseKey(sp.Signer)
	if err != nil {
		return 0, fmt.Errorf("signer key: %w", err)
	}
	sfp := ssh.FingerprintSHA256(signer)
	if revoked[sfp] {
		return 0, fmt.Errorf("policy signed by revoked device %s — not vouching", sfp)
	}
	accounts, err := liveDelegations(root, sp.Chain, sfp, now)
	if err != nil {
		return 0, err
	}
	var ap AccountPolicy
	if err := openSignedBlob(signer, ctxAccountPolicy, *sp.AccountPolicy, &ap); err != nil {
		return 0, fmt.Errorf("account policy: %w", err)
	}
	if ap.Account != account || !accounts[ap.Account] || ap.Group != group {
		return 0, fmt.Errorf("policy is for %s/%q, not %s/%q", ap.Account, ap.Group, account, group)
	}
	if ap.Version < st.Version {
		return 0, fmt.Errorf("server offers v%d, older than v%d already vouched for (withholding?) — not vouching", ap.Version, st.Version)
	}
	hash, err := accountPolicyHash(*sp.AccountPolicy)
	if err != nil {
		return 0, err
	}
	if cur.PolicyHash != "" && cur.PolicyHash != hash {
		return 0, fmt.Errorf("server hash %s ≠ computed %s", cur.PolicyHash, hash)
	}
	if acct := time.Duration(cur.Settings.WindowHours) * time.Hour; acct > 0 && acct <= maxFreshnessWindow && (window == 0 || window > acct) {
		window = acct
	} else if window == 0 {
		window = defaultFreshnessWindow
	}
	f := Freshness{Account: account, Group: group, PolicyHash: hash, Version: ap.Version, Issued: now.Unix(), Expires: now.Add(window).Unix()}
	if f.Issued <= st.Issued {
		f.Issued = st.Issued + 1 // server refuses a statement not newer than the stored one
	}
	b, err := signFreshness(key, f)
	if err != nil {
		return 0, err
	}
	if err := post(url.Values{"action": {"freshnessPut"}, "payload": {b.Payload}, "sig": {b.Sig}, "signer": {authorizedKey(key.PublicKey())}}, nil); err != nil {
		return 0, err
	}
	st.Version, st.Issued = ap.Version, f.Issued
	if sp.Revocations != nil {
		var r Revocations
		if openSignedBlob(root, ctxRevocations, *sp.Revocations, &r) == nil && r.Version > st.RevocationsVersion {
			st.RevocationsVersion = r.Version
		}
	}
	return f.Expires, nil
}

func cmdPolicyRefresh(f map[string]string) error {
	// The systemd unit passes everything through the environment (an empty --group can't be a flag).
	for flag, env := range map[string]string{"freshness-key": "P3SIG_FRESHNESS_KEY", "account": "P3SIG_ACCOUNT", "root": "P3SIG_ROOT",
		"group": "P3SIG_GROUP", "window": "P3SIG_WINDOW", "state": "P3SIG_FRESHNESS_STATE"} {
		if f[flag] == "" {
			f[flag] = os.Getenv(env)
		}
	}
	if f["account"] == "" || f["root"] == "" || f["freshness-key"] == "" {
		return errors.New("usage: p3sig policy refresh --freshness-key agent[:SHA256:…]|KEYFILE --account user:N --root SHA256:… [--group G] [--window 36h, default: the account window] [--url API]")
	}
	key, err := loadSigner(f["freshness-key"])
	if err != nil {
		return fmt.Errorf("--freshness-key: %w", err)
	}
	var window time.Duration // 0 = the account's window (server settings)
	if w := f["window"]; w != "" {
		if window, err = time.ParseDuration(w); err != nil {
			return fmt.Errorf("--window %q: %w", w, err)
		}
	}
	apiBase, _, _ := resolveIdentity(f)
	dir, _ := os.UserConfigDir()
	statePath := firstNonEmpty(f["state"], filepath.Join(dir, "p3sig", "freshness-"+strings.ReplaceAll(f["account"], ":", "_")+"-"+firstNonEmpty(f["group"], "_")+".json"))
	var st refreshState
	if data, err := os.ReadFile(statePath); err == nil {
		if err := json.Unmarshal(data, &st); err != nil {
			return fmt.Errorf("%s: %w", statePath, err)
		}
	}
	post := func(form url.Values, v any) error { return postForm(apiBase, form, v) }
	exp, err := freshnessRefresh(post, key, f["account"], f["group"], f["root"], window, &st, time.Now())
	if err != nil {
		return err
	}
	data, _ := json.Marshal(st)
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(statePath, data, 0o600); err != nil {
		return err
	}
	fmt.Printf("freshness: %s %s v%d valid until %s\n", f["account"], firstNonEmpty(f["group"], "(account)"), st.Version, time.Unix(exp, 0).UTC().Format(time.RFC3339))
	return nil
}

// cmdPolicySignAccount: `p3sig policy sign` without --machine/--all.
func cmdPolicySignAccount(call policyCall, dev ssh.Signer, f map[string]string) error {
	hours := 72
	if h := firstNonEmpty(f["expires-hours"], f["krl-hours"]); h != "" {
		var err error
		if hours, err = strconv.Atoi(h); err != nil || hours < 1 || hours > 720 {
			return errors.New("--expires-hours must be 1..720")
		}
	}
	in := bufio.NewReader(os.Stdin)
	v, err := policySignAccount(call, dev, f["group"], hours, func(p AccountPolicy, d accountDiff) bool {
		fmt.Print(describeAccountPolicy(p, d))
		return f["yes"] == "true" || confirm(in, "Sign this account policy (one signature for every machine above)?")
	})
	if err != nil {
		return err
	}
	if v > 0 {
		fmt.Printf("signed account policy v%d by %s — every listed machine picks it up on its next pull\n", v, ssh.FingerprintSHA256(dev.PublicKey()))
	}
	return nil
}
