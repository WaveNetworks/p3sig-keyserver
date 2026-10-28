package main

// p3sig policy … — the owner's side of signed policy (task #2568).
//
//	p3sig policy root     --root-key K            publish the root (once); prints the fingerprint to pin
//	p3sig policy delegate --root-key K --device D  root lets device D sign policy (enrol a dongle/chip)
//	p3sig policy revoke   --root-key K --device D  root revokes device D (versioned list, can't be rolled back)
//	p3sig policy sign     --with S --machine ID|--all   device signs the server's draft after you review it
//	p3sig policy status                            root fp, delegations, revocations, per-machine versions
//
// A signer (K, S) is a key FILE (the p3sig base64 vault key or an OpenSSH private
// key) or `agent[:SHA256:…]`: a key in the ssh-agent at SSH_AUTH_SOCK. That covers
// every device without new code — a FIDO dongle loaded with ssh-add (sk-ssh-ed25519)
// and the Secure Enclave / TPM chip key served by `p3sig ssh-agent`.
//
// The server only stores what is signed here. Requests are authenticated with the
// account's vault key (p3sig login), which need NOT be the root: the root stays in
// the safe and is needed only for root/delegate/revoke. When no vault key is
// readable (the vault USB is unplugged), `policy sign` and `policy status`
// authenticate with the delegated device itself (task #2629): the server
// re-checks its root-signed delegation and the revoked list on every request,
// and accepts a device only for policy draft/upload/status.

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// policyCall is one authenticated API call (userRequest in the CLI, a fake in tests).
type policyCall func(action string, extra url.Values, v any) error

type policyStatus struct {
	Account     string `json:"account"`
	RootFP      string `json:"root_fp"`
	Delegations []struct {
		DeviceFP string `json:"device_fp"`
		Label    string `json:"label"`
		Issued   int64  `json:"issued"`
		Expires  int64  `json:"expires"`
		Revoked  bool   `json:"revoked"`
	} `json:"delegations"`
	RevocationsVersion int64 `json:"revocations_version"`
	Machines           []struct {
		MachineID  string `json:"machine_id"`
		Name       string `json:"name"`
		Version    int64  `json:"version"`
		KRLExpires int64  `json:"krl_expires"`
	} `json:"machines"`
}

func cmdPolicy(sub string, f map[string]string) error {
	if sub == "" || sub == "help" {
		return errors.New("usage: p3sig policy root|delegate|revoke|sign|status  (run `p3sig help`)")
	}
	apiBase, keyPath, err := resolveIdentity(f)
	if err == nil {
		if _, serr := os.Stat(keyPath); serr != nil {
			err = fmt.Errorf("vault key %s is not readable (vault USB unplugged?): %w", keyPath, serr)
		}
	}
	call := func(action string, extra url.Values, v any) error {
		return userRequest(apiBase, action, keyPath, extra, v)
	}
	if err != nil {
		if sub != "sign" && sub != "status" {
			return err
		}
		dev, derr := loadSigner(firstNonEmpty(f["with"], "agent"))
		if derr != nil {
			return fmt.Errorf("%v\nand no signing device to authenticate with (--with agent[:SHA256:…]|KEYFILE): %w", err, derr)
		}
		fmt.Fprintf(os.Stderr, "no vault key — authenticating as delegated device %s (a dongle asks for a touch per request)\n",
			ssh.FingerprintSHA256(dev.PublicKey()))
		call = func(action string, extra url.Values, v any) error {
			return deviceRequest(apiBase, action, dev, f["account"], extra, v)
		}
	}
	switch sub {
	case "status":
		return policyStatusCmd(call)
	case "root", "delegate", "revoke":
		root, err := loadSigner(f["root-key"])
		if err != nil {
			return fmt.Errorf("--root-key (the root key from the safe): %w", err)
		}
		switch sub {
		case "root":
			fp, err := policySetRoot(call, root)
			if err != nil {
				return err
			}
			fmt.Printf("policy root set: %s\nPin it on every machine:  p3sig agent pull --root %s\n"+
				"and compare it with the fingerprint on the web app's SSH Access page.\n", fp, fp)
			return nil
		case "delegate":
			dev, err := deviceKeyLine(f["device"])
			if err != nil {
				return err
			}
			exp, err := parseExpiry(f["expires"], time.Now())
			if err != nil {
				return err
			}
			fp, err := policyDelegate(call, root, dev, f["label"], exp, time.Now())
			if err != nil {
				return err
			}
			fmt.Printf("delegated %s — it can now sign policy without the root key.\n", fp)
			return nil
		default:
			fp, err := deviceFingerprint(f["device"])
			if err != nil {
				return err
			}
			v, err := policyRevoke(call, root, fp)
			if err != nil {
				return err
			}
			fmt.Printf("revoked %s (revocation list v%d). Agents refuse its signatures from their next pull.\n", fp, v)
			return nil
		}
	case "sign":
		dev, err := loadSigner(firstNonEmpty(f["with"], "agent"))
		if err != nil {
			return fmt.Errorf("--with (key file or agent[:SHA256:…]): %w", err)
		}
		hours := 72
		if h := f["krl-hours"]; h != "" {
			if hours, err = strconv.Atoi(h); err != nil || hours < 1 {
				return fmt.Errorf("--krl-hours must be a positive number of hours")
			}
		}
		machines := []string{}
		if f["all"] == "true" {
			var st policyStatus
			if err := call("getPolicyStatus", nil, &st); err != nil {
				return err
			}
			for _, m := range st.Machines {
				machines = append(machines, m.MachineID)
			}
		} else if f["machine"] != "" {
			machines = append(machines, f["machine"])
		} else {
			return errors.New("usage: p3sig policy sign --machine ID | --all [--with agent[:SHA256:…]|KEYFILE] [--krl-hours 72] [--yes]")
		}
		in := bufio.NewReader(os.Stdin)
		review := func(machine string, p Policy) bool {
			fmt.Print(describePolicy(machine, p))
			return f["yes"] == "true" || confirm(in, "Sign this policy?")
		}
		for _, m := range machines {
			v, err := policySign(call, dev, m, hours, review)
			if err != nil {
				return fmt.Errorf("machine %s: %w", m, err)
			}
			if v > 0 {
				fmt.Printf("signed policy v%d for %s by %s\n", v, m, ssh.FingerprintSHA256(dev.PublicKey()))
			}
		}
		return nil
	}
	return fmt.Errorf("unknown policy subcommand %q (root | delegate | revoke | sign | status)", sub)
}

// ─── the operations (testable: call + signers in, results out) ───────────────

func policySetRoot(call policyCall, root ssh.Signer) (string, error) {
	var r struct {
		RootFP string `json:"root_fp"`
	}
	if err := call("policySetRoot", url.Values{"root_key": {authorizedKey(root.PublicKey())}}, &r); err != nil {
		return "", err
	}
	if want := ssh.FingerprintSHA256(root.PublicKey()); r.RootFP != want {
		return "", fmt.Errorf("server reports root %s, not this key %s", r.RootFP, want)
	}
	return r.RootFP, nil
}

// rootStatus fetches the status and checks root really is the account's root.
func rootStatus(call policyCall, root ssh.Signer) (policyStatus, error) {
	var st policyStatus
	if err := call("getPolicyStatus", nil, &st); err != nil {
		return st, err
	}
	if st.RootFP == "" {
		return st, errors.New("no policy root on this account yet — run `p3sig policy root --root-key …` first")
	}
	if fp := ssh.FingerprintSHA256(root.PublicKey()); fp != st.RootFP {
		return st, fmt.Errorf("%s is not this account's policy root (%s)", fp, st.RootFP)
	}
	return st, nil
}

func putBlob(call policyCall, kind string, b signedBlob, extra url.Values) error {
	form := url.Values{"kind": {kind}, "payload": {b.Payload}, "sig": {b.Sig}}
	for k, v := range extra {
		form[k] = v
	}
	return call("policyPutBlob", form, nil)
}

func policyDelegate(call policyCall, root ssh.Signer, deviceLine, label string, expires int64, now time.Time) (string, error) {
	st, err := rootStatus(call, root)
	if err != nil {
		return "", err
	}
	dk, err := parseKey(deviceLine)
	if err != nil {
		return "", fmt.Errorf("device key: %w", err)
	}
	b, err := signDelegation(root, Delegation{Account: st.Account, DeviceKey: authorizedKey(dk), Label: label, Issued: now.Unix(), Expires: expires})
	if err != nil {
		return "", err
	}
	return ssh.FingerprintSHA256(dk), putBlob(call, "delegation", b, nil)
}

func policyRevoke(call policyCall, root ssh.Signer, fp string) (int64, error) {
	st, err := rootStatus(call, root)
	if err != nil {
		return 0, err
	}
	set := map[string]bool{fp: true}
	for _, d := range st.Delegations {
		if d.Revoked {
			set[d.DeviceFP] = true
		}
	}
	r := Revocations{Account: st.Account, Version: st.RevocationsVersion + 1}
	for k := range set {
		r.Revoked = append(r.Revoked, k)
	}
	sort.Strings(r.Revoked)
	b, err := signRevocations(root, r)
	if err != nil {
		return 0, err
	}
	return r.Version, putBlob(call, "revocations", b, nil)
}

// policySign fetches the server's draft for machine, shows it to review, and signs
// exactly what was reviewed. The draft is decoded strictly into Policy, so the
// server can't slip in a field the reviewer didn't see. Returns 0 when declined.
func policySign(call policyCall, dev ssh.Signer, machine string, krlHours int, review func(string, Policy) bool) (int64, error) {
	var d struct {
		Policy json.RawMessage `json:"policy"`
	}
	if err := call("getPolicyDraft", url.Values{"machine_id": {machine}, "krl_hours": {strconv.Itoa(krlHours)}}, &d); err != nil {
		return 0, err
	}
	var p Policy
	dec := json.NewDecoder(bytes.NewReader(d.Policy))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return 0, fmt.Errorf("draft policy: %w", err)
	}
	for _, k := range p.CAKeys {
		if _, err := parseKey(k); err != nil {
			return 0, fmt.Errorf("draft CA key is not an OpenSSH public key: %w", err)
		}
	}
	if !review(machine, p) {
		fmt.Println("not signed.")
		return 0, nil
	}
	b, err := signPolicy(dev, p)
	if err != nil {
		return 0, err
	}
	err = putBlob(call, "policy", b, url.Values{"machine_id": {machine}, "signer": {authorizedKey(dev.PublicKey())}})
	return p.Version, err
}

func policyStatusCmd(call policyCall) error {
	var st policyStatus
	if err := call("getPolicyStatus", nil, &st); err != nil {
		return err
	}
	fmt.Printf("account %s\nroot    %s\n", st.Account, firstNonEmpty(st.RootFP, "(not set — p3sig policy root)"))
	fmt.Printf("signing devices (revocation list v%d):\n", st.RevocationsVersion)
	if len(st.Delegations) == 0 {
		fmt.Println("  none — p3sig policy delegate")
	}
	now := time.Now().Unix()
	for _, d := range st.Delegations {
		state := "active"
		if d.Revoked {
			state = "REVOKED"
		} else if d.Expires != 0 && now >= d.Expires {
			state = "expired"
		} else if d.Expires != 0 {
			state = "until " + time.Unix(d.Expires, 0).UTC().Format("2006-01-02")
		}
		fmt.Printf("  %s  %-12s %s\n", d.DeviceFP, firstNonEmpty(d.Label, "-"), state)
	}
	fmt.Println("machines:")
	for _, m := range st.Machines {
		v := "unsigned"
		if m.Version > 0 {
			v = fmt.Sprintf("v%d, KRL fresh until %s", m.Version, time.Unix(m.KRLExpires, 0).UTC().Format("2006-01-02 15:04Z"))
			if now >= m.KRLExpires {
				v = fmt.Sprintf("v%d, KRL EXPIRED — re-sign", m.Version)
			}
		}
		fmt.Printf("  %s  %-20s %s\n", m.MachineID, m.Name, v)
	}
	return nil
}

// describePolicy is what the owner reviews before a device signs.
func describePolicy(machine string, p Policy) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "\nmachine %s — policy v%d for %s\n  trusted CAs:\n", machine, p.Version, p.Account)
	for _, k := range p.CAKeys {
		fp, comment := "?", ""
		if pk, c, _, _, err := ssh.ParseAuthorizedKey([]byte(k)); err == nil {
			fp, comment = ssh.FingerprintSHA256(pk), c
		}
		fmt.Fprintf(&sb, "    %s %s\n", fp, comment)
	}
	if len(p.CAKeys) == 0 {
		sb.WriteString("    (none)\n")
	}
	sb.WriteString("  principals:\n")
	for _, g := range p.Grants {
		fmt.Fprintf(&sb, "    %s → %s\n", g.Principal, g.LoginUser)
	}
	krl := strings.Count(strings.TrimSpace(p.KRLSpec), "\n") + 1
	if strings.TrimSpace(p.KRLSpec) == "" {
		krl = 0
	}
	fmt.Fprintf(&sb, "  KRL: %d revoked entr(ies), must be re-signed by %s\n", krl, time.Unix(p.KRLExpires, 0).UTC().Format("2006-01-02 15:04Z"))
	return sb.String()
}

// ─── device-authenticated requests (task #2629) ──────────────────────────────

const deviceAuthCtx = "p3sig-device-auth-v1\n"

// deviceAuthForm: the auth fields for a request signed by a delegated device —
// a signature over "<ctx><action>|<fp>|<ts>" (server: p3sig_device_request_guard).
// Binding the action means a captured auth for policy status cannot upload.
func deviceAuthForm(dev ssh.Signer, action string, now time.Time) (url.Values, error) {
	fp := ssh.FingerprintSHA256(dev.PublicKey())
	ts := strconv.FormatInt(now.Unix(), 10)
	sig, err := dev.Sign(nil, []byte(deviceAuthCtx+action+"|"+fp+"|"+ts))
	if err != nil {
		return nil, fmt.Errorf("device %s did not sign the request: %w", fp, err)
	}
	return url.Values{
		"device_key": {authorizedKey(dev.PublicKey())},
		"ts":         {ts},
		"device_sig": {base64.StdEncoding.EncodeToString(ssh.Marshal(sig))},
	}, nil
}

// deviceRequest is userRequest with the delegated device as the credential.
func deviceRequest(apiBase, action string, dev ssh.Signer, account string, extra url.Values, v any) error {
	form, err := deviceAuthForm(dev, action, time.Now())
	if err != nil {
		return err
	}
	for k, vals := range extra {
		form[k] = vals
	}
	if account != "" {
		form.Set("account", account)
	}
	form.Set("action", action)
	return postForm(apiBase, form, v)
}

// ─── signers and device keys ─────────────────────────────────────────────────

// loadSigner: "agent" / "agent:SHA256:…" (ssh-agent at SSH_AUTH_SOCK: dongle via
// ssh-add, chip via `p3sig ssh-agent`) or a key file (p3sig vault key / OpenSSH).
func loadSigner(spec string) (ssh.Signer, error) {
	if spec == "" || spec == "true" {
		return nil, errors.New("no key given")
	}
	if spec == "agent" || strings.HasPrefix(spec, "agent:") {
		sock := os.Getenv("SSH_AUTH_SOCK")
		if sock == "" {
			return nil, errors.New("SSH_AUTH_SOCK is not set (ssh-add your dongle, or run `p3sig ssh-agent` for the chip key)")
		}
		conn, err := net.Dial("unix", sock)
		if err != nil {
			return nil, err
		}
		signers, err := agent.NewClient(conn).Signers()
		if err != nil {
			return nil, err
		}
		return pickSigner(signers, strings.TrimPrefix(strings.TrimPrefix(spec, "agent"), ":"))
	}
	data, err := os.ReadFile(spec)
	if err != nil {
		return nil, err
	}
	if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data))); err == nil && len(raw) == ed25519.PrivateKeySize {
		return ssh.NewSignerFromKey(ed25519.PrivateKey(raw))
	}
	s, err := ssh.ParsePrivateKey(data)
	var pe *ssh.PassphraseMissingError
	if errors.As(err, &pe) {
		return nil, fmt.Errorf("%s is passphrase-protected — ssh-add it and use --with agent", spec)
	}
	return s, err
}

func pickSigner(signers []ssh.Signer, fp string) (ssh.Signer, error) {
	var fps []string
	for _, s := range signers {
		got := ssh.FingerprintSHA256(s.PublicKey())
		if got == fp {
			return s, nil
		}
		fps = append(fps, got)
	}
	if fp == "" && len(signers) == 1 {
		return signers[0], nil
	}
	if len(signers) == 0 {
		return nil, errors.New("the ssh-agent holds no keys")
	}
	return nil, fmt.Errorf("pick one: agent:<fingerprint> — the agent holds %s", strings.Join(fps, ", "))
}

// deviceKeyLine: an OpenSSH public key line, a .pub file, or agent[:fp] (enrol the
// dongle/chip currently in the agent).
func deviceKeyLine(spec string) (string, error) {
	if spec == "" || spec == "true" {
		return "", errors.New("--device is required: a .pub file, a public key line, or agent[:SHA256:…]")
	}
	if spec == "agent" || strings.HasPrefix(spec, "agent:") {
		s, err := loadSigner(spec)
		if err != nil {
			return "", err
		}
		return authorizedKey(s.PublicKey()), nil
	}
	if _, err := parseKey(spec); err == nil {
		return spec, nil
	}
	data, err := os.ReadFile(spec)
	if err != nil {
		return "", fmt.Errorf("--device %q is neither a public key nor a readable file", spec)
	}
	return strings.TrimSpace(string(data)), nil
}

// deviceFingerprint: --device for revoke also takes the bare SHA256:… (a lost
// dongle's key is gone; its fingerprint is on `p3sig policy status`).
func deviceFingerprint(spec string) (string, error) {
	if strings.HasPrefix(spec, "SHA256:") {
		return spec, nil
	}
	line, err := deviceKeyLine(spec)
	if err != nil {
		return "", err
	}
	k, err := parseKey(line)
	if err != nil {
		return "", err
	}
	return ssh.FingerprintSHA256(k), nil
}

// parseExpiry: "" = none, "90d" / "12h" relative, or a unix timestamp.
func parseExpiry(s string, now time.Time) (int64, error) {
	if s == "" {
		return 0, nil
	}
	if n, err := strconv.ParseInt(strings.TrimSuffix(s, "d"), 10, 64); err == nil && strings.HasSuffix(s, "d") && n > 0 {
		return now.Add(time.Duration(n) * 24 * time.Hour).Unix(), nil
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return now.Add(d).Unix(), nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > now.Unix() {
		return n, nil
	}
	return 0, fmt.Errorf("--expires %q: use 90d, 12h or a future unix time", s)
}
