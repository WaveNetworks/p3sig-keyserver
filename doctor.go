package main

// doctor.go — `p3sig doctor` (task #2830): ONE read-only command that proves the
// owner's vault sticks, the dongle and the p3sig account all match, and says
// exactly what to fix. It never writes anything (no key, no file, no server
// change): every line is PASS / FAIL / WARN plus the command that fixes it.
//
//	1 sticks     every plugged p3sig stick (usb: wrapped AND old VeraCrypt), unlocked,
//	             fingerprint + DAILY/SAFE label, and whether DAILY and SAFE hold one key
//	2 account    each stick key signs getMyVaultKeys: accepted + listed; keys on the
//	             account no stick holds, stick keys the account doesn't know
//	3 secrets    one sealed copy per stick key opened locally (value never printed);
//	             secrets with NO copy for that key (a missing re-seal)
//	4 policy     the published root and whether a stick IS it; delegated devices with
//	             expiry; dead ones (no longer present here)
//	5 dongle     pairing record, BLE + unlock, vault key, delegated by the root?
//	6 machines   registered machines, last policy report, pinned to the root?
//
// The checks are a pure function (runDoctor) over facts gathered up front
// (gatherDoctor), so every FAIL case is tested against a fake account.

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// VeraCrypt sticks made by scripts/make-vault-usbs.sh (10-27): container + public key.
const (
	vcContainerFile = "p3sig-vault.hc"
	vcOpenKeyPath   = "/run/p3sig/vault/p3sig-root.key" // where the old vault-usb.sh mounted the key
)

type doctorStick struct {
	Drive  string             `json:"drive"`
	Label  string             `json:"label"`  // DAILY | SAFE | "" (unknown)
	Format string             `json:"format"` // usb | veracrypt
	FP     string             `json:"fingerprint"`
	Key    ed25519.PrivateKey `json:"-"` // nil = not unlocked
	Note   string             `json:"note,omitempty"`
	Legacy bool               `json:"veracrypt_container_left,omitempty"` // usb: format, .hc still beside it
}

type doctorDongle struct {
	Record       bool   `json:"paired"`
	RecordPath   string `json:"record_path,omitempty"`
	BLE          string `json:"ble,omitempty"`
	VaultFP      string `json:"vault_fingerprint,omitempty"`
	VaultKeyLine string `json:"vault_key,omitempty"`
	UnlockFile   bool   `json:"unlock_file_present"`
	Probed       bool   `json:"probed"`
	Unlocks      bool   `json:"unlocks"`
	ProbeError   string `json:"probe_error,omitempty"`
	ProbedFP     string `json:"probed_fingerprint,omitempty"`
	RecordError  string `json:"record_error,omitempty"`
}

type doctorInput struct {
	Sticks   []doctorStick
	Call     func(ed25519.PrivateKey) policyCall // signed as that stick's key
	Fallback policyCall                          // saved login identity, when no stick unlocked
	Dongle   doctorDongle
	Present  map[string]string // fingerprints of signing devices present here → where (agent, dongle)
	Now      time.Time
}

type doctorCheck struct {
	Area   string `json:"area"`
	Status string `json:"status"` // PASS | FAIL | WARN | INFO
	Text   string `json:"text"`
	Fix    string `json:"fix,omitempty"`
}

type doctorAccountKey struct {
	KeyID string `json:"key_id"`
	Label string `json:"label"`
	FP    string `json:"fingerprint"`
	OnStk string `json:"on_stick,omitempty"`
}

type doctorReport struct {
	SticksMatch bool               `json:"sticks_match_account"`
	AllPass     bool               `json:"all_pass"`
	Sticks      []doctorStick      `json:"sticks"`
	AccountKeys []doctorAccountKey `json:"account_keys"`
	RootFP      string             `json:"policy_root,omitempty"`
	Dongle      doctorDongle       `json:"dongle"`
	Checks      []doctorCheck      `json:"checks"`
	Fixes       []string           `json:"fixes"`
}

func (r *doctorReport) add(area, status, text, fix string) {
	r.Checks = append(r.Checks, doctorCheck{Area: area, Status: status, Text: text, Fix: fix})
	if fix != "" && status != "PASS" {
		for _, f := range r.Fixes {
			if f == fix {
				return
			}
		}
		r.Fixes = append(r.Fixes, fix)
	}
}

func edFP(pub ed25519.PublicKey) string {
	p, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "?"
	}
	return ssh.FingerprintSHA256(p)
}

func b64PubFP(b64 string) string {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return ""
	}
	return edFP(ed25519.PublicKey(raw))
}

func stickName(s doctorStick) string {
	if s.Label != "" {
		return s.Label + " (" + s.Drive + ")"
	}
	return s.Drive
}

// runDoctor runs every check over the gathered facts. No writes anywhere: the
// only calls are getMyVaultKeys, getMySecrets, getResealWork, getPolicyStatus.
func runDoctor(in doctorInput) doctorReport {
	r := doctorReport{Sticks: in.Sticks, Dongle: in.Dongle, Fixes: []string{}}
	sticksOK := true

	// ── 1 sticks ──
	unlocked := 0
	if len(in.Sticks) == 0 {
		sticksOK = false
		r.add("sticks", "FAIL", "no p3sig stick is plugged in", "plug in the DAILY stick and run `p3sig doctor` again (or name it: --drive PATH)")
	}
	for _, s := range in.Sticks {
		switch {
		case s.Key != nil:
			unlocked++
			r.add("sticks", "PASS", fmt.Sprintf("%s [%s] unlocks: %s", stickName(s), s.Format, s.FP), "")
			if s.Legacy {
				r.add("sticks", "WARN", stickName(s)+" still has the old VeraCrypt container beside the new key",
					"once both sticks are migrated: p3sig usb migrate --finish")
			}
			if s.Format == "veracrypt" {
				r.add("sticks", "WARN", stickName(s)+" is still the old VeraCrypt format",
					"p3sig usb migrate --drive "+s.Drive)
			}
		case s.Format == "veracrypt":
			sticksOK = false
			r.add("sticks", "FAIL", fmt.Sprintf("%s is the old VeraCrypt format and did not open (%s), so its key can't be checked (public key %s)", stickName(s), firstNonEmpty(s.Note, "skipped"), firstNonEmpty(s.FP, "unknown")),
				"p3sig usb migrate --drive "+s.Drive)
		default:
			sticksOK = false
			r.add("sticks", "FAIL", fmt.Sprintf("%s did not unlock: %s", stickName(s), firstNonEmpty(s.Note, "no passphrase")),
				"run `p3sig doctor --drive "+s.Drive+"` again with the right passphrase (if it is lost, the SAFE stick still holds the key: `p3sig usb clone`)")
		}
	}
	byLabel := map[string][]doctorStick{}
	for _, s := range in.Sticks {
		if s.FP != "" {
			byLabel[s.Label] = append(byLabel[s.Label], s)
		}
	}
	fps := map[string]bool{}
	for _, s := range in.Sticks {
		if s.FP != "" {
			fps[s.FP] = true
		}
	}
	if len(byLabel["DAILY"]) > 0 && len(byLabel["SAFE"]) > 0 {
		if byLabel["DAILY"][0].FP == byLabel["SAFE"][0].FP {
			r.add("sticks", "PASS", "DAILY and SAFE hold the SAME key", "")
		} else {
			sticksOK = false
			r.add("sticks", "FAIL", fmt.Sprintf("DAILY (%s) and SAFE (%s) hold DIFFERENT keys", byLabel["DAILY"][0].FP, byLabel["SAFE"][0].FP),
				"decide which key the account should use (see the account section), then copy it onto the other stick: `p3sig usb clone --drive <good stick> --to <other stick>`")
		}
	} else if len(fps) > 1 {
		sticksOK = false
		r.add("sticks", "FAIL", fmt.Sprintf("the plugged sticks hold %d different keys", len(fps)),
			"keep one key: `p3sig usb clone --drive <good stick> --to <other stick>`")
	} else if len(in.Sticks) == 1 {
		r.add("sticks", "INFO", "only one stick plugged in: plug DAILY and SAFE together to compare them", "")
	}

	// ── 2 account ──
	var call policyCall
	stickKeyID := map[string]string{} // stick fp → key_id on the account
	var acctKeys []doctorAccountKey
	accepted := 0
	seenStick := map[string]bool{}
	for _, s := range in.Sticks {
		if s.Key == nil || seenStick[s.FP] {
			continue
		}
		seenStick[s.FP] = true
		c := in.Call(s.Key)
		var res struct {
			Keys []struct {
				KeyID     string `json:"key_id"`
				PublicKey string `json:"public_key"`
				Label     string `json:"label"`
			} `json:"keys"`
		}
		if err := c("getMyVaultKeys", nil, &res); err != nil {
			sticksOK = false
			r.add("account", "FAIL", fmt.Sprintf("the account refuses %s's key %s: %v", stickName(s), s.FP, err),
				"register the stick key on your account, signed by a key it already knows: `p3sig usb register --drive "+s.Drive+" --register-with <a registered key or usb:PATH>` (or paste its public key at Vault › Keys)")
			continue
		}
		accepted++
		if call == nil {
			call = c
		}
		if acctKeys == nil {
			for _, k := range res.Keys {
				acctKeys = append(acctKeys, doctorAccountKey{KeyID: k.KeyID, Label: k.Label, FP: b64PubFP(k.PublicKey)})
			}
		}
		listed := false
		for _, k := range res.Keys {
			if b64PubFP(k.PublicKey) == s.FP {
				listed, stickKeyID[s.FP] = true, k.KeyID
			}
		}
		if listed {
			r.add("account", "PASS", fmt.Sprintf("%s's key is on the account (key %s)", stickName(s), stickKeyID[s.FP]), "")
		} else {
			sticksOK = false
			r.add("account", "FAIL", fmt.Sprintf("%s's key signed in but is not in the account's key list", stickName(s)),
				"`p3sig usb register --drive "+s.Drive+"`")
		}
	}
	if call == nil && in.Fallback != nil {
		call = in.Fallback
		if unlocked == 0 && len(in.Sticks) > 0 {
			r.add("account", "INFO", "no stick unlocked: account checks use your saved login key instead", "")
		}
	}
	for i, k := range acctKeys {
		for _, s := range in.Sticks {
			if s.FP != "" && s.FP == k.FP {
				acctKeys[i].OnStk = firstNonEmpty(s.Label, s.Drive)
			}
		}
		if acctKeys[i].OnStk == "" {
			where := ""
			if w, ok := in.Present[k.FP]; ok {
				where = " (it is the " + w + ")"
			}
			r.add("account", "WARN", fmt.Sprintf("account key %q %s is on no plugged stick%s", k.Label, k.FP, where),
				fmt.Sprintf("if key %q (%s) is an old or lost key, remove it on p3sig.com › Vault › Keys; if it is another stick, plug it in and run doctor again", k.Label, k.FP))
		}
	}
	r.AccountKeys = acctKeys
	if accepted > 0 {
		r.add("account", "INFO", fmt.Sprintf("the account has %d vault key(s)", len(acctKeys)), "")
	}

	// ── 3 secrets ──
	for _, s := range in.Sticks {
		kid, ok := stickKeyID[s.FP]
		if s.Key == nil || !ok {
			continue
		}
		delete(stickKeyID, s.FP) // once per key, even with DAILY+SAFE plugged
		c := in.Call(s.Key)
		var mine struct {
			Secrets []struct {
				SecretID string `json:"secret_id"`
				Enc      string `json:"encrypted_data"`
				Meta     string `json:"encrypted_meta"`
			} `json:"secrets"`
		}
		if err := c("getMySecrets", nil, &mine); err != nil {
			r.add("secrets", "FAIL", fmt.Sprintf("fetching %s's sealed copies failed: %v", s.FP, err), "check the connection to p3sig.com and run doctor again")
		} else if len(mine.Secrets) == 0 {
			r.add("secrets", "INFO", fmt.Sprintf("%s has no secret copies to test (the vault may be empty)", s.FP), "")
		} else {
			x := mine.Secrets[0]
			_, verr := openSealedBox(x.Enc, s.Key)
			_, merr := openSecretName(x.Meta, s.Key)
			if verr == nil && merr == nil {
				r.add("secrets", "PASS", fmt.Sprintf("%s opened a real sealed secret locally (%d copies addressed to it; value not shown)", s.FP, len(mine.Secrets)), "")
			} else {
				sticksOK = false
				r.add("secrets", "FAIL", fmt.Sprintf("a copy addressed to %s does not open with it (secret %s)", s.FP, x.SecretID),
					"re-seal from a key that opens it: p3sig.com › Vault › Seal now, or `p3sig secret reseal`")
			}
		}
		var work struct {
			Work []resealWork `json:"work"`
		}
		if err := c("getResealWork", nil, &work); err == nil {
			missing := 0
			for _, w := range work.Work {
				for _, m := range w.Missing {
					if m.KeyID == kid {
						missing++
					}
				}
			}
			if missing == 0 {
				r.add("secrets", "PASS", fmt.Sprintf("every secret has a copy for %s", s.FP), "")
			} else {
				sticksOK = false
				r.add("secrets", "FAIL", fmt.Sprintf("%d secret(s) have NO copy for %s (missing re-seal)", missing, s.FP),
					"open p3sig.com › Vault and press \"Seal now\" with a key that opens everything (or `p3sig usb register --drive "+s.Drive+"` from a registered key)")
			}
		}
	}

	// ── 4 policy ──
	var st struct {
		policyStatus
		Machines []struct {
			MachineID  string         `json:"machine_id"`
			Name       string         `json:"name"`
			Version    int64          `json:"version"`
			KRLExpires int64          `json:"krl_expires"`
			Agent      map[string]any `json:"agent"`
		} `json:"machines"`
		AccountPolicies []struct {
			Group      string   `json:"group"`
			Version    int64    `json:"version"`
			ValidUntil int64    `json:"valid_until"`
			Machines   []string `json:"machines"`
		} `json:"account_policies"`
		FreshnessKeys []struct {
			KeyFP   string `json:"key_fp"`
			Expires int64  `json:"expires"`
			Revoked bool   `json:"revoked"`
		} `json:"freshness_keys"`
	}
	delegated := map[string]bool{}
	policyOK := false
	if call == nil {
		r.add("policy", "FAIL", "no key could sign in to the account, so policy, dongle delegation and machines were not checked",
			"unlock a registered stick (or `p3sig login --key usb`) and run doctor again")
	} else if err := call("getPolicyStatus", nil, &st); err != nil {
		r.add("policy", "FAIL", "policy status: "+err.Error(), "check the connection to p3sig.com and run doctor again")
	} else {
		policyOK = true
		r.RootFP = st.RootFP
		switch {
		case st.RootFP == "":
			r.add("policy", "FAIL", "no policy root is published on the account", "p3sig policy root --root-key usb")
		case fps[st.RootFP]:
			r.add("policy", "PASS", "policy root "+st.RootFP+" IS the plugged stick's key", "")
		default:
			r.add("policy", "WARN", "policy root "+st.RootFP+" is not on any plugged stick", "plug in the stick that holds the root ("+st.RootFP+") and run doctor again")
		}
		now := in.Now.Unix()
		for _, d := range st.Delegations {
			label := firstNonEmpty(d.Label, "-")
			switch {
			case d.Revoked:
				r.add("policy", "INFO", fmt.Sprintf("device %s %q: revoked", d.DeviceFP, label), "")
				continue
			case d.Expires != 0 && now >= d.Expires:
				r.add("policy", "WARN", fmt.Sprintf("device %s %q: delegation EXPIRED %s", d.DeviceFP, label, time.Unix(d.Expires, 0).UTC().Format("2006-01-02")),
					"re-delegate it if you still use it: `p3sig policy delegate --root-key usb --device <its key>`")
				continue
			}
			delegated[d.DeviceFP] = true
			until := "no expiry"
			if d.Expires != 0 {
				until = "until " + time.Unix(d.Expires, 0).UTC().Format("2006-01-02")
			}
			if w, ok := in.Present[d.DeviceFP]; ok {
				r.add("policy", "PASS", fmt.Sprintf("device %s %q (%s) is present here: %s", d.DeviceFP, label, until, w), "")
			} else {
				r.add("policy", "WARN", fmt.Sprintf("device %s %q (%s) is delegated but not present here (dead if that device is gone)", d.DeviceFP, label, until),
					"if device "+d.DeviceFP+" no longer exists: `p3sig policy revoke --root-key usb --device "+d.DeviceFP+"`")
			}
		}
		if len(st.Delegations) == 0 {
			r.add("policy", "WARN", "no signing device is delegated", "pair and delegate the dongle: `p3sig dongle pair --unlock-out PATH`")
		}
	}

	// ── 5 dongle ──
	dg := in.Dongle
	switch {
	case dg.RecordError != "":
		r.add("dongle", "FAIL", "dongle pairing record unreadable: "+dg.RecordError, "p3sig dongle pair --unlock-out PATH")
	case !dg.Record:
		r.add("dongle", "WARN", "no dongle is paired on this machine", "p3sig dongle pair --unlock-out PATH (unlock key onto the DAILY stick or your phone)")
	default:
		r.add("dongle", "PASS", fmt.Sprintf("pairing record %s: BLE %s, vault key %s", dg.RecordPath, firstNonEmpty(dg.BLE, "?"), dg.VaultFP), "")
		if !dg.UnlockFile {
			r.add("dongle", "WARN", "the dongle's unlock key file is not reachable (plug in the stick/phone that holds it)", "plug in what holds the unlock key, then run doctor again")
		}
		switch {
		case !dg.Probed:
			r.add("dongle", "INFO", "dongle not contacted (--no-dongle, or no unlock key)", "")
		case dg.Unlocks && dg.ProbedFP == dg.VaultFP:
			r.add("dongle", "PASS", "dongle answered over BLE and unlocked: vault key "+dg.ProbedFP, "")
		case dg.Unlocks:
			r.add("dongle", "FAIL", "dongle unlocked but holds a different vault key ("+dg.ProbedFP+") than its pairing record", "re-pair it: `p3sig dongle pair --unlock-out PATH`")
		default:
			r.add("dongle", "FAIL", "dongle did not unlock over BLE: "+dg.ProbeError, "power the dongle near this machine (BLE on), then `p3sig dongle status`")
		}
		if policyOK {
			if delegated[dg.VaultFP] {
				r.add("dongle", "PASS", "the dongle's vault key is delegated by the root", "")
			} else {
				r.add("dongle", "FAIL", "the dongle's vault key "+dg.VaultFP+" is NOT delegated by the root, so it can't sign policy",
					"p3sig policy delegate --root-key usb --device '"+firstNonEmpty(dg.VaultKeyLine, "<dongle key>")+"' --label \"p3sig dongle "+dg.BLE+"\"")
			}
		}
	}

	// ── 6 machines ──
	if policyOK && st.RootFP != "" {
		inGroup := map[string]string{}
		for _, ap := range st.AccountPolicies {
			for _, m := range ap.Machines {
				inGroup[m] = ap.Group
			}
			if ap.ValidUntil != 0 && in.Now.Unix() >= ap.ValidUntil {
				r.add("machines", "FAIL", fmt.Sprintf("account policy %q v%d EXPIRED %s", ap.Group, ap.Version, time.Unix(ap.ValidUntil, 0).UTC().Format("2006-01-02 15:04Z")),
					"p3sig policy sign --with dongle --group "+ap.Group)
			}
		}
		if len(st.Machines) == 0 {
			r.add("machines", "INFO", "no machines registered", "")
		}
		for _, m := range st.Machines {
			name := firstNonEmpty(m.Name, m.MachineID)
			signed := m.Version > 0 || inGroup[m.MachineID] != ""
			if !signed {
				r.add("machines", "FAIL", name+": no signed policy (agents fall back to unsigned TLS-only pulls)", "p3sig policy sign --with dongle")
				continue
			}
			status, _ := m.Agent["status"].(string)
			reported, _ := m.Agent["reported"].(string)
			switch {
			case m.Agent == nil:
				r.add("machines", "WARN", name+": signed policy exists but its agent never reported a pull (not pinned to the root yet?)",
					"on "+name+": `p3sig agent pull --root "+st.RootFP+"`")
			case status == "applied":
				r.add("machines", "PASS", fmt.Sprintf("%s: pinned to the root, last applied a signed policy %s", name, firstNonEmpty(reported, "?")), "")
			default:
				detail, _ := m.Agent["detail"].(string)
				r.add("machines", "FAIL", fmt.Sprintf("%s: agent %s the policy (%s) at %s", name, firstNonEmpty(status, "?"), detail, firstNonEmpty(reported, "?")),
					"re-sign the policy (`p3sig policy sign --with dongle`), then on "+name+": `p3sig agent pull --root "+st.RootFP+"`")
			}
		}
	}

	r.SticksMatch = sticksOK && unlocked > 0 && accepted > 0
	r.AllPass = true
	for _, c := range r.Checks {
		if c.Status == "FAIL" || c.Status == "WARN" {
			r.AllPass = false
		}
	}
	return r
}

func printDoctor(w io.Writer, r doctorReport) {
	yes := map[bool]string{true: "yes", false: "NO"}
	fmt.Fprintf(w, "Your sticks match your account: %s\n", yes[r.SticksMatch])
	fmt.Fprintf(w, "Everything passes:              %s\n\n", yes[r.AllPass])
	area := ""
	titles := map[string]string{"sticks": "1 Sticks", "account": "2 Account", "secrets": "3 Secrets", "policy": "4 Policy",
		"dongle": "5 Dongle", "machines": "6 Machines"}
	for _, c := range r.Checks {
		if c.Area != area {
			area = c.Area
			fmt.Fprintf(w, "%s\n", titles[area])
			if area == "account" && len(r.AccountKeys) > 0 {
				for _, k := range r.AccountKeys {
					fmt.Fprintf(w, "         key %-14s %-20q %s  on stick: %s\n", k.KeyID, k.Label, k.FP, firstNonEmpty(k.OnStk, "none plugged"))
				}
			}
		}
		fmt.Fprintf(w, "  %-4s  %s\n", c.Status, c.Text)
	}
	if len(r.Fixes) == 0 {
		fmt.Fprintln(w, "\nNothing to fix.")
		return
	}
	fmt.Fprintln(w, "\nFix, in this order:")
	for i, f := range r.Fixes {
		fmt.Fprintf(w, "  %d. %s\n", i+1, f)
	}
}

// ─── gathering (the only part that touches the machine) ──────────────────────

// stickLabel: DAILY / SAFE from the volume name (P3SIG-DAILY, …) or PUBLIC-KEY.txt.
func stickLabel(drive string) string {
	up := strings.ToUpper(filepath.Base(filepath.Clean(drive)))
	for _, l := range []string{"DAILY", "SAFE"} {
		if strings.Contains(up, l) {
			return l
		}
	}
	return ""
}

// pubFromText finds the public key in a PUBLIC-KEY.txt (bare base64 Ed25519 or
// an OpenSSH line) and returns its fingerprint.
func pubFromText(b []byte) (ed25519.PublicKey, string) {
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if raw, err := base64.StdEncoding.DecodeString(line); err == nil && len(raw) == ed25519.PublicKeySize {
			return ed25519.PublicKey(raw), edFP(ed25519.PublicKey(raw))
		}
		if pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line)); err == nil {
			if cp, ok := pk.(ssh.CryptoPublicKey); ok {
				if ep, ok := cp.CryptoPublicKey().(ed25519.PublicKey); ok {
					return ep, ssh.FingerprintSHA256(pk)
				}
			}
		}
	}
	return nil, ""
}

// findSticks: --drive (comma-separated) or every removable mount holding a
// usb: key or a VeraCrypt p3sig container.
func findSticks(f map[string]string) []doctorStick {
	var drives []string
	if d := f["drive"]; d != "" && d != "true" {
		drives = strings.Split(d, ",")
	} else {
		drives = removableMounts()
	}
	var out []doctorStick
	for _, d := range drives {
		s := doctorStick{Drive: d, Label: stickLabel(d)}
		if _, err := os.Stat(usbKeyPath(d)); err == nil {
			s.Format = "usb"
			if _, err := os.Stat(filepath.Join(d, vcContainerFile)); err == nil {
				s.Legacy = true
			}
			if b, err := os.ReadFile(filepath.Join(d, usbDir, usbPubFile)); err == nil {
				_, s.FP = pubFromText(b)
			}
		} else if _, err := os.Stat(filepath.Join(d, vcContainerFile)); err == nil {
			s.Format = "veracrypt"
			if b, err := os.ReadFile(filepath.Join(d, usbPubFile)); err == nil {
				_, s.FP = pubFromText(b)
			}
		} else {
			continue
		}
		out = append(out, s)
	}
	return out
}

// unlockSticks asks each stick's passphrase (usb: format) or reads the key of an
// already-open VeraCrypt container (--vc-key, default the old vault-usb.sh path).
func unlockSticks(sticks []doctorStick, f map[string]string, ask func(string) (string, error)) {
	for i := range sticks {
		s := &sticks[i]
		switch s.Format {
		case "usb":
			p, err := ask(fmt.Sprintf("%s passphrase (Enter to skip): ", firstNonEmpty(s.Label, s.Drive)))
			if err != nil || p == "" {
				s.Note = "skipped"
				continue
			}
			k, err := readUSBKey(s.Drive, []byte(p))
			if err != nil {
				s.Note = err.Error()
				continue
			}
			s.Key = k
		case "veracrypt":
			// An already-open container (old vault-usb.sh), else open it in memory.
			path := firstNonEmpty(f["vc-key"], vcOpenKeyPath)
			if k, err := loadKeyFile(path); err == nil && (s.FP == "" || edFP(k.Public().(ed25519.PublicKey)) == s.FP) {
				s.Key = k
				break
			}
			p, err := ask(fmt.Sprintf("%s VeraCrypt passphrase (Enter to skip): ", firstNonEmpty(s.Label, s.Drive)))
			if err != nil || p == "" {
				s.Note = "skipped"
				continue
			}
			k, err := readVCKey(filepath.Join(s.Drive, vcContainerFile), []byte(p))
			if err != nil {
				s.Note = err.Error()
				continue
			}
			s.Key = k
		}
		fp := edFP(s.Key.Public().(ed25519.PublicKey))
		if s.FP != "" && s.FP != fp {
			s.Note = "PUBLIC-KEY.txt says " + s.FP + " but the key inside is " + fp
		}
		s.FP = fp
	}
}

func gatherDongle(probe bool) doctorDongle {
	var d doctorDongle
	p, _ := p3RecordPath()
	d.RecordPath = p
	rec, err := loadP3Record()
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			d.RecordError = err.Error()
		}
		return d
	}
	d.Record, d.BLE = true, rec.BLE
	if raw, err := base64.StdEncoding.DecodeString(rec.VaultEd); err == nil && len(raw) == ed25519.PublicKeySize {
		d.VaultFP = edFP(ed25519.PublicKey(raw))
		if pk, err := ssh.NewPublicKey(ed25519.PublicKey(raw)); err == nil {
			d.VaultKeyLine = authorizedKey(pk)
		}
	}
	if _, err := os.Stat(rec.UnlockPath); err == nil {
		d.UnlockFile = true
	}
	if !probe || !d.UnlockFile {
		return d
	}
	d.Probed = true
	_, ed, _, c, err := openP3Session(rec)
	if err != nil {
		d.ProbeError = err.Error()
		return d
	}
	c.Close()
	d.Unlocks, d.ProbedFP = true, edFP(ed)
	return d
}

// presentDevices: signing devices reachable here without a touch — keys in the
// ssh-agent and the paired dongle.
func presentDevices(dg doctorDongle) map[string]string {
	out := map[string]string{}
	if os.Getenv("SSH_AUTH_SOCK") != "" {
		if s, err := agentSigners(); err == nil {
			for _, k := range s {
				out[ssh.FingerprintSHA256(k.PublicKey())] = "ssh-agent key"
			}
		}
	}
	if dg.Record && dg.VaultFP != "" {
		out[dg.VaultFP] = "paired p3sig dongle " + dg.BLE
	}
	return out
}

func cmdDoctor(f map[string]string) error {
	apiBase := firstNonEmpty(f["url"], os.Getenv("P3SIG_URL"), defaultAPI)
	in := doctorInput{Now: time.Now()}
	in.Sticks = findSticks(f)
	stdin := bufio.NewReader(os.Stdin)
	ask := func(prompt string) (string, error) {
		if p, ok := os.LookupEnv("P3SIG_PASSPHRASE"); ok {
			return p, nil
		}
		if f["json"] == "true" {
			fmt.Fprint(os.Stderr, prompt)
			line, err := stdin.ReadString('\n')
			return strings.TrimRight(line, "\r\n"), err
		}
		return readPassphrase(prompt)
	}
	if f["no-unlock"] != "true" {
		unlockSticks(in.Sticks, f, ask)
	}
	in.Call = func(k ed25519.PrivateKey) policyCall {
		return func(action string, extra url.Values, v any) error {
			return userRequestKey(apiBase, action, k, extra, v)
		}
	}
	if _, kp, err := resolveIdentity(map[string]string{"url": f["url"]}); err == nil && !isUSBSpec(kp) {
		if _, serr := os.Stat(kp); serr == nil {
			in.Fallback = func(action string, extra url.Values, v any) error {
				return userRequest(apiBase, action, kp, extra, v)
			}
		}
	}
	in.Dongle = gatherDongle(f["no-dongle"] != "true")
	in.Present = presentDevices(in.Dongle)
	r := runDoctor(in)
	for i := range r.Sticks {
		r.Sticks[i].Key = nil
	}
	if f["json"] == "true" {
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			return err
		}
		os.Stdout.Write(b.Bytes())
	} else {
		printDoctor(os.Stdout, r)
	}
	if !r.AllPass {
		os.Exit(2)
	}
	return nil
}

// agentSigners lists the keys in the ssh-agent at SSH_AUTH_SOCK (no signing, no touch).
func agentSigners() ([]ssh.Signer, error) {
	conn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return agent.NewClient(conn).Signers()
}
