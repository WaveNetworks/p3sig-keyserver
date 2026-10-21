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
// pinned, or are refused outright with --require-signed / P3SIG_REQUIRE_SIGNED=1.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
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

// acceptSecretValue applies openSecretValue plus the mandatory-signature switch:
// with requireSigned an unsigned value is an error, otherwise it is returned and
// flagged so the caller can count it for the warning.
func acceptSecretValue(plain, secretID, name, recipientFP string, trust *secretTrust, now time.Time, requireSigned bool) (string, bool, error) {
	val, err := openSecretValue(plain, secretID, name, recipientFP, trust, now)
	if errors.Is(err, errUnsignedSecret) {
		if requireSigned {
			return "", false, errors.New("not signed and signatures are required (--require-signed / P3SIG_REQUIRE_SIGNED=1); re-seal it with `p3sig secret reseal --with agent`")
		}
		return val, true, nil
	}
	if err != nil {
		return "", false, err
	}
	return val, false, nil
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

// ─── p3sig secret reseal — sign-then-seal every machine copy ─────────────────
// The browser can open and re-seal but can't sign (no device key), so machine
// copies it makes are unsigned. `p3sig secret reseal --with DEVICE` asks for
// every machine copy of the account's own secrets (getResealWork resign=1),
// opens one of the account's copies with the vault key, and replaces each
// machine copy with an envelope signed by the delegated device. Own vault keys
// missing a copy get a plain one (signatures are for machines).

type resealWork struct {
	SecretID string `json:"secret_id"`
	Missing  []struct {
		KeyID     string `json:"key_id"`
		PublicKey string `json:"public_key"`
	} `json:"missing"`
	Copies map[string]struct {
		Enc  string `json:"encrypted_data"`
		Meta string `json:"encrypted_meta"`
	} `json:"copies"`
}

type resealCopy struct {
	SecretID string `json:"secret_id"`
	sealedCopy
}

func cmdSecretReseal(f map[string]string) error {
	apiBase, keyPath, err := resolveIdentity(f)
	if err != nil {
		return err
	}
	dev, err := loadSigner(firstNonEmpty(f["with"], "agent"))
	if err != nil {
		return fmt.Errorf("--with (delegated device: agent[:SHA256:…] or a key file): %w", err)
	}
	key, err := loadKey(keyPath)
	if err != nil {
		return err
	}
	call := func(action string, extra url.Values, v any) error {
		return userRequest(apiBase, action, keyPath, extra, v)
	}
	signed, plain, err := secretReseal(call, key, dev, time.Now())
	if err != nil {
		return err
	}
	if signed+plain == 0 {
		fmt.Println("nothing to re-seal: no machine is granted any of your secrets.")
		return nil
	}
	fmt.Printf("re-sealed %d machine cop(ies) signed by %s, %d vault-key cop(ies) plain.\n"+
		"Agents with a pinned root verify them on their next pull.\n", signed, ssh.FingerprintSHA256(dev.PublicKey()), plain)
	return nil
}

// secretReseal is the testable core: call in, counts out.
func secretReseal(call policyCall, vaultKey ed25519.PrivateKey, dev ssh.Signer, now time.Time) (signed, plain int, err error) {
	var st policyStatus
	if err := call("getPolicyStatus", nil, &st); err != nil {
		return 0, 0, err
	}
	if err := requireLiveDelegation(st, dev, now); err != nil {
		return 0, 0, err
	}
	var own struct {
		Keys []struct {
			KeyID string `json:"key_id"`
		} `json:"keys"`
	}
	if err := call("getMyVaultKeys", nil, &own); err != nil {
		return 0, 0, err
	}
	ownKey := map[string]bool{}
	for _, k := range own.Keys {
		ownKey[k.KeyID] = true
	}
	var res struct {
		Work []resealWork `json:"work"`
	}
	extra := url.Values{}
	extra.Set("resign", "1")
	if err := call("getResealWork", extra, &res); err != nil {
		return 0, 0, err
	}
	var out []resealCopy
	for _, w := range res.Work {
		var value string
		var meta secretMeta
		opened := false
		for _, c := range w.Copies {
			m, err := openSecretName(c.Meta, vaultKey)
			if err != nil {
				continue
			}
			if v, err := openSealedBox(c.Enc, vaultKey); err == nil {
				value, meta, opened = v, m, true
				break
			}
		}
		if !opened {
			fmt.Fprintf(os.Stderr, "skip %s: none of its copies opens with this vault key\n", w.SecretID)
			continue
		}
		if strings.HasPrefix(value, signedSecretPrefix) {
			return 0, 0, fmt.Errorf("secret %s: your own copy holds a signed envelope, refusing to nest it", w.SecretID)
		}
		mj, _ := json.Marshal(meta)
		for _, r := range w.Missing {
			var c sealedCopy
			if ownKey[r.KeyID] {
				if c, err = sealSecretFor(value, meta, r.KeyID, r.PublicKey); err != nil {
					return 0, 0, err
				}
				plain++
			} else {
				raw, err := base64.StdEncoding.DecodeString(r.PublicKey)
				if err != nil || len(raw) != ed25519.PublicKeySize {
					return 0, 0, fmt.Errorf("secret %s: machine key %s is malformed", w.SecretID, r.KeyID)
				}
				s := SignedSecret{Account: st.Account, SecretID: w.SecretID, Name: meta.Label, Value: value,
					Recipient: machineKeyFP(ed25519.PublicKey(raw)), Issued: now.Unix()}
				enc, err := sealSignedSecret(dev, s, r.PublicKey)
				if err != nil {
					return 0, 0, err
				}
				m, err := sealForKey(string(mj), r.PublicKey)
				if err != nil {
					return 0, 0, err
				}
				c = sealedCopy{KeyID: r.KeyID, Enc: enc, Meta: m}
				signed++
			}
			out = append(out, resealCopy{SecretID: w.SecretID, sealedCopy: c})
		}
	}
	if len(out) == 0 {
		return 0, 0, nil
	}
	payload, _ := json.Marshal(out)
	save := url.Values{}
	save.Set("sealed_copies", string(payload))
	if err := call("saveResealed", save, nil); err != nil {
		return 0, 0, err
	}
	return signed, plain, nil
}

// requireLiveDelegation refuses a device the account's root has not (or no longer)
// delegated: agents would reject everything it signs.
func requireLiveDelegation(st policyStatus, dev ssh.Signer, now time.Time) error {
	devFP := ssh.FingerprintSHA256(dev.PublicKey())
	for _, d := range st.Delegations {
		if d.DeviceFP == devFP && !d.Revoked && (d.Expires == 0 || now.Unix() < d.Expires) {
			return nil
		}
	}
	return fmt.Errorf("device %s has no live delegation on account %s — run `p3sig policy delegate` first, or agents will reject what it signs", devFP, st.Account)
}

// ─── p3sig org secret reseal — sign-then-seal org bundle copies on machines ──
// An org machine gets a granted bundle as copies an admin re-sealed from the org
// key (browser: unsigned). This opens each bundle secret with the org key and
// replaces every machine copy with an envelope signed by the delegated device.
// Only machines whose signed policy comes from YOUR root can verify your device,
// so machines another member registered are skipped (they keep their copies).

type orgResealResult struct {
	Signed, Machines, Skipped int
}

func cmdOrgSecretReseal(f map[string]string) error {
	apiBase, keyPath, err := resolveIdentity(f)
	if err != nil {
		return err
	}
	dev, err := loadSigner(firstNonEmpty(f["with"], "agent"))
	if err != nil {
		return fmt.Errorf("--with (delegated device: agent[:SHA256:…] or a key file): %w", err)
	}
	key, err := loadKey(keyPath)
	if err != nil {
		return err
	}
	orgPriv, err := myOrgKey(apiBase, keyPath, key)
	if err != nil {
		return err
	}
	defer zero(orgPriv)
	call := func(action string, extra url.Values, v any) error {
		return userRequest(apiBase, action, keyPath, extra, v)
	}
	r, err := orgSecretReseal(call, orgPriv, dev, time.Now())
	if err != nil {
		return err
	}
	if r.Signed == 0 && r.Skipped == 0 {
		fmt.Println("nothing to re-seal: no machine is granted an org bundle.")
		return nil
	}
	fmt.Printf("re-sealed %d org secret cop(ies) on %d machine(s), signed by %s.\n", r.Signed, r.Machines, ssh.FingerprintSHA256(dev.PublicKey()))
	if r.Skipped > 0 {
		fmt.Printf("skipped %d machine(s) another member registered: their policy root is not yours, so they could not verify this device. That member can run this command for them.\n", r.Skipped)
	}
	return nil
}

// orgSecretReseal is the testable core: call in, counts out.
func orgSecretReseal(call policyCall, orgPriv ed25519.PrivateKey, dev ssh.Signer, now time.Time) (orgResealResult, error) {
	var r orgResealResult
	var st policyStatus
	if err := call("getPolicyStatus", nil, &st); err != nil {
		return r, err
	}
	if err := requireLiveDelegation(st, dev, now); err != nil {
		return r, err
	}
	mine := map[string]bool{}
	for _, m := range st.Machines {
		mine[m.MachineID] = true
	}
	var list struct {
		Secrets []orgSecretRow `json:"secrets"`
	}
	if err := call("listOrgSecrets", nil, &list); err != nil {
		return r, err
	}
	var bundles []string
	seen := map[string]bool{}
	for _, s := range list.Secrets {
		if s.BundleID != "" && !seen[s.BundleID] {
			seen[s.BundleID] = true
			bundles = append(bundles, s.BundleID)
		}
	}
	type opened struct {
		id, value string
		meta      secretMeta
	}
	skipped := map[string]bool{}
	signedOn := map[string]bool{}
	for _, b := range bundles {
		q := url.Values{}
		q.Set("bundle_id", b)
		var bm struct {
			Machines []struct {
				MachineID string `json:"machine_id"`
				Keys      []struct {
					KeyID     string `json:"key_id"`
					PublicKey string `json:"public_key"`
				} `json:"keys"`
			} `json:"machines"`
		}
		if err := call("getBundleMachines", q, &bm); err != nil {
			return r, err
		}
		if len(bm.Machines) == 0 {
			continue
		}
		var bs struct {
			Secrets []struct {
				SecretID string `json:"secret_id"`
				Enc      string `json:"encrypted_data"`
				Meta     string `json:"encrypted_meta"`
			} `json:"secrets"`
		}
		if err := call("getOrgBundleSecrets", q, &bs); err != nil {
			return r, err
		}
		var secrets []opened
		for _, s := range bs.Secrets {
			m, err := openSecretName(s.Meta, orgPriv)
			if err != nil {
				return r, fmt.Errorf("org secret %s: open name: %w", s.SecretID, err)
			}
			v, err := openOrgSecret(s.Enc, orgPriv)
			if err != nil {
				return r, fmt.Errorf("org secret %s: open value: %w", s.SecretID, err)
			}
			if strings.HasPrefix(v, signedSecretPrefix) {
				return r, fmt.Errorf("org secret %s: the org copy holds a signed envelope, refusing to nest it", s.SecretID)
			}
			secrets = append(secrets, opened{s.SecretID, v, m})
		}
		if len(secrets) == 0 {
			continue
		}
		for _, m := range bm.Machines {
			if !mine[m.MachineID] {
				skipped[m.MachineID] = true
				continue
			}
			var out []resealCopy
			for _, k := range m.Keys {
				raw, err := base64.StdEncoding.DecodeString(k.PublicKey)
				if err != nil || len(raw) != ed25519.PublicKeySize {
					return r, fmt.Errorf("machine %s: key %s is malformed", m.MachineID, k.KeyID)
				}
				fp := machineKeyFP(ed25519.PublicKey(raw))
				for _, s := range secrets {
					enc, err := sealSignedSecret(dev, SignedSecret{Account: st.Account, SecretID: s.id, Name: s.meta.Label,
						Value: s.value, Recipient: fp, Issued: now.Unix()}, k.PublicKey)
					if err != nil {
						return r, err
					}
					mj, _ := json.Marshal(s.meta)
					meta, err := sealForKey(string(mj), k.PublicKey)
					if err != nil {
						return r, err
					}
					out = append(out, resealCopy{SecretID: s.id, sealedCopy: sealedCopy{KeyID: k.KeyID, Enc: enc, Meta: meta}})
				}
			}
			if len(out) == 0 {
				continue
			}
			payload, _ := json.Marshal(out)
			save := url.Values{}
			save.Set("machine_id", m.MachineID)
			save.Set("bundle_id", b)
			save.Set("sealed_copies", string(payload))
			if err := call("saveSealedForMachine", save, nil); err != nil {
				return r, fmt.Errorf("machine %s, bundle %s: %w", m.MachineID, b, err)
			}
			r.Signed += len(out)
			signedOn[m.MachineID] = true
		}
	}
	r.Machines, r.Skipped = len(signedOn), len(skipped)
	return r, nil
}
