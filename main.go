// Command p3sig is the v2 agent for p3sig.com (zero-knowledge vault + SSH CA).
//
// One binary, two roles:
//
//   server role — on a machine you SSH TO / that needs secrets:
//     p3sig agent pull|run|install   materialize sshd trust files (TrustedUserCAKeys,
//                                    AuthorizedPrincipalsFile, RevokedKeys/KRL)
//     p3sig secrets pull             unseal this machine's granted secrets
//     p3sig exec -- CMD              inject secrets into a process's environment
//
//   identity — every machine has an Ed25519 keypair; p3sig holds only the public
//   half. Auth is a stateless signed request: Ed25519 signature over
//   "<machine_id>|<unix_ts>" (no challenge round-trip, no token). Everything the
//   agent pulls is either public (CA keys, principals, KRL) or sealed ciphertext
//   it opens locally — so a compromised transport leaks nothing.
package main

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/nacl/box"
)

const httpTimeout = 20 * time.Second

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = cmdKeygen(parseFlags(os.Args[2:]))
	case "agent":
		if len(os.Args) < 3 {
			err = fmt.Errorf("agent needs a subcommand: pull | run | install")
			break
		}
		f := parseFlags(os.Args[3:])
		switch os.Args[2] {
		case "pull":
			err = cmdAgentPull(f)
		case "run":
			err = cmdAgentRun(f)
		case "install":
			err = cmdAgentInstall(f)
		default:
			err = fmt.Errorf("unknown agent subcommand %q", os.Args[2])
		}
	case "secrets":
		if len(os.Args) < 3 || os.Args[2] != "pull" {
			err = fmt.Errorf("usage: p3sig secrets pull --url URL --machine ID --key FILE [--bundle NAME]")
			break
		}
		err = cmdSecretsPull(parseFlags(os.Args[3:]))
	case "exec":
		err = cmdExec(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// ─── keygen ─────────────────────────────────────────────────────────────────

func cmdKeygen(f map[string]string) error {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	out := f["out"]
	if out == "" {
		out = "p3sig-machine.key"
	}
	// Store the 64-byte private key base64 — the same encoding p3sig and the
	// reference shim use, so keys are interchangeable.
	if err := os.WriteFile(out, []byte(base64.StdEncoding.EncodeToString(priv)+"\n"), 0o600); err != nil {
		return err
	}
	fmt.Printf("machine key written to %s (keep it secret, mode 600)\n", out)
	fmt.Printf("register this PUBLIC key for the machine in p3sig:\n\n%s\n", base64.StdEncoding.EncodeToString(pub))
	return nil
}

// ─── agent: materialize sshd trust files ────────────────────────────────────

func cmdAgentPull(f map[string]string) error {
	apiBase, machine, key, outDir, err := agentArgs(f)
	if err != nil {
		return err
	}
	return agentPull(apiBase, machine, key, outDir)
}

func agentPull(apiBase, machine string, key ed25519.PrivateKey, outDir string) error {
	if err := os.MkdirAll(filepath.Join(outDir, "principals"), 0o755); err != nil {
		return err
	}

	// 1. TrustedUserCAKeys
	var ca struct {
		Keys  string `json:"trusted_user_ca_keys"`
		Count int    `json:"count"`
	}
	if err := pullInto(apiBase, "getTrustedCA", machine, key, nil, &ca); err != nil {
		return fmt.Errorf("getTrustedCA: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "trusted_user_ca_keys"), []byte(ca.Keys+"\n"), 0o644); err != nil {
		return err
	}

	// 2. AuthorizedPrincipalsFile — one file per login user
	var pr struct {
		Grants []struct {
			Principal string `json:"principal"`
			LoginUser string `json:"login_user"`
		} `json:"grants"`
	}
	if err := pullInto(apiBase, "getPrincipals", machine, key, nil, &pr); err != nil {
		return fmt.Errorf("getPrincipals: %w", err)
	}
	byUser := map[string]map[string]bool{}
	for _, g := range pr.Grants {
		if byUser[g.LoginUser] == nil {
			byUser[g.LoginUser] = map[string]bool{}
		}
		byUser[g.LoginUser][g.Principal] = true
	}
	for user, set := range byUser {
		if !safeUser(user) {
			continue // never let a server value escape the principals dir
		}
		names := make([]string, 0, len(set))
		for p := range set {
			names = append(names, p)
		}
		sort.Strings(names)
		path := filepath.Join(outDir, "principals", user)
		if err := os.WriteFile(path, []byte(strings.Join(names, "\n")+"\n"), 0o644); err != nil {
			return err
		}
	}

	// 3. RevokedKeys (KRL) — compile the spec with ssh-keygen
	var krl struct {
		Spec  string `json:"krl_spec"`
		Count int    `json:"count"`
	}
	if err := pullInto(apiBase, "getKRL", machine, key, nil, &krl); err != nil {
		return fmt.Errorf("getKRL: %w", err)
	}
	specPath := filepath.Join(outDir, ".krl.spec")
	if err := os.WriteFile(specPath, []byte(krl.Spec+"\n"), 0o600); err != nil {
		return err
	}
	krlPath := filepath.Join(outDir, "revoked_keys")
	if out, err := exec.Command("ssh-keygen", "-kq", "-f", krlPath, specPath).CombinedOutput(); err != nil {
		return fmt.Errorf("compile KRL (ssh-keygen): %v: %s", err, out)
	}

	fmt.Printf("pulled: %d CA(s), %d principal grant(s), %d revocation(s) → %s\n",
		ca.Count, len(pr.Grants), krl.Count, outDir)
	return nil
}

func cmdAgentRun(f map[string]string) error {
	apiBase, machine, key, outDir, err := agentArgs(f)
	if err != nil {
		return err
	}
	interval := 300
	if f["interval"] != "" {
		if n, e := strconv.Atoi(f["interval"]); e == nil && n > 0 {
			interval = n
		}
	}
	fmt.Printf("p3sig agent: refreshing %s every %ds\n", outDir, interval)
	for {
		if err := agentPull(apiBase, machine, key, outDir); err != nil {
			fmt.Fprintln(os.Stderr, "pull failed:", err)
		}
		time.Sleep(time.Duration(interval) * time.Second)
	}
}

func cmdAgentInstall(f map[string]string) error {
	_, _, _, outDir, err := agentArgs(f)
	if err != nil {
		return err
	}
	abs, _ := filepath.Abs(outDir)
	fmt.Printf(`Add to /etc/ssh/sshd_config, then run `+"`p3sig agent run …`"+` (or a systemd timer)
to keep these files fresh, and reload sshd:

    TrustedUserCAKeys %s/trusted_user_ca_keys
    AuthorizedPrincipalsFile %s/principals/%%u
    RevokedKeys %s/revoked_keys

`, abs, abs, abs)
	return nil
}

// ─── secrets: unseal granted secrets ────────────────────────────────────────

func cmdSecretsPull(f map[string]string) error {
	apiBase, machine, key, _, err := agentArgs(f)
	if err != nil && f["out"] == "" {
		// out isn't required for secrets; only the first three are.
		if apiBase == "" || machine == "" || key == nil {
			return err
		}
	}
	pairs, err := fetchSecrets(apiBase, machine, key, f["bundle"])
	if err != nil {
		return err
	}
	for _, kv := range pairs {
		fmt.Printf("%s=%s\n", kv[0], kv[1])
	}
	return nil
}

func cmdExec(args []string) error {
	// p3sig exec --url … --machine … --key … [--bundle …] -- CMD args...
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 0 || sep == len(args)-1 {
		return fmt.Errorf("usage: p3sig exec --url URL --machine ID --key FILE [--bundle B] -- CMD [args...]")
	}
	f := parseFlags(args[:sep])
	cmdArgs := args[sep+1:]
	apiBase, machine, key := f["url"], f["machine"], (ed25519.PrivateKey)(nil)
	k, err := loadKey(f["key"])
	if err != nil {
		return err
	}
	key = k
	pairs, err := fetchSecrets(apiBase, machine, key, f["bundle"])
	if err != nil {
		return err
	}
	env := os.Environ()
	for _, kv := range pairs {
		env = append(env, kv[0]+"="+kv[1])
	}
	bin, err := exec.LookPath(cmdArgs[0])
	if err != nil {
		return err
	}
	c := exec.Command(bin, cmdArgs[1:]...)
	c.Env, c.Stdin, c.Stdout, c.Stderr = env, os.Stdin, os.Stdout, os.Stderr
	return c.Run()
}

func fetchSecrets(apiBase, machine string, key ed25519.PrivateKey, bundle string) ([][2]string, error) {
	extra := url.Values{}
	if bundle != "" {
		extra.Set("bundle", bundle)
	}
	var res struct {
		Secrets []struct {
			Label     string `json:"label"`
			Encrypted string `json:"encrypted_data"`
		} `json:"secrets"`
	}
	if err := pullInto(apiBase, "getSealedSecrets", machine, key, extra, &res); err != nil {
		return nil, err
	}
	out := make([][2]string, 0, len(res.Secrets))
	for _, s := range res.Secrets {
		val, err := openSealedBox(s.Encrypted, key)
		if err != nil {
			return nil, fmt.Errorf("unseal %s: %w", s.Label, err)
		}
		out = append(out, [2]string{s.Label, val})
	}
	return out, nil
}

// ─── signed request transport (v2) ──────────────────────────────────────────

type apiResponse struct {
	Error   string          `json:"error"`
	Results json.RawMessage `json:"results"`
}

// pullInto signs "<machine>|<ts>", POSTs the action, and unmarshals results into v.
func pullInto(apiBase, action, machine string, key ed25519.PrivateKey, extra url.Values, v any) error {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(machine+"|"+ts)))

	form := url.Values{}
	for k, vals := range extra {
		form[k] = vals
	}
	form.Set("action", action)
	form.Set("machine_id", machine)
	form.Set("ts", ts)
	form.Set("signature", sig)

	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Post(apiBase, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var ar apiResponse
	if err := json.Unmarshal(body, &ar); err != nil {
		return fmt.Errorf("invalid JSON (HTTP %d): %.200s", resp.StatusCode, body)
	}
	if ar.Error != "" {
		return fmt.Errorf("%s", ar.Error)
	}
	if v != nil && len(ar.Results) > 0 {
		return json.Unmarshal(ar.Results, v)
	}
	return nil
}

// ─── cryptography (kept from v1 — the zero-knowledge core) ───────────────────

// openSealedBox decrypts a base64 sodium_crypto_box_seal ciphertext with the
// Ed25519 private key (converted to X25519). Wire-compatible with PHP's
// sodium_crypto_box_seal / Go's box.OpenAnonymous.
func openSealedBox(encryptedB64 string, edPriv ed25519.PrivateKey) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedB64)
	if err != nil {
		return "", fmt.Errorf("invalid base64: %w", err)
	}
	edPub := edPriv.Public().(ed25519.PublicKey)
	x25519Pub, err := ed25519PubToX25519(edPub)
	if err != nil {
		return "", fmt.Errorf("public key conversion: %w", err)
	}
	x25519Priv := ed25519PrivToX25519(edPriv)
	plaintext, ok := box.OpenAnonymous(nil, ciphertext, x25519Pub, x25519Priv)
	if !ok {
		return "", fmt.Errorf("decryption failed — wrong key or corrupted ciphertext")
	}
	return string(plaintext), nil
}

func ed25519PubToX25519(edPub ed25519.PublicKey) (*[32]byte, error) {
	p, err := new(edwards25519.Point).SetBytes([]byte(edPub))
	if err != nil {
		return nil, fmt.Errorf("invalid Ed25519 public key: %w", err)
	}
	var out [32]byte
	copy(out[:], p.BytesMontgomery())
	return &out, nil
}

func ed25519PrivToX25519(edPriv ed25519.PrivateKey) *[32]byte {
	h := sha512.Sum512(edPriv.Seed())
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	var out [32]byte
	copy(out[:], h[:32])
	return &out
}

// ─── helpers ────────────────────────────────────────────────────────────────

// loadKey reads a base64 (64-byte) Ed25519 private key written by `p3sig keygen`.
func loadKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, fmt.Errorf("--key is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("key %s is not valid base64: %w", path, err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("key %s is %d bytes, want %d", path, len(raw), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(raw), nil
}

// agentArgs pulls the shared --url/--machine/--key/--out flags.
func agentArgs(f map[string]string) (apiBase, machine string, key ed25519.PrivateKey, outDir string, err error) {
	apiBase, machine, outDir = f["url"], f["machine"], f["out"]
	if outDir == "" {
		outDir = "/etc/p3sig/ssh"
	}
	if apiBase == "" || machine == "" {
		return "", "", nil, "", fmt.Errorf("--url and --machine are required")
	}
	key, err = loadKey(f["key"])
	return apiBase, machine, key, outDir, err
}

// safeUser rejects login names that could escape the principals directory.
func safeUser(u string) bool {
	if u == "" || len(u) > 64 {
		return false
	}
	for _, r := range u {
		if !(r == '_' || r == '-' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

func parseFlags(args []string) map[string]string {
	flags := make(map[string]string)
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "--") {
			key := strings.TrimPrefix(args[i], "--")
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				flags[key] = args[i+1]
				i++
			} else {
				flags[key] = "true"
			}
		}
	}
	return flags
}

func usage() {
	fmt.Print(`p3sig — agent for p3sig.com (zero-knowledge vault + SSH CA)

USAGE
  p3sig keygen [--out FILE]
        Generate this machine's Ed25519 identity; print its public key to register.

  p3sig agent pull    --url URL --machine ID --key FILE [--out DIR]
        Fetch + write TrustedUserCAKeys, AuthorizedPrincipalsFile/<user>, RevokedKeys.
  p3sig agent run     --url URL --machine ID --key FILE [--out DIR] [--interval SEC]
        Same, looping every --interval seconds (default 300).
  p3sig agent install [--out DIR]
        Print the sshd_config lines to add.

  p3sig secrets pull  --url URL --machine ID --key FILE [--bundle NAME]
        Unseal this machine's granted secrets, print KEY=VALUE.
  p3sig exec          --url URL --machine ID --key FILE [--bundle NAME] -- CMD [args...]
        Inject those secrets into CMD's environment and run it.

DEFAULTS
  --out defaults to /etc/p3sig/ssh
  --url e.g. https://p3sig.com/p3sig/api/index.php

Auth is a stateless signed request: Ed25519 over "<machine_id>|<unix_ts>".
`)
}
