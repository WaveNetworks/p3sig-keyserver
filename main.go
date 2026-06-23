// Command p3sig is the v2 agent for p3sig.com (zero-knowledge vault + SSH CA).
//
// One binary, two roles:
//
//	server role — on a machine you SSH TO / that needs secrets:
//	  p3sig agent pull|run|install   materialize sshd trust files (TrustedUserCAKeys,
//	                                 AuthorizedPrincipalsFile, RevokedKeys/KRL)
//	  p3sig secrets pull             unseal this machine's granted secrets
//	  p3sig exec -- CMD              inject secrets into a process's environment
//
//	identity — every machine has an Ed25519 keypair; p3sig holds only the public
//	half. Auth is a stateless signed request: Ed25519 signature over
//	"<machine_id>|<unix_ts>" (no challenge round-trip, no token). Everything the
//	agent pulls is either public (CA keys, principals, KRL) or sealed ciphertext
//	it opens locally — so a compromised transport leaks nothing.
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
const userAgent = "p3sig-agent/0.2"

// Fallbacks when a value isn't given by flag, env (P3SIG_*), or a saved profile.
const defaultAPI = "https://p3sig.com/p3sig/api/index.php"
const defaultOut = "/etc/p3sig/ssh"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = cmdKeygen(parseFlags(os.Args[2:]))
	case "init":
		err = cmdInit(parseFlags(os.Args[2:]))
	case "server":
		if len(os.Args) < 3 || os.Args[2] != "up" {
			err = fmt.Errorf("usage: p3sig server up")
			break
		}
		err = cmdServerUp(parseFlags(os.Args[3:]))
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
		if len(os.Args) < 3 {
			err = fmt.Errorf("usage: p3sig secrets pull|get|list  (run `p3sig help`)")
			break
		}
		rest := os.Args[3:]
		switch os.Args[2] {
		case "pull":
			err = cmdSecretsPull(parseFlags(rest))
		case "list":
			err = cmdSecretsList(parseFlags(rest))
		case "get":
			err = cmdSecretsGet(parseFlags(rest), firstPositional(rest))
		default:
			err = fmt.Errorf("unknown secrets subcommand %q (pull | get | list)", os.Args[2])
		}
	case "exec", "run":
		err = cmdExec(os.Args[2:])
	case "backup":
		err = cmdBackup(parseFlags(os.Args[2:]))
	case "restore":
		err = cmdRestore(parseFlags(os.Args[2:]))
	case "login":
		err = cmdLogin(parseFlags(os.Args[2:]))
	case "secret":
		if len(os.Args) < 3 {
			err = fmt.Errorf("usage: p3sig secret set|get NAME  (manage your own secrets via your vault key)")
			break
		}
		rest := os.Args[3:]
		switch os.Args[2] {
		case "set":
			err = cmdSecretSet(parseFlags(rest), firstPositional(rest))
		case "get":
			err = cmdSecretGetUser(parseFlags(rest), firstPositional(rest))
		default:
			err = fmt.Errorf("unknown secret subcommand %q (set | get)", os.Args[2])
		}
	case "setup":
		err = cmdSetup(parseFlags(os.Args[2:]))
	case "ssh-agent":
		err = cmdSSHAgent(parseFlags(os.Args[2:]))
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
	_, _, _, outDir := resolveRaw(f) // install only needs the out dir
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
	apiBase, machine, key, _, err := resolve(f)
	if err != nil {
		return err
	}
	pairs, err := fetchSecrets(apiBase, machine, key, f["bundle"])
	if err != nil {
		return err
	}
	for _, kv := range pairs {
		if f["export"] == "true" {
			fmt.Printf("export %s=%s\n", kv[0], shellQuote(kv[1]))
		} else {
			fmt.Printf("%s=%s\n", kv[0], kv[1])
		}
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
	apiBase, machine, key, _, err := resolve(f)
	if err != nil {
		return err
	}
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
	return postForm(apiBase, form, v)
}

// postForm POSTs a urlencoded form to the API and unmarshals results into v.
// Shared by the machine (pullInto) and user (userRequest) signed-request paths.
func postForm(apiBase string, form url.Values, v any) error {
	req, err := http.NewRequest("POST", apiBase, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// A real User-Agent: WAFs (e.g. StackCDN in front of p3sig.com) reject the
	// default "Go-http-client/1.1" with a 403 before the request reaches the app.
	req.Header.Set("User-Agent", userAgent)

	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Do(req)
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

// agentArgs resolves the shared url/machine/key/out values (flag > env > profile
// > default) so every agent command works with no flags after `p3sig init`.
func agentArgs(f map[string]string) (apiBase, machine string, key ed25519.PrivateKey, outDir string, err error) {
	return resolve(f)
}

// firstPositional returns the first non-flag argument (skipping flag values),
// e.g. NAME in `secrets get NAME --bundle b`.
func firstPositional(args []string) string {
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "--") {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				i++
			}
			continue
		}
		return args[i]
	}
	return ""
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

GETTING STARTED
  p3sig init                 Enroll this machine (guided): generate its key, walk you
                             through registering it, and save a profile. After this,
                             the commands below need no --url/--machine/--key flags.
  p3sig server up            Turnkey server: enroll if needed, pull SSH trust files,
                             offer to wire sshd + install a refresh service.

SECRETS
  p3sig secrets list         List the secret names granted to this machine.
  p3sig secrets get NAME     Print one secret's value.
  p3sig secrets pull [--export]   Print KEY=VALUE (with --export: shell-quoted exports).
  p3sig run -- CMD [args]    Run CMD with the granted secrets in its environment
                             (alias: p3sig exec).

MANAGE (your account — signs with your vault USB key)
  p3sig login --key VAULTKEY  Prove your account with your vault key; save an identity.
                             The account is whoever owns the key — nothing typed.
  p3sig secret set NAME [--type personal|developer] [--provider P] [--bundle ID]
                             Store a secret: sealed to your keys CLIENT-SIDE, only
                             ciphertext uploaded. Value via stdin or prompt (never argv).
  p3sig secret get NAME      Fetch + unseal one of your secrets locally.

SSH (certificate authority)
  p3sig agent pull           Write TrustedUserCAKeys, AuthorizedPrincipalsFile/<user>, RevokedKeys.
  p3sig agent run [--interval SEC]   Same, looping (default 300s).
  p3sig agent install        Print the sshd_config lines to add.

CLIENT (your laptop)
  p3sig setup [--label N] [--show] [--delete]
                             Create a chip-backed SSH key (TPM / Secure Enclave,
                             gated by Windows Hello / Touch ID); --show / --delete.
  p3sig ssh-agent [--label N] [--bind PATH]
                             Serve the chip key to ssh (biometric per connection).

  p3sig keygen [--out FILE]  Just generate a machine key + print its public half.

RECOVERY
  p3sig backup [--key FILE] [--out FILE] [--split M-of-N]
                             Make an offline recovery card for a key — optionally
                             passphrase-protected, or --split into N shares (any M
                             recover; each useless alone — for estates/custody).
                             Restores even if every USB is gone.
  p3sig restore [--in FILE] [--out FILE]
                             Rebuild a key from a card, or from ≥M shares (no drive/server).

CONFIG & OVERRIDES
  A profile saved by ` + "`init`" + ` supplies url/machine/key/out. Override any value with a
  flag (--url --machine --key --out --bundle), an env var (P3SIG_URL, P3SIG_MACHINE,
  P3SIG_KEY, P3SIG_OUT), or pick a profile with --profile / P3SIG_PROFILE.
  Config: $P3SIG_CONFIG, else ~/.config/p3sig/config.json, else /etc/p3sig/config.json.
  Defaults: --url ` + defaultAPI + `  --out ` + defaultOut + `

Auth is a stateless signed request: Ed25519 over "<machine_id>|<unix_ts>".
`)
}
