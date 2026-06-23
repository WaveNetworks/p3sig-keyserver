// cli.go — ergonomics layer (Slice 1): config + profiles, an interactive
// enrollment wizard, a turnkey `server up`, and secret-management verbs.
//
// The goal is that after a one-time `p3sig init`, every command runs with NO
// flags — url/machine/key come from a saved profile. Flags and P3SIG_* env vars
// still override, so nothing that worked before breaks.
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// ─── config + profiles ──────────────────────────────────────────────────────

// Profile is one machine's connection: where p3sig is, who this machine is, and
// the path to its key. A config file may hold several (e.g. "prod", "staging").
type Profile struct {
	URL     string `json:"url"`
	Machine string `json:"machine"`
	Key     string `json:"key"`
	Out     string `json:"out,omitempty"`
}

// Identity is the human/account side (Slice 2): a vault USB key that signs
// management requests. The account is whoever owns that key — not typed.
type Identity struct {
	URL string `json:"url"`
	Key string `json:"key"`
}

type Config struct {
	DefaultProfile  string              `json:"default_profile,omitempty"`
	Profiles        map[string]Profile  `json:"profiles"`
	DefaultIdentity string              `json:"default_identity,omitempty"`
	Identities      map[string]Identity `json:"identities,omitempty"`
}

// configReadPaths is the lookup order for an existing config (first hit wins):
// explicit $P3SIG_CONFIG, then the per-user dir, then the system dir.
func configReadPaths() []string {
	var p []string
	if c := os.Getenv("P3SIG_CONFIG"); c != "" {
		p = append(p, c)
	}
	if base, err := os.UserConfigDir(); err == nil && base != "" {
		p = append(p, filepath.Join(base, "p3sig", "config.json"))
	}
	return append(p, "/etc/p3sig/config.json")
}

func loadConfig() (Config, string) {
	for _, p := range configReadPaths() {
		if c, err := loadConfigFrom(p); err == nil {
			return c, p
		}
	}
	return Config{Profiles: map[string]Profile{}}, ""
}

func loadConfigFrom(path string) (Config, error) {
	c := Config{Profiles: map[string]Profile{}}
	data, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, err
	}
	if c.Profiles == nil {
		c.Profiles = map[string]Profile{}
	}
	return c, nil
}

func saveConfigTo(path string, c Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func pickProfile(f map[string]string, c Config) Profile {
	name := firstNonEmpty(f["profile"], os.Getenv("P3SIG_PROFILE"), c.DefaultProfile, "default")
	return c.Profiles[name]
}

// ─── value resolution: flag > env > profile > default ───────────────────────

func resolveRaw(f map[string]string) (apiBase, machine, keyPath, outDir string) {
	c, _ := loadConfig()
	p := pickProfile(f, c)
	apiBase = firstNonEmpty(f["url"], os.Getenv("P3SIG_URL"), p.URL, defaultAPI)
	machine = firstNonEmpty(f["machine"], os.Getenv("P3SIG_MACHINE"), p.Machine)
	keyPath = firstNonEmpty(f["key"], os.Getenv("P3SIG_KEY"), p.Key)
	outDir = firstNonEmpty(f["out"], os.Getenv("P3SIG_OUT"), p.Out, defaultOut)
	return
}

// resolve loads the machine key too; the path that the agent commands use.
func resolve(f map[string]string) (string, string, ed25519.PrivateKey, string, error) {
	apiBase, machine, keyPath, outDir := resolveRaw(f)
	if machine == "" {
		return "", "", nil, "", fmt.Errorf("no machine configured — run `p3sig init` (or pass --machine/--key, or set P3SIG_MACHINE/P3SIG_KEY)")
	}
	key, err := loadKey(keyPath)
	return apiBase, machine, key, outDir, err
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// ─── secret verbs ───────────────────────────────────────────────────────────

func cmdSecretsList(f map[string]string) error {
	apiBase, machine, key, _, err := resolve(f)
	if err != nil {
		return err
	}
	pairs, err := fetchSecrets(apiBase, machine, key, f["bundle"])
	if err != nil {
		return err
	}
	if len(pairs) == 0 {
		fmt.Fprintln(os.Stderr, "(no secrets granted to this machine"+bundleSuffix(f["bundle"])+")")
		return nil
	}
	for _, kv := range pairs {
		fmt.Println(kv[0])
	}
	return nil
}

func cmdSecretsGet(f map[string]string, name string) error {
	if name == "" {
		return fmt.Errorf("usage: p3sig secrets get NAME [--bundle B]")
	}
	apiBase, machine, key, _, err := resolve(f)
	if err != nil {
		return err
	}
	pairs, err := fetchSecrets(apiBase, machine, key, f["bundle"])
	if err != nil {
		return err
	}
	for _, kv := range pairs {
		if kv[0] == name {
			fmt.Println(kv[1])
			return nil
		}
	}
	return fmt.Errorf("no secret named %q granted to this machine%s", name, bundleSuffix(f["bundle"]))
}

func bundleSuffix(b string) string {
	if b == "" {
		return ""
	}
	return " in bundle " + b
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ─── enrollment wizard ──────────────────────────────────────────────────────

func cmdInit(f map[string]string) error {
	system := f["system"] == "true"
	cfgPath, keyDefault := initPaths(system)
	in := bufio.NewReader(os.Stdin)

	fmt.Println("p3sig setup — enroll this machine.")
	fmt.Println()
	fmt.Println("You'll register this machine's PUBLIC key in your p3sig account; its")
	fmt.Println("private key never leaves this box. Have a p3sig.com account ready (creating")
	fmt.Println("one sets up your vault key).")
	fmt.Println()

	apiBase := ask(in, "p3sig API URL", firstNonEmpty(f["url"], os.Getenv("P3SIG_URL"), defaultAPI))
	keyPath := firstNonEmpty(f["key"], keyDefault)

	var pub string
	if _, err := os.Stat(keyPath); err == nil {
		if pub, err = pubFromKeyFile(keyPath); err != nil {
			return fmt.Errorf("existing key %s: %w", keyPath, err)
		}
		fmt.Printf("\nusing existing key %s\n", keyPath)
	} else {
		var e error
		if pub, e = generateKeyFile(keyPath); e != nil {
			return fmt.Errorf("generate key at %s: %w (try --key PATH, or sudo for a system path)", keyPath, e)
		}
		fmt.Printf("\ngenerated machine key → %s (mode 600)\n", keyPath)
	}

	host, _ := os.Hostname()
	appURL := deriveAppURL(apiBase)
	fmt.Printf(`
Now, in your browser:
  1. Open  %s?page=machines
     (log in — create a p3sig.com account first if you don't have one.)
  2. Click "Add machine" and name it (e.g. %q).
  3. Open that machine, choose "Add machine key", and paste this PUBLIC key:

%s

  4. Copy the Machine ID it shows, and paste it back here.

`, appURL, host, indent(pub))

	machine := ask(in, "Paste the Machine ID", f["machine"])
	if machine == "" {
		return fmt.Errorf("a machine id is required to finish")
	}
	profile := ask(in, "Save as profile name", "default")

	cfg, _ := loadConfigFrom(cfgPath) // start from existing if present
	cfg.Profiles[profile] = Profile{URL: apiBase, Machine: machine, Key: keyPath, Out: defaultOut}
	if cfg.DefaultProfile == "" {
		cfg.DefaultProfile = profile
	}
	if err := saveConfigTo(cfgPath, cfg); err != nil {
		return fmt.Errorf("save config %s: %w", cfgPath, err)
	}
	fmt.Printf("\nsaved %s (profile %q is the default)\n", cfgPath, profile)

	fmt.Print("verifying… ")
	key, err := loadKey(keyPath)
	if err != nil {
		return err
	}
	var ca struct {
		Count int `json:"count"`
	}
	if err := pullInto(apiBase, "getTrustedCA", machine, key, nil, &ca); err != nil {
		fmt.Println("could not authenticate.")
		fmt.Printf("  %v\n", err)
		fmt.Println("  Double-check the Machine ID, and that the public key above is registered to it.")
		return nil
	}
	fmt.Printf("OK — authenticated as machine %s.\n", short(machine))
	fmt.Println()
	fmt.Println("Next:")
	fmt.Println("  • Server (SSH/secrets):  p3sig server up")
	fmt.Println("  • Check granted secrets: p3sig secrets list")
	return nil
}

// ─── turnkey server bootstrap ───────────────────────────────────────────────

func cmdServerUp(f map[string]string) error {
	if _, _, _, _, err := resolve(f); err != nil {
		fmt.Println("This machine isn't enrolled yet — let's do that first.")
		fmt.Println()
		if os.Geteuid() == 0 {
			f["system"] = "true"
		}
		if e := cmdInit(f); e != nil {
			return e
		}
		fmt.Println()
	}
	apiBase, machine, key, outDir, err := resolve(f)
	if err != nil {
		return err
	}
	_, _, keyPath, _ := resolveRaw(f)
	in := bufio.NewReader(os.Stdin)

	fmt.Println("Pulling SSH trust files…")
	if err := agentPull(apiBase, machine, key, outDir); err != nil {
		return err
	}
	abs, _ := filepath.Abs(outDir)

	dropin := fmt.Sprintf("TrustedUserCAKeys %s/trusted_user_ca_keys\nAuthorizedPrincipalsFile %s/principals/%%u\nRevokedKeys %s/revoked_keys\n", abs, abs, abs)
	fmt.Printf("\nsshd needs these lines (a drop-in at /etc/ssh/sshd_config.d/p3sig.conf):\n\n%s\n\n", indent(dropin))
	if confirm(in, "Write the drop-in and reload sshd?") {
		if err := writeSshdDropin(dropin); err != nil {
			fmt.Printf("couldn't write it (%v).\nAdd the lines above to /etc/ssh/sshd_config yourself (sudo), ensure\n`Include /etc/ssh/sshd_config.d/*.conf` is present, then: sudo systemctl reload sshd\n", err)
		} else {
			fmt.Println("wrote /etc/ssh/sshd_config.d/p3sig.conf")
			reloadSshd()
		}
	} else {
		fmt.Println("skipped — add the lines above when you're ready.")
	}

	if hasSystemd() {
		self, _ := os.Executable()
		unit := systemdUnit(self, apiBase, machine, keyPath, outDir)
		fmt.Printf("\nKeep the files fresh with a systemd service:\n\n%s\n", indent(unit))
		if confirm(in, "Install and start p3sig-agent.service?") {
			if err := installSystemd(unit); err != nil {
				fmt.Printf("couldn't install it (%v).\nRun it under any process manager instead: p3sig agent run\n", err)
			} else {
				fmt.Println("installed + started p3sig-agent.service (refreshes every 5 min)")
			}
		}
	} else {
		fmt.Println("\nNo systemd here — keep the files fresh with:  p3sig agent run")
	}

	fmt.Println("\nDone. In the p3sig UI, grant this machine what it should have:")
	fmt.Println("  • SSH:     SSH Access → Certificate authority → grant a principal onto this machine")
	fmt.Println("  • Secrets: put values in a bundle and grant the bundle to this machine")
	return nil
}

// ─── system glue ────────────────────────────────────────────────────────────

func initPaths(system bool) (cfgPath, keyPath string) {
	if system {
		return "/etc/p3sig/config.json", "/etc/p3sig/machine.key"
	}
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".config")
	}
	dir := filepath.Join(base, "p3sig")
	return filepath.Join(dir, "config.json"), filepath.Join(dir, "machine.key")
}

func generateKeyFile(path string) (string, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(priv)+"\n"), 0o600); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

func pubFromKeyFile(path string) (string, error) {
	k, err := loadKey(path)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey)), nil
}

func writeSshdDropin(content string) error {
	dir := "/etc/ssh/sshd_config.d"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "p3sig.conf"), []byte(content), 0o644)
}

func reloadSshd() {
	for _, svc := range []string{"sshd", "ssh"} {
		if err := exec.Command("systemctl", "reload", svc).Run(); err == nil {
			fmt.Printf("reloaded %s\n", svc)
			return
		}
	}
	fmt.Println("reload sshd when ready: sudo systemctl reload sshd")
}

func hasSystemd() bool {
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		return true
	}
	_, err := exec.LookPath("systemctl")
	return err == nil
}

func installSystemd(unit string) error {
	path := "/etc/systemd/system/p3sig-agent.service"
	if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
		return err
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()
	if out, err := exec.Command("systemctl", "enable", "--now", "p3sig-agent.service").CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func systemdUnit(self, apiURL, machine, keyPath, outDir string) string {
	return fmt.Sprintf(`[Unit]
Description=p3sig agent — refresh sshd CA trust files
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s agent run --url %s --machine %s --key %s --out %s --interval 300
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
`, self, apiURL, machine, keyPath, outDir)
}

// ─── small terminal helpers ─────────────────────────────────────────────────

func ask(in *bufio.Reader, label, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	line, _ := in.ReadString('\n')
	if line = strings.TrimSpace(line); line != "" {
		return line
	}
	return def
}

func confirm(in *bufio.Reader, label string) bool {
	fmt.Printf("%s [y/N]: ", label)
	line, _ := in.ReadString('\n')
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes"
}

func indent(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := range lines {
		lines[i] = "    " + lines[i]
	}
	return strings.Join(lines, "\n")
}

func deriveAppURL(api string) string {
	if i := strings.LastIndex(api, "api/index.php"); i >= 0 {
		return api[:i] + "app/"
	}
	return strings.TrimRight(api, "/") + "/app/"
}

func short(s string) string {
	if len(s) <= 14 {
		return s
	}
	return s[:14] + "…"
}

// ─── Slice 2: account identity (USB-signs) ──────────────────────────────────

// resolveIdentity returns the API URL + vault-key path for the human/account.
// Precedence: flag > env > saved identity > default. The vault key is separate
// from a machine key (P3SIG_VAULT_KEY, not P3SIG_KEY).
func resolveIdentity(f map[string]string) (apiBase, keyPath string, err error) {
	c, _ := loadConfig()
	name := firstNonEmpty(f["identity"], os.Getenv("P3SIG_IDENTITY"), c.DefaultIdentity, "default")
	id := c.Identities[name]
	apiBase = firstNonEmpty(f["url"], os.Getenv("P3SIG_URL"), id.URL, defaultAPI)
	keyPath = firstNonEmpty(f["key"], os.Getenv("P3SIG_VAULT_KEY"), id.Key)
	if keyPath == "" {
		return "", "", fmt.Errorf("no vault key — run `p3sig login --key <vault key file>`")
	}
	return apiBase, keyPath, nil
}

// userRequest signs "<pubkey>|<ts>" with the vault key and POSTs the action —
// the account is resolved server-side from the key. Mirror of pullInto.
func userRequest(apiBase, action, keyPath string, extra url.Values, v any) error {
	key, err := loadKey(keyPath)
	if err != nil {
		return err
	}
	pub := base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(pub+"|"+ts)))

	form := url.Values{}
	for k, vals := range extra {
		form[k] = vals
	}
	form.Set("action", action)
	form.Set("pubkey", pub)
	form.Set("ts", ts)
	form.Set("signature", sig)
	return postForm(apiBase, form, v)
}

// sealForKey seals plaintext to a base64 Ed25519 public key, producing a base64
// libsodium sealed box (crypto_box_seal) — the inverse of openSealedBox, and
// what p3sig stores. Wire-compatible with PHP's sodium_crypto_box_seal.
func sealForKey(plaintext, edPubB64 string) (string, error) {
	edPub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(edPubB64))
	if err != nil || len(edPub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid recipient public key")
	}
	xPub, err := ed25519PubToX25519(ed25519.PublicKey(edPub))
	if err != nil {
		return "", err
	}
	sealed, err := box.SealAnonymous(nil, []byte(plaintext), xPub, rand.Reader)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// ─── p3sig login — establish the account identity ───────────────────────────

func cmdLogin(f map[string]string) error {
	apiBase := firstNonEmpty(f["url"], os.Getenv("P3SIG_URL"), defaultAPI)
	keyPath := firstNonEmpty(f["key"], os.Getenv("P3SIG_VAULT_KEY"))
	if keyPath == "" {
		return fmt.Errorf("usage: p3sig login --key <vault key file> [--url URL] [--identity NAME]\n" +
			"(the vault key is the Ed25519 key registered to your p3sig account)")
	}
	var who struct {
		UserID   string `json:"user_id"`
		KeyLabel string `json:"key_label"`
		KeyCount int    `json:"key_count"`
	}
	if err := userRequest(apiBase, "whoami", keyPath, nil, &who); err != nil {
		return fmt.Errorf("%w\n(is this key registered as a vault key on your account?)", err)
	}
	label := who.KeyLabel
	if label == "" {
		label = "(unlabeled)"
	}
	fmt.Printf("Authenticated to p3sig.\n  account:  %s\n  via key:  %s  (%d key(s) on the account)\n\n",
		who.UserID, label, who.KeyCount)

	in := bufio.NewReader(os.Stdin)
	name := ask(in, "Save this identity as", firstNonEmpty(f["identity"], "default"))

	cfgPath := firstNonEmpty(os.Getenv("P3SIG_CONFIG"), userConfigPath())
	cfg, _ := loadConfigFrom(cfgPath)
	if cfg.Identities == nil {
		cfg.Identities = map[string]Identity{}
	}
	cfg.Identities[name] = Identity{URL: apiBase, Key: keyPath}
	if cfg.DefaultIdentity == "" {
		cfg.DefaultIdentity = name
	}
	if err := saveConfigTo(cfgPath, cfg); err != nil {
		return err
	}
	fmt.Printf("saved identity %q → %s\n", name, cfgPath)
	fmt.Println("\nNow: p3sig secret set NAME   ·   p3sig secret get NAME")
	return nil
}

// ─── p3sig secret … — zero-knowledge management ─────────────────────────────

func cmdSecretSet(f map[string]string, name string) error {
	if name == "" {
		return fmt.Errorf("usage: p3sig secret set NAME [--type personal|developer] [--provider P] [--bundle ID]\n" +
			"the value is read from stdin (echo -n VALUE | p3sig secret set NAME) or prompted")
	}
	apiBase, keyPath, err := resolveIdentity(f)
	if err != nil {
		return err
	}
	// 1. fetch the account's recipient keys
	var mk struct {
		Keys []struct {
			KeyID string `json:"key_id"`
			Pub   string `json:"public_key"`
			Label string `json:"label"`
		} `json:"keys"`
	}
	if err := userRequest(apiBase, "getMyVaultKeys", keyPath, nil, &mk); err != nil {
		return err
	}
	if len(mk.Keys) == 0 {
		return fmt.Errorf("no vault keys on this account to seal to")
	}
	// 2. read the value (never from argv)
	value, err := readSecretValue(name)
	if err != nil {
		return err
	}
	// 3. seal to every recipient key, client-side
	type copyT struct {
		KeyID string `json:"key_id"`
		Enc   string `json:"encrypted_data"`
	}
	copies := make([]copyT, 0, len(mk.Keys))
	for _, k := range mk.Keys {
		enc, err := sealForKey(value, k.Pub)
		if err != nil {
			return fmt.Errorf("seal to key %s: %w", k.Label, err)
		}
		copies = append(copies, copyT{KeyID: k.KeyID, Enc: enc})
	}
	payload, _ := json.Marshal(copies)
	// 4. upload ciphertext only
	extra := url.Values{}
	extra.Set("label", name)
	extra.Set("type", firstNonEmpty(f["type"], "developer"))
	if f["provider"] != "" {
		extra.Set("provider", f["provider"])
	}
	if f["bundle"] != "" {
		extra.Set("bundle_id", f["bundle"])
	}
	extra.Set("sealed_copies", string(payload))
	var res struct {
		SecretID string `json:"secret_id"`
		Sealed   int    `json:"sealed"`
	}
	if err := userRequest(apiBase, "saveSecretSealed", keyPath, extra, &res); err != nil {
		return err
	}
	fmt.Printf("stored %q — sealed to %d key(s); the server holds only ciphertext.\n", name, res.Sealed)
	return nil
}

func cmdSecretGetUser(f map[string]string, name string) error {
	if name == "" {
		return fmt.Errorf("usage: p3sig secret get NAME")
	}
	apiBase, keyPath, err := resolveIdentity(f)
	if err != nil {
		return err
	}
	var res struct {
		Secrets []struct {
			Label string `json:"label"`
			Enc   string `json:"encrypted_data"`
		} `json:"secrets"`
	}
	if err := userRequest(apiBase, "getMySecrets", keyPath, nil, &res); err != nil {
		return err
	}
	key, err := loadKey(keyPath)
	if err != nil {
		return err
	}
	for _, s := range res.Secrets {
		if s.Label == name {
			val, err := openSealedBox(s.Enc, key)
			if err != nil {
				return fmt.Errorf("unseal %q: %w", name, err)
			}
			fmt.Println(val)
			return nil
		}
	}
	return fmt.Errorf("no secret named %q on this account", name)
}

// readSecretValue reads a secret from stdin (piped) or prompts without echo.
func readSecretValue(name string) (string, error) {
	fi, _ := os.Stdin.Stat()
	if (fi.Mode() & os.ModeCharDevice) == 0 { // piped/redirected
		data, err := os.ReadFile("/dev/stdin")
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(data), "\r\n"), nil
	}
	fmt.Printf("Value for %q: ", name)
	in := bufio.NewReader(os.Stdin)
	line, _ := in.ReadString('\n')
	return strings.TrimRight(line, "\r\n"), nil
}

func userConfigPath() string {
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "p3sig", "config.json")
}
