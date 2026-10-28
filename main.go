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
	"errors"
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
)

const httpTimeout = 45 * time.Second

// gatewayRetryDelay is the pause before the one retry of a 502/503/504.
var gatewayRetryDelay = 5 * time.Second

const userAgent = "p3sig-agent/0.2"

// Fallbacks when a value isn't given by flag, env (P3SIG_*), or a saved profile.
const defaultAPI = "https://p3sig.com/p3sig/api/index.php"
const defaultOut = "/etc/p3sig/ssh"

// version is the release version, injected at build time via
// -ldflags "-X main.version=...". It stays "dev" for plain `go build`.
var version = "dev"

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
			err = fmt.Errorf("usage: p3sig secret set|get NAME | reseal --with DEVICE  (manage your own secrets via your vault key)")
			break
		}
		rest := os.Args[3:]
		switch os.Args[2] {
		case "set":
			err = cmdSecretSet(parseFlags(rest), firstPositional(rest))
		case "get":
			err = cmdSecretGetUser(parseFlags(rest), firstPositional(rest))
		case "reseal":
			err = cmdSecretReseal(parseFlags(rest))
		default:
			err = fmt.Errorf("unknown secret subcommand %q (set | get | reseal)", os.Args[2])
		}
	case "org":
		if len(os.Args) < 3 {
			err = fmt.Errorf("usage: p3sig org create|add|grant|secret|rotate  (run `p3sig help`)")
			break
		}
		rest := os.Args[3:]
		switch os.Args[2] {
		case "create":
			err = cmdOrgCreate(parseFlags(rest))
		case "add":
			err = cmdOrgAddMember(parseFlags(rest))
		case "grant":
			err = cmdOrgGrant(parseFlags(rest))
		case "secret":
			if len(os.Args) < 4 {
				err = fmt.Errorf("usage: p3sig org secret set|get|list [NAME] | reseal --with DEVICE")
				break
			}
			srest := os.Args[4:]
			switch os.Args[3] {
			case "set":
				err = cmdOrgSecretSet(parseFlags(srest), firstPositional(srest))
			case "get":
				err = cmdOrgSecretGet(parseFlags(srest), firstPositional(srest))
			case "list":
				err = cmdOrgSecretList(parseFlags(srest))
			case "reseal":
				err = cmdOrgSecretReseal(parseFlags(srest))
			default:
				err = fmt.Errorf("unknown org secret subcommand %q (set | get | list | reseal)", os.Args[3])
			}
		case "rotate":
			err = cmdOrgRotate(parseFlags(rest))
		default:
			err = fmt.Errorf("unknown org subcommand %q (create | add | grant | secret | rotate)", os.Args[2])
		}
	case "policy":
		sub := ""
		if len(os.Args) > 2 {
			sub = os.Args[2]
		}
		var rest []string
		if len(os.Args) > 3 {
			rest = os.Args[3:]
		}
		err = cmdPolicy(sub, parseFlags(rest))
	case "vault":
		sub := ""
		if len(os.Args) > 2 {
			sub = os.Args[2]
		}
		var rest []string
		if len(os.Args) > 3 {
			rest = os.Args[3:]
		}
		err = cmdVault(sub, parseFlags(rest))
	case "usb", "dongle":
		sub := ""
		if len(os.Args) > 2 {
			sub = os.Args[2]
		}
		var rest []string
		if len(os.Args) > 3 {
			rest = os.Args[3:]
		}
		if os.Args[1] == "usb" {
			err = cmdUSB(sub, parseFlags(rest))
		} else {
			err = cmdDongle(sub, parseFlags(rest))
		}
	case "setup":
		err = cmdSetup(parseFlags(os.Args[2:]))
	case "ssh-agent":
		err = cmdSSHAgent(parseFlags(os.Args[2:]))
	case "version", "-v", "--version":
		fmt.Println("p3sig", version)
	case "keyserver":
		err = cmdKeyserver(os.Args[2:])
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
	root, req := signedFlags(f)
	return agentPullWith(apiBase, machine, key, outDir, root, req)
}

func agentPull(apiBase, machine string, key ed25519.PrivateKey, outDir string) error {
	return agentPullWith(apiBase, machine, key, outDir, os.Getenv("P3SIG_ROOT"), os.Getenv("P3SIG_REQUIRE_SIGNED") == "1")
}

// signedFlags: --root SHA256:… pins the root (saved after the first verified
// pull); --require-signed refuses unsigned policy even before that.
func signedFlags(f map[string]string) (string, bool) {
	return firstNonEmpty(f["root"], os.Getenv("P3SIG_ROOT")),
		f["require-signed"] == "true" || os.Getenv("P3SIG_REQUIRE_SIGNED") == "1"
}

// agentPullWith pulls the sshd trust files. With a pinned root it uses the
// signed policy (task #2568) and never writes anything that fails verification;
// once one signed policy has been applied, signatures are mandatory for good.
func agentPullWith(apiBase, machine string, key ed25519.PrivateKey, outDir, rootFP string, requireSigned bool) error {
	if err := os.MkdirAll(filepath.Join(outDir, "principals"), 0o755); err != nil {
		return err
	}
	st := loadPolicyState(outDir)
	if rootFP == "" {
		rootFP = st.RootFP
	} else if st.RootFP != "" && st.RootFP != rootFP {
		return fmt.Errorf("root %s differs from the pinned root %s — refusing (re-init deliberately to change roots)", rootFP, st.RootFP)
	}
	// A pinned root means signatures are required from the first pull: falling
	// back to the unsigned path would let a MITM answer "no signed policy" and
	// have its own CA written.
	mandatory := requireSigned || st.Version > 0 || rootFP != ""

	if rootFP != "" {
		var sp SignedPolicy
		err := pullInto(apiBase, "getSignedPolicy", machine, key, nil, &sp)
		if err == nil && (sp.Policy.Payload != "" || sp.AccountPolicy != nil) {
			p, verr := verifyPolicyAny(&sp, rootFP, machine, st, time.Now())
			if verr != nil {
				reportPolicyStatus(apiBase, machine, key, "refused", verr.Error(), st)
				return fmt.Errorf("signed policy REJECTED, old config kept: %w", verr)
			}
			if err := writeSSHFiles(outDir, strings.Join(p.CAKeys, "\n"), p.Grants, p.KRLSpec); err != nil {
				return err
			}
			if err := savePolicyState(outDir, nextState(&sp, rootFP, p, st)); err != nil {
				return err
			}
			reportPolicyStatus(apiBase, machine, key, "applied", "", nextState(&sp, rootFP, p, st))
			fmt.Printf("pulled signed policy v%d: %d CA(s), %d principal grant(s), valid until %s → %s\n", p.Version, len(p.CAKeys), len(p.Grants), time.Unix(p.KRLExpires, 0).UTC().Format(time.RFC3339), outDir)
			return nil
		}
		if mandatory {
			if err == nil {
				err = fmt.Errorf("server returned no signed policy")
			}
			return fmt.Errorf("signed policy required, old config kept: %w", err)
		}
	} else if mandatory {
		return fmt.Errorf("signed policy required but no root pinned (--root SHA256:… / P3SIG_ROOT)")
	}
	fmt.Fprintln(os.Stderr, "WARNING: p3sig served an UNSIGNED policy; only TLS protects these sshd files. Pin a root (P3SIG_ROOT=SHA256:…) to require signatures.")

	// Legacy unsigned path.
	var ca struct {
		Keys  string `json:"trusted_user_ca_keys"`
		Count int    `json:"count"`
	}
	if err := pullInto(apiBase, "getTrustedCA", machine, key, nil, &ca); err != nil {
		return fmt.Errorf("getTrustedCA: %w", err)
	}
	var pr struct {
		Grants []PolicyGrant `json:"grants"`
	}
	if err := pullInto(apiBase, "getPrincipals", machine, key, nil, &pr); err != nil {
		return fmt.Errorf("getPrincipals: %w", err)
	}
	var krl struct {
		Spec  string `json:"krl_spec"`
		Count int    `json:"count"`
	}
	if err := pullInto(apiBase, "getKRL", machine, key, nil, &krl); err != nil {
		return fmt.Errorf("getKRL: %w", err)
	}
	if err := writeSSHFiles(outDir, ca.Keys, pr.Grants, krl.Spec); err != nil {
		return err
	}
	fmt.Printf("pulled: %d CA(s), %d principal grant(s), %d revocation(s) → %s\n",
		ca.Count, len(pr.Grants), krl.Count, outDir)
	return nil
}

// writeSSHFiles materializes TrustedUserCAKeys, one AuthorizedPrincipalsFile per
// login user, and the compiled KRL. The KRL compiles first, so a bad spec
// changes nothing; each file is replaced atomically.
func writeSSHFiles(outDir, caKeys string, grants []PolicyGrant, krlSpec string) error {
	specPath := filepath.Join(outDir, ".krl.spec")
	if err := os.WriteFile(specPath, []byte(krlSpec+"\n"), 0o600); err != nil {
		return err
	}
	krlPath := filepath.Join(outDir, "revoked_keys")
	if out, err := exec.Command("ssh-keygen", "-kq", "-f", krlPath+".tmp", specPath).CombinedOutput(); err != nil {
		return fmt.Errorf("compile KRL (ssh-keygen): %v: %s", err, out)
	}

	byUser := map[string]map[string]bool{}
	for _, g := range grants {
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
		if err := writeFileAtomic(path, []byte(strings.Join(names, "\n")+"\n"), 0o644); err != nil {
			return err
		}
	}
	if err := writeFileAtomic(filepath.Join(outDir, "trusted_user_ca_keys"), []byte(caKeys+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(krlPath+".tmp", krlPath)
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
	root, req := signedFlags(f)
	fmt.Printf("p3sig agent: refreshing %s every %ds\n", outDir, interval)
	for {
		if err := agentPullWith(apiBase, machine, key, outDir, root, req); err != nil {
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
	rootFP, requireSigned := signedFlags(f)
	pairs, err := fetchSecrets(apiBase, machine, key, f["bundle"], rootFP, requireSigned)
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
	rootFP, requireSigned := signedFlags(f)
	pairs, err := fetchSecrets(apiBase, machine, key, f["bundle"], rootFP, requireSigned)
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

// requireSigned (--require-signed / P3SIG_REQUIRE_SIGNED=1, the same switch as
// signed policy) refuses every unsigned value instead of warning: for agents whose
// secrets have all been re-sealed signed, a plain value can only be a forgery.
func fetchSecrets(apiBase, machine string, key ed25519.PrivateKey, bundle, rootFP string, requireSigned bool) ([][2]string, error) {
	extra := url.Values{}
	if bundle != "" {
		extra.Set("bundle", bundle)
	}
	var res struct {
		Secrets []struct {
			SecretID  string `json:"secret_id"`
			Encrypted string `json:"encrypted_data"`
			Meta      string `json:"encrypted_meta"`
		} `json:"secrets"`
	}
	if err := pullInto(apiBase, "getSealedSecrets", machine, key, extra, &res); err != nil {
		return nil, err
	}
	// Sign-then-seal (task #2598): with a pinned root, a signed value must verify
	// against the device chain before it is used.
	trust, err := loadSecretTrust(apiBase, machine, key, rootFP)
	if err != nil {
		return nil, fmt.Errorf("secret signing chain: %w", err)
	}
	if requireSigned && trust == nil {
		return nil, errors.New("signed secrets required but no root pinned (--root SHA256:… / P3SIG_ROOT)")
	}
	me := machineKeyFP(key.Public().(ed25519.PublicKey))
	// The variable name is sealed next to the value; open both with this machine's key.
	out := make([][2]string, 0, len(res.Secrets))
	unsigned := 0
	for _, s := range res.Secrets {
		name, err := openSecretName(s.Meta, key)
		if err != nil {
			return nil, fmt.Errorf("open the name of secret %s: %w", s.SecretID, err)
		}
		plain, err := openSealedBox(s.Encrypted, key)
		if err != nil {
			return nil, fmt.Errorf("unseal %s: %w", name.Label, err)
		}
		val, isUnsigned, err := acceptSecretValue(plain, s.SecretID, name.Label, me, trust, time.Now(), requireSigned)
		if err != nil {
			return nil, fmt.Errorf("secret %s REJECTED: %w", name.Label, err)
		}
		if isUnsigned {
			unsigned++
		}
		out = append(out, [2]string{name.Label, val})
	}
	warnUnsignedSecrets(unsigned, trust != nil)
	sort.SliceStable(out, func(i, j int) bool { return out[i][0] < out[j][0] })
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

	// The shared host answers short bursts with a gateway error before the
	// request reaches PHP; retry those once after a pause. Timeouts are not
	// retried — the first attempt may have landed.
	client := &http.Client{Timeout: httpTimeout}
	var body []byte
	var status int
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			time.Sleep(gatewayRetryDelay)
			req.Body = io.NopCloser(strings.NewReader(form.Encode()))
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		body, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return err
		}
		status = resp.StatusCode
		if attempt == 0 && (status == 502 || status == 503 || status == 504) {
			continue
		}
		break
	}
	var ar apiResponse
	if err := json.Unmarshal(body, &ar); err != nil {
		return fmt.Errorf("invalid JSON (HTTP %d): %.200s", status, body)
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
	raw, err := openSealedBoxRaw(encryptedB64, edPriv)
	if err != nil {
		return "", err
	}
	return string(raw), nil
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
      --root SHA256:…        verify signed secrets against this root (also P3SIG_ROOT)
      --require-signed       refuse any unsigned secret (also P3SIG_REQUIRE_SIGNED=1);
                             for secrets, run, exec, secrets get/list
  p3sig run -- CMD [args]    Run CMD with the granted secrets in its environment
                             (alias: p3sig exec).

MANAGE (your account — signs with your vault USB key)
  p3sig login --key VAULTKEY  Prove your account with your vault key; save an identity.
                             The account is whoever owns the key — nothing typed.
  p3sig secret set NAME [--type personal|developer] [--provider P] [--bundle ID]
                             Store a secret: value AND name sealed to your keys
                             CLIENT-SIDE, only ciphertext uploaded. Value via stdin or
                             prompt (never argv). Machines granted the bundle get it when
                             you re-seal (browser "Seal now", or below — signed).
  p3sig secret get NAME      Fetch + unseal one of your secrets locally.
  p3sig secret reseal --with agent[:SHA256:…]|KEYFILE
                             Re-seal every machine copy of your secrets SIGNED by a
                             delegated device (sign-then-seal), so agents with a pinned
                             root can tell you sealed them, not the server.

ORG VAULT (enterprise — shared, zero-knowledge; signs with your vault key)
  p3sig org create --name NAME     Create an organization + its vault (client-side keypair).
  p3sig org add --email A [--admin] Add a registered account to the org (member or admin).
  p3sig org grant --user ID        Give a member vault access (wraps the org key to every
                                   one of their keys).
  p3sig org secret set NAME        Store an org secret (value + name sealed to the org key).
  p3sig org secret get NAME        Fetch + open an org secret you have access to.
  p3sig org secret list            List org secret names (opened locally with the org key).
  p3sig org secret reseal --with agent[:SHA256:…]|KEYFILE
                                   Re-seal the org bundle copies on YOUR machines signed by a
                                   delegated device (machines another member registered are
                                   skipped: their agents trust that member's root, not yours).
  p3sig org rotate                 New org key: re-seal every secret, re-wrap to members.

BROWSER VAULT
  p3sig vault verify [--url API]   Check the browser vault the site serves right now against
                                   the release p3sig's deploy signed (key pinned in this
                                   binary). A FAIL means the server changed the vault code:
                                   do not use the browser vault, use this CLI.

SSH (certificate authority)
  p3sig agent pull           Write TrustedUserCAKeys, AuthorizedPrincipalsFile/<user>, RevokedKeys.
  p3sig agent run [--interval SEC]   Same, looping (default 300s).
      --root SHA256:…        pin the policy root; from then on only signed policy that chains to it
                             is written, older versions are refused (also P3SIG_ROOT)
      --require-signed       refuse unsigned policy even before the first signed pull
  p3sig agent install        Print the sshd_config lines to add.

VAULT STICKS + DONGLE (setup in 3 commands; no VeraCrypt, no sudo, no ssh-agent)
  p3sig usb init [--from KEYFILE] [--drive PATH]
                             New vault/root key on a blank FAT stick (DAILY), passphrase-wrapped
                             (Argon2id + AES-GCM), then cloned + verified onto SAFE. Resumes an
                             interrupted run; never overwrites a key. --from migrates an old key.
  p3sig usb clone [--drive FROM] [--to PATH]   Copy a vault stick to another blank stick.
  p3sig dongle add [--root-key usb]   PIN (set if none), resident ES256 ssh:p3sig-policy key
                             (PIN required), delegated with the root from the vault stick.
  Key sources: --root-key / --with take usb[:PATH] (finds the stick, asks the passphrase) and
  --with dongle[:SHA256:…] (this binary asks the PIN and the touch itself).

SIGNED POLICY (what agents accept: root in the safe → delegated dongle/chip keys)
  p3sig policy root --root-key K       Publish the root (once); prints the fingerprint to pin.
  p3sig policy delegate --root-key K --device D [--label L] [--expires 90d]
                             Let device D sign policy. D = .pub file, key line or agent[:SHA256:…].
  p3sig policy revoke --root-key K --device D|SHA256:…   Revoke a signing device.
  p3sig policy sign [--group G] [--with agent[:SHA256:…]|KEYFILE] [--expires-hours 72] [--yes]
                             ONE signature for every machine: shows the diff since the last signed version.
  p3sig policy sign --machine ID|--all [--krl-hours 72]   Legacy per-machine policies (one signature each).
  p3sig policy freshness-delegate --root-key K --freshness-key PUB [--label L] [--expires 365d]
                             Root lets a low-privilege key keep policy fresh (it can't change content).
  p3sig policy refresh --freshness-key K --account user:N --root SHA256:… [--group G] [--window 36h]
                             Timer job on the key server: verify the signed policy, vouch it is still current.
                             Review the server's draft (CAs, principals, KRL) and sign it on
                             the device. Default --with agent: the dongle (ssh-add) or the
                             chip key (p3sig ssh-agent). The root key is not needed.
  p3sig policy status        Root fingerprint, signing devices, per-machine policy versions.

CLIENT (your laptop)
  p3sig setup [--label N] [--show] [--delete]
                             Create a chip-backed SSH key (TPM / Secure Enclave,
                             gated by Windows Hello / Touch ID); --show / --delete.
  p3sig ssh-agent [--label N] [--bind PATH]
                             Serve the chip key to ssh (biometric per connection).

  p3sig keygen [--out FILE]  Just generate a machine key + print its public half.

KEY SERVER (shared-hosting fallback tier; needs a TPM)
  p3sig keyserver init [--label N]
                             Make the chip key; print the public point apps wrap to.
  p3sig keyserver serve [--config FILE] [--listen ADDR]
                             Unlock bundle keys for allowlisted apps
                             (default ~/.p3sig/keyserver.json, 127.0.0.1:8787).
  p3sig keyserver seal --pub B64 [--pub B64] --in values.json --out cache.enc
                             Encrypt an app's values to one or more key servers.

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

// reportPolicyStatus tells the dashboard what this agent applied or refused
// (task #2631), so a stale/refused policy is seen there, not only in local logs.
// Best effort: a server that doesn't know the action yet is ignored.
func reportPolicyStatus(apiBase, machine string, key ed25519.PrivateKey, status, detail string, st policyState) {
	extra := url.Values{}
	extra.Set("status", status)
	extra.Set("detail", detail)
	extra.Set("version", strconv.FormatInt(st.Version, 10))
	extra.Set("format", firstNonEmpty(st.Format, "machine"))
	extra.Set("valid_until", strconv.FormatInt(st.KRLExpires, 10))
	var out map[string]any
	_ = pullInto(apiBase, "reportPolicyStatus", machine, key, extra, &out)
}
