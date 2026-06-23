// backup.go — recovery cards. A recovery card is a self-contained, offline copy
// of a key (vault or machine), optionally protected by a passphrase. It needs
// NO drive and NO server to restore: the card *is* the key (encrypted). Lose
// every USB and you reconstitute the key from the card + passphrase.
//
//	p3sig backup  [--key FILE] [--out FILE]   create a card (passphrase optional)
//	p3sig restore [--in FILE]  [--out FILE]   rebuild the key from a card
//
// Protection (when a passphrase is set): Argon2id(passphrase, salt) → a 256-bit
// key that secretbox-encrypts the private key. Everything Argon2id needs (salt,
// fixed params) rides on the card, so card + passphrase = key. No passphrase =
// a plaintext card whose security is wherever you keep it (e.g. a safe), the
// same posture as a paper seed phrase.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/secretbox"
)

// Card binary layout (then base64): magic | mode | body | checksum(4).
//
//	mode 0 (plaintext): body = key(64)
//	mode 1 (argon2id):  body = salt(16) | nonce(24) | secretbox_ct(80)
//
// Argon2id params are fixed and versioned by the magic.
const (
	cardMagic     = "P3R1"
	cardModePlain = 0
	cardModePass  = 1
	argonTime     = 3
	argonMemory   = 64 * 1024 // 64 MiB
	argonThreads  = 4
)

var cardB64Line = regexp.MustCompile(`^[A-Za-z0-9+/=]+$`)

func cmdBackup(f map[string]string) error {
	keyPath, err := resolveAnyKeyPath(f)
	if err != nil {
		return err
	}
	key, err := loadKey(keyPath) // 64-byte ed25519 private key
	if err != nil {
		return err
	}
	fp := keyFingerprint(key)

	fmt.Println("Recovery card — an offline copy of this key. With it (and the passphrase,")
	fmt.Println("if you set one) you can restore the key even if every USB is gone.")
	fmt.Println()
	fmt.Println("Set a passphrase to protect the card, or leave it blank for a PLAINTEXT card")
	fmt.Println("(simpler — its security is wherever you store it, e.g. a safe).")
	fmt.Println()

	pass, err := readPassphraseConfirmed()
	if err != nil {
		return err
	}

	var payload []byte
	if pass == "" {
		payload = buildCard(cardModePlain, key)
	} else {
		salt := mustRandom(16)
		dk := argon2.IDKey([]byte(pass), salt, argonTime, argonMemory, argonThreads, 32)
		var nkey [32]byte
		copy(nkey[:], dk)
		var nonce [24]byte
		copy(nonce[:], mustRandom(24))
		ct := secretbox.Seal(nil, key, &nonce, &nkey)
		body := append(append(append([]byte{}, salt...), nonce[:]...), ct...)
		payload = buildCard(cardModePass, body)
	}

	protection := "NONE — keep this card physically secure (e.g. a safe)"
	if pass != "" {
		protection = "passphrase (Argon2id) — useless to anyone without the passphrase"
	}
	card := renderCard(fp, protection, payload)

	if out := f["out"]; out != "" {
		if err := os.WriteFile(out, []byte(card), 0o600); err != nil {
			return err
		}
		fmt.Printf("\nwrote recovery card → %s (mode 600)\n", out)
	} else {
		fmt.Println()
		fmt.Print(card)
	}
	fmt.Println("\nPrint it and store it. To restore later:  p3sig restore")
	return nil
}

func cmdRestore(f map[string]string) error {
	var raw string
	if in := f["in"]; in != "" {
		b, err := os.ReadFile(in)
		if err != nil {
			return err
		}
		raw = string(b)
	} else {
		fmt.Println("Paste the recovery card (including the BEGIN/END lines), then Ctrl-D:")
		b, _ := os.ReadFile("/dev/stdin")
		raw = string(b)
	}

	payload, err := parseCard(raw)
	if err != nil {
		return err
	}
	mode, body, err := openCard(payload)
	if err != nil {
		return err
	}

	var key ed25519.PrivateKey
	switch mode {
	case cardModePlain:
		if len(body) != ed25519.PrivateKeySize {
			return fmt.Errorf("card payload is malformed")
		}
		key = ed25519.PrivateKey(body)
	case cardModePass:
		if len(body) < 16+24+1 {
			return fmt.Errorf("card payload is malformed")
		}
		salt, nonceB, ct := body[:16], body[16:40], body[40:]
		pass, err := readPassphrase("Passphrase: ")
		if err != nil {
			return err
		}
		dk := argon2.IDKey([]byte(pass), salt, argonTime, argonMemory, argonThreads, 32)
		var nkey [32]byte
		copy(nkey[:], dk)
		var nonce [24]byte
		copy(nonce[:], nonceB)
		plain, ok := secretbox.Open(nil, ct, &nonce, &nkey)
		if !ok {
			return fmt.Errorf("wrong passphrase (or a corrupted card)")
		}
		if len(plain) != ed25519.PrivateKeySize {
			return fmt.Errorf("recovered key has the wrong size")
		}
		key = ed25519.PrivateKey(plain)
	default:
		return fmt.Errorf("unknown card mode %d", mode)
	}

	outPath := f["out"]
	if outPath == "" {
		outPath = "p3sig-recovered.key"
	}
	if err := os.WriteFile(outPath, []byte(base64.StdEncoding.EncodeToString(key)+"\n"), 0o600); err != nil {
		return err
	}
	fmt.Printf("\nrestored key → %s (mode 600)\n", outPath)
	fmt.Printf("public key (confirm it matches your account/machine):\n\n    %s\n",
		base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)))
	fmt.Printf("\nfingerprint: %s\n", keyFingerprint(key))
	return nil
}

// ─── card encode/decode ─────────────────────────────────────────────────────

func buildCard(mode byte, body []byte) []byte {
	p := append([]byte(cardMagic), mode)
	p = append(p, body...)
	sum := sha256.Sum256(p)
	return append(p, sum[:4]...)
}

func openCard(p []byte) (mode byte, body []byte, err error) {
	if len(p) < len(cardMagic)+1+4 || string(p[:4]) != cardMagic {
		return 0, nil, fmt.Errorf("not a p3sig recovery card")
	}
	pre, sum := p[:len(p)-4], p[len(p)-4:]
	want := sha256.Sum256(pre)
	if string(want[:4]) != string(sum) {
		return 0, nil, fmt.Errorf("card failed its checksum — a character was likely mistyped")
	}
	return pre[4], pre[5:], nil
}

func renderCard(fp, protection string, payload []byte) string {
	b64 := base64.StdEncoding.EncodeToString(payload)
	var lines []string
	for i := 0; i < len(b64); i += 48 {
		end := i + 48
		if end > len(b64) {
			end = len(b64)
		}
		lines = append(lines, b64[i:end])
	}
	return fmt.Sprintf("-----BEGIN P3SIG RECOVERY CARD-----\n"+
		"fingerprint: %s   (public — identifies the key, not secret)\n"+
		"protection:  %s\n"+
		"\n%s\n"+
		"-----END P3SIG RECOVERY CARD-----\n", fp, protection, strings.Join(lines, "\n"))
}

// parseCard pulls the base64 payload out of a pasted card (ignores the human
// header lines, which contain ':' or spaces).
func parseCard(raw string) ([]byte, error) {
	in := false
	var b strings.Builder
	for _, ln := range strings.Split(raw, "\n") {
		s := strings.TrimSpace(ln)
		switch {
		case strings.Contains(s, "BEGIN P3SIG RECOVERY CARD"):
			in = true
		case strings.Contains(s, "END P3SIG RECOVERY CARD"):
			in = false
		case in && cardB64Line.MatchString(s):
			b.WriteString(s)
		}
	}
	if b.Len() == 0 {
		return nil, fmt.Errorf("no recovery card found in the input")
	}
	p, err := base64.StdEncoding.DecodeString(b.String())
	if err != nil {
		return nil, fmt.Errorf("card payload is not valid base64: %w", err)
	}
	return p, nil
}

// ─── helpers ────────────────────────────────────────────────────────────────

func keyFingerprint(key ed25519.PrivateKey) string {
	sum := sha256.Sum256(key.Public().(ed25519.PublicKey))
	return "SHA256:" + base64.StdEncoding.EncodeToString(sum[:])
}

func resolveAnyKeyPath(f map[string]string) (string, error) {
	c, _ := loadConfig()
	idName := firstNonEmpty(f["identity"], os.Getenv("P3SIG_IDENTITY"), c.DefaultIdentity, "default")
	profName := firstNonEmpty(f["profile"], os.Getenv("P3SIG_PROFILE"), c.DefaultProfile, "default")
	p := firstNonEmpty(
		f["key"],
		os.Getenv("P3SIG_VAULT_KEY"),
		c.Identities[idName].Key,
		os.Getenv("P3SIG_KEY"),
		c.Profiles[profName].Key,
	)
	if p == "" {
		return "", fmt.Errorf("no key to back up — pass --key FILE (or set up an identity/profile)")
	}
	return p, nil
}

func mustRandom(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// readPassphrase reads one line without echo on unix terminals (best effort via
// stty); falls back to an echoed read when there's no tty (pipes) or on Windows.
// P3SIG_PASSPHRASE overrides for non-interactive use. Reads byte-by-byte so it
// never over-reads stdin (which would swallow a following prompt or the card).
func readPassphrase(prompt string) (string, error) {
	if p, ok := os.LookupEnv("P3SIG_PASSPHRASE"); ok {
		return p, nil
	}
	fmt.Print(prompt)
	restore := func() {}
	if runtime.GOOS != "windows" {
		c := exec.Command("stty", "-echo")
		c.Stdin = os.Stdin
		if c.Run() == nil {
			restore = func() {
				r := exec.Command("stty", "echo")
				r.Stdin = os.Stdin
				_ = r.Run()
				fmt.Println()
			}
		}
	}
	defer restore()
	return readLineRaw(), nil
}

// readLineRaw reads a single line from stdin one byte at a time, so no input
// past the newline is buffered/lost (multiple bufio readers on os.Stdin would).
func readLineRaw() string {
	var b []byte
	buf := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buf)
		if n > 0 {
			if buf[0] == '\n' {
				break
			}
			b = append(b, buf[0])
		}
		if err != nil {
			break
		}
	}
	return strings.TrimRight(string(b), "\r")
}

func readPassphraseConfirmed() (string, error) {
	a, err := readPassphrase("Passphrase (blank = plaintext card): ")
	if err != nil {
		return "", err
	}
	if a == "" {
		return "", nil
	}
	b, err := readPassphrase("Confirm passphrase: ")
	if err != nil {
		return "", err
	}
	if a != b {
		return "", fmt.Errorf("passphrases did not match")
	}
	return a, nil
}
