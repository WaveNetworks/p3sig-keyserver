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
	"strconv"
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
	cardMagic     = "P3R1" // single recovery card: mode | body
	shareMagic    = "P3S1" // one Shamir share: M | x | y
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

	// Split mode: N share cards, any M reconstruct. Each share is useless alone,
	// so they go to different custodians (no passphrase needed — the quorum is it).
	if spec := f["split"]; spec != "" {
		m, n, err := parseSplit(spec)
		if err != nil {
			return err
		}
		shares, err := shamirSplit(key, m, n)
		if err != nil {
			return err
		}
		for i, s := range shares {
			payload := buildBlob(shareMagic, append([]byte{s.m, s.x}, s.y...))
			card := renderShare(fp, i+1, n, m, payload)
			if out := f["out"]; out != "" {
				path := fmt.Sprintf("%s.share-%dof%d.card", out, i+1, n)
				if err := os.WriteFile(path, []byte(card), 0o600); err != nil {
					return err
				}
				fmt.Printf("wrote share %d of %d → %s\n", i+1, n, path)
			} else {
				fmt.Print(card)
				fmt.Println()
			}
		}
		fmt.Printf("\n%d shares, any %d recover the key. Give each to a separate custodian\n", n, m)
		fmt.Printf("(attorney, safety-deposit box, …). Recover with:  p3sig restore   (give it ≥%d).\n", m)
		return nil
	}

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
		payload = buildBlob(cardMagic, append([]byte{cardModePlain}, key...))
	} else {
		salt := mustRandom(16)
		dk := argon2.IDKey([]byte(pass), salt, argonTime, argonMemory, argonThreads, 32)
		var nkey [32]byte
		copy(nkey[:], dk)
		var nonce [24]byte
		copy(nonce[:], mustRandom(24))
		ct := secretbox.Seal(nil, key, &nonce, &nkey)
		body := append(append(append([]byte{cardModePass}, salt...), nonce[:]...), ct...)
		payload = buildBlob(cardMagic, body)
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

	cards, shares, err := extractBlocks(raw)
	if err != nil {
		return err
	}

	var key ed25519.PrivateKey
	switch {
	case len(cards) > 0:
		if key, err = openSingleCard(cards[0]); err != nil {
			return err
		}
	case len(shares) > 0:
		need := int(shares[0].m)
		if len(shares) < need {
			return fmt.Errorf("found %d share(s) but need %d — add the missing card(s)", len(shares), need)
		}
		secret, err := shamirCombine(shares[:need])
		if err != nil {
			return err
		}
		if len(secret) != ed25519.PrivateKeySize {
			return fmt.Errorf("recombined key has the wrong size — are these shares from the same key?")
		}
		key = ed25519.PrivateKey(secret)
	default:
		return fmt.Errorf("no recovery card or shares found in the input")
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

// buildBlob frames body under a 4-byte magic with a 4-byte checksum.
func buildBlob(magic string, body []byte) []byte {
	p := append([]byte(magic), body...)
	sum := sha256.Sum256(p)
	return append(p, sum[:4]...)
}

// openBlob verifies the checksum and returns the magic + body.
func openBlob(p []byte) (magic string, body []byte, err error) {
	if len(p) < 4+4 {
		return "", nil, fmt.Errorf("not a p3sig recovery card")
	}
	pre, sum := p[:len(p)-4], p[len(p)-4:]
	want := sha256.Sum256(pre)
	if string(want[:4]) != string(sum) {
		return "", nil, fmt.Errorf("recovery card failed its checksum — a character was likely mistyped")
	}
	return string(pre[:4]), pre[4:], nil
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

// renderShare prints one Shamir share as its own card.
func renderShare(fp string, idx, n, m int, payload []byte) string {
	b64 := base64.StdEncoding.EncodeToString(payload)
	var lines []string
	for i := 0; i < len(b64); i += 48 {
		end := i + 48
		if end > len(b64) {
			end = len(b64)
		}
		lines = append(lines, b64[i:end])
	}
	return fmt.Sprintf("-----BEGIN P3SIG RECOVERY SHARE-----\n"+
		"share:       %d of %d   (any %d recover the key)\n"+
		"fingerprint: %s   (public — identifies the key, not secret)\n"+
		"\n%s\n"+
		"-----END P3SIG RECOVERY SHARE-----\n", idx, n, m, fp, strings.Join(lines, "\n"))
}

// extractBlocks pulls every recovery block out of pasted/loaded text and sorts
// them into single cards (P3R1) and Shamir shares (P3S1).
func extractBlocks(raw string) (cards [][]byte, shares []shareT, err error) {
	in := false
	var b strings.Builder
	flush := func() error {
		if b.Len() == 0 {
			return nil
		}
		p, e := base64.StdEncoding.DecodeString(b.String())
		b.Reset()
		if e != nil {
			return fmt.Errorf("a recovery block isn't valid base64: %w", e)
		}
		magic, body, e := openBlob(p)
		if e != nil {
			return e
		}
		switch magic {
		case cardMagic:
			cards = append(cards, p)
		case shareMagic:
			if len(body) < 2 {
				return fmt.Errorf("malformed share")
			}
			shares = append(shares, shareT{m: body[0], x: body[1], y: append([]byte{}, body[2:]...)})
		default:
			return fmt.Errorf("unrecognised recovery block")
		}
		return nil
	}
	for _, ln := range strings.Split(raw, "\n") {
		s := strings.TrimSpace(ln)
		switch {
		case strings.Contains(s, "BEGIN P3SIG RECOVERY"):
			in = true
			b.Reset()
		case strings.Contains(s, "END P3SIG RECOVERY"):
			if e := flush(); e != nil {
				return nil, nil, e
			}
			in = false
		case in && cardB64Line.MatchString(s):
			b.WriteString(s)
		}
	}
	if len(cards) == 0 && len(shares) == 0 {
		return nil, nil, fmt.Errorf("no recovery card or shares found in the input")
	}
	return cards, shares, nil
}

// openSingleCard recovers the key from one P3R1 card (plaintext or passphrase).
func openSingleCard(payload []byte) (ed25519.PrivateKey, error) {
	magic, body, err := openBlob(payload)
	if err != nil {
		return nil, err
	}
	if magic != cardMagic || len(body) < 1 {
		return nil, fmt.Errorf("not a recovery card")
	}
	mode, rest := body[0], body[1:]
	switch mode {
	case cardModePlain:
		if len(rest) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("card payload is malformed")
		}
		return ed25519.PrivateKey(rest), nil
	case cardModePass:
		if len(rest) < 16+24+1 {
			return nil, fmt.Errorf("card payload is malformed")
		}
		salt, nonceB, ct := rest[:16], rest[16:40], rest[40:]
		pass, err := readPassphrase("Passphrase: ")
		if err != nil {
			return nil, err
		}
		dk := argon2.IDKey([]byte(pass), salt, argonTime, argonMemory, argonThreads, 32)
		var nkey [32]byte
		copy(nkey[:], dk)
		var nonce [24]byte
		copy(nonce[:], nonceB)
		plain, ok := secretbox.Open(nil, ct, &nonce, &nkey)
		if !ok {
			return nil, fmt.Errorf("wrong passphrase (or a corrupted card)")
		}
		if len(plain) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("recovered key has the wrong size")
		}
		return ed25519.PrivateKey(plain), nil
	}
	return nil, fmt.Errorf("unknown card mode %d", mode)
}

// parseSplit reads "M-of-N" (also "MofN", "M/N", "M-N").
func parseSplit(s string) (m, n int, err error) {
	s = strings.ToLower(strings.TrimSpace(s))
	sep := ""
	for _, d := range []string{"-of-", "of", "/", "-"} {
		if strings.Contains(s, d) {
			sep = d
			break
		}
	}
	if sep == "" {
		return 0, 0, fmt.Errorf("split must look like M-of-N (e.g. 2-of-3)")
	}
	parts := strings.SplitN(s, sep, 2)
	m, e1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	n, e2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if e1 != nil || e2 != nil {
		return 0, 0, fmt.Errorf("split must look like M-of-N (e.g. 2-of-3)")
	}
	return m, n, nil
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
