package main

// usbvault.go — the vault/root key on a plain FAT USB stick (task #2630).
//
// Replaces VeraCrypt + scripts/make-vault-usbs.sh: the key is stored as ONE
// passphrase-wrapped file (wrap.go scheme 0x02, Argon2id + AES-GCM), so there is
// no sudo, no mounting and no container — the same on Linux, macOS and Windows.
//
//	<drive>/P3SIG/vault.p3w       wrapped 64-byte Ed25519 private key
//	<drive>/P3SIG/PUBLIC-KEY.txt  the public key + fingerprint, in the clear
//
// Rules carried over from make-vault-usbs.sh: never overwrite an existing key;
// a drive that already holds a p3sig key is resumed (unwrapped and checked), any
// other non-empty drive is refused; every copy is read back and must unwrap to
// the same key before it counts.

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	usbDir     = "P3SIG"
	usbKeyFile = "vault.p3w"
	usbPubFile = "PUBLIC-KEY.txt"
)

func usbKeyPath(drive string) string { return filepath.Join(drive, usbDir, usbKeyFile) }

// ignorable: what an OS drops on a fresh FAT stick; it does not make it "used".
var usbIgnorable = map[string]bool{
	"System Volume Information": true, ".Trashes": true, ".Spotlight-V100": true,
	".fseventsd": true, ".DS_Store": true, "._.Trashes": true, "lost+found": true, ".metadata_never_index": true,
}

// usbState: "p3sig" (holds a key — resume), "blank", or an error for a used drive.
func usbState(drive string) (string, error) {
	if _, err := os.Stat(usbKeyPath(drive)); err == nil {
		return "p3sig", nil
	}
	ents, err := os.ReadDir(drive)
	if err != nil {
		return "", err
	}
	for _, e := range ents {
		if usbIgnorable[e.Name()] {
			continue
		}
		if e.Name() == usbDir { // interrupted before the key landed: only leftovers inside
			continue
		}
		return "", fmt.Errorf("%s is not empty (has %q) — use a blank stick; p3sig never writes over other files", drive, e.Name())
	}
	return "blank", nil
}

// writeUSBKey writes the wrapped key so that an existing key is never replaced:
// temp file, fsync, then a hard link to the final name (fails if it exists).
func writeUSBKey(drive string, blob []byte, pub ssh.PublicKey) error {
	dir := filepath.Join(drive, usbDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	final := usbKeyPath(drive)
	if _, err := os.Stat(final); err == nil {
		return fmt.Errorf("%s already holds a key — not overwriting it", final)
	}
	tmp := final + ".partial"
	_ = os.Remove(tmp) // leftover from an interrupted run; never a finished key
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(blob); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Link(tmp, final)
		if err != nil && !errors.Is(err, os.ErrExist) { // FAT on some OSes has no hard links
			if _, serr := os.Stat(final); serr == nil {
				err = os.ErrExist
			} else {
				err = os.Rename(tmp, final)
			}
		}
	}
	_ = os.Remove(tmp)
	if err != nil {
		return fmt.Errorf("writing %s: %w", final, err)
	}
	fp := ssh.FingerprintSHA256(pub)
	_ = os.WriteFile(filepath.Join(dir, usbPubFile), []byte(authorizedKey(pub)+" p3sig-vault\n"+fp+"\n"), 0o644)
	return nil
}

// readUSBKey unwraps the key on drive with passphrase.
func readUSBKey(drive string, passphrase []byte) (ed25519.PrivateKey, error) {
	blob, err := os.ReadFile(usbKeyPath(drive))
	if err != nil {
		return nil, err
	}
	raw, err := UnwrapPassphrase(blob, passphrase)
	if err != nil {
		return nil, errors.New("wrong passphrase (or the key file is damaged)")
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, ErrBadFormat
	}
	return ed25519.PrivateKey(raw), nil
}

// storeOnUSB puts key on drive under passphrase and proves the copy: the file
// read back from the stick must unwrap to the same key. A drive that already
// holds a key is resumed instead: it must unwrap (with passphrase) to key.
func storeOnUSB(drive string, key ed25519.PrivateKey, passphrase []byte, p Argon2Params) error {
	st, err := usbState(drive)
	if err != nil {
		return err
	}
	if st == "blank" {
		blob, err := WrapPassphrase(key, passphrase, p)
		if err != nil {
			return err
		}
		pub, _ := ssh.NewPublicKey(key.Public())
		if err := writeUSBKey(drive, blob, pub); err != nil {
			return err
		}
	}
	got, err := readUSBKey(drive, passphrase)
	if err != nil {
		return fmt.Errorf("%s: %w", drive, err)
	}
	if !bytes.Equal(got, key) {
		return fmt.Errorf("%s holds a DIFFERENT key — not touching it; use another stick", drive)
	}
	return nil
}

// pickUSB: --drive, else the removable drives (optionally only p3sig ones),
// confirmed by the user when it was guessed.
func pickUSB(f map[string]string, in *bufio.Reader, wantKey bool, label string) (string, error) {
	if d := f["drive"]; d != "" && d != "true" {
		return d, nil
	}
	var cands []string
	for _, m := range removableMounts() {
		_, err := os.Stat(usbKeyPath(m))
		if (err == nil) == wantKey || !wantKey {
			cands = append(cands, m)
		}
	}
	if len(cands) == 0 {
		return "", fmt.Errorf("no %s found — plug it in (or name it: --drive PATH)", label)
	}
	for i, c := range cands {
		fmt.Printf("  [%d] %s\n", i+1, c)
	}
	pick := cands[0]
	if len(cands) > 1 {
		fmt.Printf("Which one is the %s? number: ", label)
		line, _ := in.ReadString('\n')
		var n int
		if _, err := fmt.Sscanf(strings.TrimSpace(line), "%d", &n); err != nil || n < 1 || n > len(cands) {
			return "", errors.New("no drive picked")
		}
		pick = cands[n-1]
	}
	if !confirm(in, fmt.Sprintf("Use %s as the %s?", pick, label)) {
		return "", errors.New("stopped")
	}
	return pick, nil
}

func newUSBPassphrase(label string) ([]byte, error) {
	if p, ok := os.LookupEnv("P3SIG_PASSPHRASE"); ok {
		return []byte(p), nil
	}
	a, _ := readPassphrase(label + " passphrase: ")
	if len(a) < 8 {
		return nil, errors.New("use a passphrase of at least 8 characters")
	}
	b, _ := readPassphrase("Again: ")
	if a != b {
		return nil, errors.New("passphrases did not match")
	}
	return []byte(a), nil
}

// loadKeyFile reads a p3sig vault key (base64 Ed25519) or an OpenSSH ed25519 key.
func loadKeyFile(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data))); err == nil && len(raw) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(raw), nil
	}
	k, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		return nil, err
	}
	if pk, ok := k.(*ed25519.PrivateKey); ok {
		return *pk, nil
	}
	return nil, fmt.Errorf("%s is not an Ed25519 key", path)
}

// cmdUSB: p3sig usb init [--from KEYFILE] [--drive PATH] | clone [--drive PATH --to PATH]
func cmdUSB(sub string, f map[string]string) error {
	in := bufio.NewReader(os.Stdin)
	switch sub {
	case "init":
		drive, err := pickUSB(f, in, false, "DAILY stick")
		if err != nil {
			return err
		}
		st, err := usbState(drive)
		if err != nil {
			return err
		}
		var key ed25519.PrivateKey
		var pass []byte
		switch {
		case st == "p3sig":
			fmt.Printf("%s already holds a p3sig key — resuming with it (nothing is overwritten).\n", drive)
			p, _ := readPassphrase("DAILY passphrase: ")
			pass = []byte(p)
			if key, err = readUSBKey(drive, pass); err != nil {
				return err
			}
		case f["from"] != "" && f["from"] != "true":
			if key, err = loadKeyFile(f["from"]); err != nil {
				return fmt.Errorf("--from: %w", err)
			}
		default:
			if _, key, err = ed25519.GenerateKey(rand.Reader); err != nil {
				return err
			}
		}
		if pass == nil {
			if pass, err = newUSBPassphrase("DAILY"); err != nil {
				return err
			}
		}
		if err := storeOnUSB(drive, key, pass, DefaultArgon2); err != nil {
			return err
		}
		pub, _ := ssh.NewPublicKey(key.Public())
		fmt.Printf("DAILY ready: %s\n", ssh.FingerprintSHA256(pub))
		fmt.Println("\nNow unplug DAILY, plug the SAFE stick and press Enter (Ctrl-C to do it later with `p3sig usb clone`).")
		if _, err := in.ReadString('\n'); err != nil {
			return nil
		}
		return cloneTo(f, in, key)
	case "clone":
		src, err := pickUSB(map[string]string{"drive": f["drive"]}, in, true, "stick to copy FROM")
		if err != nil {
			return err
		}
		p, _ := readPassphrase("Its passphrase: ")
		key, err := readUSBKey(src, []byte(p))
		if err != nil {
			return err
		}
		fmt.Println("Unplug it, plug the stick to copy TO and press Enter.")
		in.ReadString('\n')
		return cloneTo(map[string]string{"drive": f["to"]}, in, key)
	}
	return errors.New("usage: p3sig usb init [--from KEYFILE] [--drive PATH] | p3sig usb clone [--drive FROM] [--to PATH]")
}

func cloneTo(f map[string]string, in *bufio.Reader, key ed25519.PrivateKey) error {
	drive, err := pickUSB(f, in, false, "SAFE stick")
	if err != nil {
		return err
	}
	pass, err := newUSBPassphrase("SAFE")
	if err != nil {
		return err
	}
	if err := storeOnUSB(drive, key, pass, DefaultArgon2); err != nil {
		return err
	}
	pub, _ := ssh.NewPublicKey(key.Public())
	fp := ssh.FingerprintSHA256(pub)
	fmt.Printf("SAFE ready and verified: %s (same key as DAILY). Keep it somewhere else.\n\n"+
		"Publish it as your policy root (once):  p3sig policy root --root-key usb\n"+
		"Pin it on every machine:               p3sig agent pull --root %s\n", fp, fp)
	return nil
}

// usbSigner is the `usb` / `usb:PATH` key source: finds the stick holding a
// p3sig key and asks for its passphrase.
func usbSigner(spec string) (ssh.Signer, error) {
	f := map[string]string{"drive": strings.TrimPrefix(strings.TrimPrefix(spec, "usb"), ":")}
	drive, err := pickUSB(f, bufio.NewReader(os.Stdin), true, "vault stick")
	if err != nil {
		return nil, err
	}
	p, _ := readPassphrase("Vault stick passphrase: ")
	key, err := readUSBKey(drive, []byte(p))
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(key)
}
