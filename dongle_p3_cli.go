package main

// dongle_p3_cli.go — `--with dongle` on our own dongle firmware (task #2628).
//
//	p3sig dongle pair --unlock-out PATH [--ble AA:BB:CC:DD:EE:FF[/random]] [--usb PATH]
//	                  [--import VAULTKEY] [--root-key usb|…] [--expires 365d]
//	p3sig dongle status
//	p3sig dongle unpair [--usb PATH]      (press the dongle button first)
//	p3sig dongle rekey [--unlock-out NEW_PATH] [--new-host-key]   (task #2829,
//	                  dongle_p3_rekey.go: new unlock key, same vault key)
//
// Pairing (USB) hands the dongle this host's Noise static and a fresh 256-bit
// unlock key, then saves the PAIRING RECORD (host Noise key, pinned dongle
// static, BLE address, vault public keys) to the config dir and writes the
// unlock key to --unlock-out — a different place on purpose (the phone, or the
// vault stick): the dongle's flash is useless without it (2-of-2, CVE-2020-27211),
// and so is the record. The vault Ed25519 key is then delegated through the
// same `p3sig policy delegate` flow as the OpenSK key, so agents accept what it
// signs unchanged (it is an ordinary ssh-ed25519 key).
//
// Once a record exists, `--with dongle` signs on it over BLE (Noise_KK, unlock,
// Ed25519 in pieces); without one it falls back to the FIDO2/OpenSK path.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// p3Record is the host's half of a pairing. HostSK is a secret only in the
// sense that it authenticates this host to the dongle; it unlocks nothing.
type p3Record struct {
	HostSK       string `json:"host_noise_sk"`
	DongleStatic string `json:"dongle_static"`
	VaultEd      string `json:"vault_ed25519"`
	VaultX       string `json:"vault_x25519"`
	BLE          string `json:"ble"`
	UnlockPath   string `json:"unlock_path"`
	// A `dongle rekey` in flight (task #2829), saved BEFORE the dongle is asked:
	// the new unlock key's file, where it ends up, and the new host Noise key.
	// openP3Session falls back to them, and `dongle rekey` settles them.
	NextUnlockPath  string `json:"next_unlock_path,omitempty"`
	NextUnlockFinal string `json:"next_unlock_final,omitempty"`
	NextHostSK      string `json:"next_host_noise_sk,omitempty"`
}

// Links are variables so tests can put the firmware simulator behind them.
var (
	p3OpenUSB = OpenDongleUSB
	p3OpenBLE = OpenDongleBLE
)

func p3RecordPath() (string, error) {
	if p := os.Getenv("P3SIG_DONGLE_RECORD"); p != "" {
		return p, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "p3sig", "dongle-p3.json"), nil
}

func loadP3Record() (*p3Record, error) {
	p, err := p3RecordPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var r p3Record
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("dongle record %s: %w", p, err)
	}
	return &r, nil
}

func b64to32(s, what string) (k [32]byte, err error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != 32 {
		return k, fmt.Errorf("dongle: bad %s (want 32 bytes base64)", what)
	}
	copy(k[:], b)
	wipeBytes(b)
	return k, nil
}

func writeSecretFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// p3Pair runs USB PAIR and saves the record + unlock key BEFORE anything else
// can fail (save before test): a delegation error must not cost the pairing.
func p3Pair(usb DongleLink, ble, unlockOut string, seed *[32]byte) (*DonglePairing, error) {
	if unlockOut == "" {
		return nil, errors.New("usage: p3sig dongle pair --unlock-out PATH [--ble AA:BB:CC:DD:EE:FF[/random]] (PATH: the phone or the vault stick, not this disk's config dir)")
	}
	if ble == "" {
		// The dongle advertises only once paired, so ask it over USB first.
		_, addr, err := DongleP3Info(usb)
		if err != nil {
			return nil, err
		}
		if addr == "" {
			return nil, errors.New("this dongle firmware does not report its BLE address: pass --ble AA:BB:CC:DD:EE:FF[/random] (or update the firmware)")
		}
		ble = addr
	}
	if _, _, err := parseBLEAddr(ble); err != nil {
		return nil, err
	}
	recPath, err := p3RecordPath()
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(recPath); err == nil {
		return nil, fmt.Errorf("%s already exists — `p3sig dongle unpair` first", recPath)
	}
	if _, err := os.Stat(unlockOut); err == nil {
		return nil, fmt.Errorf("%s already exists; never overwriting an unlock key", unlockOut)
	}
	if abs, _ := filepath.Abs(unlockOut); filepath.Dir(abs) == filepath.Dir(recPath) {
		return nil, errors.New("--unlock-out must not sit next to the pairing record (that would make it 1-of-1)")
	}
	var hostSK, unlock [32]byte
	if _, err := rand.Read(hostSK[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(unlock[:]); err != nil {
		return nil, err
	}
	defer wipeBytes(unlock[:])
	defer wipeBytes(hostSK[:])
	p, err := DonglePair(usb, hostSK, unlock, seed)
	if err != nil {
		return nil, err
	}
	p.BLE = ble
	abs, _ := filepath.Abs(unlockOut)
	rec := p3Record{
		HostSK:       base64.StdEncoding.EncodeToString(hostSK[:]),
		DongleStatic: base64.StdEncoding.EncodeToString(p.DongleStatic[:]),
		VaultEd:      base64.StdEncoding.EncodeToString(p.VaultEd),
		VaultX:       base64.StdEncoding.EncodeToString(p.VaultX[:]),
		BLE:          ble,
		UnlockPath:   abs,
	}
	if err := writeSecretFile(abs, []byte(base64.StdEncoding.EncodeToString(unlock[:])+"\n")); err != nil {
		return nil, fmt.Errorf("dongle is paired but the unlock key could not be written (%v) — unpair and retry", err)
	}
	j, _ := json.MarshalIndent(rec, "", "  ")
	if err := writeSecretFile(recPath, j); err != nil {
		return nil, fmt.Errorf("dongle is paired but the record could not be written (%v) — unpair and retry", err)
	}
	return p, nil
}

// p3Signer is an ssh-ed25519 Signer whose private key never leaves the dongle.
type p3Signer struct {
	s   *DongleSession
	pub ssh.PublicKey
	ed  ed25519.PublicKey
	c   io.Closer
}

func (d *p3Signer) PublicKey() ssh.PublicKey { return d.pub }

func (d *p3Signer) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	sig, err := d.s.Sign(data)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(d.ed, data, sig) {
		return nil, errors.New("dongle: signature does not verify under the paired vault key")
	}
	return &ssh.Signature{Format: ssh.KeyAlgoED25519, Blob: sig}, nil
}

// openP3Session: BLE connect, Noise_KK with the pinned statics, unlock with
// the share from the record's unlock path (or $P3SIG_DONGLE_UNLOCK), check the
// dongle still holds the paired vault key.
func openP3Session(rec *p3Record) (*DongleSession, ed25519.PublicKey, [32]byte, io.Closer, error) {
	var x [32]byte
	hostSK, err := b64to32(rec.HostSK, "host key in the record")
	if err != nil {
		return nil, nil, x, nil, err
	}
	defer wipeBytes(hostSK[:])
	up := firstNonEmpty(os.Getenv("P3SIG_DONGLE_UNLOCK"), rec.UnlockPath)
	unlock, uerr := readUnlockKey(up)
	defer wipeBytes(unlock[:])
	if uerr == nil {
		s, ed, x, c, err := openP3SessionKeys(rec, hostSK, unlock)
		if err == nil || rec.NextUnlockPath == "" {
			return s, ed, x, c, err
		}
	} else if rec.NextUnlockPath == "" {
		return nil, nil, x, nil, uerr
	}
	// A rekey was cut short after the dongle may have switched: try the new keys.
	nk, err := readUnlockKey(rec.NextUnlockPath)
	if err != nil {
		return nil, nil, x, nil, fmt.Errorf("%v; and the pending rekey key: %w", uerr, err)
	}
	defer wipeBytes(nk[:])
	nh := hostSK
	if rec.NextHostSK != "" {
		if nh, err = b64to32(rec.NextHostSK, "pending host key in the record"); err != nil {
			return nil, nil, x, nil, err
		}
		defer wipeBytes(nh[:])
	}
	s, ed, x, c, err := openP3SessionKeys(rec, nh, nk)
	if err == nil {
		fmt.Fprintln(os.Stderr, "note: a `p3sig dongle rekey` was interrupted after the dongle switched; run it again to finish")
	}
	return s, ed, x, c, err
}

// readUnlockKey reads a base64 unlock key file (the phone's / vault stick's share).
func readUnlockKey(path string) (k [32]byte, err error) {
	ub, err := os.ReadFile(path)
	if err != nil {
		return k, fmt.Errorf("dongle unlock key (%s): %w — it lives on the phone/vault stick; mount it or set P3SIG_DONGLE_UNLOCK", path, err)
	}
	defer wipeBytes(ub)
	return b64to32(string(ub), "unlock key")
}

// openP3SessionKeys: BLE connect, Noise_KK as hostSK, UNLOCK with unlock, and
// check the dongle still holds the paired vault key.
func openP3SessionKeys(rec *p3Record, hostSK, unlock [32]byte) (*DongleSession, ed25519.PublicKey, [32]byte, io.Closer, error) {
	var x [32]byte
	static, err := b64to32(rec.DongleStatic, "dongle static in the record")
	if err != nil {
		return nil, nil, x, nil, err
	}
	link, c, err := p3OpenBLE(rec.BLE)
	if err != nil {
		return nil, nil, x, nil, err
	}
	fail := func(e error) (*DongleSession, ed25519.PublicKey, [32]byte, io.Closer, error) {
		if c != nil {
			c.Close()
		}
		return nil, nil, x, nil, e
	}
	s, err := OpenDongleSession(link, hostSK, static)
	if err != nil {
		return fail(fmt.Errorf("dongle handshake (not the paired dongle, or this host is not paired): %w", err))
	}
	if err := s.Unlock(unlock); err != nil {
		return fail(err)
	}
	ed, x, err := s.PubKeys()
	if err != nil {
		return fail(err)
	}
	if want, _ := base64.StdEncoding.DecodeString(rec.VaultEd); !ed25519.PublicKey(want).Equal(ed) {
		return fail(errors.New("dongle: vault key differs from the pairing record"))
	}
	return s, ed, x, c, nil
}

func loadP3Signer(rec *p3Record, fp string) (ssh.Signer, error) {
	s, ed, _, c, err := openP3Session(rec)
	if err != nil {
		return nil, err
	}
	pub, err := ssh.NewPublicKey(ed)
	if err != nil {
		return nil, err
	}
	// The link stays open for the command; the dongle wipes on disconnect.
	return pickSigner([]ssh.Signer{&p3Signer{s: s, pub: pub, ed: ed, c: c}}, fp)
}

func cmdDongleP3(sub string, f map[string]string) error {
	switch sub {
	case "pair":
		var seed *[32]byte
		if f["import"] != "" {
			b, err := os.ReadFile(f["import"])
			if err != nil {
				return err
			}
			raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
			wipeBytes(b)
			if err != nil || len(raw) != ed25519.PrivateKeySize {
				return errors.New("--import takes a p3sig vault key file (base64 Ed25519 private key)")
			}
			seed = new([32]byte)
			copy(seed[:], raw[:32])
			wipeBytes(raw)
			defer wipeBytes(seed[:])
		}
		usb, c, err := p3OpenUSB(f["usb"])
		if err != nil {
			return err
		}
		p, err := p3Pair(usb, f["ble"], f["unlock-out"], seed)
		c.Close()
		if err != nil {
			return err
		}
		pub, _ := ssh.NewPublicKey(p.VaultEd)
		line := authorizedKey(pub)
		fmt.Printf("paired: vault key %s, BLE %s\nunlock key written to %s (keep it off this disk)\n", ssh.FingerprintSHA256(pub), p.BLE, f["unlock-out"])
		if err := cmdPolicy("delegate", map[string]string{
			"root-key": firstNonEmpty(f["root-key"], "usb"), "device": line,
			"label": "p3sig dongle " + p.BLE, "expires": f["expires"],
			"api": f["api"], "key": f["key"], "account": f["account"],
		}); err != nil {
			return fmt.Errorf("paired, but delegation failed (%v); retry with: p3sig policy delegate --root-key usb --device '%s'", err, line)
		}
		return nil
	case "status":
		rec, err := loadP3Record()
		if err != nil {
			return fmt.Errorf("no pairing record: %w", err)
		}
		_, ed, _, c, err := openP3Session(rec)
		if err != nil {
			return err
		}
		c.Close()
		pub, _ := ssh.NewPublicKey(ed)
		fmt.Printf("dongle %s: paired, unlocks, vault key %s\n", rec.BLE, ssh.FingerprintSHA256(pub))
		return nil
	case "rekey":
		ed, path, err := p3Rekey(f["unlock-out"], f["new-host-key"] == "true", p3WaitPress)
		if err != nil {
			return err
		}
		pub, _ := ssh.NewPublicKey(ed)
		fmt.Printf("unlock key rotated: the new key is %s; the old one is refused by the dongle (its file was renamed to .old)\n"+
			"vault key unchanged: %s (delegations and sealed secrets stay valid)\n", path, ssh.FingerprintSHA256(pub))
		return nil
	case "unpair":
		usb, c, err := p3OpenUSB(f["usb"])
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "press the dongle button now (within 10 s)…")
		err = DongleUnpair(usb)
		c.Close()
		if err != nil {
			return err
		}
		if p, perr := p3RecordPath(); perr == nil {
			os.Remove(p)
		}
		fmt.Println("dongle unpaired; revoke its key with `p3sig policy revoke --device SHA256:…`")
		return nil
	}
	return errors.New("usage: p3sig dongle add | pair --unlock-out PATH [--ble ADDR] [--usb PATH] [--import VAULTKEY] | status | unpair | rekey [--unlock-out NEW_PATH] [--new-host-key]")
}
