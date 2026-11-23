package main

// dongle_p3_rekey.go — `p3sig dongle rekey` (task #2829): rotate the dongle's
// 256-bit unlock key (the 2-of-2 share that decrypts the vault key in its
// flash) and, with --new-host-key, this host's Noise static key, WITHOUT
// re-pairing. The vault key stays the same, so its delegation and every secret
// sealed to it stay valid. (UNPAIR + PAIR would make a new vault key.)
//
//	p3sig dongle rekey [--unlock-out NEW_PATH] [--new-host-key]
//
// Save before commit, in this order:
//  1. the new unlock key is written (NEW_PATH, or <current>.new) and the pairing
//     record notes the rekey in flight (next_unlock_path, next_host_noise_sk);
//  2. the dongle is asked (REKEY inside an UNLOCKed session + a button press);
//  3. a fresh session + UNLOCK under the new key confirms it, and the old key
//     must now be refused;
//  4. only then the old key file is retired (renamed to .old, never deleted) and
//     the record updated.
//
// Any failure or uncertain answer at 2 is settled by asking the dongle which
// key it takes now (new first, then old), so a dropped link or a power cut never
// leaves the host without the key the dongle wants. Running `dongle rekey`
// again while a rekey is in flight finishes or rolls back that one.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// p3WaitPress: prompt once, then poll the dongle every second for 30 s.
func p3WaitPress(attempt int) bool {
	if attempt == 0 {
		fmt.Fprintln(os.Stderr, "press the dongle button now (it confirms the rekey)…")
	}
	if attempt >= 30 {
		return false
	}
	time.Sleep(time.Second)
	return true
}

// saveP3Record writes the record atomically (temp file + rename).
func saveP3Record(path string, rec *p3Record) error {
	j, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	os.Remove(tmp)
	if err := writeSecretFile(tmp, j); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// retireKeyFile renames a key file to .old (or .old.N), never deleting it.
func retireKeyFile(path, suffix string) (string, error) {
	dst := path + suffix
	for i := 2; ; i++ {
		if _, err := os.Lstat(dst); errors.Is(err, os.ErrNotExist) {
			break
		}
		dst = fmt.Sprintf("%s%s.%d", path, suffix, i)
	}
	return dst, os.Rename(path, dst)
}

func notNextToRecord(path, recPath string) error {
	if abs, _ := filepath.Abs(path); filepath.Dir(abs) == filepath.Dir(recPath) {
		return fmt.Errorf("%s must not sit next to the pairing record (that would make it 1-of-1)", path)
	}
	return nil
}

// p3Rekey returns the (unchanged) vault key and where the new unlock key is.
func p3Rekey(unlockOut string, newHost bool, wait func(int) bool) (ed25519.PublicKey, string, error) {
	recPath, err := p3RecordPath()
	if err != nil {
		return nil, "", err
	}
	rec, err := loadP3Record()
	if err != nil {
		return nil, "", fmt.Errorf("no pairing record: %w", err)
	}
	if rec.NextUnlockPath != "" {
		fmt.Fprintln(os.Stderr, "a rekey is already in flight: settling it first (start a new one afterwards)")
		return p3RekeySettle(rec, recPath)
	}

	oldPath, _ := filepath.Abs(firstNonEmpty(os.Getenv("P3SIG_DONGLE_UNLOCK"), rec.UnlockPath))
	oldKey, err := readUnlockKey(oldPath)
	if err != nil {
		return nil, "", err
	}
	defer wipeBytes(oldKey[:])
	hostSK, err := b64to32(rec.HostSK, "host key in the record")
	if err != nil {
		return nil, "", err
	}
	defer wipeBytes(hostSK[:])

	newPath, final := oldPath+".new", oldPath
	if unlockOut != "" {
		newPath, _ = filepath.Abs(unlockOut)
		final = newPath
	}
	if err := notNextToRecord(newPath, recPath); err != nil {
		return nil, "", fmt.Errorf("--unlock-out: %w", err)
	}
	if _, err := os.Lstat(newPath); err == nil {
		return nil, "", fmt.Errorf("%s already exists; never overwriting an unlock key", newPath)
	}

	// 1. Save before commit: the new key on disk, the rekey noted in the record.
	var newKey, newHostSK [32]byte
	if _, err := rand.Read(newKey[:]); err != nil {
		return nil, "", err
	}
	defer wipeBytes(newKey[:])
	var newHostPub []byte
	if newHost {
		if _, err := rand.Read(newHostSK[:]); err != nil {
			return nil, "", err
		}
		defer wipeBytes(newHostSK[:])
		newHostPub = pubOf(newHostSK)
	}
	if err := writeSecretFile(newPath, []byte(base64.StdEncoding.EncodeToString(newKey[:])+"\n")); err != nil {
		return nil, "", fmt.Errorf("writing the new unlock key: %w (nothing changed)", err)
	}
	rec.UnlockPath = oldPath
	rec.NextUnlockPath, rec.NextUnlockFinal = newPath, final
	if newHost {
		rec.NextHostSK = base64.StdEncoding.EncodeToString(newHostSK[:])
	}
	if err := saveP3Record(recPath, rec); err != nil {
		os.Rename(newPath, newPath+".unused")
		return nil, "", fmt.Errorf("saving the pairing record: %w (nothing changed on the dongle)", err)
	}

	// 2. Ask the dongle: unlocked with the current key, then REKEY + a press.
	s, _, _, c, err := openP3SessionKeys(rec, hostSK, oldKey)
	if err != nil {
		// The dongle was never asked: undo the host side.
		rerr := p3RekeyRollback(rec, recPath)
		return nil, "", errors.Join(fmt.Errorf("rekey not started: %w", err), rerr)
	}
	rkErr := s.Rekey(newKey, newHostPub, wait)
	c.Close()
	if rkErr != nil {
		fmt.Fprintf(os.Stderr, "REKEY answered %v; checking which key the dongle takes now…\n", rkErr)
	}
	// 3 + 4. Settle: confirm the new key (or find the old one still in use).
	ed, path, err := p3RekeySettle(rec, recPath)
	if err != nil && rkErr != nil {
		return nil, "", fmt.Errorf("%w (REKEY: %v)", err, rkErr)
	}
	return ed, path, err
}

// p3RekeySettle asks the dongle which key it takes after a rekey that may or
// may not have committed, and makes the host side match.
func p3RekeySettle(rec *p3Record, recPath string) (ed25519.PublicKey, string, error) {
	oldKey, oldErr := readUnlockKey(rec.UnlockPath)
	defer wipeBytes(oldKey[:])
	newKey, err := readUnlockKey(rec.NextUnlockPath)
	if err != nil {
		return nil, "", fmt.Errorf("the pending rekey's new key is unreadable: %w — the record still names it; restore that file and run `p3sig dongle rekey` again", err)
	}
	defer wipeBytes(newKey[:])
	hostSK, err := b64to32(rec.HostSK, "host key in the record")
	if err != nil {
		return nil, "", err
	}
	defer wipeBytes(hostSK[:])
	newHostSK := hostSK
	if rec.NextHostSK != "" {
		if newHostSK, err = b64to32(rec.NextHostSK, "pending host key in the record"); err != nil {
			return nil, "", err
		}
		defer wipeBytes(newHostSK[:])
	}

	// The new keys: a fresh session (the dongle locked itself after REKEY).
	_, ed, _, c, newErr := openP3SessionKeys(rec, newHostSK, newKey)
	if newErr == nil {
		c.Close()
		// The old key must be refused now (the old host pin too, if it changed).
		if oldErr == nil {
			if _, _, _, c2, err := openP3SessionKeys(rec, hostSK, oldKey); err == nil {
				c2.Close()
				return nil, "", errors.New("dongle: the new unlock key works but the old one still unlocks too — not finishing; both key files kept")
			}
		}
		final := firstNonEmpty(rec.NextUnlockFinal, rec.NextUnlockPath)
		if err := p3RekeyFinish(rec, recPath); err != nil {
			return nil, "", err
		}
		return ed, final, nil
	}
	if oldErr == nil {
		if _, _, _, c2, err := openP3SessionKeys(rec, hostSK, oldKey); err == nil {
			c2.Close()
			rerr := p3RekeyRollback(rec, recPath)
			return nil, "", errors.Join(errors.New("rekey did not take effect: the dongle still takes the OLD unlock key (unchanged, still in use)"), rerr)
		}
	}
	return nil, "", fmt.Errorf("the dongle took neither key just now (new: %v) — nothing retired; both key files and the pending rekey are kept. Check the dongle is in range and run `p3sig dongle rekey` again", newErr)
}

// p3RekeyFinish: the dongle takes the new key; retire the old file (.old),
// move the new one into place and update the record (crash-safe order: each
// step leaves a record that openP3Session can still use).
func p3RekeyFinish(rec *p3Record, recPath string) error {
	if _, err := os.Lstat(rec.UnlockPath); err == nil {
		if _, err := retireKeyFile(rec.UnlockPath, ".old"); err != nil {
			return fmt.Errorf("dongle switched, but retiring the old key file failed (%v); the record still points at the pending key", err)
		}
	}
	final := firstNonEmpty(rec.NextUnlockFinal, rec.NextUnlockPath)
	if final != rec.NextUnlockPath {
		if err := os.Rename(rec.NextUnlockPath, final); err != nil {
			return fmt.Errorf("dongle switched, but moving the new key to %s failed (%v); it is at %s", final, err, rec.NextUnlockPath)
		}
	}
	rec.UnlockPath = final
	if rec.NextHostSK != "" {
		rec.HostSK = rec.NextHostSK
	}
	rec.NextUnlockPath, rec.NextUnlockFinal, rec.NextHostSK = "", "", ""
	return saveP3Record(recPath, rec)
}

// p3RekeyRollback: the dongle kept the old key; set the unused new key file
// aside (never deleted) and clear the pending fields.
func p3RekeyRollback(rec *p3Record, recPath string) error {
	var errs []error
	if _, err := os.Lstat(rec.NextUnlockPath); err == nil {
		if _, err := retireKeyFile(rec.NextUnlockPath, ".unused"); err != nil {
			errs = append(errs, err)
		}
	}
	rec.NextUnlockPath, rec.NextUnlockFinal, rec.NextHostSK = "", "", ""
	if err := saveP3Record(recPath, rec); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
