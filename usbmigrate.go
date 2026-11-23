package main

// usbmigrate.go — `p3sig usb migrate` (task #2831): turn an old VeraCrypt p3sig
// stick (p3sig-vault.hc + PUBLIC-KEY.txt, made by make-vault-usbs.sh on 10-27)
// into the passphrase-wrapped usb: format ON THE SAME STICK, with no VeraCrypt,
// no sudo and no second stick.
//
//	p3sig usb migrate [--drive PATH] [--key-file PATH]   one stick (run for DAILY, then SAFE)
//	p3sig usb migrate --finish [--drive A,B]              remove the .hc once both are migrated
//	                                                      and the doctor checks pass
//
// The container is read in memory (veracrypt.go), never mounted or changed. The
// key must match the stick's PUBLIC-KEY.txt before anything is written; the new
// key file is read back and must unwrap to the same key. The .hc stays until
// --finish, which removes it only when both sticks hold the key in the new
// format and doctor's stick/account/secret checks pass.

import (
	"bufio"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// What an old VeraCrypt stick holds at its root; migrate writes next to them.
var vcLegacyFiles = map[string]bool{vcContainerFile: true, usbPubFile: true}

func legacyContainer(drive string) string { return filepath.Join(drive, vcContainerFile) }

// pickLegacyUSB: --drive, else the one plugged stick holding p3sig-vault.hc.
func pickLegacyUSB(f map[string]string, in *bufio.Reader) (string, error) {
	if d := f["drive"]; d != "" && d != "true" {
		if _, err := os.Stat(legacyContainer(d)); err != nil {
			return "", fmt.Errorf("%s has no %s — nothing to migrate", d, vcContainerFile)
		}
		return d, nil
	}
	var cands []string
	for _, m := range removableMounts() {
		if _, err := os.Stat(legacyContainer(m)); err == nil {
			cands = append(cands, m)
		}
	}
	switch len(cands) {
	case 0:
		return "", errors.New("no VeraCrypt p3sig stick (p3sig-vault.hc) is plugged in — plug it in, or name it: --drive PATH")
	case 1:
		return cands[0], nil
	}
	for i, c := range cands {
		fmt.Printf("  [%d] %s\n", i+1, c)
	}
	fmt.Print("Which stick? number: ")
	line, _ := in.ReadString('\n')
	var n int
	if _, err := fmt.Sscanf(strings.TrimSpace(line), "%d", &n); err != nil || n < 1 || n > len(cands) {
		return "", errors.New("no stick picked")
	}
	return cands[n-1], nil
}

// legacyPublicFP: the fingerprint written in the clear next to the container.
func legacyPublicFP(drive string) string {
	b, err := os.ReadFile(filepath.Join(drive, usbPubFile))
	if err != nil {
		return ""
	}
	_, fp := pubFromText(b)
	return fp
}

func cmdUSBMigrate(f map[string]string, in *bufio.Reader) error {
	if f["finish"] == "true" {
		return cmdUSBMigrateFinish(f)
	}
	drive, err := pickLegacyUSB(f, in)
	if err != nil {
		return err
	}
	label := firstNonEmpty(stickLabel(drive), "stick")
	wantFP := legacyPublicFP(drive)

	if _, err := os.Stat(usbKeyPath(drive)); err == nil { // already done: just prove it
		p, _ := readPassphrase(label + " p3sig passphrase: ")
		key, err := readUSBKey(drive, []byte(p))
		if err != nil {
			return err
		}
		defer wipeBytes(key)
		if fp := edFP(key.Public().(ed25519.PublicKey)); wantFP != "" && fp != wantFP {
			return fmt.Errorf("%s holds %s in the new format but PUBLIC-KEY.txt says %s — run `p3sig doctor`", drive, fp, wantFP)
		}
		fmt.Printf("%s is already migrated (%s). When both sticks are: p3sig usb migrate --finish\n", label, wantFP)
		return nil
	}

	var key ed25519.PrivateKey
	var vcPass []byte
	defer func() { wipeBytes(key); wipeBytes(vcPass) }()
	if kf := f["key-file"]; kf != "" && kf != "true" {
		if key, err = loadKeyFile(kf); err != nil {
			return fmt.Errorf("--key-file: %w", err)
		}
	} else {
		fmt.Printf("Opening %s on %s in memory (no VeraCrypt, no mount, nothing changes on the stick).\n", vcContainerFile, drive)
		for try := 0; try < 3; try++ {
			p, _ := readPassphrase(label + " VeraCrypt passphrase: ")
			vcPass = []byte(p)
			key, err = readVCKey(legacyContainer(drive), vcPass)
			if err == nil {
				break
			}
			if !errors.Is(err, errVCPassphrase) {
				return fmt.Errorf("%v\nIf it opens in VeraCrypt itself, open it there and run: p3sig usb migrate --drive %s --key-file <mounted>/p3sig-root.key", err, drive)
			}
			fmt.Println("That passphrase did not open it.")
		}
		if err != nil {
			return err
		}
	}
	fp := edFP(key.Public().(ed25519.PublicKey))
	switch {
	case wantFP == "":
		fmt.Printf("warning: %s has no readable PUBLIC-KEY.txt to compare with; the key inside is %s\n", drive, fp)
	case fp != wantFP:
		return fmt.Errorf("the key inside is %s but the stick's PUBLIC-KEY.txt says %s — not migrating this stick", fp, wantFP)
	default:
		fmt.Printf("Key inside matches PUBLIC-KEY.txt: %s\n", fp)
	}

	var pass []byte
	if p, ok := os.LookupEnv("P3SIG_PASSPHRASE"); ok {
		pass = []byte(p)
	} else if vcPass != nil && len(vcPass) >= 8 && confirm(in, "Keep the same passphrase for the new format?") {
		pass = append([]byte(nil), vcPass...)
	} else if pass, err = newUSBPassphrase("New " + label); err != nil {
		return err
	}
	defer wipeBytes(pass)
	if err := storeOnUSBAllow(drive, key, pass, DefaultArgon2, vcLegacyFiles); err != nil {
		return err
	}
	fmt.Printf("%s migrated and verified: %s now holds the key in the p3sig format (read back, unwraps to %s).\n"+
		"The VeraCrypt container is still on the stick; nothing was deleted.\n\n"+
		"Next: plug the other stick and run `p3sig usb migrate` again (or `p3sig usb clone` onto a blank one).\n"+
		"When both are done and `p3sig doctor` passes: p3sig usb migrate --finish\n", label, usbKeyPath(drive), fp)
	return nil
}

// usbMigrateFinishCheck: what --finish insists on before removing any .hc —
// at least two sticks in the new format, all unlocked, one key, and doctor's
// stick/account/secret checks passing. Returns the containers to remove.
func usbMigrateFinishCheck(sticks []doctorStick, call func(ed25519.PrivateKey) policyCall, now time.Time) ([]string, doctorReport, error) {
	var hcs []string
	newFmt := 0
	for _, s := range sticks {
		if s.Format != "usb" {
			return nil, doctorReport{}, fmt.Errorf("%s is not migrated yet: p3sig usb migrate --drive %s", stickName(s), s.Drive)
		}
		newFmt++
		if s.Key == nil {
			return nil, doctorReport{}, fmt.Errorf("%s did not unlock (%s)", stickName(s), firstNonEmpty(s.Note, "no passphrase"))
		}
		if _, err := os.Stat(legacyContainer(s.Drive)); err == nil {
			hcs = append(hcs, legacyContainer(s.Drive))
		}
	}
	if newFmt < 2 {
		return nil, doctorReport{}, errors.New("plug in BOTH sticks (DAILY and SAFE): --finish removes the old containers only when both hold the key in the new format")
	}
	r := runDoctor(doctorInput{Sticks: sticks, Call: call, Now: now})
	if !r.SticksMatch {
		return nil, r, errors.New("the doctor checks below do not pass yet — nothing was removed")
	}
	if len(hcs) == 0 {
		return nil, r, errors.New("no VeraCrypt container left on the plugged sticks — nothing to finish")
	}
	return hcs, r, nil
}

func cmdUSBMigrateFinish(f map[string]string) error {
	apiBase := firstNonEmpty(f["url"], os.Getenv("P3SIG_URL"), defaultAPI)
	sticks := findSticks(f)
	ask := func(prompt string) (string, error) {
		if p, ok := os.LookupEnv("P3SIG_PASSPHRASE"); ok {
			return p, nil
		}
		return readPassphrase(prompt)
	}
	unlockSticks(sticks, f, ask)
	call := func(k ed25519.PrivateKey) policyCall {
		return func(action string, extra url.Values, v any) error {
			return userRequestKey(apiBase, action, k, extra, v)
		}
	}
	hcs, r, err := usbMigrateFinishCheck(sticks, call, time.Now())
	for i := range sticks {
		wipeBytes(sticks[i].Key)
	}
	if err != nil {
		if len(r.Checks) > 0 {
			printDoctor(os.Stdout, r)
			fmt.Println()
		}
		return err
	}
	for _, hc := range hcs {
		if err := os.Remove(hc); err != nil {
			return err
		}
		fmt.Printf("removed %s\n", hc)
	}
	fmt.Println("Done: both sticks hold the key in the p3sig format only. Unlock with --key usb / --root-key usb.")
	return nil
}
