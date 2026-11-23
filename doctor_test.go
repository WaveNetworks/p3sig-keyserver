package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// doctorFixture is a fake p3sig account (task #2830): vault keys, sealed copies,
// re-seal work and policy status, answering only the four read-only actions
// doctor may call. Any other action fails the test (doctor must never write).
type doctorFixture struct {
	t        *testing.T
	keys     []ed25519.PrivateKey // registered on the account, in order
	labels   []string
	secrets  int
	missing  map[int]int // key index → secrets with no copy for it
	badCopy  bool        // copies addressed to key 0 are sealed to someone else
	rootFP   string
	delegs   []map[string]any
	machines []map[string]any
	calls    []string
}

func docKey(t *testing.T) ed25519.PrivateKey {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pubB64(k ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey))
}

func keyFPOf(k ed25519.PrivateKey) string { return edFP(k.Public().(ed25519.PublicKey)) }

func (fx *doctorFixture) call(k ed25519.PrivateKey) policyCall {
	return func(action string, extra url.Values, v any) error {
		fx.calls = append(fx.calls, action)
		idx := -1
		for i, r := range fx.keys {
			if r.Equal(k) {
				idx = i
			}
		}
		if idx < 0 {
			return errors.New("Unknown key.")
		}
		var out any
		switch action {
		case "getMyVaultKeys":
			var ks []map[string]string
			for i, r := range fx.keys {
				ks = append(ks, map[string]string{"key_id": "k" + string(rune('0'+i)), "public_key": pubB64(r), "label": fx.labels[i]})
			}
			out = map[string]any{"keys": ks, "count": len(ks)}
		case "getMySecrets":
			var ss []map[string]string
			for s := 0; s < fx.secrets; s++ {
				to := k
				if fx.badCopy && idx == 0 {
					to = docKey(fx.t)
				}
				c, err := sealSecretFor("value-not-printed", secretMeta{Label: "s"}, "k", pubB64(to))
				if err != nil {
					return err
				}
				ss = append(ss, map[string]string{"secret_id": "s" + string(rune('0'+s)), "encrypted_data": c.Enc, "encrypted_meta": c.Meta})
			}
			out = map[string]any{"secrets": ss}
		case "getResealWork":
			var work []map[string]any
			for ki, n := range fx.missing {
				for s := 0; s < n; s++ {
					work = append(work, map[string]any{"secret_id": "m", "missing": []map[string]string{{"key_id": "k" + string(rune('0'+ki)), "public_key": pubB64(fx.keys[ki])}}})
				}
			}
			out = map[string]any{"work": work}
		case "getPolicyStatus":
			out = map[string]any{"account": "user:1", "root_fp": fx.rootFP, "delegations": fx.delegs, "machines": fx.machines}
		default:
			fx.t.Fatalf("doctor called %s — it must stay read-only", action)
		}
		b, _ := json.Marshal(out)
		return json.Unmarshal(b, v)
	}
}

// healthy: one key on DAILY + SAFE, registered, root, dongle delegated, machine pinned.
func healthy(t *testing.T) (*doctorFixture, doctorInput, ed25519.PrivateKey) {
	k := docKey(t)
	dongle := docKey(t)
	fx := &doctorFixture{t: t, keys: []ed25519.PrivateKey{k}, labels: []string{"Vault USB"}, secrets: 2, missing: map[int]int{},
		rootFP: keyFPOf(k),
		delegs: []map[string]any{{"device_fp": keyFPOf(dongle), "label": "p3sig dongle", "expires": time.Now().Add(240 * time.Hour).Unix()}},
		machines: []map[string]any{{"machine_id": "m1", "name": "web1", "version": 3, "krl_expires": time.Now().Add(48 * time.Hour).Unix(),
			"agent": map[string]any{"status": "applied", "reported": "2026-11-23 10:00:00"}}}}
	in := doctorInput{
		Sticks: []doctorStick{
			{Drive: "/media/P3SIG-DAILY", Label: "DAILY", Format: "usb", FP: keyFPOf(k), Key: k},
			{Drive: "/media/P3SIG-SAFE", Label: "SAFE", Format: "usb", FP: keyFPOf(k), Key: k},
		},
		Call: fx.call,
		Dongle: doctorDongle{Record: true, BLE: "AA:BB", VaultFP: keyFPOf(dongle), UnlockFile: true, Probed: true, Unlocks: true,
			ProbedFP: keyFPOf(dongle)},
		Present: map[string]string{keyFPOf(dongle): "paired p3sig dongle"},
		Now:     time.Now(),
	}
	return fx, in, k
}

func hasCheck(r doctorReport, status, contains string) bool {
	for _, c := range r.Checks {
		if c.Status == status && strings.Contains(c.Text, contains) {
			return true
		}
	}
	return false
}

func hasFix(r doctorReport, contains string) bool {
	for _, f := range r.Fixes {
		if strings.Contains(f, contains) {
			return true
		}
	}
	return false
}

func TestDoctorAllPass(t *testing.T) {
	fx, in, _ := healthy(t)
	r := runDoctor(in)
	if !r.SticksMatch || !r.AllPass || len(r.Fixes) != 0 {
		var b bytes.Buffer
		printDoctor(&b, r)
		t.Fatalf("want all pass:\n%s", b.String())
	}
	for _, want := range []string{"DAILY and SAFE hold the SAME key", "opened a real sealed secret", "IS the plugged stick", "delegated by the root", "pinned to the root"} {
		if !hasCheck(r, "PASS", want) {
			t.Errorf("missing PASS %q", want)
		}
	}
	var b bytes.Buffer
	printDoctor(&b, r)
	if !strings.HasPrefix(b.String(), "Your sticks match your account: yes") || strings.Contains(b.String(), "value-not-printed") {
		t.Fatalf("summary/leak:\n%s", b.String())
	}
	_ = fx
}

func TestDoctorStickKeyNotOnAccount(t *testing.T) {
	fx, in, _ := healthy(t)
	other := docKey(t)
	fx.keys = []ed25519.PrivateKey{other} // the account knows only another key
	fx.rootFP = keyFPOf(other)
	r := runDoctor(in)
	if r.SticksMatch || !hasCheck(r, "FAIL", "the account refuses") || !hasFix(r, "p3sig usb register --drive /media/P3SIG-DAILY") {
		t.Fatalf("%+v", r.Checks)
	}
}

func TestDoctorOrphanAccountKey(t *testing.T) {
	fx, in, _ := healthy(t)
	fx.keys = append(fx.keys, docKey(t))
	fx.labels = append(fx.labels, "old VeraCrypt key")
	r := runDoctor(in)
	if !hasCheck(r, "WARN", `"old VeraCrypt key"`) || !hasFix(r, "Vault › Keys") || r.AllPass {
		t.Fatalf("%+v", r.Checks)
	}
	if !r.SticksMatch {
		t.Fatal("an extra account key alone does not mean the sticks mismatch")
	}
}

func TestDoctorDailySafeDiffer(t *testing.T) {
	fx, in, _ := healthy(t)
	safe := docKey(t)
	fx.keys = append(fx.keys, safe)
	fx.labels = append(fx.labels, "safe")
	in.Sticks[1].Key, in.Sticks[1].FP = safe, keyFPOf(safe)
	r := runDoctor(in)
	if r.SticksMatch || !hasCheck(r, "FAIL", "hold DIFFERENT keys") || !hasFix(r, "p3sig usb clone") {
		t.Fatalf("%+v", r.Checks)
	}
}

func TestDoctorMissingReseal(t *testing.T) {
	fx, in, _ := healthy(t)
	fx.missing[0] = 3
	r := runDoctor(in)
	if r.SticksMatch || !hasCheck(r, "FAIL", "3 secret(s) have NO copy") || !hasFix(r, "Seal now") {
		t.Fatalf("%+v", r.Checks)
	}
}

func TestDoctorCopyDoesNotOpen(t *testing.T) {
	fx, in, _ := healthy(t)
	fx.badCopy = true
	r := runDoctor(in)
	if r.SticksMatch || !hasCheck(r, "FAIL", "does not open with it") {
		t.Fatalf("%+v", r.Checks)
	}
}

func TestDoctorRootNotOnStick(t *testing.T) {
	fx, in, _ := healthy(t)
	fx.rootFP = "SHA256:zm1D8lhmOtherRoot"
	r := runDoctor(in)
	if !hasCheck(r, "WARN", "is not on any plugged stick") || r.RootFP != fx.rootFP {
		t.Fatalf("%+v", r.Checks)
	}
	fx.rootFP = ""
	if r = runDoctor(in); !hasFix(r, "p3sig policy root --root-key usb") {
		t.Fatalf("%+v", r.Checks)
	}
}

func TestDoctorDeadDelegation(t *testing.T) {
	fx, in, _ := healthy(t)
	fx.delegs = append(fx.delegs, map[string]any{"device_fp": "SHA256:mOWSNNbjOpenSK", "label": "OpenSK", "expires": 0})
	r := runDoctor(in)
	if !hasCheck(r, "WARN", "SHA256:mOWSNNbjOpenSK") || !hasFix(r, "p3sig policy revoke --root-key usb --device SHA256:mOWSNNbjOpenSK") {
		t.Fatalf("%+v", r.Checks)
	}
}

func TestDoctorDongleNotDelegated(t *testing.T) {
	fx, in, _ := healthy(t)
	fx.delegs = nil
	in.Dongle.VaultKeyLine = "ssh-ed25519 AAAAtest"
	r := runDoctor(in)
	if !hasCheck(r, "FAIL", "NOT delegated by the root") || !hasFix(r, "p3sig policy delegate --root-key usb --device 'ssh-ed25519 AAAAtest'") {
		t.Fatalf("%+v", r.Checks)
	}
}

func TestDoctorDongleProblems(t *testing.T) {
	_, in, _ := healthy(t)
	in.Dongle = doctorDongle{}
	if r := runDoctor(in); !hasCheck(r, "WARN", "no dongle is paired") || !hasFix(r, "p3sig dongle pair") {
		t.Fatalf("%+v", r.Checks)
	}
	_, in, _ = healthy(t)
	in.Dongle.Unlocks, in.Dongle.ProbeError = false, "BLE: no such device"
	if r := runDoctor(in); !hasCheck(r, "FAIL", "did not unlock over BLE") {
		t.Fatalf("%+v", r.Checks)
	}
}

func TestDoctorMachines(t *testing.T) {
	fx, in, k := healthy(t)
	fx.machines = []map[string]any{
		{"machine_id": "m2", "name": "unsigned-box", "version": 0},
		{"machine_id": "m3", "name": "refusing-box", "version": 2, "agent": map[string]any{"status": "refused", "detail": "signed KRL has expired"}},
		{"machine_id": "m4", "name": "quiet-box", "version": 2},
	}
	r := runDoctor(in)
	if !hasCheck(r, "FAIL", "unsigned-box: no signed policy") || !hasCheck(r, "FAIL", "refusing-box: agent refused") ||
		!hasCheck(r, "WARN", "quiet-box") || !hasFix(r, "p3sig agent pull --root "+keyFPOf(k)) {
		t.Fatalf("%+v", r.Checks)
	}
}

func TestDoctorVeraCryptLockedAndNoSticks(t *testing.T) {
	_, in, _ := healthy(t)
	in.Sticks = []doctorStick{{Drive: "/media/P3SIG-DAILY", Label: "DAILY", Format: "veracrypt", FP: "SHA256:x"}}
	r := runDoctor(in)
	if r.SticksMatch || !hasCheck(r, "FAIL", "old VeraCrypt format") || !hasFix(r, "p3sig usb migrate --drive /media/P3SIG-DAILY") {
		t.Fatalf("%+v", r.Checks)
	}
	in.Sticks = nil
	if r = runDoctor(in); r.SticksMatch || !hasCheck(r, "FAIL", "no p3sig stick") {
		t.Fatalf("%+v", r.Checks)
	}
}

// TestDoctorFindAndUnlockSticks: both on-disk formats are found and unlocked; a
// wrong passphrase is reported, never fatal; nothing is written to the sticks.
func TestDoctorFindAndUnlockSticks(t *testing.T) {
	root := t.TempDir()
	k := docKey(t)
	daily := filepath.Join(root, "P3SIG-DAILY")
	safe := filepath.Join(root, "P3SIG-SAFE")
	vc := filepath.Join(root, "OLDSTICK")
	for _, d := range []string{daily, safe, vc, filepath.Join(root, "random")} {
		os.MkdirAll(d, 0o700)
	}
	fast := Argon2Params{MemKiB: 64, Time: 1, Par: 1}
	if err := storeOnUSB(daily, k, []byte("daily-pass"), fast); err != nil {
		t.Fatal(err)
	}
	if err := storeOnUSB(safe, k, []byte("safe-pass!"), fast); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(vc, vcContainerFile), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(vc, usbPubFile), []byte("p3sig vault + policy-root PUBLIC key (safe to share):\n"+pubB64(k)+"\n"), 0o644)
	vcKey := filepath.Join(root, "open.key")
	os.WriteFile(vcKey, []byte(base64.StdEncoding.EncodeToString(k)), 0o600)

	f := map[string]string{"drive": strings.Join([]string{daily, safe, vc, filepath.Join(root, "random")}, ","), "vc-key": vcKey}
	st := findSticks(f)
	if len(st) != 3 || st[0].Label != "DAILY" || st[1].Label != "SAFE" || st[2].Format != "veracrypt" || st[2].FP != keyFPOf(k) {
		t.Fatalf("found %+v", st)
	}
	answers := map[string]string{"DAILY": "daily-pass", "SAFE": "wrong-pass"}
	unlockSticks(st, f, func(p string) (string, error) { return answers[strings.SplitN(p, " ", 2)[0]], nil })
	if st[0].Key == nil || !st[0].Key.Equal(k) || st[0].FP != keyFPOf(k) {
		t.Fatalf("DAILY not unlocked: %+v", st[0])
	}
	if st[1].Key != nil || !strings.Contains(st[1].Note, "wrong passphrase") {
		t.Fatalf("SAFE: %+v", st[1])
	}
	if st[2].Key == nil || !st[2].Key.Equal(k) {
		t.Fatalf("VeraCrypt open key not used: %+v", st[2])
	}
}
