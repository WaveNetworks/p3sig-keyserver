package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Cross-check with the p3sig server (WaveNetworks/p3sig tests/signed_policy_test.php).
// Opt-in: P3SIG_XCHECK=1 go test -run TestZZEmit; php …/signed_policy_test.php; P3SIG_XCHECK=1 go test -run TestZZVerify
func TestZZEmit(t *testing.T) {
	if os.Getenv("P3SIG_XCHECK") == "" {
		t.Skip("set P3SIG_XCHECK=1")
	}
	os.MkdirAll("/tmp/p3pol", 0o755)
	_, rk, _ := ed25519.GenerateKey(rand.Reader)
	root, _ := ssh.NewSignerFromKey(rk)
	_, dk, _ := ed25519.GenerateKey(rand.Reader)
	dev, _ := ssh.NewSignerFromKey(dk)
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	chip, _ := ssh.NewSignerFromKey(ek)
	now := time.Now().Unix()
	d1, _ := signDelegation(root, Delegation{Account: "user:1", DeviceKey: authorizedKey(dev.PublicKey()), Label: "dongle", Issued: now})
	d2, _ := signDelegation(root, Delegation{Account: "user:1", DeviceKey: authorizedKey(chip.PublicKey()), Label: "chip", Issued: now})
	pol := func(s ssh.Signer, v int64) signedBlob {
		b, _ := signPolicy(s, Policy{Account: "user:1", Version: v, Issued: now, KRLExpires: now + 3600,
			CAKeys: []string{authorizedKey(dev.PublicKey()) + " p3sig-ca:test"}, Grants: []PolicyGrant{{"ops", "root"}}})
		return b
	}
	rv, _ := signRevocations(root, Revocations{Account: "user:1", Version: 2, Revoked: []string{ssh.FingerprintSHA256(chip.PublicKey())}})
	out := map[string]any{"root_key": authorizedKey(root.PublicKey()), "root_fp": ssh.FingerprintSHA256(root.PublicKey()),
		"dev": authorizedKey(dev.PublicKey()), "chip": authorizedKey(chip.PublicKey()), "d1": d1, "d2": d2,
		"p_dev_10": pol(dev, 10), "p_chip_11": pol(chip, 11), "p_dev_12": pol(dev, 12), "revs": rv}
	j, _ := json.Marshal(out)
	os.WriteFile("/tmp/p3pol/fixture.json", j, 0o644)
}

func TestZZVerify(t *testing.T) {
	if os.Getenv("P3SIG_XCHECK") == "" {
		t.Skip("set P3SIG_XCHECK=1")
	}
	var fx map[string]any
	j, _ := os.ReadFile("/tmp/p3pol/fixture.json")
	json.Unmarshal(j, &fx)
	for _, f := range []string{"served_a.json", "served_b.json"} {
		var sp SignedPolicy
		b, err := os.ReadFile("/tmp/p3pol/" + f)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &sp); err != nil {
			t.Fatal(err)
		}
		p, err := verifySignedPolicy(&sp, fx["root_fp"].(string), policyState{}, time.Now())
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		t.Logf("%s verified: v%d signer=%s", f, p.Version, sp.Signer[:20])
	}
	var sp SignedPolicy
	b, _ := os.ReadFile("/tmp/p3pol/served_revoked.json")
	json.Unmarshal(b, &sp)
	_, err := verifySignedPolicy(&sp, fx["root_fp"].(string), policyState{}, time.Now())
	if err == nil {
		t.Fatal("revoked chip policy accepted")
	}
	t.Logf("served_revoked rejected: %v", err)
	_, err = verifySignedPolicy(&sp, "SHA256:not-the-root", policyState{}, time.Now())
	t.Logf("wrong pinned root: %v", err)
}

// Device-auth fixture for tests/device_auth_test.php (task #2629): a root, four
// delegated devices (ed25519, P-256 chip, sk-ecdsa, sk-ed25519) and a fresh auth
// form per device and action.  P3SIG_XCHECK=1 go test -run TestZZEmitDeviceAuth
func TestZZEmitDeviceAuth(t *testing.T) {
	if os.Getenv("P3SIG_XCHECK") == "" {
		t.Skip("set P3SIG_XCHECK=1")
	}
	os.MkdirAll("/tmp/p3pol", 0o755)
	_, rk, _ := ed25519.GenerateKey(rand.Reader)
	root, _ := ssh.NewSignerFromKey(rk)
	now := time.Now()
	out := map[string]any{"root_key": authorizedKey(root.PublicKey())}
	devs := map[string]any{}
	for name, dev := range deviceSigners(t) {
		d, _ := signDelegation(root, Delegation{Account: "user:1", DeviceKey: authorizedKey(dev.PublicKey()), Label: name, Issued: now.Unix()})
		auth := map[string]any{}
		for _, a := range []string{"getPolicyStatus", "getPolicyDraft", "policyPutBlob", "getSecret"} {
			f, err := deviceAuthForm(dev, a, now)
			if err != nil {
				t.Fatal(err)
			}
			auth[a] = map[string]string{"device_key": f.Get("device_key"), "ts": f.Get("ts"), "device_sig": f.Get("device_sig")}
		}
		devs[name] = map[string]any{"fp": ssh.FingerprintSHA256(dev.PublicKey()), "delegation": d, "auth": auth}
	}
	out["devices"] = devs
	rv, _ := signRevocations(root, Revocations{Account: "user:1", Version: 3, Revoked: []string{devs["p256"].(map[string]any)["fp"].(string)}})
	out["revs"] = rv
	j, _ := json.Marshal(out)
	os.WriteFile("/tmp/p3pol/devauth.json", j, 0o644)
}
