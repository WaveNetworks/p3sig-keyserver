package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// accountFixture: root delegates the dongle (policy) and a freshness key; the dongle
// signs ONE account policy covering m1 and m2.
type accountFixture struct {
	*policyFixture
	fresh  ssh.Signer
	ap     AccountPolicy
	caM2   string
	revoke []ssh.Signer
}

func newAccountFixture(t *testing.T) *accountFixture {
	f := &accountFixture{policyFixture: newPolicyFixture(t), fresh: newSigner(t, true)}
	f.caM2 = authorizedKey(newSigner(t, false).PublicKey()) + " lab-ca"
	f.ap = AccountPolicy{Account: "7", Version: 1793165600, Issued: f.now.Unix(), Expires: f.now.Add(24 * time.Hour).Unix(),
		KRLSpec: "# account krl",
		Machines: map[string]MachinePolicy{
			"m1": {CAKeys: []string{f.caKey}, Grants: []PolicyGrant{{Principal: "ops", LoginUser: "root"}}},
			"m2": {CAKeys: []string{f.caM2}, Grants: []PolicyGrant{{Principal: "lab", LoginUser: "deploy"}}},
		}}
	return f
}

// served builds the getSignedPolicy response; fr (optional) is the freshness statement to attach.
func (f *accountFixture) served(t *testing.T, fr func(hash string) Freshness) *SignedPolicy {
	t.Helper()
	sp := f.signed(t, f.dongle, 1, f.caKey, f.revoke...) // chain + revocations
	sp.Policy = signedBlob{}
	ab, err := signAccountPolicy(f.dongle, f.ap)
	if err != nil {
		t.Fatal(err)
	}
	sp.AccountPolicy = &ab
	db, err := signFreshnessDelegation(f.root, FreshnessDelegation{Account: "7", Key: authorizedKey(f.fresh.PublicKey()), Issued: f.now.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	sp.FreshnessChain = []signedBlob{db}
	sp.FreshnessSigner = authorizedKey(f.fresh.PublicKey())
	if fr != nil {
		h, _ := accountPolicyHash(ab)
		fb, err := signFreshness(f.fresh, fr(h))
		if err != nil {
			t.Fatal(err)
		}
		sp.Freshness = &fb
	}
	return sp
}

func (f *accountFixture) freshFor(issued time.Time, d time.Duration) func(string) Freshness {
	return func(h string) Freshness {
		return Freshness{Account: "7", PolicyHash: h, Version: f.ap.Version, Issued: issued.Unix(), Expires: issued.Add(d).Unix()}
	}
}

func TestAccountPolicyOneSignatureServesEveryMachine(t *testing.T) {
	f := newAccountFixture(t)
	sp := f.served(t, nil)
	p1, err := verifyPolicyAny(sp, f.rootFP, "m1", policyState{}, f.now)
	if err != nil || p1.CAKeys[0] != f.caKey || p1.Grants[0].Principal != "ops" {
		t.Fatalf("m1: %v %+v", err, p1)
	}
	p2, err := verifyPolicyAny(sp, f.rootFP, "m2", policyState{}, f.now)
	if err != nil || p2.CAKeys[0] != f.caM2 || p2.Grants[0].LoginUser != "deploy" {
		t.Fatalf("m2: %v %+v", err, p2)
	}
	if p1.KRLSpec != "# account krl" || p2.KRLSpec != p1.KRLSpec {
		t.Fatal("account KRL not applied on both")
	}
}

func TestAccountPolicyMachineCannotApplyAnothersGrants(t *testing.T) {
	f := newAccountFixture(t)
	if _, err := verifyPolicyAny(f.served(t, nil), f.rootFP, "m3", policyState{}, f.now); err == nil || !strings.Contains(err.Error(), "no entry") {
		t.Fatalf("unlisted machine must get nothing, got %v", err)
	}
	// The server relabelling m2's entry as m1 breaks the device signature.
	sp := f.served(t, nil)
	f.ap.Machines["m1"] = f.ap.Machines["m2"]
	forged, _ := signAccountPolicy(f.chip, f.ap) // right shape, wrong signer key
	sp.AccountPolicy = &forged
	if _, err := verifyPolicyAny(sp, f.rootFP, "m1", policyState{}, f.now); err == nil {
		t.Fatal("re-signed by a key other than Signer must fail")
	}
}

func TestFreshnessExtendsOnlyTheExactPolicy(t *testing.T) {
	f := newAccountFixture(t)
	later := f.now.Add(30 * time.Hour) // past the device-signed 24h expiry
	ok := f.served(t, f.freshFor(f.now.Add(20*time.Hour), 24*time.Hour))
	p, err := verifyPolicyAny(ok, f.rootFP, "m1", policyState{}, later)
	if err != nil || p.KRLExpires != f.now.Add(44*time.Hour).Unix() {
		t.Fatalf("fresh policy refused: %v", err)
	}

	wrong := f.served(t, func(h string) Freshness {
		return f.freshFor(f.now.Add(20*time.Hour), 24*time.Hour)("sha256:" + strings.Repeat("0", 64))
	})
	if _, err := verifyPolicyAny(wrong, f.rootFP, "m1", policyState{}, later); !errors.Is(err, errStaleKRL) || !strings.Contains(err.Error(), "different policy") {
		t.Fatalf("freshness for the wrong hash must be refused, got %v", err)
	}
}

func TestFreshnessCannotChangeContent(t *testing.T) {
	f := newAccountFixture(t)
	sp := f.served(t, f.freshFor(f.now, 24*time.Hour))
	// The freshness key signs a policy body itself: not a delegated policy signer.
	f.ap.Machines["m1"] = MachinePolicy{CAKeys: []string{authorizedKey(newSigner(t, false).PublicKey()) + " evil"}}
	evil, _ := signAccountPolicy(f.fresh, f.ap)
	sp.AccountPolicy = &evil
	sp.Signer = authorizedKey(f.fresh.PublicKey())
	if _, err := verifyPolicyAny(sp, f.rootFP, "m1", policyState{}, f.now); err == nil || !strings.Contains(err.Error(), "no live delegation") {
		t.Fatalf("freshness key must not sign policy, got %v", err)
	}
	// Smuggling content fields into a freshness statement fails strict decoding.
	sp = f.served(t, nil)
	bad, _ := signBlob(f.fresh, ctxFreshness, map[string]any{"account": "7", "policy_hash": "x", "version": 1,
		"issued": f.now.Unix(), "expires": f.now.Add(time.Hour).Unix(), "trusted_user_ca_keys": []string{"evil"}})
	sp.Freshness = &bad
	if _, err := verifyFreshness(sp, f.root.PublicKey(), nil, &f.ap, f.now); err == nil {
		t.Fatal("freshness with content fields must be refused")
	}
	// A freshness delegation is not a policy delegation (separate context).
	sp = f.served(t, nil)
	sp.Chain = append(sp.Chain, sp.FreshnessChain...)
	if _, err := verifyPolicyAny(sp, f.rootFP, "m1", policyState{}, f.now); err == nil {
		t.Fatal("freshness delegation replayed as a policy delegation must fail")
	}
}

func TestExpiredFreshnessKeepsOldConfig(t *testing.T) {
	f := newAccountFixture(t)
	sp := f.served(t, f.freshFor(f.now.Add(20*time.Hour), 24*time.Hour))
	if _, err := verifyPolicyAny(sp, f.rootFP, "m1", policyState{}, f.now.Add(45*time.Hour)); !errors.Is(err, errStaleKRL) || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("want errStaleKRL (freshness expired), got %v", err)
	}
	// A freshness key can't vouch beyond the maximum window, however long it signs for.
	sp = f.served(t, f.freshFor(f.now, 365*24*time.Hour))
	if _, err := verifyPolicyAny(sp, f.rootFP, "m1", policyState{}, f.now.Add(maxFreshnessWindow+time.Hour)); !errors.Is(err, errStaleKRL) {
		t.Fatalf("freshness must be capped at %s, got %v", maxFreshnessWindow, err)
	}
	// Future-dated statements are refused.
	sp = f.served(t, f.freshFor(f.now.Add(48*time.Hour), 24*time.Hour))
	if _, err := verifyPolicyAny(sp, f.rootFP, "m1", policyState{}, f.now.Add(30*time.Hour)); !errors.Is(err, errStaleKRL) || !strings.Contains(err.Error(), "future") {
		t.Fatalf("future freshness must be refused, got %v", err)
	}
}

func TestRevokedFreshnessKeyRefused(t *testing.T) {
	f := newAccountFixture(t)
	f.revoke = []ssh.Signer{f.fresh}
	sp := f.served(t, f.freshFor(f.now.Add(20*time.Hour), 24*time.Hour))
	if _, err := verifyPolicyAny(sp, f.rootFP, "m1", policyState{}, f.now.Add(30*time.Hour)); !errors.Is(err, errStaleKRL) || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked freshness key must be refused, got %v", err)
	}
	// The device-signed expiry still holds on its own.
	if _, err := verifyPolicyAny(sp, f.rootFP, "m1", policyState{}, f.now); err != nil {
		t.Fatalf("policy within its own expiry: %v", err)
	}
}

func TestReplayAcrossFormatsRefused(t *testing.T) {
	f := newAccountFixture(t)
	// Migration: the per-machine policy (v1793165590) keeps working before the switch.
	legacy := f.signed(t, f.dongle, 1793165590, f.caKey)
	p, err := verifyPolicyAny(legacy, f.rootFP, "m1", policyState{}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	st := nextState(legacy, f.rootFP, p, policyState{})

	// The account policy must not go backwards across the switch.
	f.ap.Version = 1793165000
	if _, err := verifyPolicyAny(f.served(t, nil), f.rootFP, "m1", st, f.now); err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("older account policy accepted after per-machine v1793165590: %v", err)
	}
	f.ap.Version = 1793165600
	acc := f.served(t, nil)
	p, err = verifyPolicyAny(acc, f.rootFP, "m1", st, f.now)
	if err != nil {
		t.Fatal(err)
	}
	st = nextState(acc, f.rootFP, p, st)
	if st.Format != formatAccount || st.Version != 1793165600 {
		t.Fatalf("state after switch: %+v", st)
	}
	// After the switch, even a NEWER per-machine policy is refused (no downgrade).
	if _, err := verifyPolicyAny(f.signed(t, f.dongle, 1793169999, f.caKey), f.rootFP, "m1", st, f.now); err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("per-machine policy after account switch: %v", err)
	}
}
