package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// One `p3sig policy sign` = one device signature that every machine's agent accepts.
func TestPolicySignAccountOneSignatureServesN(t *testing.T) {
	f := newAccountFixture(t)
	draft, _ := json.Marshal(f.ap)
	var put url.Values
	extra := ""
	call := func(action string, form url.Values, v any) error {
		switch action {
		case "getAccountPolicyDraft":
			j := draft
			if extra != "" {
				j = []byte(strings.TrimSuffix(string(j), "}") + "," + extra + "}")
			}
			return json.Unmarshal([]byte(`{"policy":`+string(j)+`,"diff":{"since_version":5,"machines_added":["m2"]}}`), v)
		case "accountPolicyPut":
			put = form
			return nil
		}
		return errors.New("unexpected " + action)
	}
	signs := 0
	counting := &countingSigner{Signer: f.dongle, n: &signs}
	var shown accountDiff
	v, err := policySignAccount(call, counting, "", 72, func(_ AccountPolicy, d accountDiff) bool { shown = d; return true })
	if err != nil || v != f.ap.Version || signs != 1 {
		t.Fatalf("v=%d err=%v signatures=%d (want exactly 1)", v, err, signs)
	}
	if shown.SinceVersion != 5 || len(shown.MachinesAdded) != 1 {
		t.Fatalf("review did not get the diff: %+v", shown)
	}
	sp := f.served(t, nil)
	sp.AccountPolicy = &signedBlob{Payload: put.Get("payload"), Sig: put.Get("sig")}
	for _, m := range []string{"m1", "m2"} {
		if _, err := verifyPolicyAny(sp, f.rootFP, m, policyState{}, f.now); err != nil {
			t.Fatalf("%s refused the one signature: %v", m, err)
		}
	}
	// declined → nothing uploaded
	put = nil
	if v, err := policySignAccount(call, f.dongle, "", 72, func(AccountPolicy, accountDiff) bool { return false }); v != 0 || err != nil || put != nil {
		t.Fatalf("declined sign uploaded: v=%d err=%v", v, err)
	}
	// a field the reviewer can't see is refused
	extra = `"sneaky":1`
	if _, err := policySignAccount(call, f.dongle, "", 72, func(AccountPolicy, accountDiff) bool { return true }); err == nil {
		t.Fatal("draft with unknown field was signed")
	}
}

type countingSigner struct {
	ssh.Signer
	n *int
}

func (c *countingSigner) Sign(r io.Reader, data []byte) (*ssh.Signature, error) {
	*c.n++
	return c.Signer.Sign(nil, data)
}

// fakeRefreshServer serves freshnessGetCurrent and records freshnessPut.
func fakeRefresh(t *testing.T, sp *SignedPolicy, got *signedBlob) func(url.Values, any) error {
	return func(form url.Values, v any) error {
		switch form.Get("action") {
		case "freshnessGetCurrent":
			j, _ := json.Marshal(sp)
			return json.Unmarshal(j, v)
		case "freshnessPut":
			*got = signedBlob{Payload: form.Get("payload"), Sig: form.Get("sig")}
			return nil
		}
		t.Fatalf("unexpected %s", form.Get("action"))
		return nil
	}
}

// The refresher keeps a policy valid past its own expiry with no human — and agents accept it.
func TestFreshnessRefreshKeepsPolicyLiveWithoutHuman(t *testing.T) {
	f := newAccountFixture(t)
	sp := f.served(t, nil)
	var st refreshState
	var fb signedBlob
	later := f.now.Add(30 * time.Hour) // past the device signature's 24h
	for tick := f.now; !tick.After(later); tick = tick.Add(6 * time.Hour) {
		if _, err := freshnessRefresh(fakeRefresh(t, sp, &fb), f.fresh, "7", "", f.rootFP, 36*time.Hour, &st, tick); err != nil {
			t.Fatalf("tick %s: %v", tick, err)
		}
	}
	if st.Version != f.ap.Version {
		t.Fatalf("state floor %d", st.Version)
	}
	sp.Freshness = &fb
	if _, err := verifyPolicyAny(sp, f.rootFP, "m1", policyState{}, later); err != nil {
		t.Fatalf("agent refused refreshed policy at +30h: %v", err)
	}
	// refresher stopped: 36h after the last tick the agent keeps the old config
	if _, err := verifyPolicyAny(sp, f.rootFP, "m1", policyState{}, later.Add(37*time.Hour)); !errors.Is(err, errStaleKRL) {
		t.Fatalf("lapse not detected: %v", err)
	}
}

func TestFreshnessRefreshRefuses(t *testing.T) {
	f := newAccountFixture(t)
	var fb signedBlob
	run := func(sp *SignedPolicy, st refreshState, key ssh.Signer) error {
		_, err := freshnessRefresh(fakeRefresh(t, sp, &fb), key, "7", "", f.rootFP, 36*time.Hour, &st, f.now)
		return err
	}
	if err := run(f.served(t, nil), refreshState{Version: f.ap.Version + 1}, f.fresh); err == nil {
		t.Fatal("vouched for an older policy than already vouched (withholding)")
	}
	sp := f.served(t, nil)
	sp.RootKey = authorizedKey(newSigner(t, false).PublicKey())
	if err := run(sp, refreshState{}, f.fresh); err == nil {
		t.Fatal("vouched under a different root")
	}
	rogue := newSigner(t, false)
	sp = f.served(t, nil)
	bad, _ := signAccountPolicy(rogue, f.ap)
	sp.AccountPolicy, sp.Signer = &bad, authorizedKey(rogue.PublicKey())
	if err := run(sp, refreshState{}, f.fresh); err == nil {
		t.Fatal("vouched for a policy signed by an undelegated key")
	}
	f.revoke = []ssh.Signer{f.fresh}
	if err := run(f.served(t, nil), refreshState{}, f.fresh); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked freshness key kept vouching: %v", err)
	}
	f.revoke = nil
	if _, err := freshnessRefresh(fakeRefresh(t, f.served(t, nil), &fb), f.fresh, "7", "", f.rootFP, 8*24*time.Hour, &refreshState{}, f.now); err == nil {
		t.Fatal("window beyond the 7d cap accepted")
	}
}

// The refresher takes its window from the account settings; a longer --window is cut to it.
func TestFreshnessRefreshUsesAccountWindow(t *testing.T) {
	f := newAccountFixture(t)
	sp := f.served(t, nil)
	var fb signedBlob
	withWindow := func(hours int) func(url.Values, any) error {
		inner := fakeRefresh(t, sp, &fb)
		return func(form url.Values, v any) error {
			if form.Get("action") != "freshnessGetCurrent" {
				return inner(form, v)
			}
			j, _ := json.Marshal(sp)
			var m map[string]any
			_ = json.Unmarshal(j, &m)
			m["settings"] = map[string]int{"window_hours": hours, "refresh_hours": 6}
			j, _ = json.Marshal(m)
			return json.Unmarshal(j, v)
		}
	}
	for _, c := range []struct {
		server int
		flag   time.Duration
		want   time.Duration
	}{{24, 0, 24 * time.Hour}, {24, 36 * time.Hour, 24 * time.Hour}, {48, 12 * time.Hour, 12 * time.Hour}, {0, 0, defaultFreshnessWindow}} {
		exp, err := freshnessRefresh(withWindow(c.server), f.fresh, "7", "", f.rootFP, c.flag, &refreshState{}, f.now)
		if err != nil {
			t.Fatalf("%+v: %v", c, err)
		}
		if got := time.Unix(exp, 0).Sub(time.Unix(f.now.Unix(), 0)); got != c.want {
			t.Fatalf("server %dh flag %s: window %s, want %s", c.server, c.flag, got, c.want)
		}
	}
}
