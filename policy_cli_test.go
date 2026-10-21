package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// fakePolicyServer mirrors p3sig policyApiActions.php: it stores blobs verbatim,
// holds no signing key, and assembles getSignedPolicy from what was stored.
type fakePolicyServer struct {
	rootKey     string
	delegations map[string]signedBlob // device fp → blob
	revocations *signedBlob
	revVersion  int64
	revoked     []string
	policy      map[string]signedBlob
	signer      map[string]string
	draft       Policy
	draftExtra  string // injected into the draft JSON (strict-decode check)
}

func newFakePolicyServer() *fakePolicyServer {
	return &fakePolicyServer{delegations: map[string]signedBlob{}, policy: map[string]signedBlob{}, signer: map[string]string{}}
}

func (s *fakePolicyServer) call(action string, f url.Values, v any) error {
	out := any(nil)
	switch action {
	case "policySetRoot":
		k, err := parseKey(f.Get("root_key"))
		if err != nil {
			return err
		}
		if s.rootKey != "" && s.rootKey != authorizedKey(k) {
			return errors.New("a different root is already set")
		}
		s.rootKey = authorizedKey(k)
		out = map[string]string{"root_fp": ssh.FingerprintSHA256(k)}
	case "getPolicyStatus":
		st := map[string]any{"account": "user:1", "revocations_version": s.revVersion, "root_fp": ""}
		if s.rootKey != "" {
			k, _ := parseKey(s.rootKey)
			st["root_fp"] = ssh.FingerprintSHA256(k)
		}
		var ds []map[string]any
		for fp := range s.delegations {
			rv := false
			for _, r := range s.revoked {
				rv = rv || r == fp
			}
			ds = append(ds, map[string]any{"device_fp": fp, "revoked": rv})
		}
		st["delegations"] = ds
		st["machines"] = []map[string]any{{"machine_id": "m1", "name": "web"}}
		out = st
	case "policyPutBlob":
		b := signedBlob{Payload: f.Get("payload"), Sig: f.Get("sig")}
		raw, _ := base64.StdEncoding.DecodeString(b.Payload)
		root, _ := parseKey(s.rootKey)
		switch f.Get("kind") {
		case "delegation":
			var d Delegation
			if err := openSignedBlob(root, ctxDelegation, b, &d); err != nil {
				return err
			}
			dk, _ := parseKey(d.DeviceKey)
			s.delegations[ssh.FingerprintSHA256(dk)] = b
		case "revocations":
			var r Revocations
			if err := openSignedBlob(root, ctxRevocations, b, &r); err != nil {
				return err
			}
			if r.Version <= s.revVersion {
				return errors.New("not newer")
			}
			s.revocations, s.revVersion, s.revoked = &b, r.Version, r.Revoked
		case "policy":
			var p Policy
			_ = json.Unmarshal(raw, &p)
			s.policy[f.Get("machine_id")] = b
			s.signer[f.Get("machine_id")] = f.Get("signer")
		}
	case "getPolicyDraft":
		j, _ := json.Marshal(s.draft)
		if s.draftExtra != "" {
			j = []byte(strings.TrimSuffix(string(j), "}") + "," + s.draftExtra + "}")
		}
		out = map[string]json.RawMessage{"policy": j}
	default:
		return errors.New("unknown action " + action)
	}
	if v != nil && out != nil {
		j, _ := json.Marshal(out)
		return json.Unmarshal(j, v)
	}
	return nil
}

func (s *fakePolicyServer) served(machine string) *SignedPolicy {
	sp := &SignedPolicy{RootKey: s.rootKey, Revocations: s.revocations, Policy: s.policy[machine], Signer: s.signer[machine]}
	for _, b := range s.delegations {
		sp.Chain = append(sp.Chain, b)
	}
	return sp
}

// serveAgent puts signers in an ssh-agent on a unix socket and points SSH_AUTH_SOCK at it.
func serveAgent(t *testing.T, keys ...any) {
	t.Helper()
	kr := agent.NewKeyring()
	for _, k := range keys {
		if err := kr.Add(agent.AddedKey{PrivateKey: k}); err != nil {
			t.Fatal(err)
		}
	}
	sock := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(kr, c)
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", sock)
}

// TestPolicyCLIFlow: root (file) → delegate the chip held in an ssh-agent → the chip
// signs the draft with no root key → the agent verifies it; then revoke the chip and
// its next signature is refused by the agent.
func TestPolicyCLIFlow(t *testing.T) {
	dir := t.TempDir()
	rootFile := filepath.Join(dir, "root.key")
	// The vault-key file format the root lives in (base64 ed25519 private key).
	_, edRoot, _ := ed25519.GenerateKey(rand.Reader)
	os.WriteFile(rootFile, []byte(base64.StdEncoding.EncodeToString(edRoot)), 0o600)

	chipPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serveAgent(t, chipPriv)

	srv := newFakePolicyServer()
	root, err := loadSigner(rootFile)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := policySetRoot(srv.call, root)
	if err != nil || fp != ssh.FingerprintSHA256(root.PublicKey()) {
		t.Fatalf("set root: %v %s", err, fp)
	}

	chipLine, err := deviceKeyLine("agent")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policyDelegate(srv.call, root, chipLine, "chip", 0, time.Now()); err != nil {
		t.Fatal(err)
	}
	// A key that is not the root can't delegate.
	if _, err := policyDelegate(srv.call, newSigner(t, false), chipLine, "x", 0, time.Now()); err == nil {
		t.Fatal("non-root delegated")
	}

	ca := authorizedKey(newSigner(t, false).PublicKey()) + " p3sig-ca:ops"
	now := time.Now()
	srv.draft = Policy{Account: "user:1", Version: now.Unix(), Issued: now.Unix(), KRLExpires: now.Add(72 * time.Hour).Unix(),
		CAKeys: []string{ca}, Grants: []PolicyGrant{{Principal: "ops", LoginUser: "root"}}}

	chip, err := loadSigner("agent")
	if err != nil {
		t.Fatal(err)
	}
	var reviewed string
	v, err := policySign(srv.call, chip, "m1", 72, func(m string, p Policy) bool { reviewed = describePolicy(m, p); return true })
	if err != nil || v != srv.draft.Version {
		t.Fatalf("sign: %v v%d", err, v)
	}
	if !strings.Contains(reviewed, "p3sig-ca:ops") || !strings.Contains(reviewed, "ops → root") {
		t.Fatalf("review did not show the CA/principals:\n%s", reviewed)
	}
	p, err := verifySignedPolicy(srv.served("m1"), fp, policyState{}, time.Now())
	if err != nil || p.CAKeys[0] != ca {
		t.Fatalf("agent rejected chip-signed policy: %v", err)
	}

	// Declined review → nothing stored.
	srv.draft.Version++
	if v, _ := policySign(srv.call, chip, "m1", 72, func(string, Policy) bool { return false }); v != 0 {
		t.Fatal("declined review still signed")
	}

	// Draft with a field the reviewer can't see → refused before signing.
	srv.draftExtra = `"authorized_keys":"evil"`
	if _, err := policySign(srv.call, chip, "m1", 72, func(string, Policy) bool { return true }); err == nil {
		t.Fatal("signed a draft with an unknown field")
	}
	srv.draftExtra = ""

	// Revoke the chip: the root signs v1 of the list; the agent then refuses the chip.
	chipFP, _ := deviceFingerprint(chipLine)
	if rv, err := policyRevoke(srv.call, root, chipFP); err != nil || rv != 1 {
		t.Fatalf("revoke: %v v%d", err, rv)
	}
	if _, err := policySign(srv.call, chip, "m1", 72, func(string, Policy) bool { return true }); err != nil {
		t.Fatal(err) // the fake server stores it; the agent is the one that must refuse
	}
	if _, err := verifySignedPolicy(srv.served("m1"), fp, policyState{}, time.Now()); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked chip accepted: %v", err)
	}
}

func TestPickSignerAndExpiry(t *testing.T) {
	a, b := newSigner(t, false), newSigner(t, true)
	if _, err := pickSigner([]ssh.Signer{a, b}, ""); err == nil {
		t.Fatal("ambiguous agent picked a key")
	}
	if s, err := pickSigner([]ssh.Signer{a, b}, ssh.FingerprintSHA256(b.PublicKey())); err != nil || s != b {
		t.Fatal("fingerprint pick failed")
	}
	now := time.Unix(1_000_000, 0)
	if e, _ := parseExpiry("90d", now); e != now.Add(90*24*time.Hour).Unix() {
		t.Fatal("90d")
	}
	if e, _ := parseExpiry("", now); e != 0 {
		t.Fatal("empty")
	}
	if _, err := parseExpiry("yesterday", now); err == nil {
		t.Fatal("bad expiry accepted")
	}
}
