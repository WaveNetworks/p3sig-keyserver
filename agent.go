package main

// Shared, OS-agnostic glue for the chip-backed client key (no build tag):
//
//   - chipAgent: an ssh-agent (golang.org/x/crypto/ssh/agent.Agent) whose single
//     identity is the platform keystore key. ssh asks it to sign; we forward to
//     keystore.Sign, which prompts the biometric. The chip private key is never
//     exposed — only signatures cross the wire — so `ssh` itself stays unmodified.
//   - normalizeECDSASig: keystores return ECDSA signatures differently (Windows
//     CNG → r||s, macOS Secure Enclave → ASN.1 DER); both become SSH wire form here.
//   - cmdSetup / cmdSSHAgent: the `p3sig setup` and `p3sig ssh-agent` commands.
//
// The actual listener (unix socket vs Windows named pipe) is platform-specific;
// see listen_other.go / listen_windows.go.

import (
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var errReadOnly = fmt.Errorf("p3sig agent is read-only: the chip key is non-extractable and managed by the secure hardware")

// chipAgent serves exactly one identity — the keystore key — over the SSH agent
// protocol. It is read-only: keys can't be added, removed, or extracted.
type chipAgent struct {
	ks    Keystore
	label string
	pub   ssh.PublicKey
}

func newChipAgent(ks Keystore, label string) (*chipAgent, error) {
	line, err := ks.PublicKey(label)
	if err != nil {
		return nil, fmt.Errorf("load public key for %q: %w", label, err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, fmt.Errorf("parse keystore public key: %w", err)
	}
	return &chipAgent{ks: ks, label: label, pub: pub}, nil
}

func (a *chipAgent) List() ([]*agent.Key, error) {
	return []*agent.Key{{
		Format:  a.pub.Type(),
		Blob:    a.pub.Marshal(),
		Comment: "p3sig:" + a.label,
	}}, nil
}

func (a *chipAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a *chipAgent) SignWithFlags(key ssh.PublicKey, data []byte, _ agent.SignatureFlags) (*ssh.Signature, error) {
	// ECDSA P-256 has no rsa-sha2 variants, so flags are irrelevant.
	if string(key.Marshal()) != string(a.pub.Marshal()) {
		return nil, fmt.Errorf("agent: no matching key for signature request")
	}
	raw, err := a.ks.Sign(a.label, data) // biometric prompt happens here
	if err != nil {
		return nil, err
	}
	r, s, err := normalizeECDSASig(raw)
	if err != nil {
		return nil, err
	}
	// SSH ecdsa signature blob: mpint r, mpint s (RFC 5656).
	blob := ssh.Marshal(struct{ R, S *big.Int }{r, s})
	return &ssh.Signature{Format: a.pub.Type(), Blob: blob}, nil
}

func (a *chipAgent) Signers() ([]ssh.Signer, error) {
	return nil, fmt.Errorf("agent: Signers unsupported (chip key is non-extractable)")
}

func (a *chipAgent) Add(agent.AddedKey) error   { return errReadOnly }
func (a *chipAgent) Remove(ssh.PublicKey) error { return errReadOnly }
func (a *chipAgent) RemoveAll() error           { return errReadOnly }
func (a *chipAgent) Lock([]byte) error          { return errReadOnly }
func (a *chipAgent) Unlock([]byte) error        { return errReadOnly }

// normalizeECDSASig turns a platform-native ECDSA signature into (r, s).
// Windows CNG returns fixed-width r||s; macOS Secure Enclave returns DER.
func normalizeECDSASig(raw []byte) (r, s *big.Int, err error) {
	// Fixed-width r||s (CNG: 64 bytes for P-256). A valid DER P-256 signature is
	// ~70-72 bytes, so an even length <= 66 is unambiguously raw r||s.
	if n := len(raw); n > 0 && n%2 == 0 && n <= 66 {
		half := n / 2
		return new(big.Int).SetBytes(raw[:half]), new(big.Int).SetBytes(raw[half:]), nil
	}
	// ASN.1 DER: SEQUENCE { INTEGER r, INTEGER s } (macOS Secure Enclave).
	var der struct{ R, S *big.Int }
	if _, e := asn1.Unmarshal(raw, &der); e == nil && der.R != nil && der.S != nil {
		return der.R, der.S, nil
	}
	return nil, nil, fmt.Errorf("unrecognized ECDSA signature format (%d bytes)", len(raw))
}

// ─── commands ───────────────────────────────────────────────────────────────

// cmdSetup creates (or shows/deletes) the chip key and prints its OpenSSH
// public key for registration in p3sig or signing by the CA.
func cmdSetup(f map[string]string) error {
	label := agentLabel(f)
	ks, err := openKeystore()
	if err != nil {
		return err
	}
	switch {
	case f["delete"] == "true":
		if err := ks.Delete(label); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "deleted chip key %q\n", label)
		return nil
	case f["show"] == "true":
		line, err := ks.PublicKey(label)
		if err != nil {
			return err
		}
		fmt.Println(line)
		return nil
	default:
		line, err := ks.Create(label)
		if err != nil {
			return err
		}
		fmt.Println(line)
		fmt.Fprintf(os.Stderr, `
Register this PUBLIC key in p3sig (Machines / SSH Access), or have your CA sign it.
Then serve it to ssh:  p3sig ssh-agent --label %s
`, label)
		return nil
	}
}

// cmdSSHAgent runs an ssh-agent backed by the chip key.
func cmdSSHAgent(f map[string]string) error {
	label := agentLabel(f)
	ks, err := openKeystore()
	if err != nil {
		return err
	}
	ag, err := newChipAgent(ks, label)
	if err != nil {
		return err
	}
	ln, cleanup, err := listenAgent(f["bind"])
	if err != nil {
		return err
	}
	defer cleanup()

	fmt.Fprintf(os.Stderr, "p3sig ssh-agent: serving key %q on %s\n", label, ln.Addr())
	fmt.Fprintf(os.Stderr, "%s\n", agentHint(f["bind"]))
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			if err := agent.ServeAgent(ag, conn); err != nil && err != io.EOF {
				fmt.Fprintln(os.Stderr, "agent connection:", err)
			}
		}()
	}
}

func agentLabel(f map[string]string) string {
	if l := f["label"]; l != "" {
		return l
	}
	return "p3sig"
}
