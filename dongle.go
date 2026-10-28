package main

// dongle.go — FIDO2 dongle as a signing device (task #2630).
//
// `--with dongle` makes the binary itself the FIDO client: it runs CTAP2
// getAssertion on the dongle (PIN asked in this terminal, then a touch) and
// encodes the result as an sk-ecdsa-sha2-nistp256@openssh.com signature, the
// same bytes ssh-agent + ssh-sk-helper would produce, so verifySignedPolicy and
// the server's device auth accept it unchanged. No ssh-agent, no askpass.
//
// The hardware sits behind the Dongle interface: libfido2 (cgo) today, our own
// firmware (#2628) later, a software dongle in tests. Commands never change.
//
// OpenSK on the nRF52840 has no Ed25519, so policy keys are ES256 (sk-ecdsa).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"runtime"
	"strings"

	"golang.org/x/crypto/ssh"
)

// policyApp is the rp id / OpenSSH "application" of the policy-signing credential.
const policyApp = "ssh:p3sig-policy"

const skECDSAType = "sk-ecdsa-sha2-nistp256@openssh.com"

// DongleInfo identifies one connected authenticator.
type DongleInfo struct {
	Path, Product, Serial string
}

// DongleCred is a credential on the dongle: its P-256 public point (SEC1
// uncompressed, 65 bytes) and the credential id needed to assert with it.
type DongleCred struct {
	App    string
	Q      []byte
	CredID []byte
}

// Assertion is what CTAP2 getAssertion returns that OpenSSH keeps: the flags
// byte and sign counter from authenticatorData, and the DER ECDSA signature over
// authenticatorData || clientDataHash.
type Assertion struct {
	Flags   byte
	Counter uint32
	DERSig  []byte
}

// Dongle is one FIDO2 authenticator. pin is "" when the caller has not asked
// for it yet; implementations return ErrPINRequired so the CLI can prompt.
type Dongle interface {
	Info() DongleInfo
	HasPIN() (bool, error)
	SetPIN(pin string) error
	// MakeCredential: resident, user-verification required, ES256.
	MakeCredential(app, user, pin string) (DongleCred, error)
	// Credentials lists resident credentials for app (needs the PIN).
	Credentials(app, pin string) ([]DongleCred, error)
	Assert(cred DongleCred, clientDataHash [32]byte, pin string) (Assertion, error)
}

var ErrPINRequired = errors.New("dongle: PIN required")

// openDongles is set by a hardware backend (dongle_libfido2.go, build tag
// libfido2). Without one, `--with dongle` explains how to get a build that has it.
var openDongles func() ([]Dongle, error)

func findDongle() (Dongle, error) {
	if openDongles == nil {
		return nil, errors.New("this p3sig build has no FIDO2 support (build with CC=gcc go build -tags libfido2, needs only the libfido2 runtime library); use --with agent meanwhile")
	}
	ds, err := openDongles()
	if err != nil {
		return nil, hidrawHint(err)
	}
	switch len(ds) {
	case 0:
		return nil, hidrawHint(errors.New("no FIDO2 dongle found — plug it in"))
	case 1:
		return ds[0], nil
	}
	var names []string
	for _, d := range ds {
		names = append(names, d.Info().Product+" "+d.Info().Serial)
	}
	return nil, fmt.Errorf("more than one dongle plugged in (%s) — leave only the one to use", strings.Join(names, ", "))
}

// udevRule is shipped in the deb/rpm (packaging/70-p3sig-fido.rules).
const udevRule = `KERNEL=="hidraw*", ENV{ID_FIDO_TOKEN}=="1", GROUP="plugdev", MODE="0660"`

// hidrawHint turns a permission error on /dev/hidraw* into the exact fix. On a
// box with no desktop login the uaccess ACL goes to gdm, not to you.
func hidrawHint(err error) error {
	if runtime.GOOS != "linux" || err == nil || !(errors.Is(err, os.ErrPermission) || strings.Contains(err.Error(), "permission denied") || strings.Contains(err.Error(), "EACCES")) {
		return err
	}
	return fmt.Errorf("%w\n\nThe dongle's /dev/hidraw* is not readable by you. Fix (once, as root):\n"+
		"  echo '%s' > /etc/udev/rules.d/70-p3sig-fido.rules\n"+
		"  udevadm control --reload && udevadm trigger\n"+
		"  usermod -aG plugdev $USER   # then log in again", err, udevRule)
}

// skPublicKey builds the sk-ecdsa OpenSSH public key for a credential.
func skPublicKey(c DongleCred) (ssh.PublicKey, error) {
	return ssh.ParsePublicKey(ssh.Marshal(struct {
		T, C string
		Q    []byte
		A    string
	}{skECDSAType, "nistp256", c.Q, c.App}))
}

// dongleSigner is an ssh.Signer whose every Sign is a getAssertion (PIN + touch).
type dongleSigner struct {
	d    Dongle
	cred DongleCred
	pub  ssh.PublicKey
	pin  func() (string, error) // asked once, then reused for this run
}

func newDongleSigner(d Dongle, cred DongleCred, pin func() (string, error)) (*dongleSigner, error) {
	pub, err := skPublicKey(cred)
	if err != nil {
		return nil, err
	}
	return &dongleSigner{d: d, cred: cred, pub: pub, pin: pin}, nil
}

func (s *dongleSigner) PublicKey() ssh.PublicKey { return s.pub }

func (s *dongleSigner) Sign(_ io.Reader, msg []byte) (*ssh.Signature, error) {
	pin, err := s.pin()
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(os.Stderr, "touch the dongle…")
	a, err := s.d.Assert(s.cred, sha256.Sum256(msg), pin)
	if err != nil {
		return nil, hidrawHint(err)
	}
	return skSignature(a)
}

// skSignature encodes an assertion the way OpenSSH does (PROTOCOL.u2f):
// blob = mpint r, mpint s; then flags byte and uint32 counter after the blob.
func skSignature(a Assertion) (*ssh.Signature, error) {
	var rs struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(a.DERSig, &rs); err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("dongle returned a malformed signature")
	}
	rest := make([]byte, 5)
	rest[0] = a.Flags
	binary.BigEndian.PutUint32(rest[1:], a.Counter)
	return &ssh.Signature{Format: skECDSAType, Blob: ssh.Marshal(rs), Rest: rest}, nil
}

// pointQ returns the SEC1 uncompressed encoding of a P-256 public key.
func pointQ(k *ecdsa.PublicKey) []byte {
	return elliptic.Marshal(elliptic.P256(), k.X, k.Y) //nolint:staticcheck // SEC1 is the wire format
}

// pinPrompt asks for the dongle PIN once per run (P3SIG_DONGLE_PIN for tests).
func pinPrompt() func() (string, error) {
	var pin string
	return func() (string, error) {
		if pin != "" {
			return pin, nil
		}
		if p, ok := os.LookupEnv("P3SIG_DONGLE_PIN"); ok {
			pin = p
			return pin, nil
		}
		p, err := readPassphrase("Dongle PIN: ")
		if err != nil {
			return "", err
		}
		if p == "" {
			return "", errors.New("no PIN given")
		}
		pin = p
		return pin, nil
	}
}

// loadDongleSigner is `--with dongle[:SHA256:…]`: the resident ssh:p3sig-policy
// credential on the plugged-in dongle.
func loadDongleSigner(fp string) (ssh.Signer, error) {
	d, err := findDongle()
	if err != nil {
		return nil, err
	}
	pin := pinPrompt()
	p, err := pin()
	if err != nil {
		return nil, err
	}
	creds, err := d.Credentials(policyApp, p)
	if err != nil {
		return nil, hidrawHint(err)
	}
	var signers []ssh.Signer
	for _, c := range creds {
		s, err := newDongleSigner(d, c, pin)
		if err != nil {
			return nil, err
		}
		signers = append(signers, s)
	}
	if len(signers) == 0 {
		return nil, fmt.Errorf("the dongle has no %s key yet — run `p3sig dongle add`", policyApp)
	}
	return pickSigner(signers, fp)
}

// cmdDongle: p3sig dongle add [--root-key usb] — set the PIN if none, create the
// resident ES256 ssh:p3sig-policy key (PIN required), delegate it with the root.
func cmdDongle(sub string, f map[string]string) error {
	if sub != "add" {
		return errors.New("usage: p3sig dongle add [--root-key usb|usb:PATH|KEYFILE] [--expires 365d]")
	}
	d, err := findDongle()
	if err != nil {
		return err
	}
	info := d.Info()
	fmt.Printf("dongle: %s (serial %s)\n", info.Product, info.Serial)
	has, err := d.HasPIN()
	if err != nil {
		return hidrawHint(err)
	}
	var pin string
	if !has {
		fmt.Println("The dongle has no PIN yet — choose one (4+ characters; it locks after repeated wrong tries).")
		a, _ := readPassphrase("New dongle PIN: ")
		b, _ := readPassphrase("Again: ")
		if len(a) < 4 || a != b {
			return errors.New("PINs did not match or too short")
		}
		if err := d.SetPIN(a); err != nil {
			return err
		}
		pin = a
	} else if pin, err = pinPrompt()(); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "touch the dongle to create the policy key…")
	cred, err := d.MakeCredential(policyApp, "p3sig-policy", pin)
	if err != nil {
		return hidrawHint(err)
	}
	pub, err := skPublicKey(cred)
	if err != nil {
		return err
	}
	line := authorizedKey(pub)
	fmt.Printf("created %s\n", ssh.FingerprintSHA256(pub))
	return cmdPolicy("delegate", map[string]string{
		"root-key": firstNonEmpty(f["root-key"], "usb"), "device": line,
		"label": strings.TrimSpace(info.Product + " " + info.Serial), "expires": f["expires"],
		"api": f["api"], "key": f["key"], "account": f["account"],
	})
}
