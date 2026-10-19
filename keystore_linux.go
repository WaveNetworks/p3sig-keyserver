//go:build linux

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"golang.org/x/crypto/ssh"
)

// Linux backend: TPM 2.0 through the kernel resource manager (/dev/tpmrm0).
//
// This is the unattended machine mode from docs (machine identity §2.2): Linux
// has no platform biometric, so no prompt. Each label is ONE unrestricted ECC
// P-256 key that can both sign (ECDSA) and do ECDH (TPM2_ECDH_ZGen), like the
// single Secure Enclave key on macOS. It lives under the TCG reference ECC SRK,
// which CreatePrimary re-derives on every use, so nothing is persisted in the
// TPM. On disk is only the key's public area and its private area as the TPM
// encrypted it for that SRK: the file loads on this TPM and nowhere else.
//
// The user needs read/write on the device (group tss). P3SIG_TPM_DEVICE and
// P3SIG_TPM_DIR override the device and the key directory.

type linuxTPM struct{}

func openKeystore() (Keystore, error) {
	if _, err := os.Stat(tpmDevice()); err != nil {
		return nil, fmt.Errorf("no TPM at %s (%v); enable the TPM in the BIOS, or run on a machine that has one", tpmDevice(), err)
	}
	return linuxTPM{}, nil
}

func tpmDevice() string {
	if d := os.Getenv("P3SIG_TPM_DEVICE"); d != "" {
		return d
	}
	return "/dev/tpmrm0"
}

func tpmKeyDir() (string, error) {
	if d := os.Getenv("P3SIG_TPM_DIR"); d != "" {
		return d, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".p3sig", "tpm"), nil
}

var tpmLabelOK = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func tpmKeyPath(label string) (string, error) {
	if !tpmLabelOK.MatchString(label) || strings.HasPrefix(label, ".") {
		return "", fmt.Errorf("label %q: use letters, digits, '.', '_' or '-'", label)
	}
	dir, err := tpmKeyDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, label+".tpmkey"), nil
}

// tpmKeyTemplate: unrestricted P-256, sign + decrypt, scheme NULL (the scheme is
// chosen per command: ECDSA for Sign, ECDH for ECDH_ZGen). No auth value; the
// key is bound to this TPM (FixedTPM) and to the SRK (FixedParent).
var tpmKeyTemplate = tpm2.TPMTPublic{
	Type:    tpm2.TPMAlgECC,
	NameAlg: tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		UserWithAuth:        true,
		NoDA:                true,
		SignEncrypt:         true,
		Decrypt:             true,
	},
	Parameters: tpm2.NewTPMUPublicParms(
		tpm2.TPMAlgECC,
		&tpm2.TPMSECCParms{
			CurveID: tpm2.TPMECCNistP256,
			Scheme:  tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgNull},
		},
	),
}

// tpmSession opens the device and loads the SRK; the caller defers close().
type tpmSession struct {
	t   transport.TPMCloser
	srk tpm2.AuthHandle
}

func openTPMSession() (*tpmSession, error) {
	t, err := linuxtpm.Open(tpmDevice())
	if err != nil {
		return nil, fmt.Errorf("open %s: %w (is this user in group tss?)", tpmDevice(), err)
	}
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(t)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("TPM CreatePrimary (SRK): %w", err)
	}
	return &tpmSession{t: t, srk: tpm2.AuthHandle{
		Handle: rsp.ObjectHandle, Name: rsp.Name, Auth: tpm2.PasswordAuth(nil),
	}}, nil
}

func (s *tpmSession) close() {
	tpm2.FlushContext{FlushHandle: s.srk.Handle}.Execute(s.t)
	s.t.Close()
}

// load reads label's key file and loads it under the SRK.
func (s *tpmSession) load(label string) (tpm2.AuthHandle, *tpm2.TPMTPublic, error) {
	pub, priv, err := readTPMKeyFile(label)
	if err != nil {
		return tpm2.AuthHandle{}, nil, err
	}
	rsp, err := tpm2.Load{ParentHandle: s.srk, InPrivate: priv, InPublic: pub}.Execute(s.t)
	if err != nil {
		return tpm2.AuthHandle{}, nil, fmt.Errorf("TPM Load %q (was it made on this TPM?): %w", label, err)
	}
	contents, err := pub.Contents()
	if err != nil {
		tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(s.t)
		return tpm2.AuthHandle{}, nil, err
	}
	return tpm2.AuthHandle{Handle: rsp.ObjectHandle, Name: rsp.Name, Auth: tpm2.PasswordAuth(nil)}, contents, nil
}

func (s *tpmSession) flush(h tpm2.AuthHandle) {
	tpm2.FlushContext{FlushHandle: h.Handle}.Execute(s.t)
}

// Key file: u32 length + TPM2B_PUBLIC bytes, u32 length + TPM2B_PRIVATE bytes.
func writeTPMKeyFile(label string, pub tpm2.TPM2BPublic, priv tpm2.TPM2BPrivate) error {
	path, err := tpmKeyPath(label)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	var buf []byte
	for _, part := range [][]byte{tpm2.Marshal(pub), tpm2.Marshal(priv)} {
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(part)))
		buf = append(buf, part...)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(buf); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	return f.Close()
}

func readTPMKeyFile(label string) (tpm2.TPM2BPublic, tpm2.TPM2BPrivate, error) {
	var pub tpm2.TPM2BPublic
	var priv tpm2.TPM2BPrivate
	path, err := tpmKeyPath(label)
	if err != nil {
		return pub, priv, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return pub, priv, fmt.Errorf("no TPM key %q (create it with: p3sig setup --label %s)", label, label)
		}
		return pub, priv, err
	}
	var parts [2][]byte
	for i := range parts {
		if len(b) < 4 || uint32(len(b)-4) < binary.BigEndian.Uint32(b) {
			return pub, priv, fmt.Errorf("%s is truncated", path)
		}
		n := binary.BigEndian.Uint32(b)
		parts[i], b = b[4:4+n], b[4+n:]
	}
	p, err := tpm2.Unmarshal[tpm2.TPM2BPublic](parts[0])
	if err != nil {
		return pub, priv, fmt.Errorf("%s: public area: %w", path, err)
	}
	k, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](parts[1])
	if err != nil {
		return pub, priv, fmt.Errorf("%s: private area: %w", path, err)
	}
	return *p, *k, nil
}

// tpmPoint returns the key's public point as uncompressed SEC1 (0x04‖X‖Y).
func tpmPoint(pub *tpm2.TPMTPublic) ([]byte, error) {
	ecc, err := pub.Unique.ECC()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 65)
	out[0] = 0x04
	new(big.Int).SetBytes(ecc.X.Buffer).FillBytes(out[1:33])
	new(big.Int).SetBytes(ecc.Y.Buffer).FillBytes(out[33:65])
	return out, nil
}

func tpmSSHLine(pub *tpm2.TPMTPublic, label string) (string, error) {
	point, err := tpmPoint(pub)
	if err != nil {
		return "", err
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), point)
	if x == nil {
		return "", fmt.Errorf("TPM returned a point that is not on P-256")
	}
	sshPub, err := ssh.NewPublicKey(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " " + label, nil
}

func (linuxTPM) Create(label string) (string, error) {
	if path, err := tpmKeyPath(label); err != nil {
		return "", err
	} else if _, err := os.Stat(path); err == nil {
		return "", fmt.Errorf("key %q already exists; remove it first: p3sig setup --label %s --delete", label, label)
	}
	s, err := openTPMSession()
	if err != nil {
		return "", err
	}
	defer s.close()
	rsp, err := tpm2.Create{ParentHandle: s.srk, InPublic: tpm2.New2B(tpmKeyTemplate)}.Execute(s.t)
	if err != nil {
		return "", fmt.Errorf("TPM Create: %w", err)
	}
	if err := writeTPMKeyFile(label, rsp.OutPublic, rsp.OutPrivate); err != nil {
		return "", err
	}
	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		return "", err
	}
	return tpmSSHLine(pub, label)
}

func (linuxTPM) PublicKey(label string) (string, error) {
	pub, _, err := readTPMKeyFile(label)
	if err != nil {
		return "", err
	}
	contents, err := pub.Contents()
	if err != nil {
		return "", err
	}
	return tpmSSHLine(contents, label)
}

// Sign hashes data with SHA-256 (as the other backends do) and returns r||s.
func (linuxTPM) Sign(label string, data []byte) ([]byte, error) {
	s, err := openTPMSession()
	if err != nil {
		return nil, err
	}
	defer s.close()
	key, _, err := s.load(label)
	if err != nil {
		return nil, err
	}
	defer s.flush(key)
	digest := sha256.Sum256(data)
	rsp, err := tpm2.Sign{
		KeyHandle: key,
		Digest:    tpm2.TPM2BDigest{Buffer: digest[:]},
		InScheme: tpm2.TPMTSigScheme{
			Scheme:  tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256}),
		},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
	}.Execute(s.t)
	if err != nil {
		return nil, fmt.Errorf("TPM Sign: %w", err)
	}
	sig, err := rsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	new(big.Int).SetBytes(sig.SignatureR.Buffer).FillBytes(out[:32])
	new(big.Int).SetBytes(sig.SignatureS.Buffer).FillBytes(out[32:])
	return out, nil
}

// CreateAgreementKey returns the label's point: like macOS, the one key does
// both signing and ECDH, so there is no second key to make.
func (linuxTPM) CreateAgreementKey(label string) ([]byte, error) {
	pub, _, err := readTPMKeyFile(label)
	if err != nil {
		return nil, err
	}
	contents, err := pub.Contents()
	if err != nil {
		return nil, err
	}
	return tpmPoint(contents)
}

func (linuxTPM) Agree(label string, peerPubSEC1 []byte) ([]byte, error) {
	if len(peerPubSEC1) != 65 || peerPubSEC1[0] != 0x04 {
		return nil, fmt.Errorf("peer key must be a 65-byte uncompressed P-256 point")
	}
	if x, _ := elliptic.Unmarshal(elliptic.P256(), peerPubSEC1); x == nil {
		return nil, fmt.Errorf("peer key is not on P-256")
	}
	s, err := openTPMSession()
	if err != nil {
		return nil, err
	}
	defer s.close()
	key, _, err := s.load(label)
	if err != nil {
		return nil, err
	}
	defer s.flush(key)
	rsp, err := tpm2.ECDHZGen{
		KeyHandle: key,
		InPoint: tpm2.New2B(tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: peerPubSEC1[1:33]},
			Y: tpm2.TPM2BECCParameter{Buffer: peerPubSEC1[33:65]},
		}),
	}.Execute(s.t)
	if err != nil {
		return nil, fmt.Errorf("TPM ECDH_ZGen: %w", err)
	}
	point, err := rsp.OutPoint.Contents()
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(point.X.Buffer).FillBytes(make([]byte, 32)), nil
}

func (linuxTPM) Delete(label string) error {
	path, err := tpmKeyPath(label)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
