//go:build windows

package main

// Windows implementation of the Keystore interface: a non-extractable ECDSA
// P-256 key held in the TPM via CNG (the "Microsoft Platform Crypto Provider")
// and gated by Windows Hello. The private key never leaves the chip; signing
// triggers a Hello prompt. See docs/TODO-windows.md.
//
// CNG is reached through ncrypt.dll via golang.org/x/sys/windows lazy-loaded
// procs — no cgo. CNG returns ECDSA signatures as r||s (each 32 bytes,
// big-endian); the shared agent (agent.go) normalizes that to the SSH wire form.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"
)

// openKeystore returns the Windows (CNG/TPM) implementation.
func openKeystore() (Keystore, error) { return winHello{}, nil }

type winHello struct{}

// ─── CNG procs (ncrypt.dll) ─────────────────────────────────────────────────

var (
	ncrypt = windows.NewLazySystemDLL("ncrypt.dll")

	procOpenStorageProvider = ncrypt.NewProc("NCryptOpenStorageProvider")
	procCreatePersistedKey  = ncrypt.NewProc("NCryptCreatePersistedKey")
	procOpenKey             = ncrypt.NewProc("NCryptOpenKey")
	procSetProperty         = ncrypt.NewProc("NCryptSetProperty")
	procFinalizeKey         = ncrypt.NewProc("NCryptFinalizeKey")
	procExportKey           = ncrypt.NewProc("NCryptExportKey")
	procImportKey           = ncrypt.NewProc("NCryptImportKey")
	procSecretAgreement     = ncrypt.NewProc("NCryptSecretAgreement")
	procDeriveKey           = ncrypt.NewProc("NCryptDeriveKey")
	procSignHash            = ncrypt.NewProc("NCryptSignHash")
	procDeleteKey           = ncrypt.NewProc("NCryptDeleteKey")
	procFreeObject          = ncrypt.NewProc("NCryptFreeObject")
)

const (
	msPlatformProvider = "Microsoft Platform Crypto Provider"      // TPM-backed
	msSoftwareProvider = "Microsoft Software Key Storage Provider" // fallback, no HW

	algECDSAP256  = "ECDSA_P256"    // BCRYPT_ECDSA_P256_ALGORITHM (signing)
	algECDHP256   = "ECDH_P256"     // NCRYPT_ECDH_P256_ALGORITHM (key agreement)
	blobECCPublic = "ECCPUBLICBLOB" // BCRYPT_ECCPUBLIC_BLOB
	propUIPolicy  = "UI Policy"     // NCRYPT_UI_POLICY_PROPERTY

	// BCRYPT_KDF_RAW_SECRET — hands back the ECDH shared secret untouched. CNG
	// spells it "TRUNCATE"; the returned bytes are LITTLE-endian (classic footgun).
	bcryptKDFRawSecret = "TRUNCATE"

	ncryptUIProtectKeyFlag = 0x00000001 // require auth (Windows Hello) on use

	bcryptECDSAPublicP256Magic = 0x31534345 // "ECS1" (BCRYPT_ECDSA_PUBLIC_P256_MAGIC)
	bcryptECDHPublicP256Magic  = 0x314B4345 // "ECK1" (BCRYPT_ECDH_PUBLIC_P256_MAGIC)
)

// ncryptUIPolicy mirrors NCRYPT_UI_POLICY (sizeof == 32 on amd64).
type ncryptUIPolicy struct {
	Version       uint32
	Flags         uint32
	CreationTitle *uint16
	FriendlyName  *uint16
	Description   *uint16
}

// keyName is the CNG key container name (namespaced under "p3sig").
func keyName(label string) string { return `p3sig\` + label }

// agreeName is the container name of the dedicated ECDH key for device enrollment.
// It is SEPARATE from the SSH signing key: CNG will not let one key do both signing
// and key agreement (the signer is BCRYPT_ECDSA_P256, agreement needs ECDH_P256).
func agreeName(label string) string { return keyName(label + "-ecdh") }

// ─── Keystore interface ─────────────────────────────────────────────────────

func (winHello) Create(label string) (string, error) {
	// Refuse to clobber an existing key — be explicit, let the user --delete.
	if prov, key, _, err := openExistingKey(label); err == nil {
		freeObject(key)
		freeObject(prov)
		return "", fmt.Errorf("key %q already exists; remove it first: p3sig setup --label %s --delete", label, label)
	}

	prov, provName, err := openProvider()
	if err != nil {
		return "", err
	}
	defer freeObject(prov)

	algPtr, _ := windows.UTF16PtrFromString(algECDSAP256)
	namePtr, _ := windows.UTF16PtrFromString(keyName(label))
	var hKey ncHandle
	r1, _, _ := procCreatePersistedKey.Call(
		uintptr(prov), uintptr(unsafe.Pointer(&hKey)),
		uintptr(unsafe.Pointer(algPtr)), uintptr(unsafe.Pointer(namePtr)), 0, 0)
	runtime.KeepAlive(algPtr)
	runtime.KeepAlive(namePtr)
	if err := ncCheck("NCryptCreatePersistedKey", r1); err != nil {
		return "", fmt.Errorf("create key in %q: %w", provName, err)
	}
	defer freeObject(hKey)

	// Require Windows Hello on every private-key use.
	title, _ := windows.UTF16PtrFromString("p3sig SSH key")
	friendly, _ := windows.UTF16PtrFromString("p3sig SSH key (" + label + ")")
	desc, _ := windows.UTF16PtrFromString("Authorize an SSH login with your p3sig chip key")
	pol := ncryptUIPolicy{
		Version:       1,
		Flags:         ncryptUIProtectKeyFlag,
		CreationTitle: title,
		FriendlyName:  friendly,
		Description:   desc,
	}
	if err := setProperty(hKey, propUIPolicy, unsafe.Pointer(&pol), uint32(unsafe.Sizeof(pol))); err != nil {
		return "", fmt.Errorf("set Windows Hello UI policy: %w", err)
	}
	runtime.KeepAlive(&pol)
	runtime.KeepAlive(title)
	runtime.KeepAlive(friendly)
	runtime.KeepAlive(desc)

	r1, _, _ = procFinalizeKey.Call(uintptr(hKey), 0)
	if err := ncCheck("NCryptFinalizeKey", r1); err != nil {
		return "", err
	}
	if provName == msSoftwareProvider {
		fmt.Fprintln(os.Stderr, "warning: key created in the SOFTWARE provider — NOT protected by the TPM")
	}
	return exportPub(hKey, label)
}

func (winHello) PublicKey(label string) (string, error) {
	prov, key, _, err := openExistingKey(label)
	if err != nil {
		return "", err
	}
	defer freeObject(prov)
	defer freeObject(key)
	return exportPub(key, label)
}

func (winHello) Sign(label string, data []byte) ([]byte, error) {
	prov, key, _, err := openExistingKey(label)
	if err != nil {
		return nil, err
	}
	defer freeObject(prov)
	defer freeObject(key)

	h := sha256.Sum256(data) // P-256 → SHA-256

	// Size probe, then sign. The signing call is where Windows Hello prompts.
	var cb uint32
	r1, _, _ := procSignHash.Call(
		uintptr(key), 0, uintptr(unsafe.Pointer(&h[0])), uintptr(len(h)),
		0, 0, uintptr(unsafe.Pointer(&cb)), 0)
	if err := ncCheck("NCryptSignHash(size)", r1); err != nil {
		return nil, err
	}
	sig := make([]byte, cb)
	r1, _, _ = procSignHash.Call(
		uintptr(key), 0, uintptr(unsafe.Pointer(&h[0])), uintptr(len(h)),
		uintptr(unsafe.Pointer(&sig[0])), uintptr(cb), uintptr(unsafe.Pointer(&cb)), 0)
	if err := ncCheck("NCryptSignHash", r1); err != nil {
		return nil, err
	}
	return sig[:cb], nil // r||s, normalized by the shared agent
}

// CreateAgreementKey creates the dedicated non-extractable ECDH P-256 key used for
// device-enrollment vault-key unwrap (gated by Windows Hello) and returns its public
// key as an uncompressed SEC1 point (0x04‖X‖Y, 65 bytes) — the server stores this as
// chip_public_key and wraps the vault key to it (see wrap.go / WrapECDH).
//
// This is a SEPARATE key from the SSH signer that Create makes: that one is
// BCRYPT_ECDSA_P256, and CNG refuses NCryptSecretAgreement on a signing key —
// agreement requires an NCRYPT_ECDH_P256_ALGORITHM key. The two live under distinct
// container names (<label> for signing, <label>-ecdh for agreement).
//
// NB: this is intentionally a concrete method on winHello, not (yet) part of the
// Keystore interface — promoting it would require a matching darwin implementation,
// which T3 owns. Promote it to the interface once the macOS side lands.
func (winHello) CreateAgreementKey(label string) ([]byte, error) {
	// Refuse to clobber an existing ECDH key — let the user --delete first.
	if prov, key, _, err := openExistingKeyByName(agreeName(label)); err == nil {
		freeObject(key)
		freeObject(prov)
		return nil, fmt.Errorf("agreement key %q already exists; remove it first: p3sig setup --label %s-ecdh --delete", label, label)
	}

	prov, provName, err := openProvider()
	if err != nil {
		return nil, err
	}
	defer freeObject(prov)

	algPtr, _ := windows.UTF16PtrFromString(algECDHP256)
	namePtr, _ := windows.UTF16PtrFromString(agreeName(label))
	var hKey ncHandle
	r1, _, _ := procCreatePersistedKey.Call(
		uintptr(prov), uintptr(unsafe.Pointer(&hKey)),
		uintptr(unsafe.Pointer(algPtr)), uintptr(unsafe.Pointer(namePtr)), 0, 0)
	runtime.KeepAlive(algPtr)
	runtime.KeepAlive(namePtr)
	if err := ncCheck("NCryptCreatePersistedKey(ECDH)", r1); err != nil {
		return nil, fmt.Errorf("create ECDH key in %q: %w", provName, err)
	}
	defer freeObject(hKey)

	// Require Windows Hello on every use of the private key (i.e. on Agree).
	title, _ := windows.UTF16PtrFromString("p3sig device key")
	friendly, _ := windows.UTF16PtrFromString("p3sig device-unlock key (" + label + ")")
	desc, _ := windows.UTF16PtrFromString("Authorize unlocking your p3sig vault key with your chip")
	pol := ncryptUIPolicy{
		Version:       1,
		Flags:         ncryptUIProtectKeyFlag,
		CreationTitle: title,
		FriendlyName:  friendly,
		Description:   desc,
	}
	if err := setProperty(hKey, propUIPolicy, unsafe.Pointer(&pol), uint32(unsafe.Sizeof(pol))); err != nil {
		return nil, fmt.Errorf("set Windows Hello UI policy: %w", err)
	}
	runtime.KeepAlive(&pol)
	runtime.KeepAlive(title)
	runtime.KeepAlive(friendly)
	runtime.KeepAlive(desc)

	r1, _, _ = procFinalizeKey.Call(uintptr(hKey), 0)
	if err := ncCheck("NCryptFinalizeKey(ECDH)", r1); err != nil {
		return nil, err
	}
	if provName == msSoftwareProvider {
		fmt.Fprintln(os.Stderr, "warning: ECDH key created in the SOFTWARE provider — NOT protected by the TPM")
	}
	return exportPubSEC1(hKey)
}

// Agree performs ECDH between the Windows Hello ECDH key <label>-ecdh (made by
// CreateAgreementKey) and peerPubSEC1 (an uncompressed SEC1 point 0x04‖X‖Y, 65 bytes),
// prompting Windows Hello. It returns the 32-byte big-endian X coordinate of the
// shared point — the raw secret UnwrapECDH feeds to HKDF.
//
// Footgun handled here: NCryptDeriveKey(BCRYPT_KDF_RAW_SECRET) returns the shared X
// LITTLE-endian, so we reverse it to big-endian to match wrap.go and the macOS backend.
func (winHello) Agree(label string, peerPubSEC1 []byte) ([]byte, error) {
	if len(peerPubSEC1) != ecdhPubLen || peerPubSEC1[0] != 0x04 {
		return nil, fmt.Errorf("peer public key must be a %d-byte uncompressed SEC1 point (0x04‖X‖Y), got %d bytes", ecdhPubLen, len(peerPubSEC1))
	}

	// Open our persisted ECDH key under whichever provider holds it (TPM, else SW).
	prov, key, _, err := openExistingKeyByName(agreeName(label))
	if err != nil {
		return nil, err
	}
	defer freeObject(prov)
	defer freeObject(key)

	// Build a BCRYPT_ECCKEY_BLOB {magic, cbKey=32} + X(32) + Y(32) for the peer and
	// import it as a bare public key (hImportKey = 0, no wrapping).
	blob := make([]byte, 8+64)
	binary.LittleEndian.PutUint32(blob[0:4], bcryptECDHPublicP256Magic)
	binary.LittleEndian.PutUint32(blob[4:8], 32)
	copy(blob[8:], peerPubSEC1[1:65]) // X‖Y, big-endian, as-is

	blobType, _ := windows.UTF16PtrFromString(blobECCPublic)
	var hPeer ncHandle
	r1, _, _ := procImportKey.Call(
		uintptr(prov), 0, uintptr(unsafe.Pointer(blobType)), 0,
		uintptr(unsafe.Pointer(&hPeer)),
		uintptr(unsafe.Pointer(&blob[0])), uintptr(len(blob)), 0)
	runtime.KeepAlive(blobType)
	runtime.KeepAlive(&blob[0])
	if err := ncCheck("NCryptImportKey(peer)", r1); err != nil {
		return nil, err
	}
	defer freeObject(hPeer)

	// The ECDH itself — this is where Windows Hello prompts.
	var hSecret ncHandle
	r1, _, _ = procSecretAgreement.Call(uintptr(key), uintptr(hPeer), uintptr(unsafe.Pointer(&hSecret)), 0)
	if err := ncCheck("NCryptSecretAgreement", r1); err != nil {
		return nil, err
	}
	defer freeObject(hSecret)

	// Extract the raw shared secret (little-endian X).
	kdf, _ := windows.UTF16PtrFromString(bcryptKDFRawSecret)
	le := make([]byte, 32)
	var cb uint32
	r1, _, _ = procDeriveKey.Call(
		uintptr(hSecret), uintptr(unsafe.Pointer(kdf)), 0,
		uintptr(unsafe.Pointer(&le[0])), uintptr(len(le)),
		uintptr(unsafe.Pointer(&cb)), 0)
	runtime.KeepAlive(kdf)
	if err := ncCheck("NCryptDeriveKey(RAW_SECRET)", r1); err != nil {
		return nil, err
	}
	if cb != 32 {
		return nil, fmt.Errorf("unexpected ECDH shared-secret length %d (want 32)", cb)
	}

	// Reverse little-endian → big-endian X coordinate.
	be := make([]byte, 32)
	for i := 0; i < 32; i++ {
		be[i] = le[31-i]
	}
	zero(le)
	return be, nil
}

func (winHello) Delete(label string) error {
	prov, key, _, err := openExistingKey(label)
	if err != nil {
		return err
	}
	defer freeObject(prov)
	// NCryptDeleteKey frees the key handle on success.
	r1, _, _ := procDeleteKey.Call(uintptr(key), 0)
	if err := ncCheck("NCryptDeleteKey", r1); err != nil {
		freeObject(key)
		return err
	}
	return nil
}

// ─── provider / key plumbing ────────────────────────────────────────────────

type ncHandle uintptr

// openProvider opens the TPM provider, falling back (loudly) to the software
// provider if no usable TPM is present.
func openProvider() (ncHandle, string, error) {
	prov, err := openProviderByName(msPlatformProvider)
	if err == nil {
		return prov, msPlatformProvider, nil
	}
	fmt.Fprintf(os.Stderr, "warning: TPM provider unavailable (%v); falling back to software key storage — NO hardware protection\n", err)
	prov, err = openProviderByName(msSoftwareProvider)
	if err != nil {
		return 0, "", err
	}
	return prov, msSoftwareProvider, nil
}

func openProviderByName(name string) (ncHandle, error) {
	np, _ := windows.UTF16PtrFromString(name)
	var h ncHandle
	r1, _, _ := procOpenStorageProvider.Call(uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(np)), 0)
	runtime.KeepAlive(np)
	if err := ncCheck("NCryptOpenStorageProvider", r1); err != nil {
		return 0, err
	}
	return h, nil
}

// openExistingKey finds the SSH signing key for label under whichever provider holds
// it (TPM first, then software), so it works regardless of which one Create landed in.
func openExistingKey(label string) (prov, key ncHandle, provName string, err error) {
	return openExistingKeyByName(keyName(label))
}

// openExistingKeyByName is openExistingKey for an already-composed CNG container name
// (used for the -ecdh agreement key, whose name is not a bare label).
func openExistingKeyByName(name string) (prov, key ncHandle, provName string, err error) {
	var firstErr error
	for _, pn := range []string{msPlatformProvider, msSoftwareProvider} {
		p, e := openProviderByName(pn)
		if e != nil {
			if firstErr == nil {
				firstErr = e
			}
			continue
		}
		k, e := openKeyHandle(p, name)
		if e == nil {
			return p, k, pn, nil
		}
		freeObject(p)
		if firstErr == nil {
			firstErr = e
		}
	}
	if firstErr == nil {
		firstErr = fmt.Errorf("key %q not found", name)
	}
	return 0, 0, "", fmt.Errorf("open key %q: %w", name, firstErr)
}

func openKeyHandle(prov ncHandle, name string) (ncHandle, error) {
	np, _ := windows.UTF16PtrFromString(name)
	var h ncHandle
	r1, _, _ := procOpenKey.Call(uintptr(prov), uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(np)), 0, 0)
	runtime.KeepAlive(np)
	if err := ncCheck("NCryptOpenKey", r1); err != nil {
		return 0, err
	}
	return h, nil
}

func setProperty(h ncHandle, name string, p unsafe.Pointer, size uint32) error {
	np, _ := windows.UTF16PtrFromString(name)
	r1, _, _ := procSetProperty.Call(uintptr(h), uintptr(unsafe.Pointer(np)), uintptr(p), uintptr(size), 0)
	runtime.KeepAlive(np)
	return ncCheck("NCryptSetProperty", r1)
}

func freeObject(h ncHandle) {
	if h != 0 {
		procFreeObject.Call(uintptr(h))
	}
}

// exportPub exports the public ECC blob and renders it as an OpenSSH line.
func exportPub(hKey ncHandle, label string) (string, error) {
	blobType, _ := windows.UTF16PtrFromString(blobECCPublic)
	var cb uint32
	r1, _, _ := procExportKey.Call(uintptr(hKey), 0, uintptr(unsafe.Pointer(blobType)), 0, 0, 0, uintptr(unsafe.Pointer(&cb)), 0)
	if err := ncCheck("NCryptExportKey(size)", r1); err != nil {
		runtime.KeepAlive(blobType)
		return "", err
	}
	buf := make([]byte, cb)
	r1, _, _ = procExportKey.Call(uintptr(hKey), 0, uintptr(unsafe.Pointer(blobType)), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(cb), uintptr(unsafe.Pointer(&cb)), 0)
	runtime.KeepAlive(blobType)
	if err := ncCheck("NCryptExportKey", r1); err != nil {
		return "", err
	}
	return eccBlobToSSH(buf[:cb], label)
}

// exportPubSEC1 exports an ECDH public key as an uncompressed SEC1 point (0x04‖X‖Y,
// 65 bytes). CNG exports X and Y big-endian, which is exactly SEC1 order.
func exportPubSEC1(hKey ncHandle) ([]byte, error) {
	blobType, _ := windows.UTF16PtrFromString(blobECCPublic)
	var cb uint32
	r1, _, _ := procExportKey.Call(uintptr(hKey), 0, uintptr(unsafe.Pointer(blobType)), 0, 0, 0, uintptr(unsafe.Pointer(&cb)), 0)
	if err := ncCheck("NCryptExportKey(ECDH size)", r1); err != nil {
		runtime.KeepAlive(blobType)
		return nil, err
	}
	buf := make([]byte, cb)
	r1, _, _ = procExportKey.Call(uintptr(hKey), 0, uintptr(unsafe.Pointer(blobType)), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(cb), uintptr(unsafe.Pointer(&cb)), 0)
	runtime.KeepAlive(blobType)
	if err := ncCheck("NCryptExportKey(ECDH)", r1); err != nil {
		return nil, err
	}
	blob := buf[:cb]
	if len(blob) < 8 {
		return nil, fmt.Errorf("ECDH ECC blob too short (%d bytes)", len(blob))
	}
	magic := binary.LittleEndian.Uint32(blob[0:4])
	cbKey := binary.LittleEndian.Uint32(blob[4:8])
	if magic != bcryptECDHPublicP256Magic {
		return nil, fmt.Errorf("unexpected ECDH blob magic 0x%08X (want P-256 ECDH public)", magic)
	}
	if int(8+2*cbKey) > len(blob) {
		return nil, fmt.Errorf("ECDH blob truncated: have %d, need %d", len(blob), 8+2*cbKey)
	}
	sec1 := make([]byte, 1+2*cbKey)
	sec1[0] = 0x04
	copy(sec1[1:], blob[8:8+2*cbKey]) // X‖Y big-endian, as CNG exports
	return sec1, nil
}

// eccBlobToSSH parses a BCRYPT_ECCKEY_BLOB public blob (header + X||Y) into an
// "ecdsa-sha2-nistp256 AAAA... label" OpenSSH public key line.
func eccBlobToSSH(blob []byte, label string) (string, error) {
	if len(blob) < 8 {
		return "", fmt.Errorf("ECC blob too short (%d bytes)", len(blob))
	}
	magic := binary.LittleEndian.Uint32(blob[0:4])
	cbKey := binary.LittleEndian.Uint32(blob[4:8])
	if magic != bcryptECDSAPublicP256Magic {
		return "", fmt.Errorf("unexpected ECC blob magic 0x%08X (want P-256 public)", magic)
	}
	if int(8+2*cbKey) > len(blob) {
		return "", fmt.Errorf("ECC blob truncated: have %d, need %d", len(blob), 8+2*cbKey)
	}
	x := new(big.Int).SetBytes(blob[8 : 8+cbKey])
	y := new(big.Int).SetBytes(blob[8+cbKey : 8+2*cbKey])
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", err
	}
	line := string(ssh.MarshalAuthorizedKey(sshPub)) // ends with '\n'
	line = line[:len(line)-1]
	if label != "" {
		line += " " + label
	}
	return line, nil
}

// ─── error mapping ──────────────────────────────────────────────────────────

func ncCheck(op string, r1 uintptr) error {
	if r1 == 0 { // ERROR_SUCCESS
		return nil
	}
	code := uint32(r1)
	if msg, ok := ncMessages[code]; ok {
		return fmt.Errorf("%s: %s (0x%08X)", op, msg, code)
	}
	return fmt.Errorf("%s: NCrypt error 0x%08X", op, code)
}

// A few SECURITY_STATUS codes worth a human-readable hint.
var ncMessages = map[uint32]string{
	0x80090009: "NTE_BAD_FLAGS",
	0x8009000F: "NTE_EXISTS (key already exists)",
	0x80090011: "NTE_NOT_FOUND (key not found)",
	0x80090016: "NTE_BAD_KEYSET (key not found / keyset not defined)",
	0x80090022: "NTE_PERM (access denied — Windows Hello prompt may have been cancelled)",
	0x80090026: "NTE_INVALID_HANDLE",
	0x80090027: "NTE_INVALID_PARAMETER",
	0x80090029: "NTE_NOT_SUPPORTED (TPM may not support this key type/curve)",
	0x8009002A: "NTE_NO_MEMORY",
	0x80090030: "NTE_DEVICE_NOT_READY (no TPM / Hello not enrolled)",
	0x80070057: "E_INVALIDARG",
}
