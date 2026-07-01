//go:build darwin

package main

// macOS implementation of the Keystore interface: a non-extractable ECDSA P-256
// key held in the Apple Secure Enclave and gated by Touch ID. The private key
// never leaves the Enclave; signing triggers a Touch ID (user-presence) prompt.
// See docs/TODO-macos.md.
//
// This reaches the Security framework through cgo. SecKeyCreateSignature returns
// an ASN.1 DER ECDSA signature; the shared agent (agent.go) normalizes DER to the
// SSH wire form, so Sign just returns the DER bytes.

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation -framework LocalAuthentication
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

static void se_set_err(char *errOut, size_t errCap, CFErrorRef e) {
	if (!errOut || errCap == 0) return;
	errOut[0] = '\0';
	if (!e) { snprintf(errOut, errCap, "unknown Security framework error"); return; }
	CFStringRef desc = CFErrorCopyDescription(e);
	if (desc) {
		CFStringGetCString(desc, errOut, (CFIndex)errCap, kCFStringEncodingUTF8);
		CFRelease(desc);
	}
}

static CFDataRef se_tag_data(const char *tag) {
	return CFDataCreate(kCFAllocatorDefault, (const UInt8 *)tag, (CFIndex)strlen(tag));
}

// Set kSecAttrAccessGroup on a dict when group is non-NULL/non-empty. On a
// codesigned macOS build the keychain operations must name the app's access
// group (its application-identifier); on an unsigned build group is empty and
// the default group is used.
static void se_set_group(CFMutableDictionaryRef d, const char *group) {
	if (!group || group[0] == '\0') return;
	CFStringRef g = CFStringCreateWithCString(kCFAllocatorDefault, group, kCFStringEncodingUTF8);
	CFDictionarySetValue(d, kSecAttrAccessGroup, g);
	CFRelease(g);
}

// Locate the private SecKeyRef for tag. Caller CFReleases. prompt may be NULL;
// when set, it is shown on the Touch ID dialog the next time the key is used.
static SecKeyRef se_copy_key(const char *tag, const char *group, const char *prompt) {
	CFDataRef t = se_tag_data(tag);
	CFMutableDictionaryRef q = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionarySetValue(q, kSecClass, kSecClassKey);
	CFDictionarySetValue(q, kSecAttrApplicationTag, t);
	CFDictionarySetValue(q, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
	CFDictionarySetValue(q, kSecReturnRef, kCFBooleanTrue);
	se_set_group(q, group);
	if (prompt) {
		CFStringRef p = CFStringCreateWithCString(kCFAllocatorDefault, prompt, kCFStringEncodingUTF8);
		CFDictionarySetValue(q, kSecUseOperationPrompt, p);
		CFRelease(p);
	}
	SecKeyRef key = NULL;
	OSStatus st = SecItemCopyMatching(q, (CFTypeRef *)&key);
	CFRelease(q);
	CFRelease(t);
	if (st != errSecSuccess) return NULL;
	return key;
}

// Copy the X9.63 uncompressed public point (0x04 || X || Y, 65 bytes for P-256).
static int se_export_pub(SecKeyRef priv, uint8_t *out, size_t *outLen, char *errOut, size_t errCap) {
	SecKeyRef pub = SecKeyCopyPublicKey(priv);
	if (!pub) { snprintf(errOut, errCap, "SecKeyCopyPublicKey failed"); return -1; }
	CFErrorRef e = NULL;
	CFDataRef d = SecKeyCopyExternalRepresentation(pub, &e);
	CFRelease(pub);
	if (!d) { se_set_err(errOut, errCap, e); if (e) CFRelease(e); return -1; }
	CFIndex n = CFDataGetLength(d);
	if ((size_t)n > *outLen) { CFRelease(d); snprintf(errOut, errCap, "public key too large (%ld bytes)", (long)n); return -1; }
	memcpy(out, CFDataGetBytePtr(d), (size_t)n);
	*outLen = (size_t)n;
	CFRelease(d);
	return 0;
}

int se_create(const char *tag, const char *group, uint8_t *out, size_t *outLen, char *errOut, size_t errCap) {
	CFErrorRef e = NULL;
	SecAccessControlRef ac = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
		kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
		kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryCurrentSet, &e);
	if (!ac) { se_set_err(errOut, errCap, e); if (e) CFRelease(e); return -1; }

	CFDataRef t = se_tag_data(tag);

	CFMutableDictionaryRef pk = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionarySetValue(pk, kSecAttrIsPermanent, kCFBooleanTrue);
	CFDictionarySetValue(pk, kSecAttrApplicationTag, t);
	CFDictionarySetValue(pk, kSecAttrAccessControl, ac);
	se_set_group(pk, group);

	int bits = 256;
	CFNumberRef bitsNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bits);

	CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionarySetValue(attrs, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
	CFDictionarySetValue(attrs, kSecAttrKeySizeInBits, bitsNum);
	CFDictionarySetValue(attrs, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
	CFDictionarySetValue(attrs, kSecPrivateKeyAttrs, pk);

	SecKeyRef priv = SecKeyCreateRandomKey(attrs, &e);
	CFRelease(attrs);
	CFRelease(bitsNum);
	CFRelease(pk);
	CFRelease(t);
	CFRelease(ac);
	if (!priv) { se_set_err(errOut, errCap, e); if (e) CFRelease(e); return -1; }
	int rc = se_export_pub(priv, out, outLen, errOut, errCap);
	CFRelease(priv);
	return rc;
}

int se_pubkey(const char *tag, const char *group, uint8_t *out, size_t *outLen, char *errOut, size_t errCap) {
	SecKeyRef priv = se_copy_key(tag, group, NULL);
	if (!priv) { snprintf(errOut, errCap, "key not found for tag %s", tag); return -1; }
	int rc = se_export_pub(priv, out, outLen, errOut, errCap);
	CFRelease(priv);
	return rc;
}

int se_sign(const char *tag, const char *group, const uint8_t *data, size_t dataLen,
            uint8_t *out, size_t *outLen, char *errOut, size_t errCap) {
	SecKeyRef priv = se_copy_key(tag, group, "Authenticate SSH login");
	if (!priv) { snprintf(errOut, errCap, "key not found for tag %s", tag); return -1; }
	CFDataRef d = CFDataCreate(kCFAllocatorDefault, data, (CFIndex)dataLen);
	CFErrorRef e = NULL;
	// Hashes data with SHA-256 internally, then signs; returns ASN.1 DER. Touch ID fires here.
	CFDataRef sig = SecKeyCreateSignature(priv, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, d, &e);
	CFRelease(d);
	CFRelease(priv);
	if (!sig) { se_set_err(errOut, errCap, e); if (e) CFRelease(e); return -1; }
	CFIndex n = CFDataGetLength(sig);
	if ((size_t)n > *outLen) { CFRelease(sig); snprintf(errOut, errCap, "signature too large (%ld bytes)", (long)n); return -1; }
	memcpy(out, CFDataGetBytePtr(sig), (size_t)n);
	*outLen = (size_t)n;
	CFRelease(sig);
	return 0;
}

// se_agree: ECDH between the SE private key <tag> and a peer public key given as
// an X9.63 uncompressed point (0x04||X||Y). Writes the raw shared value — the
// 32-byte big-endian X coordinate for P-256 — to out. Prompts Touch ID.
// Returns 0 on success, -1 on error, and -2 for the specific case where the key
// exists but does not support ECDH key exchange (so Go can report that a
// dedicated agreement key is needed — see the T3 handoff key-purpose gotcha).
int se_agree(const char *tag, const char *group,
             const uint8_t *peer, size_t peerLen,
             uint8_t *out, size_t *outLen, char *errOut, size_t errCap) {
	SecKeyRef priv = se_copy_key(tag, group, "Unlock the p3sig vault");
	if (!priv) { snprintf(errOut, errCap, "key not found for tag %s", tag); return -1; }

	// Key-purpose check: a P-256 SE key created for signing usually also supports
	// kSecKeyAlgorithmECDHKeyExchangeStandard, but verify before use.
	if (!SecKeyIsAlgorithmSupported(priv, kSecKeyOperationTypeKeyExchange,
	                                kSecKeyAlgorithmECDHKeyExchangeStandard)) {
		CFRelease(priv);
		snprintf(errOut, errCap, "secure enclave key does not support ECDH key exchange (needs a dedicated agreement key)");
		return -2;
	}

	// Rebuild the peer public key from its X9.63 uncompressed representation.
	CFDataRef peerData = CFDataCreate(kCFAllocatorDefault, peer, (CFIndex)peerLen);
	CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionarySetValue(attrs, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
	CFDictionarySetValue(attrs, kSecAttrKeyClass, kSecAttrKeyClassPublic);
	CFErrorRef e = NULL;
	SecKeyRef peerPub = SecKeyCreateWithData(peerData, attrs, &e);
	CFRelease(attrs);
	CFRelease(peerData);
	if (!peerPub) { se_set_err(errOut, errCap, e); if (e) CFRelease(e); CFRelease(priv); return -1; }

	// ECDH — Touch ID fires here. Standard exchange returns the raw shared X.
	CFDictionaryRef params = CFDictionaryCreate(kCFAllocatorDefault, NULL, NULL, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDataRef shared = SecKeyCopyKeyExchangeResult(priv,
		kSecKeyAlgorithmECDHKeyExchangeStandard, peerPub, params, &e);
	CFRelease(params);
	CFRelease(peerPub);
	CFRelease(priv);
	if (!shared) { se_set_err(errOut, errCap, e); if (e) CFRelease(e); return -1; }

	CFIndex n = CFDataGetLength(shared);
	if ((size_t)n > *outLen) { CFRelease(shared); snprintf(errOut, errCap, "shared secret too large (%ld bytes)", (long)n); return -1; }
	memcpy(out, CFDataGetBytePtr(shared), (size_t)n);
	*outLen = (size_t)n;
	CFRelease(shared);
	return 0;
}

int se_delete(const char *tag, const char *group, char *errOut, size_t errCap) {
	CFDataRef t = se_tag_data(tag);
	CFMutableDictionaryRef q = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionarySetValue(q, kSecClass, kSecClassKey);
	CFDictionarySetValue(q, kSecAttrApplicationTag, t);
	CFDictionarySetValue(q, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
	se_set_group(q, group);
	OSStatus st = SecItemDelete(q);
	CFRelease(q);
	CFRelease(t);
	if (st != errSecSuccess && st != errSecItemNotFound) {
		snprintf(errOut, errCap, "SecItemDelete failed: %d", (int)st);
		return -1;
	}
	return 0;
}
*/
import "C"

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/crypto/ssh"
)

// openKeystore returns the macOS (Secure Enclave) implementation.
func openKeystore() (Keystore, error) { return secureEnclave{}, nil }

type secureEnclave struct{}

// appTag is the kSecAttrApplicationTag used to find a key; namespaced per label.
func appTag(label string) string { return "com.p3sig." + label }

// accessGroup is the keychain access group used for all keychain operations.
// A codesigned macOS build must scope items to its own access group (its
// application-identifier, e.g. "TEAMID.com.p3sig.keys"); set it via
// P3SIG_KEYCHAIN_GROUP. Empty (unsigned/dev builds) uses the default group.
//
// Returns a C string the caller must C.free, or nil when unset.
func accessGroup() *C.char {
	g := os.Getenv("P3SIG_KEYCHAIN_GROUP")
	if g == "" {
		return nil
	}
	return C.CString(g)
}

// cStr reads a NUL-terminated C string out of a Go-owned buffer the C side wrote.
func cStr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// x963ToSSHLine turns an X9.63 uncompressed P-256 point into an OpenSSH public
// key line ("ecdsa-sha2-nistp256 AAAA... label").
func x963ToSSHLine(raw []byte, label string) (string, error) {
	if len(raw) != 65 || raw[0] != 0x04 {
		return "", fmt.Errorf("unexpected Secure Enclave public key (%d bytes, want 65-byte uncompressed point)", len(raw))
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(raw[1:33]),
		Y:     new(big.Int).SetBytes(raw[33:65]),
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	return line + " " + label, nil
}

func (secureEnclave) Create(label string) (string, error) {
	tag := C.CString(appTag(label))
	defer C.free(unsafe.Pointer(tag))
	group := accessGroup()
	if group != nil {
		defer C.free(unsafe.Pointer(group))
	}
	out := make([]byte, 128)
	outLen := C.size_t(len(out))
	errBuf := make([]byte, 256)
	rc := C.se_create(tag, group,
		(*C.uint8_t)(unsafe.Pointer(&out[0])), &outLen,
		(*C.char)(unsafe.Pointer(&errBuf[0])), C.size_t(len(errBuf)))
	if rc != 0 {
		return "", fmt.Errorf("secure enclave: create key %q: %s", label, cStr(errBuf))
	}
	return x963ToSSHLine(out[:outLen], label)
}

func (secureEnclave) PublicKey(label string) (string, error) {
	tag := C.CString(appTag(label))
	defer C.free(unsafe.Pointer(tag))
	group := accessGroup()
	if group != nil {
		defer C.free(unsafe.Pointer(group))
	}
	out := make([]byte, 128)
	outLen := C.size_t(len(out))
	errBuf := make([]byte, 256)
	rc := C.se_pubkey(tag, group,
		(*C.uint8_t)(unsafe.Pointer(&out[0])), &outLen,
		(*C.char)(unsafe.Pointer(&errBuf[0])), C.size_t(len(errBuf)))
	if rc != 0 {
		return "", fmt.Errorf("secure enclave: public key %q: %s", label, cStr(errBuf))
	}
	return x963ToSSHLine(out[:outLen], label)
}

func (secureEnclave) Sign(label string, data []byte) ([]byte, error) {
	tag := C.CString(appTag(label))
	defer C.free(unsafe.Pointer(tag))
	group := accessGroup()
	if group != nil {
		defer C.free(unsafe.Pointer(group))
	}
	var dptr *C.uint8_t
	if len(data) > 0 {
		dptr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	out := make([]byte, 256) // DER P-256 signature is ~70-72 bytes
	outLen := C.size_t(len(out))
	errBuf := make([]byte, 256)
	rc := C.se_sign(tag, group, dptr, C.size_t(len(data)),
		(*C.uint8_t)(unsafe.Pointer(&out[0])), &outLen,
		(*C.char)(unsafe.Pointer(&errBuf[0])), C.size_t(len(errBuf)))
	if rc != 0 {
		return nil, fmt.Errorf("secure enclave: sign with %q: %s", label, cStr(errBuf))
	}
	sig := make([]byte, int(outLen))
	copy(sig, out[:outLen])
	return sig, nil // ASN.1 DER; agent.go normalizeECDSASig handles it
}

// Agree performs ECDH between the Secure Enclave key for label and peerPubSEC1
// (a peer/ephemeral public key as a 65-byte uncompressed SEC1 point, 0x04||X||Y),
// prompting Touch ID. It returns the 32-byte big-endian X coordinate of the
// shared point — the Standard ECDH result is already big-endian on macOS, so no
// byte reversal is needed (that's a Windows concern). Used to unwrap an
// enclave-held vault key; see wrap.go's UnwrapECDH and the T3 handoff.
func (secureEnclave) Agree(label string, peerPubSEC1 []byte) ([]byte, error) {
	if len(peerPubSEC1) != 65 || peerPubSEC1[0] != 0x04 {
		return nil, fmt.Errorf("secure enclave: agree with %q: peer key must be a 65-byte uncompressed SEC1 point (0x04||X||Y), got %d bytes", label, len(peerPubSEC1))
	}
	tag := C.CString(appTag(label))
	defer C.free(unsafe.Pointer(tag))
	group := accessGroup()
	if group != nil {
		defer C.free(unsafe.Pointer(group))
	}
	out := make([]byte, 32) // P-256 shared X is exactly 32 bytes
	outLen := C.size_t(len(out))
	errBuf := make([]byte, 256)
	rc := C.se_agree(tag, group,
		(*C.uint8_t)(unsafe.Pointer(&peerPubSEC1[0])), C.size_t(len(peerPubSEC1)),
		(*C.uint8_t)(unsafe.Pointer(&out[0])), &outLen,
		(*C.char)(unsafe.Pointer(&errBuf[0])), C.size_t(len(errBuf)))
	if rc != 0 {
		return nil, fmt.Errorf("secure enclave: agree with %q: %s", label, cStr(errBuf))
	}
	shared := make([]byte, int(outLen))
	copy(shared, out[:outLen])
	return shared, nil
}

func (secureEnclave) Delete(label string) error {
	tag := C.CString(appTag(label))
	defer C.free(unsafe.Pointer(tag))
	group := accessGroup()
	if group != nil {
		defer C.free(unsafe.Pointer(group))
	}
	errBuf := make([]byte, 256)
	rc := C.se_delete(tag, group, (*C.char)(unsafe.Pointer(&errBuf[0])), C.size_t(len(errBuf)))
	if rc != 0 {
		return fmt.Errorf("secure enclave: delete %q: %s", label, cStr(errBuf))
	}
	return nil
}
