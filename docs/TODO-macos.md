# TODO — macOS Secure Enclave keystore (Touch ID)

Read `CONTEXT.md` first. Goal: implement the `Keystore` interface on macOS using a
Secure Enclave key gated by Touch ID, plus the shared `setup` / `ssh-agent` glue.

**Build/test on a Mac** — this is cgo against Apple frameworks and cannot be
cross-compiled or tested from Linux. Apple Silicon or any Mac with a Secure Enclave + Touch ID.

## Approach

Secure Enclave keys are **ECDSA P-256**, non-extractable, created via the Security
framework. The private key never leaves the Enclave; you hold only a reference, and
every signature requires a Touch ID (user-presence) check.

Implement in `keystore_darwin.go` (`//go:build darwin`) with cgo:

```
#cgo LDFLAGS: -framework Security -framework CoreFoundation -framework LocalAuthentication
```

### Create(label)
1. Build a `SecAccessControl` with `SecAccessControlCreateWithFlags(kCFAllocatorDefault,
   kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
   kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryCurrentSet, &err)`.
2. `SecKeyCreateRandomKey` with attributes:
   `kSecAttrKeyType = kSecAttrKeyTypeECSECPrimeRandom`, `kSecAttrKeySizeInBits = 256`,
   `kSecAttrTokenID = kSecAttrTokenIDSecureEnclave`, and a `kSecPrivateKeyAttrs` dict
   with `kSecAttrIsPermanent = true`, `kSecAttrApplicationTag = "com.p3sig.<label>"`,
   `kSecAttrAccessControl = <the access control above>`.
3. `SecKeyCopyPublicKey` → `SecKeyCopyExternalRepresentation` returns the **X9.63
   uncompressed point** (0x04 || X || Y, 65 bytes). Parse into a Go `*ecdsa.PublicKey`
   on `elliptic.P256()`, then `ssh.NewPublicKey(pub)` → `ssh.MarshalAuthorizedKey` for
   the `ecdsa-sha2-nistp256 …` line.

### PublicKey(label) / lookup
`SecItemCopyMatching` with `kSecClass = kSecClassKey`, `kSecAttrApplicationTag =
"com.p3sig.<label>"`, `kSecReturnRef = true` → the `SecKeyRef`. Derive the public key as above.

### Sign(label, data)
1. Look up the key ref (as above). Optionally attach an `LAContext` with a reason string
   ("Authenticate SSH login") so the Touch ID prompt is meaningful.
2. `SecKeyCreateSignature(privRef, kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
   data, &err)` → **DER-encoded ECDSA** signature. (This triggers Touch ID.)
3. Return the DER bytes. The shared ssh-agent converts DER → SSH ecdsa signature blob
   (two mpints r,s); put that conversion in the shared agent code so Windows reuses it.

### Delete(label)
`SecItemDelete` matching the application tag.

## Reference implementations (lean on these, don't start blank)

- **`github.com/facebookincubator/sks`** — "Secure Key Store", a Go wrapper around exactly
  this Secure Enclave flow (create / sign / lookup with biometric access control). Strong
  template; consider vendoring or adapting it behind the `Keystore` interface.
- **`github.com/maxgoedjen/secretive`** (Swift) — reference for the UX and the
  Enclave+agent pattern.
- Apple docs: "Storing Keys in the Secure Enclave", `SecKeyCreateSignature`.

## ssh-agent on macOS
Unix socket is fine. `golang.org/x/crypto/ssh/agent.Agent`: `List` → the chip pubkey;
`Sign` → `keystore.Sign` then DER→SSH-sig conversion. Verify the Touch ID prompt fires
on each `ssh`.

## Acceptance
- `p3sig setup --label test` creates an Enclave key and prints `ecdsa-sha2-nistp256 …`.
- With `p3sig ssh-agent` running and `SSH_AUTH_SOCK` set, `ssh` to a test host that trusts
  the pubkey (direct) **and** to one with `TrustedUserCAKeys` + a cert over the chip pubkey
  succeeds, prompting Touch ID each time.
- No private key material on disk (`security find-key`/Keychain Access shows a non-exportable
  Enclave key). `go vet` clean; `go build` still works on Linux (stub returns unsupported).

## Gotchas
- Signing requires the app to be allowed Touch ID; unsigned dev binaries work in a terminal
  but a codesigned binary with the keychain-access-groups entitlement is smoother — note in README.
- `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` + `BiometryCurrentSet` means re-enrolling a
  fingerprint invalidates the key (by design). Document recovery (register a 2nd machine/USB).
- P-256 only — don't attempt Ed25519 in the Enclave.
