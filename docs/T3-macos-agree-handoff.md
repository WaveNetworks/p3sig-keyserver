# T3 handoff — Secure Enclave `Agree` (ECDH) — run on a Mac

**You are a Claude session on a Mac.** Implement + test task **T3**: the Secure Enclave
ECDH backend for device-enrollment vault-key unwrap. This *cannot* be built or tested
from Linux (cgo against Apple frameworks), which is why it's handed to you.

Background (design + why): `docs/device-enrollment-*` in the **p3sig** repo (sibling
product repo). You only need this file + the code in *this* repo. Read `CONTEXT.md` and
`docs/BUILD-macos.md` for the build environment; `docs/TODO-macos.md` documents the
already-implemented Create/Sign SE plumbing you'll mirror.

## What already exists (don't redo)
- `keystore.go` — the `Keystore` interface. **T1 already added** `Agree(label string,
  peerPubSEC1 []byte) (shared []byte, err error)`.
- `keystore_darwin.go` — `secureEnclave` implements Create/PublicKey/Sign/Delete via a
  cgo shim (`se_*` C functions). It has a **not-implemented `Agree` stub** — that's what
  you replace.
- `wrap.go` (task T2) — portable wrap/unwrap. `UnwrapECDH(blob, agree)` calls your
  `Agree`. It's fully tested and platform-independent.

## Step 0 — sanity: toolchain + T2 vectors pass on your Mac
```
git pull                      # get latest main (has T1 + T2)
go build ./...
go test -run 'TestHKDF|TestWrap|TestAssemble|TestPassphrase|TestArgon2id|TestTamper|TestCross|TestScheme' -v
```
All T2 tests must pass (they're pure Go). If they don't, stop and report — something's
wrong with the toolchain, not your work.

## The contract (from keystore.go)
`Agree(label, peerPubSEC1)` performs ECDH between the Enclave key named `label` and
`peerPubSEC1` (a peer/ephemeral public key as an **uncompressed SEC1 point**,
`0x04‖X‖Y`, 65 bytes), prompting Touch ID, and returns the **32-byte big-endian X**
coordinate of the shared point. On macOS the Standard ECDH result is already big-endian —
no byte reversal (that's a Windows-only concern).

## ⚠️ Key-purpose gotcha — verify first
The SE key `Create` makes is a P-256 key used for ECDSA signing (SSH). ECDH key agreement
is a *different* operation. On Secure Enclave a single P-256 key **usually supports both**
signing and `kSecKeyAlgorithmECDHKeyExchangeStandard`, but **verify** with
`SecKeyIsAlgorithmSupported(privKey, kSecKeyOperationTypeKeyExchange, algo)`.
- If the existing key supports ECDH → `Agree` can use the same key `Create` made. 
- If it does **not** (e.g. the access-control flags restrict it) → the enroll flow needs
  a **dedicated ECDH key**. In that case add a `CreateAgreementKey(label)` to the
  interface (compile it on Linux too as a stub, mirroring T1) and have `Agree` open that
  key. **Report which case you hit** — it decides whether T7's enroll creates one key or
  two. (Windows definitely needs a separate ECDH key; see the T4 handoff.)

## Implement `Agree`
Add a `se_agree` C function next to `se_sign`, and call it from Go. Sketch:

C shim (in the cgo preamble):
```c
// se_agree: ECDH(SE key <tag>, peer X9.63 pubkey) -> raw 32-byte shared X.
int se_agree(const char *tag, const char *group,
             const uint8_t *peer, size_t peerLen,
             uint8_t *out, size_t *outLen,
             char *err, size_t errLen);
```
Implementation:
1. Look up the private `SecKeyRef` by application tag (same query `se_sign` uses).
2. Rebuild the peer key: `SecKeyCreateWithData(CFData(peer,peerLen), {kSecAttrKeyType:
   kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPublic}, &err)`.
   (X9.63 uncompressed is exactly what `Create`'s public export produces, so formats match.)
3. `CFDataRef shared = SecKeyCopyKeyExchangeResult(priv,
   kSecKeyAlgorithmECDHKeyExchangeStandard, peerPub, emptyParams, &err);` — prompts Touch ID.
4. Copy the 32 bytes out; set `*outLen`. Release CF objects.

Go side (replace the stub):
```go
func (secureEnclave) Agree(label string, peerPubSEC1 []byte) ([]byte, error) {
    // ... marshal tag/group like Sign, call C.se_agree, return the 32-byte result ...
}
```
Return `Err... fmt.Errorf` on the C error string, exactly like `Sign`.

## Test — real round-trip through the Enclave
Add to `keystore_darwin_test.go`. You need to turn the chip's public key into an
`*ecdh.PublicKey` for `WrapECDH`. Helper (works for any ECDSA SSH pubkey line):
```go
func sshPubToECDH(t *testing.T, line string) *ecdh.PublicKey {
    pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
    if err != nil { t.Fatal(err) }
    ecpub := pk.(ssh.CryptoPublicKey).CryptoPublicKey().(*ecdsa.PublicKey)
    k, err := ecpub.ECDH()            // Go 1.20+: *ecdsa.PublicKey -> *ecdh.PublicKey
    if err != nil { t.Fatal(err) }
    return k
}
```
Round-trip test (prompts Touch ID twice — create + agree; guard with an env flag so CI
without a human doesn't hang):
```go
func TestSecureEnclave_AgreeRoundTrip(t *testing.T) {
    if os.Getenv("P3SIG_HW_TEST") == "" { t.Skip("set P3SIG_HW_TEST=1 to run (Touch ID)") }
    ks := secureEnclave{}
    label := "p3sig-test-agree"
    defer ks.Delete(label)
    pub, err := ks.Create(label); if err != nil { t.Fatal(err) }

    chipPub := sshPubToECDH(t, pub)
    secret := bytes.Repeat([]byte{0x5a}, 32)               // stands in for the vault key
    blob, err := WrapECDH(secret, chipPub); if err != nil { t.Fatal(err) }

    got, err := UnwrapECDH(blob, func(eph []byte) ([]byte, error) {
        return ks.Agree(label, eph)                        // Touch ID here
    })
    if err != nil { t.Fatal(err) }
    if !bytes.Equal(got, secret) { t.Fatalf("round-trip mismatch") }
}
```
Run:
```
go build ./...
P3SIG_HW_TEST=1 go test -run TestSecureEnclave_AgreeRoundTrip -v
go test ./...        # confirm nothing else broke
gofmt -l . ; go vet ./...
```

## Definition of done / report back
- `Agree` implemented; `WrapECDH`→`UnwrapECDH` round-trips through the real Enclave with
  Touch ID; T2 vectors still pass; build/vet/gofmt clean.
- **Report:** did the Create'd SE key support ECDH directly, or did you need a dedicated
  ECDH key (`CreateAgreementKey`)? Any prompt-count / UX notes for enroll (T7).
- Commit to `main` with a `T3:` message (no release — tag-driven). Update
  `docs/device-enrollment-phase1-tasks.md` T3 → done in the **p3sig** repo, or note it in
  your report so it can be recorded.
