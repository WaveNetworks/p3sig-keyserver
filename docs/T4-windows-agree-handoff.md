# T4 handoff — Windows Hello / CNG `Agree` (ECDH) — run on Windows

**You are a Claude session on the Windows desktop.** Implement + test task **T4**: the
Windows Hello / TPM ECDH backend for device-enrollment vault-key unwrap. This *cannot* be
built or tested from Linux (CNG/TPM via syscalls), which is why it's handed to you.

Background: `docs/device-enrollment-*` in the **p3sig** repo. You only need this file +
the code in *this* repo. `CONTEXT.md` and `docs/TODO-windows.md` document the already-
implemented Create/Sign CNG plumbing (`ncrypt.dll`/`bcrypt.dll` via
`golang.org/x/sys/windows`, no cgo) that you'll mirror.

## What already exists (don't redo)
- `keystore.go` — the `Keystore` interface. **T1 already added** `Agree(label string,
  peerPubSEC1 []byte) (shared []byte, err error)`.
- `keystore_windows.go` — `winHello` implements Create/PublicKey/Sign/Delete via NCrypt.
  It has a **not-implemented `Agree` stub** — that's what you replace.
- `wrap.go` (task T2) — portable wrap/unwrap; `UnwrapECDH(blob, agree)` calls your `Agree`.

## Step 0 — sanity: toolchain + T2 vectors pass on Windows
```
git pull
go build ./...
go test -run "TestHKDF|TestWrap|TestAssemble|TestPassphrase|TestArgon2id|TestTamper|TestCross|TestScheme" -v
```
All T2 tests must pass (pure Go). If not, stop and report.

## The contract (from keystore.go)
`Agree(label, peerPubSEC1)` = ECDH between the Hello/TPM key `label` and `peerPubSEC1`
(uncompressed SEC1 point `0x04‖X‖Y`, 65 bytes), prompting Hello, returning the
**32-byte big-endian X**.

## ⚠️ Two gotchas — read before coding

1. **ECDSA keys cannot do ECDH on CNG.** The key `Create` makes is
   `BCRYPT_ECDSA_P256` — a *signing* key. `NCryptSecretAgreement` requires an
   **`NCRYPT_ECDH_P256_ALGORITHM`** key. They are different algorithms; one key cannot do
   both on Windows. So device enrollment needs a **dedicated ECDH key**, separate from the
   SSH signing key. Recommended: add `CreateAgreementKey(label)` to the `Keystore`
   interface (also add a Linux stub so it compiles cross-platform, mirroring T1), create
   it with `NCRYPT_ECDH_P256_ALGORITHM` + the Hello UI policy, and have `Agree` open *that*
   key. (The macOS session may get away with one dual-purpose key; Windows will not.)

2. **`NCryptDeriveKey(BCRYPT_KDF_RAW_SECRET)` returns the shared secret little-endian.**
   You MUST reverse the bytes to return the big-endian X coordinate (wrap.go / the macOS
   backend both use big-endian). This is a classic CNG footgun.

## Implement `Agree` (and the ECDH key creation)
Add lazy-proc bindings next to the existing ones: `NCryptImportKey`,
`NCryptSecretAgreement`, `NCryptDeriveKey`, `NCryptCreatePersistedKey` (if not already
present for the ECDH key).

`CreateAgreementKey(label)` (or a purpose flag on Create):
1. `NCryptOpenStorageProvider(&hProv, "Microsoft Platform Crypto Provider", 0)` (TPM;
   fall back to the software KSP and note it).
2. `NCryptCreatePersistedKey(hProv, &hKey, NCRYPT_ECDH_P256_ALGORITHM, L"p3sig\\<label>-ecdh", 0, 0)`.
3. Set `NCRYPT_UI_POLICY` with `NCRYPT_UI_PROTECT_KEY_FLAG` (Hello prompt on use).
4. `NCryptFinalizeKey`. Export `BCRYPT_ECCPUBLIC_BLOB`, build the SEC1 `0x04‖X‖Y` (65B)
   for the server (store as `chip_public_key`).

`Agree(label, peerPubSEC1)`:
1. Open the persisted ECDH key (`NCryptOpenKey`, `p3sig\\<label>-ecdh`).
2. Import the peer public key: build a `BCRYPT_ECCKEY_BLOB` =
   `{dwMagic: BCRYPT_ECDH_PUBLIC_P256_MAGIC (0x314B4345), cbKey: 32}` followed by
   `X = peerPubSEC1[1:33]`, `Y = peerPubSEC1[33:65]` (big-endian, as-is). Import via
   `NCryptImportKey(hProv, 0, BCRYPT_ECCPUBLIC_BLOB, ..., &hPeer, blob, len, 0)`.
3. `NCryptSecretAgreement(hKey, hPeer, &hSecret, 0)` — prompts Hello.
4. `NCryptDeriveKey(hSecret, BCRYPT_KDF_RAW_SECRET, NULL, out(32), &cb, 0)`.
5. **Reverse `out`** → big-endian 32-byte X. Free all handles. Return it.

Replace the stub:
```go
func (winHello) Agree(label string, peerPubSEC1 []byte) ([]byte, error) {
    // open ECDH key, import peer, NCryptSecretAgreement + NCryptDeriveKey(RAW_SECRET),
    // reverse to big-endian, return 32 bytes.
}
```

## Test — real round-trip through Hello/TPM
Add to `keystore_windows_test.go`. Convert the chip ECDH pubkey to `*ecdh.PublicKey`.
If `CreateAgreementKey` returns the SEC1 point directly, use
`ecdh.P256().NewPublicKey(sec1)`; otherwise convert from the SSH line as below.
```go
func TestWinHello_AgreeRoundTrip(t *testing.T) {
    if os.Getenv("P3SIG_HW_TEST") == "" { t.Skip("set P3SIG_HW_TEST=1 to run (Windows Hello)") }
    ks := winHello{}
    label := "p3sig-test-agree"
    defer ks.Delete(label + "-ecdh")            // delete whatever CreateAgreementKey made
    sec1, err := ks.CreateAgreementKey(label)   // returns the chip ECDH pub (SEC1 65B)
    if err != nil { t.Fatal(err) }
    chipPub, err := ecdh.P256().NewPublicKey(sec1)
    if err != nil { t.Fatal(err) }

    secret := bytes.Repeat([]byte{0x5a}, 32)
    blob, err := WrapECDH(secret, chipPub); if err != nil { t.Fatal(err) }
    got, err := UnwrapECDH(blob, func(eph []byte) ([]byte, error) {
        return ks.Agree(label, eph)             // Hello prompt here
    })
    if err != nil { t.Fatal(err) }
    if !bytes.Equal(got, secret) { t.Fatalf("round-trip mismatch") }
}
```
Run:
```
go build ./...
$env:P3SIG_HW_TEST=1; go test -run TestWinHello_AgreeRoundTrip -v
go test ./...
gofmt -l .; go vet ./...
```

## Definition of done / report back
- ECDH key creation + `Agree` implemented (with the little-endian reversal); real
  round-trip passes through Hello/TPM; T2 vectors still pass; build/vet/gofmt clean.
- **Report:** the interface shape you settled on (`CreateAgreementKey` vs a purpose flag),
  TPM provider vs software-KSP fallback, and any Hello prompt-count / UX notes for enroll.
- Commit to `main` with a `T4:` message (no release — tag-driven). Note T4 done so
  `docs/device-enrollment-phase1-tasks.md` in the **p3sig** repo can be updated.

## Coordinate with T3
T3 (macOS) and T4 (Windows) must agree on the interface. If you add `CreateAgreementKey`,
the macOS session should implement the same method (its SE key can likely back both Agree
and the SSH signer, but the method keeps enroll/T7 platform-uniform). Whichever session
lands first, put the interface method + Linux stub in `keystore.go`/`keystore_stub.go` so
the other rebases onto it.
