# Dev setup — Windows (Windows Hello / TPM)

The environment a fresh Windows session otherwise re-derives each time.

## Toolchain
- **Go 1.21** (matches `go.mod` + CI). Install from go.dev or `winget install GoLang.Go`.
- **No cgo needed.** `keystore_windows.go` is pure Go — it calls CNG/NCrypt via
  `golang.org/x/sys/windows` (lazy `ncrypt.dll`), and the named-pipe agent uses
  `github.com/Microsoft/go-winio`. So it also **cross-compiles from Linux**
  (`GOOS=windows GOARCH=amd64 go build ./...`) — CI's ubuntu job effectively covers the
  Windows *compile*; only the Hello round-trip needs a real machine.
- A machine with **Windows Hello** configured (PIN/biometric) and ideally a **TPM 2.0**.

## Device-free checks (same as CI)
```pwsh
go build ./...
go vet ./...
gofmt -l .        # must print nothing
go test ./...     # Hello tests self-skip without P3SIG_HW_TEST / P3SIG_HELLO_TEST
```

## Running the Windows Hello / TPM hardware test (the part only Windows can do)

No code signing needed — just run the opt-in test; each agreement/sign prompts Hello.

```pwsh
$env:P3SIG_HW_TEST = "1"
go test -run TestWinHello_AgreeRoundTrip -v
# Sign round-trip: $env:P3SIG_HELLO_TEST = "1"; optionally $env:P3SIG_HELLO_LABEL = "..."
```
Expect a Windows Hello prompt and a PASS (`WrapECDH → Agree → UnwrapECDH` recovers the
secret). Paste that line into your handoff report.

## Gotchas (confirmed in the T4 session — `keystore_windows.go`)
- **CNG ECDSA signing keys cannot do ECDH.** Agreement uses a *dedicated* ECDH P-256 key
  (`NCRYPT_ECDH_P256_ALGORITHM`) held under `p3sig\<label>-ecdh`, created by
  `CreateAgreementKey`, which returns the chip's uncompressed **SEC1** point (65 bytes)
  for `chip_public_key`.
- **`NCryptSecretAgreement` → `NCryptDeriveKey(BCRYPT_KDF_RAW_SECRET)` yields the shared
  secret little-endian** — the backend reverses it to big-endian X to match SEC1 / the
  T2 wrap spec. Don't double-reverse.
- TPM provider is tried first with a **loud software-KSP fallback** — note in output which
  was used; a software key is not hardware-bound.
- Open follow-up: `CreateAgreementKey` is currently a concrete `winHello` method, **not**
  on the `Keystore` interface — promote it (interface + darwin impl) once a Mac session
  can compile-verify the darwin side. That is an **interface-first** change → its own PR
  to `main` before any dependent platform work (see `CONTRIBUTING.md`).
