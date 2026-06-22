# TODO — Windows Hello / TPM keystore

Read `CONTEXT.md` first. Goal: implement the `Keystore` interface on Windows using a
TPM-backed key gated by Windows Hello, plus the shared `setup` / `ssh-agent` glue.

**Build/test on the Windows desktop** — this is CNG/TPM via syscalls and cannot be
tested from Linux. Needs a TPM 2.0 (standard on Win10/11) and Windows Hello enrolled.

## Approach (recommended: CNG + Microsoft Platform Crypto Provider)

A persistent **ECDSA P-256** key in the TPM via CNG (NCrypt), gated by Windows Hello.
The private key is non-extractable (TPM-resident); signing prompts Hello.

Implement in `keystore_windows.go` (`//go:build windows`). You can use
`golang.org/x/sys/windows` to call `ncrypt.dll`/`bcrypt.dll` via `syscall.NewLazyDLL`
(no cgo needed), or cgo if you prefer.

### Create(label)
1. `NCryptOpenStorageProvider(&hProv, "Microsoft Platform Crypto Provider", 0)` — the
   TPM-backed provider. (Fallback "Microsoft Software Key Storage Provider" for machines
   without a usable TPM — note which was used.)
2. `NCryptCreatePersistedKey(hProv, &hKey, "ECDSA_P256", L"p3sig\\<label>", 0, 0)`.
3. Set `NCRYPT_UI_POLICY_PROPERTY` (`NCryptSetProperty`) with
   `NCRYPT_UI_PROTECT_KEY_FLAG` so Windows Hello prompts on use; set a friendly name.
4. `NCryptFinalizeKey(hKey, 0)`.
5. Export the **public** blob: `NCryptExportKey(hKey, 0, BCRYPT_ECCPUBLIC_BLOB, …)` →
   `BCRYPT_ECCKEY_BLOB` (X,Y as 32-byte big-endian). Build a Go `*ecdsa.PublicKey` on
   `elliptic.P256()` → `ssh.NewPublicKey` → `ssh.MarshalAuthorizedKey` for the
   `ecdsa-sha2-nistp256 …` line.

### PublicKey(label)
`NCryptOpenKey(hProv, &hKey, L"p3sig\\<label>", 0, 0)` then export the public blob as above.

### Sign(label, data)
1. `NCryptOpenKey` the key. SHA-256 the `data`.
2. `NCryptSignHash(hKey, NULL, hash, hashLen, sig, …, &cb, 0)` — Hello prompts here.
   CNG returns the ECDSA signature as **r||s** (each 32 bytes, big-endian).
3. Return r||s; the shared agent converts to the SSH ecdsa signature blob (two mpints).
   (Note: macOS returns DER, Windows returns r||s — normalize both to (r,s) big.Ints in
   the shared agent before SSH-encoding.)

### Delete(label)
`NCryptOpenKey` then `NCryptDeleteKey(hKey, 0)`.

## Reference implementations
- **`github.com/foxboron/ssh-tpm-agent`** + **`github.com/google/go-tpm`** — TPM-backed
  SSH keys + agent in Go. ssh-tpm-agent is primarily Linux/TPM2 but the key/sign patterns
  and the ssh-agent integration are directly reusable.
- **`github.com/google/go-attestation`** / `go-tpm` for TPM specifics if you go direct-TPM
  instead of CNG.
- Microsoft docs: CNG `NCryptCreatePersistedKey`, `NCRYPT_UI_POLICY`, `NCryptSignHash`,
  `BCRYPT_ECCKEY_BLOB`.

> Alternative route (note, don't default to it): Windows Hello as a **FIDO2 platform
> authenticator** via `webauthn.dll` yields `sk-ecdsa-sha2-nistp256@openssh.com` keys.
> Closer to OpenSSH `-sk` keys but harder to serve through an agent. Prefer CNG/TPM above.

## ssh-agent on Windows
Windows OpenSSH uses a **named pipe** (`\\.\pipe\openssh-ssh-agent`), not a unix socket.
`p3sig ssh-agent` should listen on a named pipe and speak the agent protocol
(`golang.org/x/crypto/ssh/agent.ServeAgent` over the pipe connection). Document setting
`SSH_AUTH_SOCK` / using the pipe so `ssh.exe` finds it.

## Acceptance
- `p3sig setup --label test` creates a TPM key (Hello enrollment) and prints
  `ecdsa-sha2-nistp256 …`.
- With `p3sig ssh-agent` on the named pipe, `ssh.exe` to a test host trusting the pubkey
  (direct) **and** to one with `TrustedUserCAKeys` + a cert over the chip pubkey succeeds,
  prompting Windows Hello each time.
- Key is TPM-resident / non-exportable (`certutil -key -user` or provider enumeration shows
  it under the Platform Crypto Provider). `go vet` clean; `go build` still works on Linux
  (stub returns unsupported).

## Gotchas
- Some TPMs/firmware restrict P-256; if `NCryptCreatePersistedKey` fails, log the provider
  and fall back to the software KSP **only with a clear warning** (no hardware protection).
- The Hello prompt needs a foreground window/session; a headless service won't prompt —
  the agent must run in the user's interactive session.
- Normalize signature form: Windows r||s vs macOS DER — handle both in the shared agent.
