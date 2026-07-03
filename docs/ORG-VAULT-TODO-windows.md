# Org Vault client — Windows (native Go CLI) — TODO

Read `ORG-VAULT-CONTEXT.md`, `ORG-VAULT-TODO-web.md` (reference), and
`ORG-VAULT-TODO-macos.md` first — the **org logic is identical to macOS**; only the
*personal-key unlock via the chip* differs (TPM / Windows Hello via CNG instead of the
Secure Enclave). Everything in the macOS doc's "Add to the shared Go" + "CLI verbs"
sections is platform-independent and shared verbatim — implement it once, not twice.

## Reuse — do NOT reimplement
Same as macOS: `sealForKey` (cli.go:508), `openSealedBox` (main.go:418), `userRequest`
(cli.go:485), `cmdKeygen` (main.go:140), `wrap.go`. The org verbs live in the shared
`org.go` and build on Linux and Windows alike.

## Windows-specific: unlocking the personal vault key
Identical shape to macOS — obtain the personal Ed25519 vault key by:
1. `--key <file>` / USB — no chip.
2. **TPM/Hello-wrapped device blob** — `listDeviceKeys` → an `ecdh-p256-hkdf-aesgcm` blob →
   `wrap.go` unwrap → `keystore_windows.go` `Agree(label, peerPubSEC1)` → Windows Hello prompt
   → shared secret → HKDF → AES-GCM → personal Ed25519 secret key. **Already implemented**
   (the CNG/NCrypt P-256 keystore, pure Go via `x/sys/windows` lazy `ncrypt.dll` — cross-compiles
   from Linux). ⚠️ Per `keystore.go:27`, NCrypt yields the ECDH shared secret **little-endian**;
   the Windows backend already reverses it to big-endian — don't double-reverse.
3. Passphrase-wrapped device blob (Argon2id) — no chip.

No new CNG code is needed for org support — the chip only does the ECDH unwrap of the vault
key; the org key is Ed25519 and can't live in the TPM.

## Acceptance
- On Windows: `p3sig org secret set DEMO` (Hello unlock via an enrolled TPM device key, or
  `--key`) uploads only ciphertext; `p3sig org secret get DEMO` returns the plaintext.
- Cross-client: CLI-set secret opens in the browser and vice-versa; PHP opens both.
- `p3sig org grant --user B` → B opens with no re-seal.
- `go build` clean on Linux and `GOOS=windows` (org verbs pure Go; Hello unlock behind
  `//go:build windows`). `go vet` clean.

## Gotchas
- Base64 `StdEncoding`; zero private-key slices after use.
- The named-pipe ssh-agent (`listen_windows.go`, go-winio) is unrelated to org verbs — don't
  entangle them.
- Same recovery note as macOS: if the TPM key/Hello enrollment is reset, the chip can't unwrap
  the device blob; USB/passphrase is the fallback.
