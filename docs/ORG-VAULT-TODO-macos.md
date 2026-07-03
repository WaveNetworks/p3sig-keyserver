# Org Vault client — macOS (native Go CLI) — TODO

Read `ORG-VAULT-CONTEXT.md` and `ORG-VAULT-TODO-web.md` (the reference) first. Goal: add
`p3sig org …` verbs so a Mac user manages and reads Org Vault secrets from the terminal,
zero-knowledge, with the **personal** vault key optionally unlocked from the Secure Enclave.

**Most of this is platform-independent Go** — the org crypto reuses primitives that already
exist and cross-compile. macOS-specific work is limited to the *personal-key unlock* path
(Enclave), which is already implemented (`keystore_darwin.go` `Agree` + `wrap.go`). Build/test
the Enclave path **on a Mac** (cgo); the org verbs themselves build on Linux.

## Reuse — do NOT reimplement
- Seal/open: `sealForKey` (cli.go:508), `openSealedBox` (main.go:418) — `box.Seal/OpenAnonymous`.
- Signed API auth: `userRequest` (cli.go:485).
- Ed25519 keygen: the `cmdKeygen` path (main.go:140).
- Personal-key unwrap from a chip-wrapped device blob: `wrap.go` (`ecdh-p256-hkdf-aesgcm`)
  driving `keystore.Agree` (keystore.go:27) — the Enclave ECDH unlock. Passphrase blobs use
  the Argon2id path, no chip.

## Add to the shared Go (platform-independent) — put in a new `org.go`
1. **Raw-byte seal/open variants** (the org private key is 64 raw bytes, not a UTF-8 string):
   `sealForKeyRaw(plaintext []byte, edPubB64 string) (string, error)` and
   `openSealedBoxRaw(ctB64 string, edPriv ed25519.PrivateKey) ([]byte, error)` — factor these
   out of the existing string versions (which then call the raw ones).
2. **Org ops** mirroring `P3Crypto` (see the CONTEXT table): `unwrapOrgKey`, `openOrgSecret`,
   `wrapOrgKeyFor`, `createOrgVaultFor`, `rotate`. Pure Go over the primitives above.
3. **CLI verbs** (auth = `userRequest` with the personal vault key):
   - `p3sig org create --name X` → `createOrgVaultFor(ownerPub)` → POST `createOrg`.
   - `p3sig org add --email a@b.com [--admin]` → POST `addMember`.
   - `p3sig org grant --user <id>` → `getMemberKeys` → `wrapOrgKeyFor(memberPub)` → `wrapOrgKeyForMember`.
   - `p3sig org secret set NAME` (value from stdin; seal to `getOrgRecipients`) → `saveSealedSecret`.
   - `p3sig org secret get NAME` → `getSealedSecret` → `unwrapOrgKey` + `openOrgSecret`.
   - `p3sig org rotate` → pull all secrets + member keys → `rotate(...)` → `rotateOrgVault`.

## macOS-specific: unlocking the personal vault key
The personal Ed25519 vault key is obtained one of three ways (offer in this order):
1. `--key <file>` / USB (already how `login`/`secret set` work) — no chip.
2. **Enclave-wrapped device blob** — `listDeviceKeys` → pick a `wrap_scheme=ecdh-p256-hkdf-aesgcm`
   blob → `wrap.go` unwrap, which calls `keystore_darwin.go` `Agree(label, peerPubSEC1)` →
   Touch ID → shared secret → HKDF → AES-GCM → the personal Ed25519 secret key. **This already
   works** (device-enrollment Phase 1); the org verbs just call it to get `personalPriv`.
3. Passphrase-wrapped device blob (Argon2id) — no chip.

There is **no new Enclave code** — the vault key is Ed25519 and can't live in the Enclave;
the Enclave only performs the ECDH that unwraps it. Don't attempt to hold the org key in the
Enclave either.

## Acceptance
- On a Mac: `p3sig org secret set DEMO` (Touch ID unlock via an enrolled Enclave device key,
  or `--key`) uploads only ciphertext; `p3sig org secret get DEMO` returns the plaintext.
- A secret set by the CLI opens in the browser (P3Crypto) and vice-versa; PHP opens both.
- `p3sig org grant --user B` lets user B (web or CLI) open the secret with no re-seal.
- `go build` clean on Linux (org verbs are pure Go; Enclave unlock behind `//go:build darwin`,
  stub elsewhere). `go vet` clean.

## Gotchas
- Base64 must be `StdEncoding` to match PHP/browser (CONTEXT).
- Zero the personal/org private key slices after use (the web `lock()` analogue).
- Re-enrolling Touch ID invalidates the Enclave key (`BiometryCurrentSet`) → the device blob
  can't be unwrapped by the chip; the USB/passphrase path is the recovery. Document it.
- Wrap to a member's key(s): match the web client (first active key for now; note if you do all).
