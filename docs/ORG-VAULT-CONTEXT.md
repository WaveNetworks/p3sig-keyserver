# Org Vault client — shared CONTEXT (read first)

Handoff for bringing the **enterprise Org Vault** to every client "version":
**web** (done — the reference), **macOS**, **Windows**. Read this before the
per-platform `ORG-VAULT-TODO-*.md`. Pairs with the chip-keystore handoffs
(`CONTEXT.md`, `TODO-macos.md`, `TODO-windows.md`) — same pattern, different feature.

## Where the feature lives
- **Server (PHP):** repo `WaveNetworks/p3sig`, branch **`feat/organizations`** (commits
  `4429b84`, `b239a09`) — **pushed, NOT merged** (`main` auto-deploys to p3sig.com; merge
  only after the multi-user E2E). Endpoints + schema below are on that branch.
- **Web client (reference impl):** `WaveNetworks/p3sig` → `assets/js/p3sig-crypto.js`
  (`window.P3Crypto`) + vendored `assets/js/vendor/sodium.js`. **Verified** end-to-end
  (create→wrap→open→rotate→old-cipher-rejected) and wire-compat with PHP. See
  `ORG-VAULT-TODO-web.md`.
- **Native client (this repo):** the Go CLI already has the crypto primitives; the org
  verbs are new assembly. See `ORG-VAULT-TODO-macos.md` / `-windows.md`.

## The model (one paragraph)
Each org has its own **Ed25519 vault keypair**, generated client-side. Org secrets seal
**once** to the org **public** key (`crypto_box_seal`). The org **private** key is
distributed by *wrapping* (also `crypto_box_seal`) it to each member's **personal** public
key → `p3sig_org_key_wraps` (server stores ciphertext only). To read a secret a member:
unwraps the org private key with their personal key, then opens the secret. The server
never sees org secret plaintext or the org private key. Admit a member = one wrap (O(1));
remove = revoke + **rotate** (new org keypair, re-seal every secret, re-wrap remaining).

## The seal format (identical across all three clients — DO NOT diverge)
`crypto_box_seal` to an **Ed25519 public key converted to X25519**. Wire-identical across:
- PHP `p3sig_vault_seal_for_key` (`include/common/crypto.php:64`)
- Browser `P3Crypto.sealTo` (libsodium `crypto_box_seal`)
- Go `sealForKey` (`cli.go:508`, `box.SealAnonymous`) / `openSealedBox` (`main.go:418`,
  `box.OpenAnonymous`) — already used for personal secrets, proven compatible.
All base64 is **standard** (PHP `base64_encode`; libsodium `base64_variants.ORIGINAL`;
Go `base64.StdEncoding`). A personal/org **private key** is a 64-byte Ed25519 secret key,
base64. A public key is 32 bytes, base64 (44 chars).

## The operations any client must implement (P3Crypto is the spec)
Map of `window.P3Crypto` (`assets/js/p3sig-crypto.js`) → what each does. A native client
mirrors these; most already exist in Go.

| Operation | What it does | Go primitive today |
|---|---|---|
| `unlockPersonal(privB64)` | hold the personal Ed25519 secret key | key file / USB, **or** unwrap a `p3sig_device_keys` blob via `wrap.go` (`keystore.Agree` chip / Argon2id passphrase) |
| `sealTo(str, edPub)` / `sealRawTo(bytes, edPub)` | seal a value / raw bytes to a pubkey | `sealForKey` (cli.go:508) — **add a `[]byte` variant** for wrapping the org private key |
| `openWithPersonal(ctB64)` / raw | open a copy sealed to the personal key | `openSealedBox` (main.go:418) — **add a raw `[]byte` variant** (org priv is 64 raw bytes, not UTF-8) |
| `unwrapOrgKey(wrappedB64)` | personal-open the wrapped org key → hold org priv | `openSealedBox`-raw(wrapped, personalPriv) |
| `openOrgSecret(ctB64)` | open a secret with the held org priv | `openSealedBox`(ct, orgPriv) |
| `wrapOrgKeyFor(memberPub)` | seal the held org priv to a member | `sealForKey`-raw(orgPriv, memberPub) |
| `createOrgVaultFor(ownerPub)` | new org keypair; wrap priv to owner | `cmdKeygen`-style ed25519 + `sealForKey`-raw |
| `rotate(members, secrets)` | new org key; re-seal all secrets; re-wrap members | open-all → keygen → seal-all → wrap-all |
| `lock()` | zero the held private keys | `sodium_memzero` equiv / zero slices |

**The only genuinely platform-specific piece is `unlockPersonal`** — obtaining the personal
Ed25519 vault key. On native platforms it comes from a USB/key-file **or** by unwrapping a
device-key blob using the chip (`keystore.Agree` P-256 ECDH → HKDF → AES-GCM, already in
`wrap.go` per `device-enrollment-phase1-T2-wrap-spec.md`). **The chip cannot hold the vault
key itself** — Enclave/TPM keys are ECDSA P-256 and can't do the seal crypto; they only
*unwrap* it. Everything after unlock is identical, platform-independent Go.

## Server API (all signed-request, via `userRequest` cli.go:485; browser via `apiPost`)
Auth = Ed25519 detached signature over `"<pubkey>|<ts>"` with the personal vault key
(`p3sig_user_request_guard`). Endpoints (on `feat/organizations`):
- `getOrgRecipients` → `{recipients:[{key_id, public_key}]}` — seal new org secrets to these (the org vault key).
- `getOrgKeyWrap` → `{wrap:{wrapped_org_key, org_key_id, member_key_id}|null}` — caller's wrapped org key (null = no vault access yet).
- `getMemberKeys {member_user_id}` → `{keys:[{key_id, public_key}]}` — a member's personal pubkeys (admin, to wrap for them).
- `saveSealedSecret {label, provider?, bundle_id?, sealed_copies:JSON}` — store a client-sealed org secret (ciphertext only; server validates key_ids ∈ org recipient set).
- `getSealedSecret {secret_id}` → `{label, provider, encrypted_data, wrapped_org_key}` — the org-key copy + caller's wrap, to open in-client.
- `revokeOrgSecret {secret_id}` (admin).
- Member mgmt (memberActions, also on the API endpoint): `createOrg {name, org_public_key, wrapped_org_key, owner_key_id}`, `addMember {email, role}` (registered accounts only — no invites), `wrapOrgKeyForMember {member_user_id, member_key_id, wrapped_org_key}`, `changeMemberRole`, `removeMember`, `rotateOrgVault {new_org_public_key, sealed:JSON, wraps:JSON}`.

## Schema (server, FYI) — `include/common/schemaFunctions.php`
`p3sig_keys.owner_type` widened to `('user','machine','org')`; new `p3sig_orgs`,
`p3sig_org_members`, `p3sig_org_key_wraps`; nullable `org_id` on `p3sig_secrets`/`p3sig_bundles`.
All via `ensure_p3sig_schema()`, **no `$child_db_version` bump**.

## Two planes (enforce in the client UX, mirror the server)
- **Control plane** — role owner/admin/member gates management (server: `p3sig_is_org_admin`).
- **Data plane** — a member can decrypt only if the org key is wrapped to them (an active
  `p3sig_org_key_wraps` row). Role never grants read; a fresh member is "pending wrap" until
  an admin runs the wrap (grant) flow.

## Acceptance (shared, all clients)
- A value sealed by this client opens in PHP `sodium_crypto_box_seal_open` **and** the
  browser P3Crypto, and vice-versa (round-trip both directions).
- The client never transmits an org secret value or an org/personal private key — only
  ciphertext (sealed copies, wrapped keys, signatures).
- `lock()` equivalent zeroes private-key memory.
