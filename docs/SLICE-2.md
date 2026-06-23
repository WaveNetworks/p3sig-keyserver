# Slice 2 — CLI management (USB-signs) + device-code enroll

Status: **design, not built.** Slice 1 (config/profiles, `init`, `server up`, secret
read verbs) shipped in `main`. Slice 2 adds the *management* surface to the CLI and a
no-copy-paste enrollment. It needs **new server endpoints in the p3sig app repo**
(`WaveNetworks/p3sig`, child app under `/p3sig/`), not just binary work — each item below
marks **[server]** vs **[binary]**.

The north star: a human manages their vault from the terminal — store a secret, grant a
bundle, register a machine — **without a browser and without p3sig ever seeing plaintext**.

---

## 1. Two principals, two identities (recap)

p3sig already has two authorization principals. Slice 1 only used the first:

| Principal | Identity = | Powers | Auth |
|---|---|---|---|
| **Machine** | the machine's Ed25519 key (`p3sig keygen`) | read-only: pull its own grants | sign `"<machine_id>\|<ts>"` |
| **User** (the human) | the **vault USB key** (`p3sig_keys`, `owner_type='user'`) | manage everything they own | sign `"<pubkey>\|<ts>"` ← **new in Slice 2** |

The machine key answers "which machine." The **vault key answers "which account"** — see §3.

---

## 2. Vault-key uniqueness (DECIDED — enforce it) **[server]**

A vault public key maps to **exactly one account**, so a signature with it identifies the
account unambiguously with nothing typed.

- Enforce a **globally unique** active vault public key: on `addUserKey` / `generateUserKey`,
  reject a key whose fingerprint already exists as an active `p3sig_keys` row for **any**
  user (not just the current one). Today the dup check is per-user; widen it.
- Fingerprint = `SHA256` of the raw 32-byte Ed25519 public key, base64 — the same
  derivation used elsewhere (`p3sig_validate_public_key` / `p3sig_parse_ssh_pubkey`).
- Add a unique index on the fingerprint of active user keys (or enforce in the action +
  an `ensure`-time guard; remember the MariaDB DDL-drop rule — add the index via an
  idempotent `ensure`, not the migration runner).

---

## 3. User signed-request auth — the guard **[server]**

Sibling of the existing `p3sig_machine_pull_guard`. Stateless, same shape as machines.

**Request params:** `pubkey` (base64 Ed25519, 32-byte), `ts` (unix seconds), `signature`
(base64 Ed25519 over the ASCII string `"<pubkey>|<ts>"`).

**`p3sig_user_request_guard($errs)` returns `user_id|false`:**
1. `±300s` clock-skew check on `ts`.
2. Look up `p3sig_keys WHERE public_key = :pubkey AND owner_type='user' AND status='active'`.
   No row → 403 "key not registered to any account." (Uniqueness ⇒ at most one row.)
3. Verify the Ed25519 signature over `"<pubkey>|<ts>"` with that pubkey. Bad → 403.
4. Return the row's `owner_id` (= the account). Rate-limit per account.

Everything a management call then does is scoped to that `user_id` — identical to a web
session's `$_SESSION['user_id']`, just proven by a key instead of a cookie. Writes that
seal happen **client-side** (§5), so this transport still never carries plaintext.

Optional hardening for destructive writes: a server-issued short-lived nonce instead of
`ts` (prevents replay within the window). Start with `ts`; add nonce if needed.

---

## 4. `p3sig login` — establish the identity **[binary]**

One-time, like `init` but for the human instead of the machine.

```
p3sig login --key /Volumes/USB/vault.key   [--url URL] [--identity NAME]
  → POST action=whoami  (pubkey/ts/signature over the vault key)   [server, §3 guard]
  ← { user_id, email, display_name }
  → "Logged in as jeevan@gmail.com — save this identity? [Y/n]"
  → writes an *identity* profile to config (next to machine profiles)
```

- **The server tells the CLI which account it resolved**, and the user confirms it. This
  is the answer to "how does it know which account": the key resolves it; `whoami` echoes
  it back for confirmation. No email/username is ever typed.
- Config gains an `identities` map mirroring `profiles` (AWS-style). Select with
  `--identity NAME` / `P3SIG_IDENTITY`; `default_identity` for the unflagged case. Multiple
  accounts on one box = multiple identities.
- The vault key is **read** by the CLI to sign; for a chip-held vault key later, route
  through the `Keystore` interface instead of a file. (Vault keys are Ed25519 / USB today;
  the SE chip is P-256 and used for SSH login, not vault sealing — keep them distinct.)
- **`whoami`** is the only new endpoint needed for login: it's just the §3 guard returning
  the resolved account. **[server]**

---

## 5. `p3sig secret …` — zero-knowledge management **[binary + server]**

### `p3sig secret set NAME [--bundle B] [--provider P]`
Reads the value (stdin or prompt, never argv), **seals it client-side**, uploads ciphertext.

1. `getMyVaultKeys` (user-authed) → the account's active recipient pubkeys (both USB
   sticks). **[server]** — returns `[{ key_id, public_key, label }]` for
   `owner_type='user'`, active.
2. CLI seals the plaintext to **each** recipient key (Ed25519→X25519 `crypto_box_seal`,
   the exact code already in `openSealedBox`'s inverse — add `sealForKey()`), producing one
   sealed copy per key. Same as what the browser does today.
3. `saveSecretSealed` (user-authed): `{ label, provider, type, bundle_id?, sealed_copies:
   [{ key_id, encrypted_data }] }`. Server stores the secret row + `p3sig_sealed_copies`,
   **plaintext never sent**. **[server]** (a headless sibling of the web `saveSecret`).

> This is *more* secure than the web form (no plaintext in a browser DOM/extension surface)
> and is the flagship of the USB-signs model.

### `p3sig secret get NAME` (human, manage)
Distinct from Slice 1's machine-side `secrets get` (that uses machine auth and the
machine's sealed copy). This one is user-authed: pull **your** sealed copy
(`getMySecret`/reuse `getSealedSecrets` keyed by user) and unseal with the vault key.

### `p3sig grant bundle B --to MACHINE` / `p3sig revoke …`
User-authed wrappers over `grantBundle` / `revokeBundleGrant`. **Re-seal boundary applies**
(the documented v1 boundary): granting a bundle to a *new* recipient that already has
secrets needs a sealed copy for the new key — the server has no plaintext, so the CLI (which
can unseal as the user) re-seals client-side and uploads. `p3sig grant` should do this
transparently: unseal-with-vault → seal-to-new-recipient → upload. **[binary]**

### Endpoint summary (all **[server]**, all behind the §3 user guard)
`whoami` · `getMyVaultKeys` · `saveSecretSealed` · `getMySecrets` (or extend
`getSealedSecrets` for user principal) · the grant/revoke management actions exposed to
signed requests (today they're web-session only).

---

## 6. `p3sig enroll` — device-code, no copy-paste **[binary + server]**

The other Slice 2 item. Replaces the manual paste in `init`'s wizard. **Account binding
comes from the browser session, not the binary** (this is the answer to "which account" for
enrollment): the human approves the code while logged in, and the server binds the new
machine to *that* session's account.

```
p3sig enroll [--name web-01]
  → keygen locally (private stays)
  → POST action=startMachineLink { pubkey, name }      [server] → { code, verify_url, link_id }
  → "Open https://p3sig.com/link and enter  ABCD-1234"
  → poll action=pollMachineLink { link_id }            [server] → pending… → { machine_id }
  → writes the machine profile (same as init)
```
**[server]:** a `p3sig_machine_links` table (code, pubkey, name, status, requested_at,
approved_by user_id, machine_id) + three actions: `startMachineLink` (anonymous, rate-limited,
short TTL), a web `?page=link` approval screen (user-session: shows the code/name/pubkey,
"Approve" → creates the machine bound to `$_SESSION['user_id']`), and `pollMachineLink`
(anonymous, returns the machine_id once approved). Keep the manual wizard as the fallback for
air-gapped/no-browser hosts.

---

## 7. Organization level — multiple admins (FUTURE, capture the shape)

Jeevan's call (2026-06-23): we'll likely want an **org/team layer** so several admins manage
shared machines and secrets. This is a real schema change and its own design pass; recording
the shape so Slice 2's auth doesn't paint us into a corner.

**Model.** Add **`org`** as a third owner principal alongside `user`/`machine`:
- `p3sig_orgs` (org_id, name, created_by) + `p3sig_org_members` (org_id, user_id, role
  ENUM('owner','admin','member'), status). Roles gate management.
- Let secrets / bundles / machines / CAs be **owned by an org** (`owner_type='org'`,
  `owner_id=org_id`) instead of a single user. The §3 user guard resolves the human; an
  **authz** step then checks org membership/role for org-owned resources.
- The CLI identity (§4) stays the human's vault key; add `--org SLUG` / `P3SIG_ORG` to act
  within an org. `whoami` returns the human's orgs + roles.

**The zero-knowledge cost (the hard part).** An org secret must be sealed to **every admin
who may read it** — i.e. to each admin's vault pubkey. Consequences:
- Storing an org secret seals to all current admins' keys (CLI fetches the admin key set,
  seals N copies). Fine.
- **Adding an admin can't retroactively grant plaintext** — the server has no plaintext to
  re-seal. So a *new admin can't read pre-existing org secrets until an existing admin
  re-seals them* to the new admin's key. This is the same documented re-seal boundary, one
  level up. Surface it honestly: `p3sig org add-admin alice@…` warns "alice can't read
  existing secrets until you run `p3sig org reseal`," and `org reseal` (run by an admin who
  *can* unseal) pulls → unseals → re-seals to the full admin set → uploads.
- Removing an admin: drop their grant + sealed copies immediately (they lose future access);
  rotate the affected secrets if you must invalidate what they already saw (same as any
  shared-secret system — the secret value, not just access, is what leaked).

**Phasing.** (a) personal accounts only = Slice 2 as written. (b) org = a later slice: orgs +
membership + `owner_type='org'` + the authz step + `org reseal`. Don't block Slice 2 on it,
but: make the §3 guard return a *user_id* (not assume "owns everything"), and keep authorization
a separate check from authentication, so org authz slots in without reworking auth.

---

## 8. Build order

1. **[server]** §2 uniqueness + §3 user guard + `whoami` — the foundation; verifiable with curl.
2. **[binary]** §4 `p3sig login` + identity profiles in `cli.go`.
3. **[server+binary]** §5 `getMyVaultKeys` + `sealForKey()` + `saveSecretSealed` → `secret set`
   (the flagship), then `secret get` / `grant`.
4. **[server+binary]** §6 device-code `enroll`.
5. **(later slice)** §7 organizations.

Keep every management write **sealed client-side**; the server stores only ciphertext and
public keys, exactly as today. If a feature would require the server to hold plaintext, it's
wrong — re-seal on the client instead.
