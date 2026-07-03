# Org Vault — server (PHP) TODO: signed-request endpoints for native CLI clients

> **Provenance / handoff.** Filed by the **Windows CLI session** — the one that landed
> T4 (Windows Hello ECDH, `keystore_windows.go` `7d593a2`) and the Org Vault **client
> crypto core** `org.go` (`fe7fa8d`, this repo). While wiring the `p3sig org …` verbs I
> hit a hard blocker that is **server-side, in the `WaveNetworks/p3sig` repo** — it can't
> be fixed from the client. **Please address this before any further Mac/Windows client
> handoff work**, because both native clients (macOS T3 + Windows T4) depend on it and
> will otherwise ship verbs that can't authenticate.

## ✅ RESOLVED 2026-07-03 (WaveNetworks/p3sig `main` `8bb04f6`, deployed to p3sig.com)
All three gaps fixed and live:
1. **Auth mismatch** → a single `p3sig_org_actor()` resolver (new
   `include/common/userRequestAuth.php`) resolves the caller from an established
   session **or** the existing `p3sig_user_request_guard` signed request. Applied to
   every org action in **both** `apiActions/orgApiActions.php` **and**
   `memberActions/orgActions.php` — one pattern, no duplicate/weaker endpoints. The
   guard + `p3sig_user_guard_fail` were relocated from `userApiActions.php` into the
   `common/` library so they're defined before the (earlier-sorting) org action files
   execute. Verified: session=used, valid-sig=resolved, bad-sig=null, no-auth=null.
2. **Management API** → the memberActions are already globbed onto the API endpoint, so
   the actor makes `createOrg/addMember/wrapOrgKeyForMember/changeMemberRole/removeMember/
   rotateOrgVault` authenticate via signed request too. No new endpoints added.
3. **listOrgSecrets** → added to `orgApiActions.php`
   (`{secrets:[{secret_id,label,provider}]}`, org-scoped, active) for the name→id map.

**Client is now unblocked** — the `p3sig org …` verbs (thin layer over `org.go` +
`userRequest`) can proceed. ZK invariants unchanged. The rest of this doc is the original
Windows-session spec, kept for reference.

---

## TL;DR
The client crypto is done and tested (`org.go`: `createOrgVault`, `unwrapOrgKey`,
`openOrgSecret`, `wrapOrgKeyFor`, `rotateOrgVault`; wire-compatible with the browser
`P3Crypto` and PHP `sodium_crypto_box_seal`). But the merged org **server endpoints are
browser-session-only**, and the native CLI authenticates with **stateless Ed25519 signed
requests**. `ORG-VAULT-CONTEXT.md` says the org API is "all signed-request via
`p3sig_user_request_guard`" — the merged PHP does **not** implement that. Until it does,
`p3sig org …` verbs get "Login required" and cannot be written.

## What's wrong (all PHP, in `WaveNetworks/p3sig`)

1. **Auth mismatch.** `include/actions/apiActions/orgApiActions.php` reads
   `$_SESSION['user_id']`. The CLI path uses `p3sig_user_request_guard(&$errs)`
   (`userApiActions.php:22`), which *returns* `['user_id','key_id','pubkey']` and **never
   sets `$_SESSION`**. So a CLI signed request to any org action fails as unauthenticated.
   - **Fix:** resolve the caller via the guard when `pubkey`/`ts`/`signature` are present,
     else fall back to the session. E.g. at the top of each org action:
     `$uid = $_SESSION['user_id'] ?? null; if (!$uid && isset($_POST['signature'])) { $g = p3sig_user_request_guard($errs); $uid = $g['user_id'] ?? null; }`
     Preserve the ZK invariants (never read `$_POST['value']`, always validate every
     submitted `key_id ∈ p3sig_org_recipient_keys()`).

2. **No management API.** `createOrg`, `addMember`, `wrapOrgKeyForMember`,
   `changeMemberRole`, `removeMember`, `rotateOrgVault` exist only as **browser
   member-actions** (`memberActions/orgActions.php`). Add signed-request equivalents (or
   route them through the guarded apiActions) so `p3sig org create/add/grant/rotate` work.

3. **No list-by-name endpoint.** `getSealedSecret` takes a `secret_id`; nothing maps a
   label. `p3sig org secret get NAME` (and `org secret list`) needs a new
   `listOrgSecrets` → `{secrets:[{secret_id,label,provider}]}` (org-scoped, `status='active'`).

## Endpoint checklist (contract from `ORG-VAULT-CONTEXT.md` + `org.go`)
| Endpoint | Response | Status |
|---|---|---|
| `getOrgRecipients` | `{org_id, recipients:[{key_id,public_key}]}` | ✅ exists — **needs guard** |
| `getMemberKeys {member_user_id}` | `{keys:[{key_id,public_key}]}` | ✅ exists — **needs guard** |
| `getOrgKeyWrap` | `{wrap:{wrapped_org_key,org_key_id,member_key_id}\|null}` | ✅ exists — **needs guard** |
| `saveSealedSecret {label,provider?,bundle_id?,sealed_copies}` | `{secret_id,sealed}` | ✅ exists — **needs guard** |
| `getSealedSecret {secret_id}` | `{label,provider,encrypted_data,wrapped_org_key}` | ✅ exists — **needs guard** |
| `revokeOrgSecret {secret_id}` | `{secret_id,revoked}` | ✅ exists — **needs guard** |
| `listOrgSecrets` | `{secrets:[{secret_id,label,provider}]}` | ❌ **missing** |
| `createOrg {name,org_public_key,wrapped_org_key,owner_key_id}` | `{org_id}` | ❌ signed-request missing |
| `addMember {email,role}` | `{member_user_id}` | ❌ signed-request missing |
| `wrapOrgKeyForMember {member_user_id,member_key_id,wrapped_org_key}` | `{ok}` | ❌ signed-request missing |
| `changeMemberRole` / `removeMember` | `{ok}` | ❌ signed-request missing |
| `rotateOrgVault {new_org_public_key,sealed,wraps}` | `{org_key_id}` | ❌ signed-request missing |

`sealed` = `[{secret_id,encrypted_data}]`, `wraps` = `[{member_user_id,member_key_id,wrapped_org_key}]`
— exactly what `org.go` `rotateOrgVault` / `RotateResult` emit.

## Acceptance (unblocks both native clients)
- `p3sig org secret set DEMO` (signed request, `--key`) stores ciphertext only;
  `p3sig org secret get DEMO` returns plaintext.
- A CLI-set secret opens in the browser and vice-versa; PHP opens both.
- `p3sig org grant --user B` → B opens with no re-seal.
- Static ZK check still holds: org actions never read `$_POST['value']` / never call
  `p3sig_seal_secret`.

## After the server lands this
The `p3sig org …` verbs are a thin client layer over the **existing** `org.go` funcs +
`userRequest` (cli.go:485) — a quick follow-up in `p3sig-keyserver`, doable from Linux
(pure Go; the chip only unlocks the personal key, already done in T3/T4). No further
platform-specific work is required.

## Related open item (client, low priority)
T3 shipped the Secure Enclave `Agree` but did **not** promote `CreateAgreementKey` onto
the shared `Keystore` interface (still a concrete `winHello`/`secureEnclave` method).
Promote it (interface + both backends) when convenient; it's independent of the above.
