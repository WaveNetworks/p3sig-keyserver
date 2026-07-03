# Org Vault client — WEB (P3Crypto / libsodium) — REFERENCE IMPL, mostly DONE

Read `ORG-VAULT-CONTEXT.md` first. The web client is the **reference implementation**;
the macOS/Windows docs mirror it. Status: **BUILT + verified**, one gate remaining.

## What exists (repo `WaveNetworks/p3sig`, branch `feat/organizations`)
- `assets/js/vendor/sodium.js` — **libsodium-wrappers-SUMO** browser build (the *non-sumo*
  build lacks `crypto_sign_ed25519_pk_to_curve25519`; source:
  `raw.githubusercontent.com/jedisct1/libsodium.js/master/dist/browsers-sumo/sodium.js`).
  ⚠️ **.gitignore trap:** `vendor/` was un-scoped → change to `/vendor/` + `!assets/js/vendor/`
  or this file silently won't commit and the page 500s with `P3Crypto is not defined`.
- `assets/js/p3sig-crypto.js` — `window.P3Crypto`: `ready, generateKeypair, unlockPersonal,
  lock, sealTo, sealRawTo, openWithPersonal, unwrapOrgKey, openOrgSecret, wrapOrgKeyFor,
  createOrgVaultFor, rotate`. Base64 = `ORIGINAL`. Private keys live only in the module
  closure, wiped by `lock()`.
- `views/organization.php` — self-loads the two scripts via an idempotent
  `window.__p3cryptoReady` promise (spa-nav re-executes view `<script>`s but NOT shell
  ones; gating in `template.php` would break create-org for null-org users). Drives all
  flows via `apiPost(action, data, cb)` → `../api/index.php`.

## Verified (headless, on the openclaw box)
- Full JS lifecycle through the real `P3Crypto` API: create org vault → seal secret →
  wrap to member → member unwraps + opens → rotate → old ciphertext rejected under new key.
- **Wire-compat both directions:** browser `crypto_box_seal` ↔ PHP
  `sodium_crypto_box_seal_open` (unicode-clean, 44-char/32-byte pubkey).
- Static ZK audit: org server code never reads `$_POST['value']` / never calls
  `p3sig_seal_secret` (org secrets go only through the client-sealed `saveSealedSecret`).
- Dual-engine DDL (MySQL 8 + MariaDB 11, fresh + retrofit): enum widened, tables + `org_id`
  present, idempotent.

## THE ONE GATE before merge to `main`
Full **multi-user E2E in a running app** (nobody has run this yet — cloud sandbox had no
DB; local can't drive the login/browser headlessly):
1. `docker compose up -d --build` (against the admin-core sibling).
2. Register users A and B; each enrolls a personal key (`vault-setup.php`).
3. As A: create org (Network tab: **no private key** in any request body).
4. As A: create an org secret (Network tab: `saveSealedSecret` payload has only
   `encrypted_data`, never `value`). In MySQL, grep the plaintext across all DBs → **0 hits**.
5. As A: `addMember` B (by B's registered email) → grant B vault access (wrap). As B: open
   the secret — decrypts in-browser, with **no re-seal** of the secret (one new wrap row).
6. Rotate: new `owner_type='org'` key, old revoked, secrets re-sealed, B still opens, a
   removed member cannot.
7. Plan gating: a third user with no org sees the personal experience unchanged.

Then merge, and flush opcache on deploy (makershost pins `opcache.validate_timestamps=0` —
see `project_opcache_deploy_bust`; the p3sig repo already has the bust step).

## Follow-ups (nice-to-have, not blockers)
- Wrapping to **all** of a member's active keys (currently wraps to their first key).
- Surface `p3sig_members_pending_org_wrap` more prominently after `addMember`.
- Org **bundles** UI (schema supports `org_id` on bundles; no UI yet).
