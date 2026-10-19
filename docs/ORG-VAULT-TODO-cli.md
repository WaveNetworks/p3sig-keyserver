# Org Vault — CLI (`org_cli.go`) TODO: wrap to ALL keys, try ALL wraps

> **DONE 2026-10-19 (v0.6.0).** All four gaps are fixed in `org_cli.go`: create and grant wrap
> to every key, rotate (`p3sig org rotate`, now implemented) re-wraps every key of members
> with access, and reads try every wrap (`myOrgKey`). Org secret names are also sealed now
> (`encrypted_meta`), so `list`/`get` open names locally with the org key.


> **Provenance.** Filed by the p3sig server/main session after fixing the **browser** to
> wrap the org key to *all* of a user's personal keys (p3sig `a3cccb8`). The native CLI
> still wraps to **one** key — the same single-point-of-failure the browser just shed.
> Pure Go, Linux, no hardware. Land per `CONTRIBUTING.md` (branch → PR → CI).

## Why
The org private key is distributed by wrapping (`crypto_box_seal`) it to a member's
personal **public** key → `p3sig_org_key_wraps`. p3sig's resilience rule is: wrap/seal to
**every** one of a user's keys, so losing/deleting one key never locks them out (working
key + backup key in the safe). The browser now does this; `org_cli.go` does not, so an
org created (or a member granted) from the CLI is fragile, and a CLI client reading a
browser-created org can be handed a wrap for the wrong key.

## Gaps to fix in `org_cli.go` / `org.go`

1. **`org create` — wrap to all your vault keys.** Today it wraps the org key to one key.
   Fix: after `createOrgVault` + `createOrg` (first key), call **`getMyVaultKeys`** →
   for each *other* active vault key, `wrapOrgKeyFor(pub)` → POST **`wrapOrgKeyForMember`**
   (`member_user_id` = self, `member_key_id`, `wrapped_org_key`). Same sequence the
   browser uses.
2. **`org grant` — wrap to all the member's keys.** `getMemberKeys` returns *all* of a
   member's active keys; wrap the org key to each (loop), not just `keys[0]`.
3. **`org rotate` — re-wrap to all keys per member.** Flatten members × their keys → one
   wrap per key, so everyone keeps multi-key resilience after a rotate. (`rotateOrgVault`
   accepts `wraps: [{member_user_id, member_key_id, wrapped_org_key}]`.)
4. **Read / unwrap — try ALL wraps.** `getOrgKeyWrap` now returns
   **`wraps: [{member_key_id, public_key, wrapped_org_key}, …]`** (plus `wrap` singular,
   kept for back-compat). `org secret get` should iterate `wraps` and try each with the
   loaded personal key until `openSealedBox` succeeds (mirror the browser `ensureOrgKey`
   loop), instead of relying on `.wrap`. Otherwise a browser-created org (wrapped to
   several keys) may hand the CLI a wrap for a key it doesn't hold.

## Server: no change needed
The read path already returns all wraps; `wrapOrgKeyForMember` is idempotent
(`ON DUPLICATE KEY UPDATE` on `(org_key_id, member_key_id)`), so wrapping every key is
safe to repeat.

## Acceptance
- `org create` on an account with 2 vault keys stores **2** owner wraps; after
  deleting/losing one key, `org secret get` still works with the other.
- A CLI-created org opens in the **browser** with either key, and a browser-created org
  opens in the **CLI** with whichever key it holds.
- No key material in logs; org private key zeroed after use.
