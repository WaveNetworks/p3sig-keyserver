# Device Enrollment — Task Tracker (CANONICAL, single source of truth)

> **This is the one canonical tracker.** Moved here (from `p3sig/docs/device-
> enrollment-phase1-tasks.md`) so status lives beside the code + handoffs it tracks —
> per `docs/SESSION-WORKFLOW-PROPOSAL.md` #3. The p3sig copy is now a pointer to this
> file. **Updating a task to ✅ with its landing commit/PR link is a required final step
> of every handoff** (`CONTRIBUTING.md`).
>
> Design: [`device-enrollment-enclave.md`](device-enrollment-enclave.md) §12.
> Handoffs: [`handoffs/TEMPLATE.md`](handoffs/TEMPLATE.md) · dev setup:
> [`dev-mac.md`](dev-mac.md) · [`dev-windows.md`](dev-windows.md).

**Goal:** *USB once → biometric thereafter* on Windows + Mac, with a passphrase fallback
everywhere (incl. Linux).

Sizes: **S** ≤ half-day · **M** 1–2 days · **L** multi-day. Repo tag: **[ks]** =
p3sig-keyserver (Go) · **[php]** = p3sig (server).

| Task | What | Size | Status |
|---|---|---|---|
| T1 | `Keystore.Agree` (ECDH) on the interface + backend stubs [ks] | S | ✅ DONE `898caa8` |
| T2 | `wrap.go` portable wrap/unwrap + passphrase scheme (+ tests) [ks] | M | ✅ DONE `594a1b7` |
| T3 | Secure Enclave `Agree` backend (darwin, cgo) [ks] | M | ✅ DONE `57eacec` |
| T4 | Windows Hello/TPM `Agree` backend [ks] | M | ✅ DONE `7d593a2` (v0.5.0) |
| T5 | `p3sig_device_keys` table [php] | S | ✅ DONE |
| T6 | Device-key endpoints (USB-signed) [php] | M | ✅ DONE |
| T7 | `p3sig enroll` (USB → chip → wrap → upload) [ks] | M | ⬜ TODO |
| T8 | Key-source abstraction: login/secret use the wrapped key [ks] | M | ⬜ TODO |
| T9 | Tier/keyring scoping (minimal enforcement) [php+ks] | M | ⬜ TODO |
| T10 | Security review + zeroization audit | M | ⬜ TODO |
| T11 | Dogfood run + doc status | S | ⬜ TODO |
| T12 | Promote `CreateAgreementKey` onto the `Keystore` interface [ks] | S | ⏳ HANDED OFF (needs a Mac) |

## Notes on the done items
- **T1** added `Agree(label, peerPubSEC1) (shared, err)` + not-implemented stubs on both
  backends so all platforms keep compiling (the interface-first pattern).
- **T3** implemented `Agree` in `keystore_darwin.go` (Secure Enclave ECDH) with a real
  Touch ID round-trip.
- **T4** implemented `Agree` in `keystore_windows.go` via `NCryptSecretAgreement` +
  `NCryptDeriveKey(BCRYPT_KDF_RAW_SECRET)` (little→big-endian reversal), using a dedicated
  ECDH P-256 key created by a new **concrete** `CreateAgreementKey` (CNG ECDSA keys can't
  do ECDH). Real Windows Hello/TPM round-trip; shipped v0.5.0.

## Open follow-ups
### T12 — promote `CreateAgreementKey` onto the `Keystore` interface · [ks] · S · ⏳
T4 landed `CreateAgreementKey` as a concrete `winHello` method, not on the interface,
because promoting it needs a matching **darwin** implementation and couldn't be
compile-verified off a Mac. Now that T3 (Secure Enclave `Agree`) has landed, add
`CreateAgreementKey` to the `Keystore` interface + a Secure Enclave impl. **This is an
interface change → interface-first PR to `main`** (method + stubs on every backend),
then verify the darwin impl on a Mac. Handoff: author from `handoffs/TEMPLATE.md`.

## Remaining sequence (T7 onward)
T7 (enroll) → T8 (wire login/secret to the wrapped key) → T9 (tiers) → T10 (security
review) → T11 (dogfood). Fastest first demo: T7 → T8 on one platform proves "USB once →
biometric thereafter". Full task detail preserved in git history of the former
`p3sig/docs/device-enrollment-phase1-tasks.md`.
