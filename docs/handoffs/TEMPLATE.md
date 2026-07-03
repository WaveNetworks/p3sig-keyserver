# Handoff: <task id> — <one-line title>  (<platform>)

> Author every hardware-session handoff from this template. Fixed sections so nothing
> is forgotten and they read consistently. Delete these quote lines when filling it in.
> Existing examples: `../T3-macos-agree-handoff.md`, `../T4-windows-agree-handoff.md`.

**Task:** <T# from `docs/device-enrollment-tasks.md`> · **Platform:** <macOS | Windows>
· **Size:** <S/M/L> · **Depends on:** <T#, T# — note which are DONE>

## Context
What this task is, why it exists, and the *one* thing that genuinely needs this
platform's hardware (the biometric round-trip). Link the design section and the
canonical tracker entry. State what already exists so the session doesn't rebuild it.

## Prerequisites & environment
- Read `docs/dev-<platform>.md` first and get a **device-signed test build working**
  before touching code (macOS: the Secure Enclave test needs a signed `.app` or it
  fails `-34018`).
- Toolchain: Go 1.21 (matches `go.mod` + CI), platform SDK/cgo notes from the dev doc.
- Any keys/labels/env the hardware test needs (e.g. `P3SIG_HW_TEST=1`,
  `P3SIG_KEYCHAIN_GROUP`, `P3SIG_HELLO_LABEL`).

## What to implement
Concrete API/behavior. Cite the exact files/symbols. Call out gotchas discovered in
prior sessions (e.g. Windows CNG ECDSA keys can't do ECDH → need a dedicated ECDH key;
NCrypt raw secret is little-endian).

## Definition of Done
- [ ] `go build ./...`, `go vet ./...`, `gofmt -l .` clean (CI enforces on all 3 OSes).
- [ ] Unit tests pass; the **opt-in hardware test passes on real hardware** (the part
      only this session can do) — paste the command + the confirming output line.
- [ ] No secret/key material in logs or errors; sensitive buffers zeroed.
- [ ] Tracker entry updated to ✅ with the landing commit/PR link.

## How to land it  (branch + PR — NOT direct to main)
1. If this touches the shared `Keystore` interface, that change is a **separate,
   interface-first PR to `main`** with stubs on every backend — land it before the impl.
2. Implementation goes on `claude/<task>-<platform>` → open a PR → wait for green CI →
   merge. See `CONTRIBUTING.md`.
3. **Final step:** update `docs/device-enrollment-tasks.md` (✅ + commit link) in the
   same PR.

## Report-back
- Landing commit(s)/PR link.
- The hardware-test command run + its success line.
- Anything that surprised you (feeds the next handoff / dev doc).
- Any follow-up items you spawned (e.g. an interface promotion needing the other OS).
