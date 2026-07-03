# Contributing / cross-platform workflow

This repo carries per-platform, hardware-backed code (`keystore_darwin.go` = Secure
Enclave, `keystore_windows.go` = Windows Hello/TPM) that **cannot be built or
hardware-tested from Linux**. Work on it is handed to Claude sessions running on
physical Mac / Windows machines. These rules keep that safe under concurrency and
fast. See `docs/SESSION-WORKFLOW-PROPOSAL.md` for the rationale.

## The one rule that prevents collisions: interface-first, branch-per-platform

The platform files are disjoint and never conflict with each other. The **only** real
collision point is the shared `Keystore` interface (`keystore.go`).

1. **Shared / interface changes land on `main` FIRST, as their own task.** Add the
   interface method + not-implemented stubs on every backend so all platforms keep
   compiling (this is what T1 did — `Agree` + stubs — before T3/T4 filled them in).
   Do this as one small PR, merge it, *then* fan out.
2. **Platform implementations fan out in parallel, each on its own branch.**
   `claude/<task>-<platform>` (e.g. `claude/t3-macos-agree`, `claude/t4-windows-agree`)
   → PR → merge. **Never push platform work directly to `main`** while another platform
   session may be running. (T3 and T4 ran at once and only avoided clobbering `main`
   because a human manually warned each session — this rule removes that.)

Because interface changes are serialized and impls are branched, concurrent Mac +
Windows sessions are safe by construction.

## How to land any change

- Branch → PR → let **CI** (`.github/workflows/ci.yml`) go green → merge. CI builds,
  vets, gofmt-checks, and tests on ubuntu + macos-14 + windows-latest, so a change that
  breaks another OS's build is caught in minutes, not days.
- **Every handoff's final step is to update the task tracker** to ✅ with the landing
  commit/PR link — see below. This is required, not optional.

## What CI does and does NOT cover

- ✅ Covers: `go build`, `go vet`, `gofmt -l`, `go test ./...` on all three OSes.
  Hardware tests self-skip (they gate on `P3SIG_HW_TEST` / `P3SIG_TOUCHID_TEST` /
  `P3SIG_HELLO_TEST`), so CI is device-free.
- ❌ Does NOT cover: the actual biometric round-trip (Touch ID / Windows Hello on real
  hardware). That is the *only* thing a physical session must still do — run the
  opt-in hardware test per `docs/dev-mac.md` / `docs/dev-windows.md`.

## Single source of truth

- **Task tracker:** [`docs/device-enrollment-tasks.md`](docs/device-enrollment-tasks.md)
  (canonical, in this repo — alongside the code and handoffs).
- **Handoffs:** [`docs/handoffs/TEMPLATE.md`](docs/handoffs/TEMPLATE.md) — author every
  new handoff from this template so nothing is forgotten.
- **Per-platform dev setup:** [`docs/dev-mac.md`](docs/dev-mac.md),
  [`docs/dev-windows.md`](docs/dev-windows.md).
- **Kickoff:** the `/next-handoff` command (`.claude/commands/next-handoff.md`) finds and
  starts the next pending task for your platform.
