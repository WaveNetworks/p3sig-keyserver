# Proposal: streamlining Mac/Windows hardware-session handoffs

**Status:** proposal for the main session to implement. Nothing here changes code
behavior — it's build tooling, docs, and process. Authored after the
device-enrollment T3 (macOS SE `Agree`) session; the handoff model works, this
just makes it faster, safer under concurrency, and self-documenting.

## The problem we're solving

Cross-platform work (`keystore_darwin.go` = Secure Enclave, `keystore_windows.go`
= Windows Hello) can't be built or hardware-tested from the Linux dev
environment, so it's handed to Claude sessions running on physical Mac / Windows
machines (see `T3-macos-agree-handoff.md`, `T4-windows-agree-handoff.md`). Pain
points observed in practice:

1. **A physical session does two unrelated jobs at once** — basic sanity
   (compile / vet / unit tests on that OS) *and* hardware validation (Touch ID /
   Windows Hello round-trips). Only the second needs a device + a human, but the
   first is what usually breaks and it's discovered late.
2. **Concurrent sessions race on `main`.** T3 (Mac) and T4 (Windows) ran at the
   same time, both pushing to `main`; collisions were avoided only by the human
   manually warning each session.
3. **Status lives in a different repo than the code.** The task tracker is
   `p3sig/docs/device-enrollment-phase1-tasks.md`; the code + handoffs are here.
   Updating status is a second-repo, easily-skipped step.
4. **Each handoff re-derives the environment.** Toolchain paths, cgo `SDKROOT` /
   `DEVELOPER_DIR`, and the signed-`.app` recipe needed to run hardware tests
   locally are rediscovered per session.

## The bottleneck to design around

The only thing that genuinely cannot be automated is **a human pressing the
biometric sensor on real hardware.** Everything else — build, vet, gofmt, unit
tests, even compiling the cgo darwin/windows code — can run without a device.
So the guiding principle is: **push everything except the biometric round-trip
into CI, and make the physical session as short as possible.**

---

## Work items (ordered by leverage)

### 1. Cross-platform build/test CI matrix  ← highest leverage
**What:** a GitHub Actions workflow (e.g. `.github/workflows/ci.yml`) that runs on
every PR and push, matrixed over `ubuntu-latest`, `macos-14`, `windows-latest`:
`go build ./...`, `go vet ./...`, `gofmt -l .` (fail if non-empty), and
`go test ./...` **excluding** the hardware tests (they self-skip unless
`P3SIG_HW_TEST` / `P3SIG_TOUCHID_TEST` is set, so a plain `go test` is safe).

**Why:** a Windows change that breaks the darwin build (or vice-versa) is caught
in minutes by CI instead of days later when a physical session finally compiles
it — the exact risk `T4-windows-agree-handoff.md` flags ("can't be
compile-verified off a Mac"). This shrinks every physical session down to *just*
the biometric validation, which is the whole point.

**Done when:** a PR that breaks compilation on any OS gets a red check; the
darwin build uses the same CLT-clang + Xcode-SDK setup as
`scripts/build-macos-ci.sh` (cgo needs it).

### 2. Branch-per-platform, serialize the shared interface
**What:** adopt the branch/PR flow the `p3sig` repo already uses, for this repo
too:
- **Shared / interface changes** (`keystore.go`) are their own task that lands on
  `main` *first* (this is what T1 did — added `Agree` + stubs before T3/T4 filled
  them in).
- **Platform implementations** fan out in parallel, each on its own
  `claude/<task>-<platform>` branch → PR → merge. Never direct-to-`main` for
  concurrent platform work.

**Why:** the platform files are disjoint and never conflict; the *only* real
collision point is the shared interface. Serializing interface changes and
branching the platform impls makes concurrent sessions safe by construction and
removes the manual "the other session is pushing right now" coordination.

**Done when:** `CONTRIBUTING`/handoff docs state this rule and the handoff
template's "How to land it" step says *branch + PR*, not push to `main`.

### 3. One source of truth for task status
**What:** move the phase task tracker into this repo (e.g.
`docs/device-enrollment-phase1-tasks.md` alongside the code and handoffs), or
otherwise designate a single canonical tracker. Make "update the tracker to ✅
with the landing commit link" a **required** final step of every handoff, not the
current optional "update it, *or* note it in your report."

**Why:** today a session touches two repos and the status update is easy to skip.
Co-locating status with code + handoffs means one session, one repo, one PR
updates code *and* status together.

**Done when:** the tracker has a single home, cross-links to the handoff docs, and
the handoff template requires updating it.

### 4. Handoff template + committed per-platform dev runbooks
**What:** two documentation artifacts.
- **`docs/handoffs/TEMPLATE.md`** — fixed sections every handoff fills in:
  *Context · Prerequisites & environment · Definition of Done · Report-back ·
  How to land it (branch + PR)*. Generate `T3`/`T4`-style docs from it so nothing
  is forgotten and they read consistently.
- **`docs/dev-mac.md` and `docs/dev-windows.md`** — the environment a fresh
  session currently rediscovers each time. For macOS this must include the
  **signed-`.app` recipe for running `P3SIG_HW_TEST` tests locally** (an unsigned
  `go test` binary fails Secure Enclave ops with `-34018`): build with
  `go test -c`, wrap in a `com.p3sig.keys` `.app` with the embedded provisioning
  profile exactly like `scripts/build-macos-ci.sh`, sign with the Developer ID
  identity, and run with `P3SIG_KEYCHAIN_GROUP=YGD7MTGWMF.com.p3sig.keys`. The
  Apple-Development-identity + app-identifier-only shortcut (no profile) does
  **not** work — the embedded profile is required. (Reference: `BUILD-macos.md`,
  `MACOS-SECRETS-SETUP.md`.)

**Why:** the handoff *content* is good; the cost is reinventing structure and
re-deriving setup every time. Committing both removes that per-session tax and is
the "more documented" half of the ask.

**Done when:** `T3`/`T4` are reformatted to match the template (or the next new
handoff is authored from it), and a fresh session can get a signed hardware-test
build working from `dev-mac.md` alone.

### 5. Self-serve kickoff
**What:** a small committed skill / slash command (e.g. `/next-handoff`) that
reads the tracker, finds the next `⏳ HANDED OFF` task for *this* platform, and
runs it against the template. Optionally, a scheduled/triggered session on each
physical machine that batches pending hardware tests so the human approves
several biometric prompts in one sitting.

**Why:** starting a session becomes one prompt instead of a doc hunt, and
batching amortizes the human-in-the-loop cost — directly improving "timely."

**Done when:** starting platform work is a single command that lands on the right
task.

---

## Net effect

CI absorbs build + unit sanity across all three OSes; physical Mac/Windows
sessions become short and biometric-only; branch-per-platform keeps parallel
sessions from colliding; and one tracker + one template keeps the whole thing
legible. Item **#1 is the single highest-leverage change** — it's what actually
makes builds timely, because it removes the human and the device from everything
except the biometric test.

## Suggested implementation order

1. CI matrix (#1) — immediate, unblocks everything else.
2. Branch/PR + interface-first rule (#2) — process, adopt alongside #1.
3. Tracker consolidation (#3) + handoff template & dev runbooks (#4).
4. `/next-handoff` kickoff (#5) — nice-to-have once the above are in place.
