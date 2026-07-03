---
description: Find and start the next pending hardware handoff for this machine's platform
---

You are starting a hardware handoff session for the **p3sig-keyserver** repo. Do this:

1. **Detect the platform** of the machine you're running on (macOS or Windows) — e.g.
   `uname -s` (Darwin = macOS) or check `$OS` / `go env GOOS`. If the argument
   `$ARGUMENTS` names a platform or a specific task id (e.g. `T3`, `windows`), honor it.

2. **Read the canonical tracker** `docs/device-enrollment-tasks.md`. Find the highest-
   priority task that is (a) **not** ✅ DONE, (b) marked `⏳ HANDED OFF` or otherwise
   ready, (c) for **this platform**, and (d) whose dependencies are all DONE. If none
   match, say so and stop (don't invent work).

3. **Read the handoff doc** it references (e.g. `docs/T3-macos-agree-handoff.md`) and
   `docs/dev-<platform>.md`. If no handoff doc exists yet, author one from
   `docs/handoffs/TEMPLATE.md` first.

4. **Gate on a device-signed build BEFORE coding:** run the device-free checks from the
   dev doc (`go build/vet/gofmt/test`), then get the **opt-in hardware test building and
   signed** per the dev doc (macOS: the `.app` recipe — an unsigned test fails `-34018`).
   Only proceed once that's working.

5. **Implement per the handoff.** Honor `CONTRIBUTING.md`:
   - If it touches the shared `Keystore` interface → that's a **separate interface-first
     PR to `main`** (method + stubs on every backend) landed *before* the impl.
   - The implementation goes on a **`claude/<task>-<platform>` branch → PR**, never
     direct to `main`.

6. **Definition of Done** (from the template): build/vet/gofmt clean, unit tests pass,
   the **biometric hardware test passes on real hardware** (paste the command + success
   line), no secrets in logs, buffers zeroed.

7. **Final step (required):** update `docs/device-enrollment-tasks.md` to ✅ with the
   landing commit/PR link, in the same PR. Then report back per the template's
   Report-back section.

Argument (optional): `$ARGUMENTS` — a task id (`T3`) and/or platform to target instead of
auto-picking.
