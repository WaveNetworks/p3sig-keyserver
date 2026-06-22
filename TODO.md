# TODO

## Done
- [x] v2 protocol rewrite — signed-request auth, SSH-CA agent, secret injection (`main.go`)
- [x] Released v0.2.0 (5 platform binaries)
- [x] Shared `Keystore` interface + build-tag scaffolding (`keystore.go`, `keystore_stub.go`)

## Next: chip-backed client keys (one Claude Code session per machine)
The login key on a client machine should live in its security chip, unlocked by the
biometric, never extractable. Each platform is cgo/syscall against OS frameworks and
**must be built and tested on that machine**.

- [ ] **macOS — Secure Enclave / Touch ID** → `docs/TODO-macos.md` (implement
      `keystore_darwin.go`, the shared `setup` + `ssh-agent` glue)
- [ ] **Windows — Windows Hello / TPM** → `docs/TODO-windows.md` (implement
      `keystore_windows.go`, named-pipe agent)

Start with **`docs/CONTEXT.md`** (shared design, the interface, and a fully-local test
recipe that needs no live p3sig), then your platform's TODO.

### Shared work either session can land (no build tag)
- [ ] `p3sig setup --label NAME` — create the chip key, print its pubkey to register
- [ ] `p3sig ssh-agent --bind PATH` — serve the chip key via `ssh/agent`, normalizing the
      macOS-DER vs Windows-r||s signature forms into the SSH ecdsa blob
- [ ] (phase 2) `p3sig ssh login` — get the chip pubkey signed by the USB-resident CA
      (mint a day-pass cert) rather than registering the key directly

## Later
- [ ] systemd unit / launchd / Windows service templates for `agent run`
- [ ] `p3sig setup` auto-registration via an authenticated p3sig session (vs. copy/paste)
