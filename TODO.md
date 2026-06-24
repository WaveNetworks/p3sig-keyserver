# TODO

## Done
- [x] v2 protocol rewrite — signed-request auth, SSH-CA agent, secret injection (`main.go`)
- [x] Released v0.2.0 (5 platform binaries)
- [x] Shared `Keystore` interface + build-tag scaffolding (`keystore.go`, `keystore_stub.go`)
- [x] `p3sig setup` / `p3sig ssh-agent` — chip-key create + serve to ssh
- [x] **Chip-backed client keys implemented:** `keystore_darwin.go` (Secure Enclave / Touch ID,
      cgo) + `keystore_windows.go` (Windows Hello / TPM via pure-Go `ncrypt.dll`)
- [x] **Slice 1 ergonomics** (`cli.go`, `550921c`): config + profiles, `p3sig init` enroll
      wizard, `p3sig server up` (writes sshd drop-in + systemd service), `secrets list`/`get`,
      `secrets pull --export`, `run` alias. All pure Go; verified E2E vs live p3sig.com.

## Released
- [x] **v0.3.0 (2026-06-23)** — Slice 1 + Slice 2 + recovery cards/split + chip-backed SSH
      keys (macOS Secure Enclave, Windows TPM/CNG). 5 assets: darwin amd64/arm64 `.app` zips,
      linux amd64/arm64, windows amd64. Published linux binary smoke-tested (recovery round-trip).
      darwin **arm64 is cross-built + UNVERIFIED** (built on an Intel Mac) — confirm on Apple
      Silicon when available; amd64 verified end-to-end with Touch ID.

## Next: Slice 2 — CLI management (USB-signs) + device-code enroll
Full spec in **`docs/SLICE-2.md`**. Needs new server endpoints in `WaveNetworks/p3sig`.
- [ ] [server] Enforce globally-unique vault keys + `p3sig_user_request_guard` + `whoami`
- [ ] [binary] `p3sig login` + identity profiles (account = your vault key)
- [ ] [server+binary] `getMyVaultKeys` + `sealForKey()` + `saveSecretSealed` → `secret set`
      (zero-knowledge secret-create from the terminal), then `secret get` / `grant`
- [ ] [server+binary] device-code `p3sig enroll` (no copy-paste; account = browser approver)
- [ ] (later slice) **Organizations** — multi-admin management, `owner_type='org'`, roles,
      `org reseal` for the zero-knowledge re-seal boundary (see `docs/SLICE-2.md` §7)

## Later
- [ ] `p3sig client up` — chip key + enroll + auto-start ssh-agent as a launchd/systemd-user/
      Windows service (the client twin of `server up`)
- [ ] `p3sig ssh login` — mint a day-pass cert from the USB-resident CA (vs. registering the
      chip key directly)
- [ ] Offline resilience cache — re-seal pulled artifacts to the machine's own key so boot
      survives p3sig being down (promised in the website docs, never built)
