# Cutting a release (and the macOS binary)

Read this before publishing. **Slice 1 landed in `main`** (commit `550921c`): config +
profiles, the `init` and `server up` wizards, and `secrets list/get` + `secrets pull
--export` + `run`. These are **pure Go** — they build on every target with no platform work
— but the published binaries predate them, so a fresh release is needed to ship Slice 1.

## What each target needs

| Target | Toolchain | Carries the SE/chip key? |
|---|---|---|
| linux amd64/arm64 | `CGO_ENABLED=0` cross-compile (any host) | no (server/secrets/SSH-CA + Slice 1) |
| windows amd64 | `CGO_ENABLED=0` cross-compile (any host) | yes — Windows Hello/TPM via pure-Go `ncrypt.dll` |
| **darwin arm64/amd64** | **cgo, ON a Mac** | yes — Secure Enclave/Touch ID (`keystore_darwin.go`) |

linux + windows can be built anywhere (they're cgo-free). **darwin cannot be
cross-compiled** — `keystore_darwin.go` is `//go:build darwin` + cgo, and there is no
non-cgo darwin stub, so `CGO_ENABLED=0 GOOS=darwin` fails with `undefined: openKeystore`
by design. The darwin asset must be produced on a Mac.

## For the Mac session — produce the darwin binaries

1. **Pull latest `main`** — it now includes `cli.go` (Slice 1). Nothing darwin-specific
   changed; just build current `main` so the darwin binary has the new commands.
2. Build the **signed Secure Enclave** binary per **`docs/BUILD-macos.md`**
   (`scripts/build-macos.sh` → `p3sig.app/Contents/MacOS/p3sig`). Do this for **arm64**
   (Apple Silicon) and, if supporting Intel Macs, **amd64**.
3. **Smoke test — pure-Go commands (no chip needed):**
   ```sh
   BIN=./p3sig.app/Contents/MacOS/p3sig
   $BIN help                 # shows init / server up / secrets get|list
   XDG_CONFIG_HOME=/tmp/p3 $BIN init --key /path/to/some.key   # wizard runs, saves a profile
   $BIN secrets list         # resolves the profile, hits the API
   ```
4. **Smoke test — Secure Enclave (the Mac-only delta):** the `setup` / `ssh-agent` / Touch-ID
   login acceptance test in `docs/BUILD-macos.md` §5.
5. **Publish.** Attach the darwin asset(s) to the GitHub release alongside the cross-built
   linux/windows binaries (below). Name them `p3sig-darwin-arm64` / `p3sig-darwin-amd64`.
   > Note the **packaging split**: the SE features need the **signed `.app`** (the binary
   > must carry the provisioning profile). The server/secrets/SSH-CA + Slice 1 features work
   > from a **plain binary**. Decide whether the darwin release asset is the bare signed
   > executable extracted from the `.app`, or the `.app` zipped. The bare signed
   > `p3sig.app/Contents/MacOS/p3sig` retains the entitlement and works for both — prefer
   > shipping that (zipped to preserve the signature).

## Cross-built targets (any host, cgo-free)

```sh
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -o dist/p3sig-linux-amd64   .
CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -o dist/p3sig-linux-arm64   .
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o dist/p3sig-windows-amd64.exe .
```

## Release checklist

- [ ] `gofmt -l .` clean, `go vet ./...` clean, `go build` OK.
- [ ] Cross-build linux amd64/arm64 + windows amd64 (cgo-free, above).
- [ ] Mac session builds + signs darwin arm64 (+ amd64 if needed) from the **same commit**.
- [ ] Smoke-test Slice 1 on at least one binary (`init` → `secrets list` flag-free).
- [ ] `dist/`, `*.key`, `p3sig`, `p3sig.app` stay gitignored — don't commit binaries.
- [ ] Tag + `gh release create vX.Y.Z dist/* <darwin assets>` with notes.
- [ ] Update `WaveNetworks/p3sig-website` docs once published (quickstart / key-server-binary
      should lead with `p3sig init` → flag-free usage; they still show per-flag commands).
