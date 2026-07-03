# Dev setup — macOS (Secure Enclave / Touch ID)

The environment a fresh Mac session otherwise re-derives each time. Get a **device-signed
test build** working from this doc alone before touching code.

## Toolchain
- **Go 1.21** (matches `go.mod` + CI). `brew install go` or the official pkg.
- **Xcode Command Line Tools** (`xcode-select --install`) — cgo needs clang + the macOS
  SDK. `keystore_darwin.go` links `-framework Security -framework CoreFoundation
  -framework LocalAuthentication`.
- Export the SDK path for cgo builds: `export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"`.

## Device-free checks (same as CI — do these first)
```sh
go build ./...     # cgo darwin compiles unsigned; signing is NOT needed to build
go vet ./...
gofmt -l .         # must print nothing
go test ./...      # Enclave tests self-skip without P3SIG_HW_TEST / P3SIG_TOUCHID_TEST
```
If these pass, the only thing left for a physical session is the biometric round-trip.

## Running the Secure Enclave hardware test (the part only a Mac can do)

⚠️ **An unsigned `go test` binary fails Secure Enclave ops with `errSecMissingEntitlement
(-34018)`.** The Enclave `keychain-access-groups` entitlement is authorized by an
**embedded provisioning profile** — you must build the test binary, wrap it in a signed
`.app` carrying that profile, and run it from inside the bundle. The "Apple Development
identity + application-identifier only, no profile" shortcut does **not** work.

Prereqs (one-time — see `MACOS-SECRETS-SETUP.md` / `PACKAGING.md`):
- A signing identity (Developer ID Application, or an Apple Development identity for
  purely-local runs) in your keychain.
- A **provisioning profile** authorizing `TEAMID.com.p3sig.keys` with the Keychain
  Sharing capability. Team ID = `YGD7MTGWMF`; group = `YGD7MTGWMF.com.p3sig.keys`.

```sh
TEAMID=YGD7MTGWMF
GROUP="$TEAMID.com.p3sig.keys"
IDENTITY="Developer ID Application: Wave Networks ($TEAMID)"   # or your Apple Development identity
PROFILE=~/p3sig-secure-enclave.provisionprofile               # the profile above

export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"

# 1) compile the test binary (cgo)
CGO_ENABLED=1 go test -c -o p3sig.test .

# 2) wrap it in a .app with the embedded profile (mirrors scripts/build-macos-ci.sh)
APP=p3sig-test.app
rm -rf "$APP"; mkdir -p "$APP/Contents/MacOS"
cp p3sig.test "$APP/Contents/MacOS/p3sig"
cp "$PROFILE" "$APP/Contents/embedded.provisionprofile"
cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.p3sig.keys</string>
  <key>CFBundleExecutable</key><string>p3sig</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
</dict></plist>
EOF

# 3) entitlements + sign (local test build MAY keep get-task-allow; a DISTRIBUTION
#    build must omit it — that's the difference vs scripts/build-macos-ci.sh)
cat > ent.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>com.apple.application-identifier</key><string>$GROUP</string>
  <key>com.apple.developer.team-identifier</key><string>$TEAMID</string>
  <key>keychain-access-groups</key><array><string>$GROUP</string></array>
  <key>com.apple.security.get-task-allow</key><true/>
</dict></plist>
EOF
codesign --force --options runtime --sign "$IDENTITY" --entitlements ent.plist "$APP"
codesign --verify --strict --verbose=2 "$APP"

# 4) run the hardware test FROM INSIDE the bundle (Touch ID prompts fire)
P3SIG_HW_TEST=1 P3SIG_KEYCHAIN_GROUP="$GROUP" \
  "$APP/Contents/MacOS/p3sig" -test.run 'TestSecureEnclave_AgreeRoundTrip' -test.v
# Sign/Touch-ID round-trip: P3SIG_TOUCHID_TEST=1 -test.run TestSignRoundTrip
```
Expect a Touch ID prompt and a PASS. Paste that line into your handoff report.

## Gotchas
- `-34018` = the entitlement/profile isn't taking. Re-check the profile authorizes the
  group and that you're running the binary **inside** the signed `.app`, not the bare
  `p3sig.test`.
- Re-enrolling a fingerprint invalidates `BiometryCurrentSet` keys by design — recovery
  is the USB/passphrase path.
- P-256 only in the Enclave — never attempt Ed25519 there.
- For a **distributable** build (Developer ID + notarize, no get-task-allow), use
  `scripts/build-macos-ci.sh`, not this recipe.
