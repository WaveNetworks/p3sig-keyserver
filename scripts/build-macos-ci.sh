#!/usr/bin/env bash
# CI variant of build-macos.sh: build, wrap, codesign, NOTARIZE and zip a
# DISTRIBUTABLE macOS build of p3sig for a single architecture.
#
# Differs from scripts/build-macos.sh (a local dev build) in three ways that
# matter for public distribution:
#   1. signs with a *Developer ID Application* identity (not "Apple Development")
#   2. entitlements OMIT com.apple.security.get-task-allow — a dev-only
#      entitlement that makes notarization REJECT the build
#   3. notarizes + staples so Gatekeeper allows it on other people's Macs
#
# The Secure Enclave keychain-access-groups entitlement still requires a
# provisioning profile authorizing TEAMID.<group>. For Developer ID + that
# entitlement you need a *Developer ID provisioning profile* with the
# Keychain Sharing capability — see docs/PACKAGING.md.
#
# Usage:  scripts/build-macos-ci.sh <arm64|amd64>
#
# Required env (from CI secrets):
#   APPLE_TEAM_ID         Apple Team ID, e.g. ABCDE12345
#   MACOS_SIGN_IDENTITY   e.g. "Developer ID Application: Wave Networks (ABCDE12345)"
#   PROFILE               path to the Developer ID .provisionprofile
#   AC_API_KEY_ID         App Store Connect API key id          (notarytool)
#   AC_API_ISSUER_ID      App Store Connect issuer id           (notarytool)
#   AC_API_KEY_PATH       path to the App Store Connect .p8 key (notarytool)
# Optional env:
#   KEYCHAIN_GROUP        keychain access group suffix (default: com.p3sig.keys)
#   VERSION               version string baked via -ldflags (default: dev)
#   OUTDIR                where to drop the zip (default: macos-dist)
set -euo pipefail
cd "$(dirname "$0")/.."

ARCH="${1:?usage: build-macos-ci.sh <arm64|amd64>}"
case "$ARCH" in
  arm64) CLANG_ARCH=arm64 ;;
  amd64) CLANG_ARCH=x86_64 ;;
  *) echo "arch must be arm64 or amd64" >&2; exit 2 ;;
esac

: "${APPLE_TEAM_ID:?set APPLE_TEAM_ID}"
: "${MACOS_SIGN_IDENTITY:?set MACOS_SIGN_IDENTITY}"
: "${PROFILE:?set PROFILE (Developer ID provisioning profile path)}"
: "${AC_API_KEY_ID:?set AC_API_KEY_ID}"
: "${AC_API_ISSUER_ID:?set AC_API_ISSUER_ID}"
: "${AC_API_KEY_PATH:?set AC_API_KEY_PATH}"
[ -f "$PROFILE" ] || { echo "PROFILE not found: $PROFILE" >&2; exit 1; }

KEYCHAIN_GROUP="${KEYCHAIN_GROUP:-com.p3sig.keys}"
GROUP="$APPLE_TEAM_ID.$KEYCHAIN_GROUP"
VERSION="${VERSION:-dev}"
OUTDIR="${OUTDIR:-macos-dist}"
APP="p3sig.app"
ZIP="$OUTDIR/p3sig-darwin-$ARCH.zip"

export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"

echo "==> building darwin/$ARCH (cgo, version $VERSION)"
CGO_ENABLED=1 GOOS=darwin GOARCH="$ARCH" \
  CC="clang -arch $CLANG_ARCH" \
  go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o p3sig .

echo "==> assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp p3sig "$APP/Contents/MacOS/p3sig"
cp "$PROFILE" "$APP/Contents/embedded.provisionprofile"
cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>com.p3sig.keys</string>
  <key>CFBundleExecutable</key><string>p3sig</string>
  <key>CFBundleName</key><string>p3sig</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>${VERSION#v}</string>
  <key>CFBundleVersion</key><string>${VERSION#v}</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
</dict>
</plist>
EOF

# Distribution entitlements: NO get-task-allow (would fail notarization).
ENT="$(mktemp -t p3sig-ent).plist"
trap 'rm -f "$ENT"' EXIT
cat > "$ENT" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.application-identifier</key><string>$GROUP</string>
  <key>com.apple.developer.team-identifier</key><string>$APPLE_TEAM_ID</string>
  <key>keychain-access-groups</key><array><string>$GROUP</string></array>
</dict>
</plist>
EOF

echo "==> signing (hardened runtime) as: $MACOS_SIGN_IDENTITY"
codesign --force --timestamp --options runtime \
  --sign "$MACOS_SIGN_IDENTITY" --entitlements "$ENT" "$APP"
codesign --verify --strict --verbose=2 "$APP"

echo "==> zipping (preserve signature)"
mkdir -p "$OUTDIR"
rm -f "$ZIP"
/usr/bin/ditto -c -k --keepParent "$APP" "$ZIP"

echo "==> notarizing $ZIP"
xcrun notarytool submit "$ZIP" \
  --key "$AC_API_KEY_PATH" --key-id "$AC_API_KEY_ID" --issuer "$AC_API_ISSUER_ID" \
  --wait

echo "==> stapling"
xcrun stapler staple "$APP"
# re-zip so the downloaded artifact carries the stapled ticket
rm -f "$ZIP"
/usr/bin/ditto -c -k --keepParent "$APP" "$ZIP"
xcrun stapler validate "$APP"

echo "built + notarized: $ZIP"
