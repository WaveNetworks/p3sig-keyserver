#!/usr/bin/env bash
# Build, wrap, and codesign the macOS Secure Enclave build of p3sig.
#
# The Secure Enclave client key needs a codesigned binary whose entitlements
# carry a keychain access group authorized by a provisioning profile. A bare
# executable can't hold a profile, so we wrap it in a minimal .app bundle. See
# docs/BUILD-macos.md for how to obtain the profile.
#
# Required env:
#   TEAM_ID        Apple Team ID (the OU of your signing cert), e.g. ABCDE12345
#   SIGN_IDENTITY  codesign identity, e.g. "Apple Development: You (ABCDE12345)"
#   PROFILE        path to a provisioning profile authorizing keychain-access-groups
#                  TEAM_ID.*  (a "Mac Team Provisioning Profile: *" works)
# Optional env:
#   KEYCHAIN_GROUP keychain access group suffix (default: com.p3sig.keys)
#   SDKROOT        macOS SDK path (auto-detected via xcrun if unset)
#   DEVELOPER_DIR  toolchain dir (defaults to Command Line Tools if present)
set -euo pipefail

cd "$(dirname "$0")/.."

: "${TEAM_ID:?set TEAM_ID (your Apple Team ID, e.g. ABCDE12345)}"
: "${SIGN_IDENTITY:?set SIGN_IDENTITY (see: security find-identity -v -p codesigning)}"
: "${PROFILE:?set PROFILE (path to a .provisionprofile authorizing keychain-access-groups $TEAM_ID.*)}"
[ -f "$PROFILE" ] || { echo "PROFILE not found: $PROFILE" >&2; exit 1; }

KEYCHAIN_GROUP="${KEYCHAIN_GROUP:-com.p3sig.keys}"
GROUP="$TEAM_ID.$KEYCHAIN_GROUP"
APP="p3sig.app"

# Toolchain: prefer Command Line Tools clang (no Xcode license gate) but link
# against a modern SDK (the CLT-only SDK may lack SecTrustCopyCertificateChain).
if [ -z "${DEVELOPER_DIR:-}" ] && [ -d /Library/Developer/CommandLineTools ]; then
	export DEVELOPER_DIR=/Library/Developer/CommandLineTools
fi
if [ -z "${SDKROOT:-}" ]; then
	SDKROOT="$(xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)"
	# xcrun under CLT may return the old SDK; prefer an Xcode SDK if present.
	xcode_sdk="$(ls -d /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX*.sdk 2>/dev/null | tail -1 || true)"
	[ -n "$xcode_sdk" ] && SDKROOT="$xcode_sdk"
	export SDKROOT
fi
echo "DEVELOPER_DIR=${DEVELOPER_DIR:-<default>}"
echo "SDKROOT=${SDKROOT:-<default>}"

echo "==> building (cgo)"
CGO_ENABLED=1 go build -o p3sig .

echo "==> assembling $APP (bundle id com.p3sig.keys)"
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
  <key>CFBundleShortVersionString</key><string>0.1</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
</dict>
</plist>
EOF

ENT="$(mktemp -t p3sig-ent).plist"
trap 'rm -f "$ENT"' EXIT
cat > "$ENT" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.application-identifier</key><string>$GROUP</string>
  <key>com.apple.developer.team-identifier</key><string>$TEAM_ID</string>
  <key>keychain-access-groups</key><array><string>$GROUP</string></array>
  <key>com.apple.security.get-task-allow</key><true/>
</dict>
</plist>
EOF

echo "==> signing $APP as: $SIGN_IDENTITY"
codesign --force --options runtime --sign "$SIGN_IDENTITY" --entitlements "$ENT" "$APP"
codesign --verify --verbose=2 "$APP"

cat <<EOF

Built: $APP/Contents/MacOS/p3sig
Run with:
  export P3SIG_KEYCHAIN_GROUP=$GROUP
  ./$APP/Contents/MacOS/p3sig setup --label test
EOF
