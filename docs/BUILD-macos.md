# Building the macOS binary (Secure Enclave / Touch ID)

The macOS chip-backed client key (`keystore_darwin.go`) uses **cgo** against the
Security framework and a key that lives in the **Secure Enclave**, gated by Touch
ID. Because the Enclave requires the process to hold a *keychain access group*
entitlement, the macOS build has two extra requirements beyond `go build`:

1. a recent **macOS SDK** (cgo links `crypto/x509`'s `SecTrustCopyCertificateChain`,
   which the old standalone Command Line Tools SDK lacks), and
2. a **codesigned binary with a provisioning profile** that authorizes
   `keychain-access-groups` — otherwise key creation fails with
   `errSecMissingEntitlement (-34018)`, and a profile-less restricted entitlement
   gets the process **SIGKILLed by AMFI** ("Taskgated Invalid Signature").

The non-Enclave roles (agent/server) still build as plain pure-Go binaries — see
the **Build** section of the top-level `README.md`. This doc is only about the
Secure Enclave client path.

## TL;DR

```sh
# one-time: get a wildcard Mac provisioning profile (see below), then:
export TEAM_ID=XXXXXXXXXX
export SIGN_IDENTITY="Apple Development: Your Name (XXXXXXXXXX)"
export PROFILE=/path/to/mac-team.provisionprofile
./scripts/build-macos.sh

# run it (the access group must match what you signed with):
export P3SIG_KEYCHAIN_GROUP=$TEAM_ID.com.p3sig.keys
./p3sig.app/Contents/MacOS/p3sig setup --label test       # prints ecdsa-sha2-nistp256 …
./p3sig.app/Contents/MacOS/p3sig ssh-agent --label test --bind /tmp/p3sig.sock
```

## 1. Toolchain / SDK

cgo needs clang + a macOS SDK with modern Security symbols. If you have full
Xcode, just build natively. If `go build` fails at link with
`Undefined symbols … _SecTrustCopyCertificateChain` (old Command Line Tools SDK),
point the build at the Xcode SDK while keeping the CLT clang driver:

```sh
export DEVELOPER_DIR=/Library/Developer/CommandLineTools
export SDKROOT="$(ls -d /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX*.sdk | tail -1)"
CGO_ENABLED=1 go build -o p3sig .
```

(`scripts/build-macos.sh` does this automatically.)

## 2. Signing identity

You need an **Apple Development** (or Developer ID) code-signing identity in your
login keychain. In Xcode: **Settings → Accounts →** your team **→ Manage
Certificates → + → Apple Development**. Verify:

```sh
security find-identity -v -p codesigning
```

The certificate's `OU` is your **Team ID** (`TEAM_ID` above).

## 3. Provisioning profile (the key step)

Secure Enclave key creation requires the `keychain-access-groups` entitlement,
which on macOS must be authorized by a provisioning profile. The easiest way to
get a reusable one is to let Xcode generate the **wildcard team profile**:

1. **File → New → Project → macOS → App.** Set the Team to your paid team
   (keychain sharing isn't available on free teams).
2. Target → **Signing & Capabilities** → keep **Automatically manage signing** on.
3. Click **+ Capability → Keychain Sharing** (this adds `keychain-access-groups`).
4. **Build once** (⌘B). Xcode registers an App ID and installs a profile named
   **"Mac Team Provisioning Profile: \*"** — a wildcard authorizing
   `keychain-access-groups: TEAMID.*`, valid ~1 year, no App Sandbox required.

Find the embedded profile in the built app and copy it out:

```sh
APP="$HOME/Library/Developer/Xcode/DerivedData/<proj>/Build/Products/Debug/<App>.app"
cp "$APP/Contents/embedded.provisionprofile" ./mac-team.provisionprofile
# inspect what it authorizes:
security cms -D -i ./mac-team.provisionprofile | plutil -extract Entitlements xml1 -o - -
```

You want `keychain-access-groups` = `TEAMID.*` and **no** App Sandbox so the
ssh-agent keeps its unix-socket / filesystem access.

## 4. Wrap + sign

A standalone executable can't carry a provisioning profile, so the binary is
wrapped in a minimal `.app` bundle with the profile at
`Contents/embedded.provisionprofile`, then codesigned with matching entitlements.
`scripts/build-macos.sh` builds, wraps, generates the entitlements (from
`$TEAM_ID`), and signs. The resulting executable is
`p3sig.app/Contents/MacOS/p3sig`.

## 5. Run / acceptance test

```sh
export P3SIG_KEYCHAIN_GROUP=$TEAM_ID.com.p3sig.keys   # must match signed entitlements
BIN=./p3sig.app/Contents/MacOS/p3sig

$BIN setup --label test                # creates Enclave key, prints pubkey (no Touch ID)
$BIN ssh-agent --label test --bind /tmp/p3sig.sock &
export SSH_AUTH_SOCK=/tmp/p3sig.sock
ssh-add -L                             # lists the chip key (no Touch ID)

# loopback sshd trusting the chip pubkey, then:
ssh -o IdentitiesOnly=no test@localhost true   # prompts Touch ID, authenticates
```

`P3SIG_KEYCHAIN_GROUP` tells the keystore which access group to scope keychain
items to; it must equal the access group in the signed entitlements
(`TEAMID.com.p3sig.keys`). Unsigned/dev builds can leave it unset (default group),
but then Enclave operations fail with `-34018`.

## Gotchas

- **`IdentitiesOnly=yes` offers nothing** when no `-i` file is given — use
  `IdentitiesOnly=no` so the agent's key is offered.
- **Biometric re-enrollment invalidates the key.** The key is created with
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` + `BiometryCurrentSet`, so adding
  or removing a fingerprint (or wiping Touch ID) permanently destroys it — by
  design. Recovery: register a second machine / a USB-token CA so you're never
  locked out. Re-run `p3sig setup` to mint a fresh key and re-register its pubkey.
- **P-256 only** — the Secure Enclave does not do Ed25519.
