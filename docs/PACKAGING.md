# Packaging & release automation

Pushing a semver tag (`git tag v0.4.0 && git push origin v0.4.0`) runs
`.github/workflows/release.yml`, which:

1. **macOS job** (`macos-14`): cgo-builds darwin arm64 + amd64, signs with your
   Developer ID + provisioning profile, **notarizes + staples**, and zips each
   `.app` → `p3sig-darwin-<arch>.zip`.
2. **release job** (`ubuntu`): GoReleaser builds linux amd64/arm64 + windows
   amd64 (cgo-free), creates the GitHub Release (attaching the macOS zips), and
   publishes to the package managers below. Then it renders the **Homebrew cask**
   and pushes it to the tap.

Once secrets are in place, **the only manual step per release is pushing the tag.**

---

## What ships where

| Channel | Install command | Gating secret |
|---|---|---|
| GitHub Release (tar.gz/zip) | `curl … install.sh \| sh` | none (`GITHUB_TOKEN`) |
| Homebrew (macOS) | `brew install --cask WaveNetworks/tap/p3sig` | `TAP_GITHUB_TOKEN` + macOS secrets |
| Scoop (Windows) | `scoop bucket add p3sig …; scoop install p3sig` | `TAP_GITHUB_TOKEN` |
| winget (Windows) | `winget install WaveNetworks.p3sig` | `WINGET_GITHUB_TOKEN` |
| apt/dnf (.deb/.rpm) | download from release, `dpkg -i` / `rpm -i` | none |
| AUR (Arch) | `yay -S p3sig-bin` | `AUR_KEY` |

To roll out incrementally, set the repo **variable** `GORELEASER_SKIP` (Settings
→ Secrets and variables → Actions → Variables), e.g. `winget,aur,cask`, and
remove names as each channel's prerequisites are met. Empty = publish everything.

---

## One-time setup

### 1. Tap + bucket repos (Homebrew + Scoop)
Create two public repos under the WaveNetworks org:
- **`homebrew-tap`** — the cask lands in `Casks/p3sig.rb`. Users add it implicitly
  via `WaveNetworks/tap`.
- **`scoop-bucket`** — GoReleaser writes `bucket/p3sig.json`.

`TAP_GITHUB_TOKEN`: a fine-grained or classic PAT with **Contents: write** on both
repos. Add it as a repo secret on `p3sig-keyserver`.

### 2. winget
- Fork `microsoft/winget-pkgs` to `WaveNetworks/winget-pkgs`.
- `WINGET_GITHUB_TOKEN`: PAT with **Contents: write** on the fork and
  **Pull requests: write** (it opens the PR into microsoft/winget-pkgs).
- First submission of a new package id may need manual review by the winget team.

### 3. AUR
- Register an AUR account, add an SSH public key to it.
- `ssh aur@aur.archlinux.org setup-repo p3sig-bin` to reserve the name.
- `AUR_KEY`: the **private** SSH key (full PEM) as a secret.

### 4. macOS signing + notarization (the involved one)
You need an **Apple Developer Program** membership.

**Certificate** — a *Developer ID Application* cert (not "Apple Development"):
- Create it in the Apple Developer portal, export from Keychain Access as a
  `.p12` with a password.
- `MACOS_CERT_P12_BASE64` = `base64 -i cert.p12` (one line).
- `MACOS_CERT_PASSWORD` = the .p12 password.
- `KEYCHAIN_PASSWORD` = any throwaway string (a temp keychain in CI).
- `MACOS_SIGN_IDENTITY` = e.g. `Developer ID Application: Wave Networks (ABCDE12345)`.
- `APPLE_TEAM_ID` = e.g. `ABCDE12345`.

**Provisioning profile** — the Secure Enclave `keychain-access-groups` entitlement
(`TEAMID.com.p3sig.keys`) requires a profile that authorizes it. Create a
**Developer ID provisioning profile** for an App ID `com.p3sig.keys` with the
**Keychain Sharing** capability enabled, download the `.provisionprofile`:
- `MACOS_PROVISION_PROFILE_BASE64` = `base64 -i p3sig.provisionprofile`.
- ⚠️ Profiles expire (typically a year). When notarization/sign starts failing,
  regenerate and update this secret.

**Notarization** — App Store Connect API key (Keys tab, Developer access):
- `AC_API_KEY_P8_BASE64` = `base64 -i AuthKey_XXXX.p8`.
- `AC_API_KEY_ID` = the key id (e.g. `2X9R4HXF34`).
- `AC_API_ISSUER_ID` = the issuer UUID.

> The CI entitlements deliberately **omit `com.apple.security.get-task-allow`**
> (a dev-only entitlement that makes notarization reject the build). The local
> `scripts/build-macos.sh` keeps it for debugging; `scripts/build-macos-ci.sh`
> is the distribution variant.

---

## Full secret checklist

```
# cross-repo publishing
TAP_GITHUB_TOKEN
WINGET_GITHUB_TOKEN          # optional until winget enabled
AUR_KEY                      # optional until AUR enabled
# macOS signing
APPLE_TEAM_ID
MACOS_SIGN_IDENTITY
MACOS_CERT_P12_BASE64
MACOS_CERT_PASSWORD
KEYCHAIN_PASSWORD
MACOS_PROVISION_PROFILE_BASE64
AC_API_KEY_P8_BASE64
AC_API_KEY_ID
AC_API_ISSUER_ID
```

## Validate the config locally

```sh
go install github.com/goreleaser/goreleaser/v2@latest
goreleaser check                 # lint .goreleaser.yaml
goreleaser release --snapshot --clean --skip=publish,winget,aur   # dry-run linux/windows
```

(macOS signing can only be exercised on a Mac with the secrets present; the
snapshot run skips it.)
