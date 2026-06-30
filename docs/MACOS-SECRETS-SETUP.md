# Loading the release secrets (runbook for Claude Code on a Mac)

This is a step-by-step runbook for a **Claude Code agent running on a Mac** to
populate the GitHub Actions secrets that `.github/workflows/release.yml` needs.
The Apple signing material can only be exported/created on a Mac with the
developer's keychain + Apple account, which is why this runs there rather than in
the Linux dev environment.

Target repo for every secret below: **`WaveNetworks/p3sig-keyserver`**.

---

## Division of labor

**A human must hand you these files/values** (Claude Code cannot click through
Apple's authenticated portal or approve a Keychain export GUI prompt):

| Item | Where the human gets it |
|---|---|
| `cert.p12` + its password | Keychain Access → the *Developer ID Application* cert → right-click → **Export** as `.p12` |
| `p3sig.provisionprofile` | Apple Developer portal → Profiles → the **Developer ID** profile for App ID `com.p3sig.keys` (Keychain Sharing capability) → Download |
| `AuthKey_XXXX.p8` + Key ID + Issuer ID | App Store Connect → Users and Access → Integrations → **Keys** (Developer access) |
| GitHub PAT for the tap/bucket | github.com → Settings → Developer settings → PAT with **Contents: write** on `homebrew-tap` + `scoop-bucket` |
| *(optional)* winget PAT, AUR ssh private key | see `docs/PACKAGING.md` |

Ask the human to drop the three files into one staging dir and tell you the
passwords/IDs. **Everything else below, you (Claude Code) run yourself.**

```sh
# Agent: confirm prerequisites first
gh auth status                      # must be logged in with repo access
gh auth status | grep -q . || { echo "run: gh auth login"; exit 1; }
SECDIR="$HOME/p3sig-secrets"        # where the human placed cert.p12 etc.
REPO="WaveNetworks/p3sig-keyserver"
ls "$SECDIR"                        # expect: cert.p12  p3sig.provisionprofile  AuthKey_*.p8
```

> ⚠️ The staging dir holds private keys. Keep it OUTSIDE any git repo and delete
> it when done (`rm -rf "$SECDIR"`). Never paste secret contents into the repo,
> commit them, or echo them into the transcript.

---

## 1. Derive the signing identity from the keychain (no human needed)

```sh
SIGN_IDENTITY="$(security find-identity -v -p codesigning \
  | grep 'Developer ID Application' | head -1 | sed -E 's/.*"(.*)"/\1/')"
TEAM_ID="$(printf '%s' "$SIGN_IDENTITY" | sed -E 's/.*\(([A-Z0-9]+)\)$/\1/')"
echo "identity: $SIGN_IDENTITY"
echo "team id : $TEAM_ID"
# sanity: both must be non-empty. If empty, the cert isn't imported — have the
# human install the Developer ID Application cert into the login keychain first.

gh secret set MACOS_SIGN_IDENTITY -R "$REPO" --body "$SIGN_IDENTITY"
gh secret set APPLE_TEAM_ID       -R "$REPO" --body "$TEAM_ID"
```

## 2. A throwaway password for the CI keychain (you generate it)

```sh
gh secret set KEYCHAIN_PASSWORD -R "$REPO" --body "$(openssl rand -base64 24)"
```

## 3. Certificate (.p12) — base64, then its export password

```sh
# single-line base64 (macOS base64 can wrap; strip newlines to be safe)
base64 -i "$SECDIR/cert.p12" | tr -d '\n' \
  | gh secret set MACOS_CERT_P12_BASE64 -R "$REPO"

# the password the human used when exporting the .p12:
read -rs -p 'cert .p12 export password: ' P12PW; echo
gh secret set MACOS_CERT_PASSWORD -R "$REPO" --body "$P12PW"; unset P12PW
```

## 4. Provisioning profile

```sh
base64 -i "$SECDIR/p3sig.provisionprofile" | tr -d '\n' \
  | gh secret set MACOS_PROVISION_PROFILE_BASE64 -R "$REPO"
```

## 5. App Store Connect API key (notarization)

```sh
P8="$(ls "$SECDIR"/AuthKey_*.p8)"
base64 -i "$P8" | tr -d '\n' | gh secret set AC_API_KEY_P8_BASE64 -R "$REPO"

# the Key ID is the XXXX in the filename AuthKey_XXXX.p8; confirm with the human:
read -rp  'App Store Connect Key ID   : ' KEYID;  gh secret set AC_API_KEY_ID    -R "$REPO" --body "$KEYID"
read -rp  'App Store Connect Issuer ID: ' ISSUER; gh secret set AC_API_ISSUER_ID -R "$REPO" --body "$ISSUER"
```

## 6. Cross-repo publishing tokens

```sh
read -rs -p 'TAP_GITHUB_TOKEN (PAT, Contents:write on tap+bucket): ' TAPTOK; echo
gh secret set TAP_GITHUB_TOKEN -R "$REPO" --body "$TAPTOK"; unset TAPTOK

# optional — only if enabling these channels (see docs/PACKAGING.md):
# read -rs -p 'WINGET_GITHUB_TOKEN: ' W; echo; gh secret set WINGET_GITHUB_TOKEN -R "$REPO" --body "$W"; unset W
# gh secret set AUR_KEY -R "$REPO" < /path/to/aur_ed25519_private_key
```

---

## 7. Verify and clean up

```sh
gh secret list -R "$REPO"
# Expect at least:
#   APPLE_TEAM_ID  MACOS_SIGN_IDENTITY  KEYCHAIN_PASSWORD  MACOS_CERT_P12_BASE64
#   MACOS_CERT_PASSWORD  MACOS_PROVISION_PROFILE_BASE64  AC_API_KEY_P8_BASE64
#   AC_API_KEY_ID  AC_API_ISSUER_ID  TAP_GITHUB_TOKEN

rm -rf "$SECDIR"        # destroy the local private keys
```

Then a tag push from anywhere cuts a full release:
```sh
git tag v0.4.0 && git push origin v0.4.0 && gh run watch
```

If only some secrets are loaded, set the repo **variable** `GORELEASER_SKIP`
(e.g. `winget,aur`) so the release doesn't fail on the unconfigured channels —
see `docs/PACKAGING.md`.

## Renewing later

The **provisioning profile expires (~yearly)**. When a release starts failing at
the sign/notarize step, the human re-downloads the profile and you re-run **step
4** only. The certificate and App Store Connect key last longer but rotate the
same way (steps 3 / 5).
