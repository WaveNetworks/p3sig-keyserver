#!/usr/bin/env sh
# p3sig installer.  Usage:
#   curl -fsSL https://raw.githubusercontent.com/WaveNetworks/p3sig-keyserver/main/install.sh | sh
#
# Installs the latest release binary to a directory on your PATH.
# Override the target with:  P3SIG_BINDIR=$HOME/.local/bin sh install.sh
#
# Linux: downloads the static binary (no chip support is needed there beyond
#   what the static binary already carries).
# macOS: the Secure Enclave build ships as a signed .app — install it with
#   Homebrew instead:  brew install --cask WaveNetworks/tap/p3sig
set -eu

REPO="WaveNetworks/p3sig-keyserver"
BINDIR="${P3SIG_BINDIR:-/usr/local/bin}"

os="$(uname -s)"
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac

case "$os" in
  Linux) goos=linux ;;
  Darwin)
    echo "macOS uses the signed .app — install with Homebrew:" >&2
    echo "  brew install --cask WaveNetworks/tap/p3sig" >&2
    exit 1 ;;
  *) echo "unsupported OS: $os (Windows: use 'scoop install p3sig' or 'winget install WaveNetworks.p3sig')" >&2; exit 1 ;;
esac

echo "Resolving latest release…"
tag="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
  | grep '"tag_name"' | head -1 | cut -d '"' -f4)"
[ -n "$tag" ] || { echo "could not resolve latest release tag" >&2; exit 1; }
version="${tag#v}"

asset="p3sig_${version}_${goos}_${arch}.tar.gz"
url="https://github.com/$REPO/releases/download/$tag/$asset"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
echo "Downloading $asset …"
curl -fsSL "$url" -o "$tmp/p3sig.tgz"
tar -xzf "$tmp/p3sig.tgz" -C "$tmp" p3sig

if [ -w "$BINDIR" ]; then
  install -m 0755 "$tmp/p3sig" "$BINDIR/p3sig"
else
  echo "Installing to $BINDIR (needs sudo)…"
  sudo install -m 0755 "$tmp/p3sig" "$BINDIR/p3sig"
fi

echo "Installed: $("$BINDIR/p3sig" version 2>/dev/null || echo "$BINDIR/p3sig")"
