#!/usr/bin/env bash
# hw-acceptance.sh — the owner's real-hardware run for task #2630 (vault sticks + dongle).
#
# Everything here is the shipped CLI; this script only puts the steps in order, makes sure
# no ssh-agent is involved, and checks the result the way a pinned agent would. The only
# human parts: plug the sticks in, choose the passphrase, type the dongle PIN, touch it.
#
#   scripts/hw-acceptance.sh --machine ID --machine-key KEYFILE [--skip-usb] [--skip-dongle]
#
#   --machine ID          test machine to sign a policy for (must already be registered)
#   --machine-key FILE    that machine's agent key (what `p3sig agent pull` uses), so the
#                         pinned-agent check runs here into a temp dir, not /etc/ssh
#   --skip-usb            sticks already made (re-run after a later step failed)
#   --skip-dongle         dongle already added
#
# Builds ./p3sig-hw with the libfido2 backend first (CC=gcc: ~/.local/bin/cc is Claude Code).
set -euo pipefail

machine="" mkey="" skip_usb=0 skip_dongle=0
while [ $# -gt 0 ]; do
  case "$1" in
    --machine) machine="$2"; shift 2 ;;
    --machine-key) mkey="$2"; shift 2 ;;
    --skip-usb) skip_usb=1; shift ;;
    --skip-dongle) skip_dongle=1; shift ;;
    -h|--help) sed -n 2,16p "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$machine" ] && [ -n "$mkey" ] || { echo "need --machine ID and --machine-key FILE (see --help)" >&2; exit 2; }
[ -r "$mkey" ] || { echo "cannot read machine key $mkey" >&2; exit 2; }

cd "$(dirname "$0")/.."
step() { printf '\n== %s\n' "$*"; }

step "build with the libfido2 dongle backend"
CC=gcc go build -tags libfido2 -o p3sig-hw .
bin=$PWD/p3sig-hw

# The point of --with dongle is that no ssh-agent is involved: drop it for every step.
unset SSH_AUTH_SOCK SSH_AGENT_PID

if [ "$skip_usb" = 0 ]; then
  step "1/4 p3sig usb init — plug in DAILY (blank), then SAFE (blank) when asked"
  "$bin" usb init
fi

if [ "$skip_dongle" = 0 ]; then
  step "2/4 p3sig dongle add — DAILY plugged in, dongle plugged in (PIN, then touch)"
  "$bin" dongle add --root-key usb
fi

step "3/4 p3sig policy sign --machine $machine --with dongle (no ssh-agent)"
"$bin" policy sign --machine "$machine" --with dongle

step "4/4 pinned agent accepts it"
root=$("$bin" policy status | grep -oE 'SHA256:[A-Za-z0-9+/]+' | head -1)
[ -n "$root" ] || { echo "FAIL: no root fingerprint in 'p3sig policy status'" >&2; exit 1; }
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
P3SIG_KEY="$mkey" P3SIG_OUT="$out" "$bin" agent pull --machine "$machine" --root "$root" --require-signed
[ -s "$out/TrustedUserCAKeys" ] || { echo "FAIL: agent wrote no TrustedUserCAKeys" >&2; exit 1; }
echo
echo "PASS: root $root, policy for $machine signed by the dongle with no ssh-agent, accepted by an agent pinned to that root."
