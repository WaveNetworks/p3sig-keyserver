#!/usr/bin/env bash
# vault-usb.sh — open / close a p3sig vault USB made by make-vault-usbs.sh.
#   sudo scripts/vault-usb.sh open  [PARTITION]   (default: the drive labelled P3SIG-DAILY)
#   sudo scripts/vault-usb.sh close
# Open mounts the drive at /run/p3sig/fat and its VeraCrypt container at
# /run/p3sig/vault (owned by the sudo user, mode 700), so the key is
# /run/p3sig/vault/p3sig-root.key. The passphrase goes to VeraCrypt on stdin.
set -euo pipefail

OWNER=${SUDO_USER:-root}
OWNER_UID=$(id -u "$OWNER"); OWNER_GID=$(id -g "$OWNER")
FAT=/run/p3sig/fat; VAULT=/run/p3sig/vault

die() { echo "error: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run with sudo"

case "${1:-}" in
open)
  PART=${2:-/dev/disk/by-label/P3SIG-DAILY}
  [ -b "$PART" ] || die "$PART not found — is the drive plugged in?"
  mountpoint -q "$VAULT" && die "a vault is already open at $VAULT (close it first)"
  mkdir -p "$FAT" "$VAULT"; chmod 700 /run/p3sig
  mountpoint -q "$FAT" || mount -o "uid=$OWNER_UID,gid=$OWNER_GID,umask=077" "$PART" "$FAT"
  [ -e "$FAT/p3sig-vault.hc" ] || { umount "$FAT"; die "$PART has no p3sig-vault.hc"; }
  for try in 1 2 3; do
    read -rs -p "Passphrase for $(lsblk -no LABEL "$(readlink -f "$PART")"): " pw; echo
    if printf '%s\n' "$pw" | veracrypt -t --non-interactive --stdin --hash=SHA-512 --pim=0 -k "" \
         --protect-hidden=no --fs-options="uid=$OWNER_UID,gid=$OWNER_GID,umask=077" \
         "$FAT/p3sig-vault.hc" "$VAULT" >/dev/null 2>&1; then
      pw=; echo "Open: $VAULT"; ls "$VAULT"; exit 0
    fi
    echo "That passphrase did not open it."
  done
  pw=; umount "$FAT"; die "not opened"
  ;;
close)
  mountpoint -q "$VAULT" && veracrypt -t -d "$FAT/p3sig-vault.hc"
  mountpoint -q "$FAT" && umount "$FAT"
  sync; echo "Closed. Safe to unplug."
  ;;
*) die "usage: sudo $0 open [PARTITION] | close" ;;
esac
