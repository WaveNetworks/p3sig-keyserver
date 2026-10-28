#!/usr/bin/env bash
# SUPERSEDED (task #2630): use `p3sig usb init` + `p3sig usb clone`.
# make-vault-usbs.sh — turn two blank USB drives into the p3sig vault pair:
# DAILY (carry) and SAFE (disaster recovery). Each gets a VeraCrypt container
# (p3sig-vault.hc, same layout as the Windows E:\keys.hc) holding ONE fresh
# Ed25519 key that is both the account vault key and the signed-policy root.
#
# The key is generated straight into the mounted container and copied
# container-to-container; it never touches the host disk. Only the PUBLIC key
# is written in the clear (PUBLIC-KEY.txt on each drive, and printed).
#
# Run at the machine, as root (VeraCrypt prompts for each passphrase; it is
# never on the command line):
#   sudo scripts/make-vault-usbs.sh /dev/disk/by-id/usb-…DAILY…-part1 /dev/disk/by-id/usb-…SAFE…-part1
#
# Needs: veracrypt (console or GUI build), dosfstools, a built p3sig binary
# (P3SIG=/path/to/p3sig, default: p3sig on PATH).
set -euo pipefail

P3SIG=${P3SIG:-$(command -v p3sig || true)}
OWNER=${SUDO_USER:-root}
OWNER_UID=$(id -u "$OWNER"); OWNER_GID=$(id -g "$OWNER")
SIZE=${SIZE:-64M}

die() { echo "error: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run with sudo"
[ $# = 2 ] || die "usage: $0 DAILY-PARTITION SAFE-PARTITION"
[ -x "$P3SIG" ] || die "p3sig binary not found (set P3SIG=)"
command -v veracrypt >/dev/null || die "veracrypt not installed"
command -v fatlabel >/dev/null || die "fatlabel not installed (apt install dosfstools)"

DAILY=$(readlink -f "$1"); SAFE=$(readlink -f "$2")
[ "$DAILY" != "$SAFE" ] || die "both arguments are the same device"
for p in "$DAILY" "$SAFE"; do
  [ -b "$p" ] || die "$p is not a block device"
  [ "$(lsblk -no TRAN "/dev/$(lsblk -no PKNAME "$p")")" = usb ] || die "$p is not on a USB disk"
  [ "$(lsblk -no FSTYPE "$p")" = vfat ] || die "$p is not FAT"
done

WORK=$(mktemp -d /run/p3sig-vault.XXXXXX)
cleanup() {
  veracrypt -t -d >/dev/null 2>&1 || true
  for m in "$WORK"/fat-* "$WORK"/vc-*; do mountpoint -q "$m" && umount "$m"; done 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

prep() { # prep PARTITION LABEL → mounts the plain FAT at $WORK/fat-LABEL
  local p=$1 label=$2
  echo; lsblk -o NAME,SIZE,MODEL,SERIAL,LABEL "/dev/$(lsblk -no PKNAME "$p")"
  if [ -n "$(lsblk -no MOUNTPOINT "$p")" ]; then umount "$p"; fi
  mkdir -p "$WORK/fat-$label"
  mount -o "uid=$OWNER_UID,gid=$OWNER_GID,umask=077" "$p" "$WORK/fat-$label"
  # A rerun after an interrupted run: DAILY keeps its container (it may hold the
  # key); SAFE never got the key unless PUBLIC-KEY.txt exists, so its leftover
  # container is empty and is made again.
  if [ "$(ls -A "$WORK/fat-$label")" = p3sig-vault.hc ]; then
    if [ "$label" = DAILY ]; then
      echo "$p already has a vault container — it will be opened, not replaced."
      read -r -p "Continue? type yes: " ok
      [ "$ok" = yes ] || die "stopped"
      return
    fi
    read -r -p "$p has an unfinished vault container (no key in it). Delete it and start this drive again? type yes: " ok
    [ "$ok" = yes ] || die "stopped"
    rm "$WORK/fat-$label/p3sig-vault.hc"
    return
  fi
  if [ -n "$(ls -A "$WORK/fat-$label")" ]; then
    ls -la "$WORK/fat-$label"
    die "$p is not empty — refusing to touch it"
  fi
  read -r -p "Make $p the $label vault drive? type yes: " ok
  [ "$ok" = yes ] || die "stopped"
  umount "$WORK/fat-$label"
  fatlabel "$p" "P3SIG-$label" >/dev/null
  mount -o "uid=$OWNER_UID,gid=$OWNER_GID,umask=077" "$p" "$WORK/fat-$label"
}

container() { # container LABEL → creates + mounts p3sig-vault.hc at $WORK/vc-LABEL
  local label=$1
  local hc="$WORK/fat-$label/p3sig-vault.hc"
  if [ ! -e "$hc" ]; then
    echo; echo "== $label drive: choose its VeraCrypt passphrase (asked twice) =="
    veracrypt -t -c --volume-type=normal --size="$SIZE" --encryption=AES --hash=SHA-512 \
      --filesystem=FAT --pim=0 -k "" --random-source=/dev/urandom "$hc"
  fi
  mkdir -p "$WORK/vc-$label"
  # --hash and --pim pinned so a mistyped passphrase fails in seconds; VeraCrypt's
  # own retry prompt asks for a PIM and tries every hash (minutes), so we loop.
  # The passphrase goes in on stdin, never argv.
  local try pw
  for try in 1 2 3; do
    read -rs -p "== $label drive: passphrase to open it (no PIM): " pw; echo
    if printf '%s\n' "$pw" | veracrypt -t --non-interactive --stdin --hash=SHA-512 --pim=0 -k "" \
         --protect-hidden=no --fs-options="uid=$OWNER_UID,gid=$OWNER_GID,umask=077" \
         "$hc" "$WORK/vc-$label" >/dev/null 2>&1; then
      pw=; return
    fi
    echo "That passphrase did not open the $label container."
  done
  pw=
  die "could not open the $label container"
}

prep "$DAILY" DAILY
prep "$SAFE" SAFE

container DAILY
KEY="$WORK/vc-DAILY/p3sig-root.key"
if [ -e "$KEY" ]; then
  # Rerun: never replace an existing key. Public half = last 32 bytes of the
  # 64-byte Ed25519 private key.
  echo "DAILY already holds a key; keeping it."
  PUB=$(base64 -d "$KEY" | tail -c 32 | base64 -w0)
else
  PUB=$("$P3SIG" keygen --out "$KEY" | tail -1)
fi
chown "$OWNER_UID:$OWNER_GID" "$KEY"

container SAFE
cp "$KEY" "$WORK/vc-SAFE/p3sig-root.key"
sync
[ "$(sha256sum <"$KEY")" = "$(sha256sum <"$WORK/vc-SAFE/p3sig-root.key")" ] || die "copy to SAFE does not match"

for label in DAILY SAFE; do
  printf 'p3sig vault + policy-root PUBLIC key (safe to share):\n%s\n\nThe private key is inside p3sig-vault.hc (VeraCrypt).\n' "$PUB" \
    > "$WORK/fat-$label/PUBLIC-KEY.txt"
done

veracrypt -t -d
sync
for label in DAILY SAFE; do umount "$WORK/fat-$label"; done

cat <<EOF

Done. Both drives hold the same key; both containers are closed.
  DAILY: $DAILY   SAFE: $SAFE
Public key (register it on p3sig.com → Vault setup → Register key):

$PUB

Then put the SAFE drive in the safe.
EOF
