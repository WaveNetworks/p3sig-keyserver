#!/bin/sh
# Install p3sig as a key server on a Linux machine with a TPM 2.0 (p3sig doc §4.4).
# Run as root from a checkout or release dir that has the p3sig binary next to this
# script (or pass its path as $1). Safe to re-run: it keeps the existing chip key,
# config and app allowlist.
#
# Afterwards: publish 127.0.0.1:8787 (Tailscale Funnel or Cloudflare Tunnel) and add
# apps to /etc/p3sig/keyserver.json, then `systemctl reload p3sig-keyserver`.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
BIN=${1:-$HERE/p3sig}
[ -x "$BIN" ] || BIN=$HERE/../../p3sig
[ -x "$BIN" ] || { echo "p3sig binary not found; pass its path" >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
[ -c /dev/tpmrm0 ] || { echo "no /dev/tpmrm0: enable the TPM in the BIOS first" >&2; exit 1; }

getent group tss >/dev/null || groupadd --system tss
chgrp tss /dev/tpmrm0 && chmod 660 /dev/tpmrm0
id p3sig-ks >/dev/null 2>&1 || useradd --system --home-dir /var/lib/p3sig-keyserver \
    --no-create-home --shell /usr/sbin/nologin --groups tss p3sig-ks

install -m 0755 "$BIN" /usr/local/bin/p3sig
install -d -m 0700 -o p3sig-ks -g p3sig-ks /var/lib/p3sig-keyserver
install -d -m 0755 /etc/p3sig
if [ ! -f /etc/p3sig/keyserver.json ]; then
    old_umask=$(umask); umask 027
    cat > /etc/p3sig/keyserver.json <<'EOF'
{
  "label": "keyserver",
  "client_ip_header": "X-Forwarded-For",
  "apps": {}
}
EOF
    chgrp p3sig-ks /etc/p3sig/keyserver.json
    umask "$old_umask"
fi

POINT=$(runuser -u p3sig-ks -- env P3SIG_TPM_DIR=/var/lib/p3sig-keyserver/tpm \
    /usr/local/bin/p3sig keyserver init --label keyserver)
echo "$POINT" > /etc/p3sig/keyserver.pub
chmod 0644 /etc/p3sig/keyserver.pub

install -m 0644 "$HERE/p3sig-keyserver.service" /etc/systemd/system/p3sig-keyserver.service
systemctl daemon-reload
systemctl enable --now p3sig-keyserver
systemctl restart p3sig-keyserver

echo "key server running on 127.0.0.1:8787"
echo "chip public point (apps wrap their bundle key to this; also in /etc/p3sig/keyserver.pub):"
echo "$POINT"
