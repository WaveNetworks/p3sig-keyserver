#!/usr/bin/env bash
# dongle-agent.sh — run an ssh-agent holding the FIDO dongle's policy key, with
# the dongle PIN asked in THIS terminal (ssh-agent has no tty, so a PIN-required
# (verify-required) key would otherwise need a desktop askpass dialog).
#
#   scripts/dongle-agent.sh [KEY]      (default ~/.ssh/p3sig_dongle)
#
# Keep it running in its own terminal. In another shell:
#   export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/p3sig-dongle.sock
#   p3sig policy sign --all --with agent
# Each signature prompts for the PIN here, then the LED blinks: touch the dongle.
set -euo pipefail

KEY=${1:-$HOME/.ssh/p3sig_dongle}
SOCK=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/p3sig-dongle.sock
[ -e "$KEY" ] || { echo "error: $KEY not found" >&2; exit 1; }
[ -t 0 ] || { echo "error: run this in a terminal" >&2; exit 1; }

ASKPASS=$(mktemp "${XDG_RUNTIME_DIR:-/tmp}/p3sig-askpass.XXXXXX")
trap 'rm -f "$ASKPASS" "$SOCK"' EXIT
cat >"$ASKPASS" <<'EOF'
#!/bin/sh
# Touch notices come with SSH_ASKPASS_PROMPT=none: show them, then wait to be killed.
t=$P3SIG_PIN_TTY
if [ "${SSH_ASKPASS_PROMPT:-}" = none ]; then printf '%s\n' "$1" >"$t"; exec sleep 60; fi
printf '%s ' "$1" >"$t"; stty -echo <"$t"; read -r pin <"$t"; stty echo <"$t"; printf '\n' >"$t"
printf '%s\n' "$pin"
EOF
chmod 700 "$ASKPASS"

rm -f "$SOCK"
export P3SIG_PIN_TTY=$(tty) SSH_ASKPASS=$ASKPASS SSH_ASKPASS_REQUIRE=force DISPLAY=${DISPLAY:-:0}
( sleep 1; SSH_AUTH_SOCK=$SOCK ssh-add "$KEY" </dev/null && \
  echo "Dongle key loaded. In another shell: export SSH_AUTH_SOCK=$SOCK" ) &
echo "Agent on $SOCK — leave this running; PIN prompts appear here. Ctrl-C to stop."
ssh-agent -D -a "$SOCK" >/dev/null
