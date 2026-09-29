#!/usr/bin/env bash
# =============================================================================
#  uninstall-cups-printer.sh — remove the Cipherjet CUPS printer + files.
#
#  Run with sudo:   sudo ./install/uninstall-cups-printer.sh
#
#  By default this KEEPS the system data dir (/usr/local/var/cipherjet) and the
#  passphrase, so already-spooled encrypted jobs and the master key survive.
#  Pass --purge to also delete the key, spool and passphrase (irreversible).
# =============================================================================
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run with sudo:  sudo $0" >&2
  exit 1
fi

QUEUE_NAME="${CIPHERJET_QUEUE:-Cipherjet}"
BIN_DIR="/usr/local/bin"
ETC_DIR="/usr/local/etc/cipherjet"
VAR_DIR="/usr/local/var/cipherjet"
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

if   [ -d /usr/libexec/cups/backend ]; then BACKEND_DIR=/usr/libexec/cups/backend
elif [ -d /usr/lib/cups/backend ];     then BACKEND_DIR=/usr/lib/cups/backend
else BACKEND_DIR=""; fi

echo "==> Removing CUPS queue '$QUEUE_NAME'"
lpadmin -x "$QUEUE_NAME" 2>/dev/null || echo "    (queue not present)"

echo "==> Removing backend + binaries"
[ -n "$BACKEND_DIR" ] && rm -f "$BACKEND_DIR/cipherjet"
rm -f "$BIN_DIR/cipherjet" "$BIN_DIR/cipherjet-release" \
      "$BIN_DIR/cipherjet-keygen" "$BIN_DIR/cipherjet-admin" \
      "$BIN_DIR/cipherjet-send" "$BIN_DIR/cipherjet-server" \
      "$BIN_DIR/cipherjet-print"

if [ "$PURGE" -eq 1 ]; then
  echo "==> Purging keys, spool and passphrase (irreversible)"
  rm -rf "$VAR_DIR" "$ETC_DIR"
else
  echo "==> Keeping $VAR_DIR and $ETC_DIR (use --purge to delete them)"
fi

echo "✔ Uninstalled."
