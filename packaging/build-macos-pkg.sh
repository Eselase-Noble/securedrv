#!/usr/bin/env bash
# =============================================================================
#  build-macos-pkg.sh — build a double-click macOS installer (.pkg).
#
#  Installs the Cipherjet command-line tools to /usr/local/bin (on PATH).
#  Usage:  BUILD_DIR=build ./packaging/build-macos-pkg.sh cipherjet-macos-<arch>.pkg
# =============================================================================
set -euo pipefail

BUILD_DIR="${BUILD_DIR:-build}"
OUT="${1:-cipherjet-macos.pkg}"
VER="$("$BUILD_DIR/cipherjet" --version | awk '{print $2}')"

WORK="$(mktemp -d)"
ROOT="$WORK/root"
SCRIPTS="$WORK/scripts"
mkdir -p "$ROOT/usr/local/bin" "$SCRIPTS"
export COPYFILE_DISABLE=1
for b in cipherjet cipherjet-release cipherjet-keygen cipherjet-send cipherjet-server; do
  cp "$BUILD_DIR/$b" "$ROOT/usr/local/bin/"
done
cp bin/cipherjet-print "$ROOT/usr/local/bin/"
chmod 755 "$ROOT/usr/local/bin/"*

# macOS auto-applies an unremovable com.apple.provenance xattr to executables,
# which pkgbuild encodes as ._ sidecar files in the payload. A postinstall script
# removes those junk sidecars so the installed /usr/local/bin stays clean.
cat > "$SCRIPTS/postinstall" <<'EOF'
#!/bin/sh
find /usr/local/bin -maxdepth 1 -name '._cipherjet*' -delete 2>/dev/null || true
exit 0
EOF
chmod 755 "$SCRIPTS/postinstall"

pkgbuild --root "$ROOT" \
         --scripts "$SCRIPTS" \
         --identifier com.cipherjet.cli \
         --version "$VER" \
         --install-location / \
         "$OUT"
echo "Built $OUT (version $VER)"
