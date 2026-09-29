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

ROOT="$(mktemp -d)/root"
mkdir -p "$ROOT/usr/local/bin"
export COPYFILE_DISABLE=1   # don't emit ._ AppleDouble sidecar files
for b in cipherjet cipherjet-release cipherjet-keygen cipherjet-send cipherjet-server; do
  cp "$BUILD_DIR/$b" "$ROOT/usr/local/bin/"
done
cp bin/cipherjet-print "$ROOT/usr/local/bin/"
find "$ROOT" -name '._*' -delete
xattr -cr "$ROOT" 2>/dev/null || true
chmod 755 "$ROOT/usr/local/bin/"*

pkgbuild --root "$ROOT" \
         --identifier com.cipherjet.cli \
         --version "$VER" \
         --install-location / \
         "$OUT"
echo "Built $OUT (version $VER)"
