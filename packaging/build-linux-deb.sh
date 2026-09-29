#!/usr/bin/env bash
# =============================================================================
#  build-linux-deb.sh — build a Debian/Ubuntu package (.deb).
#
#  Installs the Cipherjet tools to /usr/bin (on PATH). The binaries are static,
#  so the package declares no dependencies.
#  Usage:  BUILD_DIR=build ./packaging/build-linux-deb.sh cipherjet-linux-amd64.deb
# =============================================================================
set -euo pipefail

BUILD_DIR="${BUILD_DIR:-build}"
OUT="${1:-cipherjet-linux-amd64.deb}"
VER="$("$BUILD_DIR/cipherjet" --version | awk '{print $2}')"

PKG="$(mktemp -d)"
mkdir -p "$PKG/DEBIAN" "$PKG/usr/bin"
for b in cipherjet cipherjet-release cipherjet-keygen cipherjet-send cipherjet-server; do
  install -m 0755 "$BUILD_DIR/$b" "$PKG/usr/bin/"
done
install -m 0755 bin/cipherjet-print "$PKG/usr/bin/"

cat > "$PKG/DEBIAN/control" <<EOF
Package: cipherjet
Version: $VER
Section: utils
Priority: optional
Architecture: amd64
Maintainer: Noble Eselase Vulley <noble@cipherjet.local>
Homepage: https://github.com/Eselase-Noble/securedrv
Description: Cipherjet encrypting printer driver
 Encrypts every print job at capture and decrypts only at release, so
 documents are never spooled in the clear. Includes local and networked
 (client to server) printing.
EOF

dpkg-deb --build --root-owner-group "$PKG" "$OUT"
echo "Built $OUT (version $VER)"
