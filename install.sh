#!/usr/bin/env bash
# =============================================================================
#  install.sh — one-command installer for Cipherjet.
#
#  Usage (from a clone):
#      ./install.sh                 build, install binaries, register printer
#      ./install.sh --no-printer    build + install binaries only
#      ./install.sh --uninstall     remove Cipherjet
#
#  Usage (remote, no clone needed):
#      curl -fsSL https://raw.githubusercontent.com/Eselase-Noble/securedrv/main/install.sh | bash
#
#  It will:
#    1. Ensure build dependencies (libsodium, cmake, pkg-config, a C++ compiler)
#       via the platform package manager (Homebrew / apt / dnf / pacman / zypper).
#    2. Build Cipherjet in Release mode.
#    3. Install the binaries to /usr/local/bin (uses sudo).
#    4. Register the "Cipherjet (Encrypted)" printer (unless --no-printer).
#
#  Building runs as you; only the install/registration steps use sudo.
# =============================================================================
set -euo pipefail

REPO_URL="https://github.com/Eselase-Noble/securedrv.git"
WITH_PRINTER=1
DO_UNINSTALL=0
for arg in "$@"; do
  case "$arg" in
    --no-printer) WITH_PRINTER=0 ;;
    --uninstall)  DO_UNINSTALL=1 ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

OS="$(uname -s)"

# --- Locate the source tree: use the current clone, else clone into a cache ---
locate_source() {
  local here
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
  if [ -n "$here" ] && grep -q "project(Cipherjet" "$here/CMakeLists.txt" 2>/dev/null; then
    echo "$here"; return
  fi
  # Running via curl | bash: fetch the repository.
  command -v git >/dev/null 2>&1 || die "git is required to fetch Cipherjet"
  local dst="${HOME}/.cache/cipherjet/src"
  log "Fetching Cipherjet source into $dst"
  if [ -d "$dst/.git" ]; then git -C "$dst" pull --ff-only; else
    mkdir -p "$(dirname "$dst")"; git clone --depth 1 "$REPO_URL" "$dst"; fi
  echo "$dst"
}

# --- Ensure build dependencies -----------------------------------------------
ensure_deps() {
  if [ "$OS" = "Darwin" ]; then
    command -v brew >/dev/null 2>&1 || die "Homebrew not found. Install it from https://brew.sh then re-run."
    log "Installing dependencies via Homebrew"
    brew list libsodium  >/dev/null 2>&1 || brew install libsodium
    brew list cmake      >/dev/null 2>&1 || brew install cmake
    brew list pkg-config >/dev/null 2>&1 || brew install pkg-config
  elif [ "$OS" = "Linux" ]; then
    if   command -v apt-get >/dev/null 2>&1; then
      log "Installing dependencies via apt"
      sudo apt-get update -y
      sudo apt-get install -y libsodium-dev cmake pkg-config g++ cups
    elif command -v dnf >/dev/null 2>&1; then
      log "Installing dependencies via dnf"
      sudo dnf install -y libsodium-devel cmake pkgconf-pkg-config gcc-c++ cups
    elif command -v pacman >/dev/null 2>&1; then
      log "Installing dependencies via pacman"
      sudo pacman -Sy --needed --noconfirm libsodium cmake pkgconf gcc cups
    elif command -v zypper >/dev/null 2>&1; then
      log "Installing dependencies via zypper"
      sudo zypper install -y libsodium-devel cmake pkg-config gcc-c++ cups
    else
      warn "No known package manager found — install libsodium, cmake, pkg-config and a C++ compiler manually."
    fi
  else
    die "Unsupported OS '$OS'. On Windows, build with vcpkg + CMake (see README)."
  fi
}

uninstall() {
  local src; src="$(locate_source)"
  if [ -x "$src/install/uninstall-cups-printer.sh" ]; then
    sudo "$src/install/uninstall-cups-printer.sh"
  else
    sudo rm -f /usr/local/bin/cipherjet /usr/local/bin/cipherjet-release \
               /usr/local/bin/cipherjet-keygen /usr/local/bin/cipherjet-admin
  fi
  log "Cipherjet removed."
}

main() {
  [ "$DO_UNINSTALL" -eq 1 ] && { uninstall; exit 0; }

  local SRC BUILD
  SRC="$(locate_source)"
  BUILD="$SRC/build"
  ensure_deps

  log "Building Cipherjet (Release)"
  cmake -S "$SRC" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release
  cmake --build "$BUILD" -j
  ctest --test-dir "$BUILD" --output-on-failure || warn "self-tests reported failures"

  if [ "$WITH_PRINTER" -eq 1 ] && { [ "$OS" = "Darwin" ] || [ "$OS" = "Linux" ]; }; then
    log "Registering the 'Cipherjet (Encrypted)' printer (requires sudo)"
    sudo "$SRC/install/install-cups-printer.sh"
  else
    log "Installing binaries to /usr/local/bin (requires sudo)"
    sudo cmake --install "$BUILD"
    cat <<EOF

✔ Binaries installed. To use the CLI without a printer queue:
    export CIPHERJET_PASSPHRASE='choose-a-strong-passphrase'
    cipherjet-keygen init
    cat file.pdf | cipherjet job you Title 1 ""
    cipherjet-release list
EOF
  fi
  log "Done."
}

main
