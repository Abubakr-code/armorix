#!/bin/sh
# Armorix CLI installer — Linux (x86_64, arm64) and macOS (Apple Silicon, Intel). No Python or pip needed.
#
#   curl -fsSL https://abubakr-code.github.io/install.sh | sh
#
# Options (environment variables):
#   ARMORIX_VERSION=v0.3.0     install a specific release (default: latest)
#   ARMORIX_INSTALL=~/.armorix install location
#   ARMORIX_NO_MODIFY_PATH=1   do not touch shell startup files
#   ARMORIX_DOWNLOAD_BASE=URL  download from a mirror (air-gapped networks) instead of GitHub
set -eu

REPO="Abubakr-code/armorix"
INSTALL_DIR="${ARMORIX_INSTALL:-$HOME/.armorix}"
VERSION="${ARMORIX_VERSION:-latest}"

say() { printf '\033[1;34marmorix\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31marmorix: %s\033[0m\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "'$1' is required"; }

need uname
need tar
if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q -O "$2" "$1"; }
else
  fail "curl or wget is required"
fi

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=macos ;;
  *) fail "unsupported OS $(uname -s) — on Windows run: irm https://abubakr-code.github.io/install.ps1 | iex" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=x86_64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) fail "unsupported CPU $(uname -m)" ;;
esac

asset="armorix-cli-$os-$arch.tar.gz"
if [ -n "${ARMORIX_DOWNLOAD_BASE:-}" ]; then
  base="$ARMORIX_DOWNLOAD_BASE"  # a mirror inside your network
elif [ "$VERSION" = latest ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$VERSION"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

say "downloading $asset ($VERSION)"
fetch "$base/$asset" "$tmp/$asset" || fail "download failed: $base/$asset"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || fail "could not download checksums"

expected="$(grep " $asset\$" "$tmp/SHA256SUMS" | awk '{print $1}')"
[ -n "$expected" ] || fail "$asset is missing from SHA256SUMS"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp/$asset" | awk '{print $1}')"
else
  actual="$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')"
fi
[ "$expected" = "$actual" ] || fail "checksum mismatch — the download is corrupted or was tampered with"
say "checksum verified"

mkdir -p "$INSTALL_DIR/bin"
rm -rf "$INSTALL_DIR/lib.new"
mkdir -p "$INSTALL_DIR/lib.new"
tar -xzf "$tmp/$asset" -C "$INSTALL_DIR/lib.new"
rm -rf "$INSTALL_DIR/lib"
mv "$INSTALL_DIR/lib.new" "$INSTALL_DIR/lib"
ln -sf "$INSTALL_DIR/lib/armorix/armorix" "$INSTALL_DIR/bin/armorix"
if [ "$os" = macos ]; then
  xattr -dr com.apple.quarantine "$INSTALL_DIR/lib" 2>/dev/null || true
fi

version="$("$INSTALL_DIR/bin/armorix" --version 2>/dev/null || true)"
[ -n "$version" ] || fail "installed, but the binary does not run on this system"
say "installed $version → $INSTALL_DIR/bin/armorix"

# Put it on PATH: ~/.local/bin when that is already on PATH, otherwise the shell startup file.
case ":$PATH:" in
  *":$INSTALL_DIR/bin:"*) on_path=1 ;;
  *) on_path=0 ;;
esac
if [ "$on_path" = 0 ] && [ -d "$HOME/.local/bin" ]; then
  case ":$PATH:" in
    *":$HOME/.local/bin:"*) ln -sf "$INSTALL_DIR/bin/armorix" "$HOME/.local/bin/armorix"; on_path=1 ;;
  esac
fi
if [ "$on_path" = 0 ] && [ "${ARMORIX_NO_MODIFY_PATH:-0}" != 1 ]; then
  line="export PATH=\"$INSTALL_DIR/bin:\$PATH\""
  for rc in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.profile"; do
    if [ -f "$rc" ] && ! grep -qs "$INSTALL_DIR/bin" "$rc"; then
      printf '\n# Armorix\n%s\n' "$line" >> "$rc"
      say "added $INSTALL_DIR/bin to PATH in $rc"
    fi
  done
  say "open a new terminal (or run: $line)"
fi

cat <<MSG

  Next steps
    armorix scan .              scan the current project
    armorix db update           offline CVE database for npm / PyPI (once)
    armorix ai setup            local AI for fixes (once, 1.1 GB)
    armorix hook install        block commits with critical issues
    armorix update              update Armorix later

MSG
