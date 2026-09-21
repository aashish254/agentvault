#!/bin/sh
# AgentVault installer — downloads the right binary for your platform,
# verifies its checksum, and installs to ~/.local/bin.
# Usage: curl -fsSL https://agentvault.dev/install.sh | sh
set -eu

REPO="aashish/agentvault"
VERSION="${AGENTVAULT_VERSION:-latest}"
INSTALL_DIR="${AGENTVAULT_INSTALL_DIR:-$HOME/.local/bin}"

say() { printf '%s\n' "$*"; }
die() { say "install: $*" >&2; exit 1; }

# --- platform detection ---
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$OS" in
  darwin) OS="darwin" ;;
  linux)  OS="linux" ;;
  *)      die "unsupported OS: $OS (Windows: download agentvault-windows-amd64.zip from releases)" ;;
esac
case "$ARCH" in
  x86_64|amd64)  ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *)             die "unsupported arch: $ARCH" ;;
esac

# --- resolve version ---
if [ "$VERSION" = "latest" ]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p')
  [ -n "$VERSION" ] || die "could not resolve latest release"
fi

ARCHIVE="agentvault-${OS}-${ARCH}.tar.gz"
BASE="https://github.com/$REPO/releases/download/$VERSION"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

say "↓ downloading $ARCHIVE ($VERSION)"
curl -fsSL "$BASE/$ARCHIVE" -o "$TMP/$ARCHIVE" || die "download failed"
curl -fsSL "$BASE/checksums.txt" -o "$TMP/checksums.txt" || die "checksums download failed"

# --- checksum verification (mandatory; install fails without it) ---
say "✓ verifying checksum"
( cd "$TMP" && grep "  $ARCHIVE\$" checksums.txt | shasum -a 256 -c - ) \
  || die "checksum mismatch — refusing to install"

# --- install ---
mkdir -p "$INSTALL_DIR"
tar -xzf "$TMP/$ARCHIVE" -C "$TMP"
install -m 0755 "$TMP/agentvault" "$INSTALL_DIR/agentvault"
say "✓ installed to $INSTALL_DIR/agentvault"

case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) say "note: $INSTALL_DIR is not on PATH — add it to your shell profile" ;;
esac

say ""
say "next: agentvault init"
