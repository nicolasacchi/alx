#!/bin/sh
set -e

REPO="nicolasacchi/alx"
INSTALL_DIR="${INSTALL_DIR:-$HOME/bin}"

# Detect OS
OS="$(uname -s)"
case "$OS" in
    Linux)  OS_TARGET="unknown-linux-gnu" ;;
    Darwin) OS_TARGET="apple-darwin" ;;
    *)      echo "Unsupported OS: $OS" >&2; exit 1 ;;
esac

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)  ARCH_TARGET="x86_64" ;;
    aarch64|arm64) ARCH_TARGET="aarch64" ;;
    *)             echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

TARGET="${ARCH_TARGET}-${OS_TARGET}"
ASSET="alx-${TARGET}.tar.gz"

# Get latest release URL
LATEST_URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"

echo "Downloading alx for ${TARGET}..."
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

curl -fsSL "$LATEST_URL" -o "${TMPDIR}/${ASSET}"
tar xzf "${TMPDIR}/${ASSET}" -C "$TMPDIR"

mkdir -p "$INSTALL_DIR"
mv "${TMPDIR}/alx" "${INSTALL_DIR}/alx"
chmod +x "${INSTALL_DIR}/alx"

echo "Installed alx to ${INSTALL_DIR}/alx"

# Check if install dir is on PATH
case ":$PATH:" in
    *":${INSTALL_DIR}:"*) ;;
    *) echo "Add ${INSTALL_DIR} to your PATH: export PATH=\"${INSTALL_DIR}:\$PATH\"" ;;
esac
