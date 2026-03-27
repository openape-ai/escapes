#!/bin/bash
# OpenApe Escapes installer
# Usage: curl -sSf https://raw.githubusercontent.com/openape-ai/escapes/main/packaging/install.sh | sudo bash
set -euo pipefail

VERSION="${ESCAPES_VERSION:-latest}"
PREFIX="${ESCAPES_PREFIX:-/usr/local}"
BINDIR="${PREFIX}/bin"
CONFDIR="/etc/openape"
LOGDIR="/var/log/openape"
SHAREDIR="${PREFIX}/share/openape"
REPO="openape-ai/escapes"

detect_platform() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"
    case "$os" in
        Darwin) os="apple-darwin" ;;
        Linux)  os="unknown-linux-gnu" ;;
        *)      echo "Unsupported OS: $os" >&2; exit 1 ;;
    esac
    case "$arch" in
        x86_64|amd64)  arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        *)             echo "Unsupported architecture: $arch" >&2; exit 1 ;;
    esac
    echo "${arch}-${os}"
}

if [ "$(id -u)" != "0" ]; then
    echo "Error: this installer must be run as root (use sudo)." >&2
    exit 1
fi

PLATFORM="$(detect_platform)"

# Resolve latest version from GitHub Releases API
if [ "$VERSION" = "latest" ]; then
    VERSION=$(curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' | sed 's/.*"v\(.*\)".*/\1/')
    if [ -z "$VERSION" ]; then
        echo "Error: could not determine latest version." >&2
        exit 1
    fi
fi

TARBALL="escapes-v${VERSION}-${PLATFORM}.tar.gz"
URL="https://github.com/${REPO}/releases/download/v${VERSION}/${TARBALL}"
CHECKSUM_URL="https://github.com/${REPO}/releases/download/v${VERSION}/checksums-sha256.txt"

echo "Installing escapes v${VERSION} for ${PLATFORM}..."

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

curl -sSfL "$URL" -o "$TMPDIR/$TARBALL"
curl -sSfL "$CHECKSUM_URL" -o "$TMPDIR/checksums-sha256.txt"

# Verify checksum
cd "$TMPDIR"
if command -v sha256sum >/dev/null 2>&1; then
    grep "$TARBALL" checksums-sha256.txt | sha256sum -c -
elif command -v shasum >/dev/null 2>&1; then
    grep "$TARBALL" checksums-sha256.txt | shasum -a 256 -c -
else
    echo "Warning: no sha256sum or shasum found, skipping checksum verification." >&2
fi

# Extract and install
tar xzf "$TARBALL"
mkdir -p "$BINDIR" "$SHAREDIR"
install -m 4755 -o root escapes "$BINDIR/escapes"

# Install config example
if [ -f config.example.toml ]; then
    cp config.example.toml "$SHAREDIR/config.example.toml"
    chmod 0644 "$SHAREDIR/config.example.toml"
fi

# Create directories
mkdir -p "$CONFDIR" "$LOGDIR"
chmod 0755 "$CONFDIR"
chmod 0700 "$LOGDIR"

# Install config template if no config exists
if [ ! -f "$CONFDIR/config.toml" ]; then
    cp "$SHAREDIR/config.example.toml" "$CONFDIR/config.toml"
    chmod 0644 "$CONFDIR/config.toml"
fi

echo ""
echo "Installed: $BINDIR/escapes (setuid root)"
echo ""
echo "Next steps:"
echo "  1. Edit /etc/openape/config.toml"
echo "  2. Set allowed_issuers to your IdP URL"
echo "  3. Set allowed_approvers to your admin email(s)"
echo ""
