#!/bin/bash
set -e

REPO="broomva/lago"
INSTALL_DIR="$HOME/.local/bin"

# Detect OS and Architecture
OS=$(uname -s)
ARCH=$(uname -m)

case $OS in
    Darwin)
        if [ "$ARCH" == "arm64" ]; then
            ASSET="lago-darwin-arm64"
        else
            ASSET="lago-darwin-amd64"
        fi
        ;;
    Linux)
        ASSET="lago-linux-amd64"
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

echo "Detected $OS $ARCH. Installing $ASSET..."

# Create install directory
mkdir -p "$INSTALL_DIR"

# Download latest release
# Note: This uses the 'latest' release endpoint.
# Since the repo might be private or token-protected during dev, handle errors.

URL="https://github.com/$REPO/releases/latest/download/$ASSET"

echo "Downloading from $URL..."
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$URL" -o "$INSTALL_DIR/lago"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$INSTALL_DIR/lago" "$URL"
else
    echo "Error: curl or wget is required."
    exit 1
fi

chmod +x "$INSTALL_DIR/lago"

echo "Successfully installed 'lago' to $INSTALL_DIR/lago"

# Check if in PATH
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo ""
    echo "Please add $INSTALL_DIR to your PATH:"
    echo "  export PATH=\"\$PATH:$INSTALL_DIR\""
fi
