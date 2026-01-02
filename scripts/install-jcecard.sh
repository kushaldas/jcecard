#!/bin/bash
# Install script for jcecard IFD handler
# Run as: sudo ./install-jcecard.sh

set -e

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Installation paths
BUNDLE_DIR="/usr/lib/pcsc/drivers/ifd-jcecard.bundle"
CONF_DIR="/etc/reader.conf.d"

# Required files (relative to script directory)
SO_FILE="$SCRIPT_DIR/libifd_jcecard.so"
PLIST_FILE="$SCRIPT_DIR/Info.plist"
CONF_FILE="$SCRIPT_DIR/jcecard.conf"

# Verify all required files exist
echo "Checking required files..."
for file in "$SO_FILE" "$PLIST_FILE" "$CONF_FILE"; do
    if [ ! -f "$file" ]; then
        echo "Error: Required file not found: $file"
        exit 1
    fi
done

echo "Installing jcecard IFD handler..."

# Create bundle directory structure
echo "  Creating bundle directory..."
mkdir -p "$BUNDLE_DIR/Contents/Linux"

# Install Info.plist
echo "  Installing Info.plist..."
cp "$PLIST_FILE" "$BUNDLE_DIR/Contents/"

# Install shared library
echo "  Installing libifd_jcecard.so..."
cp "$SO_FILE" "$BUNDLE_DIR/Contents/Linux/"
chmod 644 "$BUNDLE_DIR/Contents/Linux/libifd_jcecard.so"

# Install reader configuration
echo "  Installing reader configuration..."
mkdir -p "$CONF_DIR"
cp "$CONF_FILE" "$CONF_DIR/jcecard"
chmod 644 "$CONF_DIR/jcecard"

echo ""
echo "Installation complete!"
echo ""
echo "Installed files:"
echo "  $BUNDLE_DIR/Contents/Info.plist"
echo "  $BUNDLE_DIR/Contents/Linux/libifd_jcecard.so"
echo "  $CONF_DIR/jcecard"
echo ""
echo "To use the virtual card:"
echo "  1. Stop any running pcscd: sudo pkill -9 pcscd"
echo "  2. Start pcscd: sudo pcscd --foreground --debug --apdu"
echo "  3. Or use: ./start-pcscd-debug.sh"
echo ""
echo "Card state will be stored in ~/.jcecard/card_state.json"
