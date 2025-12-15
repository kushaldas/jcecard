#!/bin/bash
# Installation script for ifd-jcecard

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_DIR="/usr/lib/pcsc/drivers/ifd-jcecard.bundle"
CONF_DIR="/etc/reader.conf.d"

echo "Installing driver bundle..."
sudo mkdir -p "$BUNDLE_DIR/Contents/Linux"
sudo cp "$SCRIPT_DIR/bundle/ifd-jcecard.bundle/Contents/Info.plist" "$BUNDLE_DIR/Contents/"
sudo cp "$SCRIPT_DIR/libifd_jcecard.so" "$BUNDLE_DIR/Contents/Linux/"

echo "Installing reader configuration..."
sudo mkdir -p "$CONF_DIR"
sudo cp "$SCRIPT_DIR/bundle/jcecard.conf" "$CONF_DIR/jcecard"

echo "IFD handler installed successfully"
