#!/bin/bash
# Installation script for ifd-jcecard

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_DIR="/usr/lib/pcsc/drivers/ifd-jcecard.bundle"
CONF_DIR="/etc/reader.conf.d"

echo "Building ifd-jcecard..."
cd "$SCRIPT_DIR"
cargo build --release

echo "Installing driver bundle..."
sudo mkdir -p "$BUNDLE_DIR/Contents/Linux"
sudo cp bundle/ifd-jcecard.bundle/Contents/Info.plist "$BUNDLE_DIR/Contents/"
sudo cp target/release/libifd_jcecard.so "$BUNDLE_DIR/Contents/Linux/"

echo "Installing reader configuration..."
sudo mkdir -p "$CONF_DIR"
sudo cp bundle/jcecard.conf "$CONF_DIR/jcecard"

echo "Restarting pcscd..."
sudo systemctl restart pcscd || sudo killall pcscd

echo "Done! The jcecard virtual reader should now be available."
echo "Check with: pcsc_scan"
