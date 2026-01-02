#!/bin/bash
# Start pcscd in debug mode for jcecard virtual smart card
# Run as: sudo ./start-pcscd-debug.sh
# Or: ./start-pcscd-debug.sh (will prompt for sudo)

set -e

# Function to start pcscd
start_pcscd() {
    # Kill any existing pcscd processes
    echo "Stopping any existing pcscd processes..."
    pkill -9 pcscd 2>/dev/null || true
    sleep 1

    # Determine storage directory (use invoking user's home if running via sudo)
    if [ -n "$SUDO_USER" ]; then
        STORAGE_DIR="$(getent passwd "$SUDO_USER" | cut -d: -f6)/.jcecard"
    else
        STORAGE_DIR="$HOME/.jcecard"
    fi

    # Create storage directory if it doesn't exist
    mkdir -p "$STORAGE_DIR"

    # Start pcscd with debug output
    echo "Starting pcscd in debug mode..."
    echo "  Storage directory: $STORAGE_DIR"
    echo "  Log file: /tmp/pcscd_debug.log"
    echo ""

    JCECARD_STORAGE_DIR="$STORAGE_DIR" /usr/sbin/pcscd --foreground --debug --apdu > /tmp/pcscd_debug.log 2>&1 &
    PCSCD_PID=$!

    sleep 2

    # Check if pcscd started successfully
    if kill -0 "$PCSCD_PID" 2>/dev/null; then
        echo "pcscd started successfully (PID: $PCSCD_PID)"
        echo ""
        echo "To view debug log: tail -f /tmp/pcscd_debug.log"
        echo "To stop: sudo pkill -9 pcscd"
    else
        echo "Error: pcscd failed to start"
        echo "Check /tmp/pcscd_debug.log for details"
        exit 1
    fi
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "This script requires root privileges to manage pcscd"
    echo "Re-running with sudo..."
    exec sudo "$0" "$@"
fi

start_pcscd
