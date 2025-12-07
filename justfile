# Justfile for simpcsc development

# Default recipe
default:
    @just --list

# Build the IFD handler (Rust)
build-ifd:
    cd ifd-jcecard && cargo build --release

# Install the IFD handler to pcscd drivers directory
install-ifd: build-ifd
    #!/usr/bin/env bash
    set -e
    BUNDLE_DIR="/usr/lib/pcsc/drivers/ifd-jcecard.bundle"
    CONF_DIR="/etc/reader.conf.d"
    IFD_DIR="ifd-jcecard"
    
    echo "Installing driver bundle..."
    sudo mkdir -p "$BUNDLE_DIR/Contents/Linux"
    sudo cp "$IFD_DIR/bundle/ifd-jcecard.bundle/Contents/Info.plist" "$BUNDLE_DIR/Contents/"
    sudo cp "$IFD_DIR/target/release/libifd_jcecard.so" "$BUNDLE_DIR/Contents/Linux/"
    
    echo "Installing reader configuration..."
    sudo mkdir -p "$CONF_DIR"
    sudo cp "$IFD_DIR/bundle/jcecard.conf" "$CONF_DIR/jcecard"
    
    echo "IFD handler installed successfully"

# Restart the TCP server
restart-tcp: && restart-pcscd
    #!/usr/bin/env bash
    pkill -f "python -m jcecard.tcp_server" 2>/dev/null || true
    sleep 1
    source .venv/bin/activate
    nohup python -m jcecard.tcp_server --debug > /tmp/tcp_server.log 2>&1 &
    sleep 2
    pgrep -f tcp_server && echo "TCP server restarted successfully"

# Restart pcscd in debug mode
restart-pcscd:
    #!/usr/bin/env bash
    sudo pkill -9 pcscd 2>/dev/null || true
    sleep 1
    # Start pcscd and redirect all output to log file (no STDOUT)
    sudo /usr/sbin/pcscd --foreground --debug --apdu > /tmp/pcscd_debug.log 2>&1 &
    sleep 2
    echo "pcscd started in debug mode, logging to /tmp/pcscd_debug.log"

# Restart both services
restart-all: restart-tcp restart-pcscd

# Run RSA signing tests
test-rsa-sign:
    source .venv/bin/activate && timeout 300 pytest tests/test_smartcard_crypto.py::TestSmartcardRSAOperations::test_rsa_sign_and_verify tests/test_smartcard_crypto.py::TestSmartcardRSAOperations::test_rsa_sign_multiple_messages -xvs

# Run all RSA tests
test-rsa:
    source .venv/bin/activate && timeout 300 pytest tests/test_smartcard_crypto.py::TestSmartcardRSAOperations -xvs

# Check if services are running
status:
    @echo "TCP Server:"
    @pgrep -f tcp_server && echo "  Running" || echo "  Not running"
    @echo "pcscd:"
    @pgrep pcscd && echo "  Running" || echo "  Not running"
    @echo "Port 9999:"
    @nc -z localhost 9999 && echo "  Open" || echo "  Closed"

# Full rebuild: build IFD, install, and restart all services
rebuild: install-ifd restart-all
    @echo "Full rebuild complete"

# Check linting with ty & ruff
lint:
    ty check .
    ruff check .

