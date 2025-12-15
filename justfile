# Justfile for simpcsc development

# Default recipe
default:
    @just --list

# Build the IFD handler (Rust)
build-ifd:
    cd ifd-jcecard && cargo build --release

# Package the IFD handler as a tarball
package-ifd: build-ifd
    #!/usr/bin/env bash
    set -e
    STAGING_DIR=$(mktemp -d)
    PKG_DIR="$STAGING_DIR/ifd-jcecard"
    mkdir -p "$PKG_DIR/bundle"
    
    # Copy the built library
    cp ifd-jcecard/target/release/libifd_jcecard.so "$PKG_DIR/"
    
    # Copy bundle configuration files
    cp -r ifd-jcecard/bundle/ifd-jcecard.bundle "$PKG_DIR/bundle/"
    cp ifd-jcecard/bundle/jcecard.conf "$PKG_DIR/bundle/"
    
    # Copy install script
    cp ifd-jcecard/install.sh "$PKG_DIR/"
    chmod +x "$PKG_DIR/install.sh"
    
    # Create tarball
    tar -C "$STAGING_DIR" -czvf ifd-jcecard.tar.gz ifd-jcecard
    
    # Print sha256sum
    echo ""
    echo "Package created: ifd-jcecard.tar.gz"
    sha256sum ifd-jcecard.tar.gz
    
    # Cleanup
    rm -rf "$STAGING_DIR"

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

# Uninstall the IFD handler from pcscd drivers directory
uninstall-ifd:
    #!/usr/bin/env bash
    set -e
    BUNDLE_DIR="/usr/lib/pcsc/drivers/ifd-jcecard.bundle"
    CONF_DIR="/etc/reader.conf.d"
    
    echo "Uninstalling driver bundle..."
    sudo rm -rf "$BUNDLE_DIR"
    
    echo "Uninstalling reader configuration..."
    sudo rm -f "$CONF_DIR/jcecard"
    
    echo "IFD handler uninstalled successfully"

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

# CI: Install ifd from kushal's build for speedup
install-prbuilt-ifd:
    #!/usr/bin/env bash
    set -e
    wget https://kushaldas.in/ifd-jcecard.tar.gz
    echo "b9f10211f2c283829f0018d6254279387f131e3003df3084d0f4717f241d0ba5  ifd-jcecard.tar.gz" | sha256sum -c -
    tar xvf ifd-jcecard.tar.gz
    cd ifd-jcecard
    sudo ./install.sh

# Full rebuild: build IFD, install, and restart all services
rebuild: install-ifd restart-all
    @echo "Full rebuild complete"

# Check linting with ty & ruff
lint:
    #!/usr/bin/env bash
    set -x
    source .venv/bin/activate
    ty check .
    ruff check .

# Configure gpg-agent for loopback pinentry and restart it
gpg-loopback:
    #!/usr/bin/env bash
    set -e
    mkdir -p ~/.gnupg
    chmod 700 ~/.gnupg
    grep -q "allow-loopback-pinentry" ~/.gnupg/gpg-agent.conf 2>/dev/null || echo "allow-loopback-pinentry" >> ~/.gnupg/gpg-agent.conf
    gpgconf --kill gpg-agent
    gpg-connect-agent /bye
    echo "gpg-agent configured for loopback pinentry and restarted"

# CI: Install system dependencies
ci-install-deps:
    #!/usr/bin/env bash
    set -e
    sudo apt-get update
    sudo apt-get install -y \
      pcscd \
      libpcsclite-dev \
      libpcsclite1 \
      pcsc-tools \
      gnupg \
      gnupg-agent \
      scdaemon \
      libclang-dev \
      nettle-dev \
      pkg-config \
      build-essential

# CI: Install yubico-piv-tool from kushal's build
ci-install-yubico:
    #!/usr/bin/env bash
    set -e
    wget https://kushaldas.in/yubico.tar.gz
    echo "222b9deb97dcd2ad03f216ac42caea91bd875d6f3e838d3f4a9ab0d01c433c4c  yubico.tar.gz" | sha256sum -c -
    tar xvf yubico.tar.gz
    sudo apt install ./yubico/*.deb

# CI: Create Python virtualenv and install dependencies
ci-setup-venv:
    #!/usr/bin/env bash
    set -e
    python -m venv .venv
    source .venv/bin/activate
    python -m pip install --upgrade pip
    python -m pip install -e ".[dev]"
    python -m pip install pexpect pyscard

# CI: Build Rust IFD handler
ci-build-ifd: build-ifd

# CI: Configure gpg-agent for loopback pinentry
ci-gpg-loopback: gpg-loopback


# CI: Start TCP server and pcscd
ci-start-services: restart-all

# CI: Run tests
ci-test:
    #!/usr/bin/env bash
    set -e
    source .venv/bin/activate
    timeout 600 pytest -vvv

