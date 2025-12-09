# jcecard

A virtual OpenPGP smart card implementation that connects to pcscd via local
TCP server, made for testing
[johnnycanencrypt](https://github.com/kushaldas/johnnycanencrypt) and related
desktop applications.


## Available/tested features for OpenPGP

- Import RSA4096 and CV25519 keys/subkeys
- Signing operation
- Encryption / decryption operation
- On card CV25519 generation
- On card RSA4096 key generaion

## Written but not tested yet in OpenPGP

- Authention (for SSH)


## Available/tested features for PIV (via yubico-piv-tool 2.7.2)

- Card status and version information
- PIN verification and PIN change
- Management key authentication (TDES mutual auth)
- Set CHUID (Card Holder Unique Identifier) data object
- Set CCC (Card Capability Container) data object
- On-card ECC P-256 key generation for all slots:
  - Slot 9a (PIV Authentication)
  - Slot 9c (Digital Signature)
  - Slot 9d (Key Management)
  - Slot 9e (Card Authentication)
- Self-signed certificate generation
- Certificate import
- Certificate read
- ECDSA signature operations
- ECDH key agreement (key derivation)
- Full ECC workflow (key generation → certificate → signing)

### Default credentials

- PIN: `123456`
- PUK: `12345678`
- Management Key: `010203040506070801020304050607080102030405060708`

## Using jcecard in CI (GitHub Actions)

Below is an example of how to set up the virtual OpenPGP card in GitHub Actions for testing.

### Required System Dependencies

```yaml
- name: Install system dependencies
  run: |
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
```

### Install yubico-piv-tool 2.7.2 for PIV related operations/tests

You will need `yubico-piv-tool` version `2.7.2` for testing the PIV operations.
I have built the package for `ubuntu-latest` on Github.

```yaml
- name: Install yubico-piv-tool from kushal's build
  run: |
    wget https://kushaldas.in/yubico.tar.gz
    echo "222b9deb97dcd2ad03f216ac42caea91bd875d6f3e838d3f4a9ab0d01c433c4c  yubico.tar.gz" | sha256sum -c -
    tar xvf yubico.tar.gz
    sudo apt install ./yubico/*.deb
```

### Install Rust and Just

```yaml
- name: Install Rust
  uses: dtolnay/rust-toolchain@stable

- name: Install just
  uses: extractions/setup-just@v2

- name: Make just available for root
  run: |
    sudo ln -sf $(which just) /usr/local/bin/just
```

### Build the IFD Handler

```yaml
- name: Build Rust IFD handler
  run: |
    cd ifd-jcecard
    cargo build --release
```

### Set Up Python Environment

```yaml
- name: Set up Python
  uses: actions/setup-python@v5
  with:
    python-version: '3.12'

- name: Create Python virtualenv and install dependencies
  run: |
    python -m venv .venv
    source .venv/bin/activate
    python -m pip install --upgrade pip
    python -m pip install -e ".[dev]"
    python -m pip install pexpect pyscard
```

### Install IFD Handler to pcscd

```yaml
- name: Install IFD handler to pcscd
  run: |
    just install-ifd
```

### Configure gnupg for Loopback Pinentry

This is required if you want to use `gnupg` with the virtual card in CI:

```yaml
- name: Configure gpg-agent for loopback pinentry
  run: |
    mkdir -p ~/.gnupg
    chmod 700 ~/.gnupg
    echo "allow-loopback-pinentry" >> ~/.gnupg/gpg-agent.conf
    echo "disable-ccid" >> ~/.gnupg/scdaemon.conf
    gpgconf --kill all || true
```

### Start the Virtual Card Services

```yaml
- name: Start TCP server and pcscd
  run: |
    source .venv/bin/activate
    # Start TCP server in background
    nohup python -m jcecard.tcp_server --debug > /tmp/tcp_server.log 2>&1 &
    sleep 2
    # Start pcscd in debug mode
    sudo /usr/sbin/pcscd --foreground --debug --apdu > /tmp/pcscd_debug.log 2>&1 &
    sleep 3
    # Verify services are running
    pgrep -f tcp_server && echo "TCP server is running"
    pgrep pcscd && echo "pcscd is running"
```

### Run Your Tests

```yaml
- name: Run tests
  run: |
    source .venv/bin/activate
    timeout 600 pytest tests/ -v
```

### Upload Debug Logs on Failure (Optional)

```yaml
- name: Upload logs on failure
  if: failure()
  uses: actions/upload-artifact@v4
  with:
    name: debug-logs
    path: |
      /tmp/tcp_server.log
      /tmp/pcscd_debug.log
    retention-days: 5
```

### Default PINs for OpenPGP card

- **User PIN**: `123456`
- **Admin PIN**: `12345678`


