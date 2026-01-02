# ifd-jcecard

A PC/SC IFD (Interface Device) handler that provides a virtual OpenPGP and PIV smart card for testing and development.

## Overview

This crate provides a PC/SC driver with an embedded virtual smart card implementation. It allows `pcscd` (PC/SC Smart Card Daemon) to expose a virtual smart card that implements both OpenPGP card 3.4 and PIV (NIST SP 800-73-4) specifications. Applications like GnuPG, OpenSC, and yubico-piv-tool can interact with this virtual card just like a physical hardware token.

## How it Works

```
┌─────────────────┐     ┌─────────┐     ┌──────────────────────────────────┐
│ Application     │     │ pcscd   │     │ ifd-jcecard (this crate)         │
│ (gpg, piv-tool) │────▶│         │────▶│ ┌────────────┐  ┌─────────────┐  │
└─────────────────┘     └─────────┘     │ │  OpenPGP   │  │     PIV     │  │
                                        │ │  Applet    │  │   Applet    │  │
                                        │ └────────────┘  └─────────────┘  │
                                        └──────────────────────────────────┘
```

1. **Application** sends PC/SC commands (e.g., `gpg --card-status`)
2. **pcscd** routes commands to the IFD handler
3. **ifd-jcecard** processes APDUs using the embedded virtual card
4. Responses flow back through the same path

The virtual card implementation is fully embedded in the shared library - no external server is needed.

## Features

- **OpenPGP Card 3.4**: Sign, decrypt, authenticate with RSA 2048/4096, Ed25519, X25519, NIST P-256/P-384
- **PIV (NIST SP 800-73-4)**: PIV Authentication, Digital Signature, Key Management, Card Authentication slots
- **Key Generation**: Generate keys on-card or import existing keys
- **Persistent Storage**: Card state persisted to `~/.jcecard/card_state.json`
- **No External Dependencies**: Everything runs inside the shared library

## Supported Algorithms

| OpenPGP Key Slot | Algorithms |
|------------------|------------|
| Signature (1)    | RSA 2048/4096, Ed25519, ECDSA P-256/P-384 |
| Decryption (2)   | RSA 2048/4096, X25519, ECDH P-256/P-384 |
| Authentication (3) | RSA 2048/4096, Ed25519, ECDSA P-256/P-384 |

| PIV Key Slot | Algorithms |
|--------------|------------|
| 9A (PIV Authentication) | RSA 2048, ECDSA P-256/P-384 |
| 9C (Digital Signature) | RSA 2048, ECDSA P-256/P-384 |
| 9D (Key Management) | RSA 2048, ECDH P-256/P-384 |
| 9E (Card Authentication) | RSA 2048, ECDSA P-256/P-384 |

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/kushaldas/jcecard.git
cd jcecard/ifd-jcecard

# Build
cargo build --release

# Install (requires sudo)
just install-ifd
```

### Manual Installation

The IFD handler needs to be installed to system directories:

1. Copy `libifd_jcecard.so` to `/usr/lib/pcsc/drivers/ifd-jcecard.bundle/Contents/Linux/`
2. Copy `Info.plist` to `/usr/lib/pcsc/drivers/ifd-jcecard.bundle/Contents/`
3. Copy reader configuration to `/etc/reader.conf.d/jcecard`
4. Restart pcscd: `sudo systemctl restart pcscd`

## Usage

1. Install the IFD handler (see above)

2. Restart pcscd to load the driver:
   ```bash
   sudo systemctl restart pcscd
   ```

3. Verify the virtual reader is available:
   ```bash
   pcsc_scan
   ```

4. Use with your favorite smart card application:
   ```bash
   gpg --card-status
   yubico-piv-tool -a status
   ```

## Default Credentials

- **OpenPGP User PIN (PW1):** `123456`
- **OpenPGP Admin PIN (PW3):** `12345678`
- **PIV PIN:** `123456`
- **PIV PUK:** `12345678`
- **PIV Management Key:** `010203040506070801020304050607080102030405060708`

## Requirements

- Linux with pcscd installed (`sudo apt install pcscd libpcsclite-dev`)
- Rust toolchain for building from source

## Development

```bash
# Run Rust unit tests
cargo test

# Build in debug mode
cargo build

# Run clippy lints
cargo clippy
```

## Related Projects

- [johnnycanencrypt](https://github.com/kushaldas/johnnycanencrypt) - OpenPGP library for Rust/Python
- [talktosc](https://github.com/user/talktosc) - Smart card communication library (patterns used here)

## License

BSD-2-Clause License - see [LICENSE](LICENSE) for details.
