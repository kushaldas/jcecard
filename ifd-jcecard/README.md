# ifd-jcecard

A PC/SC IFD (Interface Device) handler for the [jcecard](https://github.com/kushaldas/jcecard) virtual smart card.

## Overview

This crate provides a PC/SC driver that allows `pcscd` (PC/SC Smart Card Daemon) to communicate with the jcecard virtual smart card server. It acts as a bridge between PC/SC applications (like GnuPG, OpenSC, yubico-piv-tool) and the jcecard TCP server.

## How it Works

```
┌─────────────────┐     ┌─────────┐     ┌──────────────┐     ┌─────────────┐
│ Application     │     │ pcscd   │     │ ifd-jcecard  │     │ jcecard     │
│ (gpg, piv-tool) │────▶│         │────▶│ (this crate) │────▶│ TCP Server  │
└─────────────────┘     └─────────┘     └──────────────┘     └─────────────┘
                                              │                     │
                                              │   TCP localhost:9999│
                                              └─────────────────────┘
```

1. **Application** sends PC/SC commands (e.g., `gpg --card-status`)
2. **pcscd** routes commands to the appropriate IFD handler
3. **ifd-jcecard** (this crate) receives the APDU commands
4. Commands are forwarded via TCP to the **jcecard server** running on port 9999
5. Responses flow back through the same path

## Protocol

The IFD handler communicates with the jcecard TCP server using a simple length-prefixed protocol:

- **Send**: 4-byte big-endian length + message data
- **Receive**: 4-byte big-endian length + response data

Message types:
- `0x01` - APDU command/response
- `0x02` - POWER_ON
- `0x03` - POWER_OFF
- `0x04` - RESET

## Installation

### From Source

```bash
# Clone the jcecard repository
git clone https://github.com/kushaldas/jcecard.git
cd jcecard/ifd-jcecard

# Build
cargo build --release

# Install (requires sudo)
sudo ./target/release/ifd-jcecard-install
```

### Using Cargo

```bash
# Install the binary
cargo install ifd-jcecard

# Run the installer (requires sudo)
# Note: You'll need to build the library separately
cd /path/to/jcecard/ifd-jcecard
cargo build --release
sudo ifd-jcecard-install
```

### Manual Installation

The IFD handler needs to be installed to system directories:

1. Copy `libifd_jcecard.so` to `/usr/lib/pcsc/drivers/ifd-jcecard.bundle/Contents/Linux/`
2. Copy `Info.plist` to `/usr/lib/pcsc/drivers/ifd-jcecard.bundle/Contents/`
3. Copy reader configuration to `/etc/reader.conf.d/jcecard`
4. Restart pcscd: `sudo systemctl restart pcscd`

## Usage

1. Start the jcecard TCP server:
   ```bash
   jcecard
   # or
   python -m jcecard.tcp_server
   ```

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

## Requirements

- Linux with pcscd installed (`sudo apt install pcscd libpcsclite-dev`)
- jcecard TCP server running on localhost:9999

## Related Projects

- [jcecard](https://github.com/kushaldas/jcecard) - Virtual OpenPGP and PIV smart card implementation
- [johnnycanencrypt](https://github.com/kushaldas/johnnycanencrypt) - OpenPGP library used by jcecard

## License

BSD-2-Clause License - see [LICENSE](LICENSE) for details.
