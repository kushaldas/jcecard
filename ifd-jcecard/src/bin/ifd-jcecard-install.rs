//! Installer for ifd-jcecard IFD handler
//!
//! This binary installs the ifd-jcecard driver files to the appropriate
//! system directories for pcscd to find them.
//!
//! Usage: sudo ifd-jcecard-install
//!
//! After running `cargo install ifd-jcecard`, run:
//!   sudo ifd-jcecard-install

use std::env;
use std::fs;
use std::path::Path;
use std::process;

const BUNDLE_DIR: &str = "/usr/lib/pcsc/drivers/ifd-jcecard.bundle";
const CONF_DIR: &str = "/etc/reader.conf.d";

const INFO_PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>English</string>
    <key>CFBundleExecutable</key>
    <string>libifd_jcecard.so</string>
    <key>CFBundleIdentifier</key>
    <string>org.jcecard.ifd-handler</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>ifd-jcecard</string>
    <key>CFBundlePackageType</key>
    <string>BNDL</string>
    <key>CFBundleShortVersionString</key>
    <string>0.1.0</string>
    <key>CFBundleSignature</key>
    <string>????</string>
    <key>CFBundleVersion</key>
    <string>0.1.0</string>
    <key>ifdCapabilities</key>
    <string>0x00000000</string>
    <key>ifdProtocolSupport</key>
    <string>0x00000003</string>
    <key>ifdVersionNumber</key>
    <string>0x00000001</string>
    <key>ifdManufacturerString</key>
    <string>jcecard</string>
    <key>ifdProductString</key>
    <string>jcecard Virtual Reader</string>
    <key>ifdSerialNumber</key>
    <string>0</string>
    <key>Copyright</key>
    <string>Copyright (C) 2024 jcecard</string>
    <key>ifdLogLevel</key>
    <string>0x0007</string>
</dict>
</plist>
"#;

const JCECARD_CONF: &str = r#"# jcecard Virtual Smart Card Reader
# This configuration tells pcscd to load the ifd-jcecard driver

FRIENDLYNAME      "Yubikey jcecard Virtual Smart Card"
DEVICENAME        /dev/null
LIBPATH           /usr/lib/pcsc/drivers/ifd-jcecard.bundle/Contents/Linux/libifd_jcecard.so
CHANNELID         0x00000001
"#;

fn main() {
    // Check if running as root
    if !is_root() {
        eprintln!("Error: This installer must be run as root (use sudo)");
        process::exit(1);
    }

    println!("Installing ifd-jcecard IFD handler...");

    // Find the library
    let lib_path = find_library();
    if lib_path.is_none() {
        eprintln!("Error: Could not find libifd_jcecard.so");
        eprintln!("Make sure you have built the library with: cargo build --release");
        process::exit(1);
    }
    let lib_path = lib_path.unwrap();
    println!("Found library at: {}", lib_path.display());

    // Create bundle directory
    let bundle_contents = format!("{}/Contents", BUNDLE_DIR);
    let bundle_linux = format!("{}/Contents/Linux", BUNDLE_DIR);
    
    if let Err(e) = fs::create_dir_all(&bundle_linux) {
        eprintln!("Error creating bundle directory: {}", e);
        process::exit(1);
    }
    println!("Created bundle directory: {}", BUNDLE_DIR);

    // Write Info.plist
    let plist_path = format!("{}/Info.plist", bundle_contents);
    if let Err(e) = fs::write(&plist_path, INFO_PLIST) {
        eprintln!("Error writing Info.plist: {}", e);
        process::exit(1);
    }
    println!("Wrote Info.plist");

    // Copy library
    let dest_lib = format!("{}/libifd_jcecard.so", bundle_linux);
    if let Err(e) = fs::copy(&lib_path, &dest_lib) {
        eprintln!("Error copying library: {}", e);
        process::exit(1);
    }
    println!("Copied library to: {}", dest_lib);

    // Create conf directory
    if let Err(e) = fs::create_dir_all(CONF_DIR) {
        eprintln!("Error creating conf directory: {}", e);
        process::exit(1);
    }

    // Write jcecard.conf
    let conf_path = format!("{}/jcecard", CONF_DIR);
    if let Err(e) = fs::write(&conf_path, JCECARD_CONF) {
        eprintln!("Error writing jcecard.conf: {}", e);
        process::exit(1);
    }
    println!("Wrote reader configuration: {}", conf_path);

    println!();
    println!("IFD handler installed successfully!");
    println!();
    println!("Next steps:");
    println!("  1. Restart pcscd: sudo systemctl restart pcscd");
    println!("  2. Start the jcecard TCP server: jcecard");
    println!("  3. Verify with: pcsc_scan");
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn find_library() -> Option<std::path::PathBuf> {
    // Check common locations
    let locations = [
        // Cargo install location
        format!("{}/.cargo/bin/../lib/libifd_jcecard.so", env::var("HOME").unwrap_or_default()),
        // Current directory (for development)
        "target/release/libifd_jcecard.so".to_string(),
        "../target/release/libifd_jcecard.so".to_string(),
        // System library paths
        "/usr/local/lib/libifd_jcecard.so".to_string(),
        "/usr/lib/libifd_jcecard.so".to_string(),
    ];

    for loc in &locations {
        let path = Path::new(loc);
        if path.exists() {
            return Some(path.to_path_buf());
        }
    }

    // Also check LD_LIBRARY_PATH
    if let Ok(ld_path) = env::var("LD_LIBRARY_PATH") {
        for dir in ld_path.split(':') {
            let path = Path::new(dir).join("libifd_jcecard.so");
            if path.exists() {
                return Some(path);
            }
        }
    }

    None
}
