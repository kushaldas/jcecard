fn main() {
    // Just make sure we can find pcsclite headers
    // The library itself is dynamically linked by pcscd
    println!("cargo:rerun-if-changed=src/lib.rs");
}
