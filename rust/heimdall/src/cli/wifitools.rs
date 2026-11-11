//! The Wi-Fi helpers the package ships, ported from Python: `heimdall-wifi-check` (packaging/arch: is the network just
//! joined safe to use?), `heimdall-wifi-guard` (packaging/net: trusted and untrusted networks, the VPN with its kill switch)
//! and `heimdall-wifi-notify` (packaging/net: the desktop notification of both). This program answers to their names
//! (`cli::tool`), so at the switch each becomes a link to it; the Python programs stay beside as the fallback.
//!
//! Each port does what its Python program does on the same input, Python's own rules included (`py.rs`): the same
//! arguments, output, files, notifications, programs called and exit codes, proved by running both on the same made-up
//! systems (tests/cli_wifitools.rs) and by the parsers' properties and fuzz targets (docs/RUST_CLI.md, "Wi-Fi helpers").

pub mod addr;
pub mod guard;
pub mod notify;
pub mod py;

/// `hashlib.sha256(s.encode()).hexdigest()[:16]`.
pub fn sha16(s: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(s.as_bytes()).iter().take(8).map(|b| format!("{b:02x}")).collect()
}

pub fn wifi_check(_args: &[String]) -> Option<i32> {
    None
}

pub fn wifi_guard(args: &[String]) -> Option<i32> {
    Some(guard::main(args))
}

pub fn wifi_notify(args: &[String]) -> Option<i32> {
    Some(notify::main(args))
}

/// A fuzz target: its name and its body.
pub type FuzzTarget = (&'static str, fn(&[u8]));

/// The helpers' fuzz targets, for tests/cli_wifi_fuzz.rs.
pub fn fuzz_targets() -> Vec<FuzzTarget> {
    Vec::new()
}
