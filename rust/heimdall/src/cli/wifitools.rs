//! The Wi-Fi helpers, Python today: `heimdall-wifi-check` (packaging/arch), `heimdall-wifi-guard` and
//! `heimdall-wifi-notify` (packaging/net).
//!
//! Not ported yet: every function answers None and the command goes to the Go binary (or, for a helper, stays the script).

pub fn wifi_check(_args: &[String]) -> Option<i32> {
    None
}

pub fn wifi_guard(_args: &[String]) -> Option<i32> {
    None
}

pub fn wifi_notify(_args: &[String]) -> Option<i32> {
    None
}
