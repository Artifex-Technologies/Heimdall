//! `heimdalld wifi-health [--speed] [--json] [--iface IF] [--api ADDR]` (Go: cmd/heimdalld/wifihealth.go, internal/wifihealth):
//! why the Wi-Fi is slow. Settings runs it with `--json` and reads the report; the text is for people. Same arguments,
//! outside commands, report and exit codes as the Go command (docs/RUST_CLI.md, "Wi-Fi").

pub mod fuzzing;
pub mod gosort;
pub mod gostr;
pub mod http;
pub mod judge;
pub mod parse;
pub mod run;

use super::goflag::FlagSet;
use std::io::Write;

pub fn main(args: &[String]) -> Option<i32> {
    let mut fs = FlagSet::new("wifi-health");
    fs.bool("speed", false, "also run a speed test (Cloudflare's public speed test; up to a few hundred MB)");
    fs.bool("json", false, "print the report as JSON");
    fs.string("iface", "", "Wi-Fi interface (default: the one carrying the default route)");
    fs.string("api", "127.0.0.1:8930", "Heimdall's API, for the number of devices on the network (empty: skip)");
    if fs.parse(args).is_err() {
        return Some(2);
    }
    let o = run::Options { iface: fs.get_str("iface"), speed: fs.get_bool("speed"), api: fs.get_str("api"), ..Default::default() };
    let r = match run::check(&o) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("wifi-health: {e}");
            return Some(1);
        }
    };
    let mut out = std::io::stdout().lock();
    if fs.get_bool("json") {
        if let Some(j) = r.to_json() {
            let _ = out.write_all(j.as_bytes());
        }
        return Some(0);
    }
    let _ = out.write_all(&r.to_text());
    Some(0)
}
