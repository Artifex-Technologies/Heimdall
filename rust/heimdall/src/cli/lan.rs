//! `heimdalld lan scan|list` (Go: cmd/heimdalld/lan.go, internal/lan): the device list of trusted home networks. `scan` runs
//! every 5 minutes from heimdall-lan-scan.timer (its own sandboxed unit, user heimdall; heimdalld itself stays off the
//! network) and does nothing on a network the owner has not trusted; `list` prints the list.

pub mod discover;
pub mod dns;
pub mod net;
pub mod oui;
pub mod resolver;
pub mod scan;
pub mod store;
pub mod text;

use super::goflag::FlagSet;
use super::golog::Logger;
use super::tabwriter::TabWriter;

/// One scan of the current network, or the list, as `heimdalld lan` does.
pub fn main(args: &[String]) -> Option<i32> {
    let what = args.first().map(String::as_str);
    if what != Some("scan") && what != Some("list") {
        eprintln!("usage: heimdalld lan scan|list [--dir DIR]");
        return Some(2);
    }
    let what = what.unwrap_or_default();
    let mut fs = FlagSet::new(&format!("lan {what}"));
    fs.string("dir", "/var/lib/heimdall/lan", "state directory");
    if fs.parse(&args[1..]).is_err() {
        return Some(2);
    }
    let dir = fs.get_str("dir");
    if what == "scan" {
        return Some(scan_command(&dir));
    }
    Some(list(&dir))
}

fn scan_command(dir: &str) -> i32 {
    if let Err(e) = crate::gopath::mkdir_all(dir, 0o750) {
        eprintln!("{e}");
        return 1;
    }
    let log = |m: &str| Logger::std().print(m);
    match scan::scan(dir, std::time::Duration::from_secs(2), &log) {
        Err(e) => {
            eprintln!("lan scan: {e}");
            1
        }
        Ok(r) => {
            match r.status.as_str() {
                "scanned" => println!("{} devices, {} new", r.devices, r.new.len()),
                "not_trusted" => println!("this network is not trusted: no scan (heimdall-wifi-guard trust, at home)"),
                "router_changed" => println!("the router is not the one recorded when this network was trusted: no scan"),
                s => println!("{s}"),
            }
            0
        }
    }
}

/// The list: per network a line, then a table of its devices (Go's tabwriter: minwidth 2, tab width 4, padding 2).
pub fn list(dir: &str) -> i32 {
    let (st, err) = store::load(&format!("{dir}/devices.json"));
    if let Some(e) = err {
        eprintln!("{e}");
        return 1;
    }
    let mut out = String::new();
    for n in st.networks.iter().flatten() {
        let devices = n.devices.as_deref().unwrap_or_default();
        out.push_str(&format!("{}: {} devices, last scan {}\n", n.ssid, devices.len(), n.last_scan.local().format("2006-01-02 15:04:05")));
        let mut tw = TabWriter::new(2, 4, 2);
        tw.write("  IP\tNAME\tMAKER\tKIND\tFIRST SEEN\tLAST SEEN\n");
        for d in devices {
            tw.write(&format!(
                "  {}\t{}\t{}\t{}\t{}\t{}\n",
                d.ip,
                d.name,
                d.vendor,
                d.kind,
                d.first_seen.local().format("2006-01-02 15:04"),
                d.last_seen.local().format("2006-01-02 15:04")
            ));
        }
        out.push_str(&tw.flush());
    }
    use std::io::Write;
    let _ = std::io::stdout().write_all(out.as_bytes());
    0
}
