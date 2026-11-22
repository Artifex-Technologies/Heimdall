//! `heimdalld lan scan|list|kind` (Go: cmd/heimdalld/lan.go, internal/lan): the device list of trusted home networks. `scan`
//! runs every 5 minutes from heimdall-lan-scan.timer (its own sandboxed unit, user heimdall; heimdalld itself stays off the
//! network) and does nothing on a network the owner has not trusted; `list` prints the list; `kind MAC KIND|guess` (as root,
//! Settings runs it through pkexec) records what the owner says a device is. Only in the Rust heimdalld: `look` (HEI-74),
//! a listen-only look at a network that is not home, run by Settings as the owner when that network's page opens; it sends
//! nothing and writes nothing (look.rs).

pub mod discover;
pub mod dns;
pub mod fuzz;
pub mod look;
pub mod net;
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
    if what == Some("look") {
        return Some(look_command(&args[1..]));
    }
    if what != Some("scan") && what != Some("list") && what != Some("kind") {
        eprintln!("usage: heimdalld lan scan|list|kind [--dir DIR] [MAC KIND|guess]");
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
    if what == "kind" {
        return Some(kind(&dir, fs.args()));
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
                "not_home" => println!(
                    "this network is trusted, but not as your home network: no scan (heimdall-wifi-guard trust --home turns the device list on)"
                ),
                "router_changed" => println!("the router is not the one recorded when this network was trusted: no scan"),
                s => println!("{s}"),
            }
            0
        }
    }
}

/// `lan look [--wait SECONDS] [UUID]`: one listen-only look, printed as JSON (look.rs). The wait is held to 1-60 seconds.
fn look_command(args: &[String]) -> i32 {
    let mut fs = FlagSet::new("lan look");
    fs.int("wait", 8, "seconds to listen for multicast DNS");
    if fs.parse(args).is_err() {
        return 2;
    }
    if fs.narg() > 1 {
        eprintln!("usage: heimdalld lan look [--wait SECONDS] [UUID]");
        return 2;
    }
    let wait = std::time::Duration::from_secs(fs.get_int("wait").clamp(1, 60) as u64);
    let l = look::look(fs.args().first().map(String::as_str), wait);
    println!("{}", look::to_json(&l));
    0
}

/// What the owner says a device is (Go: the "kind" branch of cmdLAN).
fn kind(dir: &str, args: &[String]) -> i32 {
    if args.len() != 2 {
        eprintln!("usage: heimdalld lan kind [--dir DIR] MAC KIND|guess");
        return 2;
    }
    match store::set_kind(&format!("{dir}/{}", store::KINDS_FILE), &args[0], &args[1]) {
        Err(e) => {
            eprintln!("lan kind: {e}");
            1
        }
        Ok(m) => {
            if args[1] == "guess" {
                println!("{m}: the list's guess");
            } else {
                println!("{m}: {}", args[1]);
            }
            0
        }
    }
}

/// The list: per network a line, then a table of its devices (Go's tabwriter: minwidth 2, tab width 4, padding 2).
pub fn list(dir: &str) -> i32 {
    let (mut st, err) = store::load(&format!("{dir}/devices.json"));
    if let Some(e) = err {
        eprintln!("{e}");
        return 1;
    }
    st.apply_kinds(store::load_kinds(&format!("{dir}/{}", store::KINDS_FILE)).as_ref());
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
                if d.owner_kind.is_empty() { &d.kind } else { &d.owner_kind }, // the owner's word over the guess
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
