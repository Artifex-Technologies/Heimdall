//! `heimdalld maintenance on|off|status` (Go: cmd/heimdalld/main.go's cmdMaintenance, internal/maintenance): the owner's window
//! in which routine alerts become info. Labyrinth's `labyrinth-agent` opens one (`on --for 15m --reason ...`) around the
//! installs it makes, and closes it.

use crate::cli::goflag::FlagSet;
use crate::config::Config;
use crate::gotime::Time;
use crate::maintenance;

/// Go's `config.Load` as the commands print its errors ("config: read PATH: open PATH: permission denied").
pub fn load_config(path: &str) -> Result<Config, String> {
    if path.is_empty() {
        return Ok(Config::default());
    }
    match std::fs::read(path) {
        Ok(b) => Config::parse(&b).map_err(|e| format!("config: parse {path}: {}", go_config_error(&e, &b))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(e) => Err(format!("config: read {path}: {}", crate::gopath::read_err(path, &e))),
    }
}

/// The daemon's JSON reader names a wrong type in the config as "number 5 into Go struct field net_ports of type string";
/// Go's `UnmarshalTypeError` says "number into Go struct field Config.net_ports of type string" (the value only when the
/// target is a number, the field after the struct's name), "number into Config.vault_dirs.0 of type string" for a list's
/// element (the index, and no "Go struct field"), and "bool into Go value of type config.Config" for the whole document.
/// The commands print Go's text; `doc` is the config file, read again for an element's index.
pub fn go_config_error(e: &str, doc: &[u8]) -> String {
    use crate::gojson::{self, Value};
    if let Some(what) = e.strip_prefix("json: cannot unmarshal ").and_then(|r| r.strip_suffix(" into Go value of type Config")) {
        return format!("json: cannot unmarshal {what} into Go value of type config.Config");
    }
    const FIELD: &str = " into Go struct field ";
    let (Some(_), Some(i)) = (e.strip_prefix("json: cannot unmarshal "), e.find(FIELD)) else { return e.to_string() };
    let what = &e["json: cannot unmarshal ".len()..i];
    let after = &e[i + FIELD.len()..];
    let Some(j) = after.find(" of type ") else { return e.to_string() };
    let (field, mut ty) = (&after[..j], &after[j + " of type ".len()..]);
    if ty == "slice" {
        // the reader says "slice"; Go names the type: the config's lists are of strings, but net_ports of ints
        ty = if field == "net_ports" { "[]int" } else { "[]string" };
    }
    let numeric = matches!(ty, "int" | "int64" | "uint32" | "float64");
    let what = if what.starts_with("number ") && !numeric { "number" } else { what };
    // an element of a list: the first element (in the file's order) that does not read as the element type
    if !ty.starts_with("[]") {
        if let Ok(Some(members)) = gojson::parse(doc).as_ref().map(|v| gojson::struct_members(v, &[field], "Config")).unwrap_or(Ok(None)) {
            for (_, v) in members {
                let Value::Array(items) = v else { continue };
                let bad = items.iter().position(|it| match (ty, it) {
                    (_, Value::Null) => false,
                    ("string", Value::String(_)) => false,
                    ("int", Value::Number(n)) => n.parse::<i64>().is_err(),
                    _ => true,
                });
                if let Some(k) = bad {
                    return format!("json: cannot unmarshal {what} into Config.{field}.{k} of type {ty}");
                }
            }
        }
    }
    format!("json: cannot unmarshal {what}{FIELD}Config.{field} of type {ty}")
}

pub fn main(args: &[String]) -> Option<i32> {
    Some(run(args))
}

fn run(args: &[String]) -> i32 {
    let action = args.first().map(String::as_str).unwrap_or("");
    if !matches!(action, "on" | "off" | "status") {
        eprintln!(r#"usage: heimdalld maintenance on --for 2h --reason "why" | off | status   [--config PATH]"#);
        return 2;
    }
    let mut fs = FlagSet::new("maintenance");
    fs.string("config", "/etc/heimdall/config.json", "config file");
    fs.duration("for", 0, "how long (at most 4h)");
    fs.string("reason", "", "why (required for on)");
    if fs.parse(&args[1..]).is_err() {
        return 2;
    }
    let cfg = match load_config(&fs.get_str("config")) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("heimdalld: {e}");
            return 2;
        }
    };
    let now = Time::now().local();
    if action == "status" {
        println!("{}", maintenance::describe(maintenance::read(&cfg.maintenance_path).as_ref(), &now));
        return 0;
    }
    // who is asking: the user behind sudo, else the current user
    let mut actor = std::env::var("SUDO_USER").unwrap_or_default();
    if actor.is_empty() {
        actor = std::env::var("USER").unwrap_or_default();
    }
    if !rustix::process::geteuid().is_root() {
        eprintln!("heimdalld: only root can change the maintenance window (use sudo)");
        return 1;
    }
    if !cfg.maintenance_actors.is_empty() && !cfg.maintenance_actors.contains(&actor) {
        eprintln!("heimdalld: {} is not in maintenance_actors", crate::gotext::quote(&actor));
        return 1;
    }
    if action == "off" {
        if let Err(e) = maintenance::clear(&cfg.maintenance_path) {
            eprintln!("heimdalld: {e}");
            return 1;
        }
        println!("maintenance window closed");
        return 0;
    }
    let mut w = match maintenance::open(&actor, &fs.get_str("reason"), fs.get_duration("for"), now) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("heimdalld: {e}");
            return 2;
        }
    };
    w.until = w.until.local(); // Go's time.Now().Add(d) is shown in the local zone at its own instant
    if let Err(e) = maintenance::write(&cfg.maintenance_path, &w) {
        eprintln!("heimdalld: {e}");
        return 1;
    }
    println!("{}", maintenance::describe(Some(&w), &now));
    0
}
