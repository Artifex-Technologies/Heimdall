//! heimdall-multilink: several internet connections at once (docs/MULTILINK.md).

use std::path::PathBuf;
use std::process::Command;

use heimdall_multilink::config::{valid_ifname, Config, Period, Role};
use heimdall_multilink::service::{self, Paths};

const HELP: &str = "heimdall-multilink: use several internet connections at once

  heimdall-multilink status [--json]       what it does now (no password needed)
  heimdall-multilink on | off              switch it on or off (as root; Settings asks for the password)
  heimdall-multilink set LINK use|backup|off [--share PERCENT|none] [--cap MB|none] [--per day|month]
                                           a link's role, its largest share of new connections, its data cap
  heimdall-multilink new-links use|backup|off
                                           the role of a link seen for the first time (a phone plugged in)
  heimdall-multilink run                   the service itself (heimdall-multilink.service)
  heimdall-multilink restore               remove its routing and put the kernel settings back (systemd runs it
                                           after the service stops, also after a crash)

Options for run, restore and status (for tests): --config FILE --run-dir DIR --state-dir DIR --no-nm

Off, NetworkManager's normal routing is untouched. It pauses while a VPN is on.";

const UNIT: &str = "heimdall-multilink.service";

fn paths(args: &mut Vec<String>) -> Result<(Paths, bool), String> {
    let mut p = Paths::default();
    let mut nm = true;
    let mut i = 0;
    while i < args.len() {
        let take = |args: &mut Vec<String>, i: usize| -> Result<PathBuf, String> {
            if i + 1 >= args.len() {
                return Err(format!("{} needs a value", args[i]));
            }
            let v = args.remove(i + 1);
            args.remove(i);
            Ok(PathBuf::from(v))
        };
        match args[i].as_str() {
            "--config" => p.config = take(args, i)?,
            "--run-dir" => p.run = take(args, i)?,
            "--state-dir" => p.state = take(args, i)?,
            "--no-nm" => {
                args.remove(i);
                nm = false;
            }
            _ => i += 1,
        }
    }
    Ok((p, nm))
}

fn root() -> Result<(), String> {
    // SAFETY: geteuid has no preconditions
    if unsafe { libc::geteuid() } != 0 {
        return Err("this needs root: run it with sudo, or switch it in Settings > Wi-Fi & Network".into());
    }
    Ok(())
}

fn systemctl(args: &[&str]) -> Result<(), String> {
    let s = Command::new("/usr/bin/systemctl").args(args).status().map_err(|e| format!("systemctl: {e}"))?;
    if s.success() {
        Ok(())
    } else {
        Err(format!("systemctl {} failed", args.join(" ")))
    }
}

fn human(v: &serde_json::Value) {
    let state = v["state"].as_str().unwrap_or("?");
    let reason = v["reason"].as_str().unwrap_or("");
    println!("{state}{}{reason}", if reason.is_empty() { "" } else { ": " });
    for l in v["links"].as_array().into_iter().flatten() {
        let rate = l["rate"].as_u64().unwrap_or(0) as f64 * 8.0 / 1e6;
        let health = match (l["healthy4"].as_bool(), l["healthy6"].as_bool()) {
            (Some(true), _) | (_, Some(true)) => "works",
            (Some(false), Some(false)) => "no internet",
            _ => "",
        };
        println!(
            "  {:<16} {:<7} {:<12} weight {:>3}  {:>7.1} Mbit/s  {:>3} % now",
            l["name"].as_str().unwrap_or(""),
            l["role"].as_str().unwrap_or(""),
            health,
            l["weight4"].as_u64().or(l["weight6"].as_u64()).map_or("-".into(), |w| w.to_string()),
            rate,
            l["share_now"].as_u64().unwrap_or(0)
        );
    }
    if state == "active" {
        println!("  combined: {:.1} Mbit/s", v["combined_rate"].as_u64().unwrap_or(0) as f64 * 8.0 / 1e6);
    }
}

fn set(paths: &Paths, args: &[String]) -> Result<(), String> {
    let [link, role, rest @ ..] = args else { return Err(HELP.into()) };
    if !valid_ifname(link) {
        return Err(format!("{link:?} is not an interface name"));
    }
    let role = Role::parse(role).ok_or(format!("unknown role {role}: use, backup or off"))?;
    let mut cfg = Config::load(&paths.config)?;
    let mut lc = cfg.link(link);
    lc.role = role;
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        let v = it.next().ok_or(format!("{a} needs a value"))?;
        match a.as_str() {
            "--share" if v == "none" => lc.share = None,
            "--share" => {
                let n: u8 = v.parse().map_err(|_| format!("--share {v}: a percentage, 1 to 99"))?;
                if !(1..=99).contains(&n) {
                    return Err("--share: 1 to 99".into());
                }
                lc.share = Some(n);
            }
            "--cap" if v == "none" => lc.data_cap_mb = None,
            "--cap" => lc.data_cap_mb = Some(v.parse().ok().filter(|&n: &u64| n > 0).ok_or(format!("--cap {v}: megabytes"))?),
            "--per" => {
                lc.period = match v.as_str() {
                    "day" => Period::Day,
                    "month" => Period::Month,
                    _ => return Err("--per: day or month".into()),
                }
            }
            _ => return Err(format!("unknown option {a}")),
        }
    }
    cfg.links.insert(link.clone(), lc);
    cfg.save(&paths.config)
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let r = (|| -> Result<(), String> {
        let custom = args.iter().any(|a| matches!(a.as_str(), "--config" | "--run-dir" | "--state-dir"));
        let (paths, nm) = paths(&mut args)?;
        // through pkexec only the real files: the password asked for is for this computer's settings, not any file
        if custom && std::env::var_os("PKEXEC_UID").is_some() {
            return Err("--config, --run-dir and --state-dir are for tests, not through pkexec".into());
        }
        let cmd = args.first().cloned().unwrap_or_default();
        match cmd.as_str() {
            "run" => service::run(paths, nm),
            "restore" => {
                for e in service::restore(&paths) {
                    eprintln!("heimdall-multilink: {e}");
                }
                Ok(())
            }
            "status" => {
                let v = service::status_file(&paths).unwrap_or_else(|| service::status_when_off(&paths));
                if args.iter().any(|a| a == "--json") {
                    println!("{v}");
                } else {
                    human(&v);
                }
                Ok(())
            }
            "on" => {
                root()?;
                systemctl(&["enable", "--now", UNIT])
            }
            "off" => {
                root()?;
                systemctl(&["disable", "--now", UNIT])
            }
            "set" => {
                root()?;
                set(&paths, &args[1..])
            }
            "new-links" => {
                root()?;
                let r = args.get(1).and_then(|r| Role::parse(r)).ok_or("new-links: use, backup or off")?;
                let mut cfg = Config::load(&paths.config)?;
                cfg.new_links = r;
                cfg.save(&paths.config)
            }
            "help" | "--help" | "-h" => {
                println!("{HELP}");
                Ok(())
            }
            _ => Err(HELP.into()),
        }
    })();
    if let Err(e) = r {
        eprintln!("{e}");
        std::process::exit(2);
    }
}
