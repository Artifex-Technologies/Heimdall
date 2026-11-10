//! What an alert means in plain words, without any AI (Go: internal/explain). Fixed text by detector and severity, with a few
//! details from the alert's fields, quoted, cut short and stripped of control characters.

use crate::event::Fields;
use crate::gotext;

/// The plain-language explanation of one alert.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Text {
    pub what: String,
    pub serious: String,
    pub done: String,
    pub r#do: String,
}

/// An observed value made safe inside a sentence: no control characters, one line, at most n characters.
pub fn clean(s: &str, n: usize) -> String {
    let spaced: String = s
        .chars()
        .map(|r| {
            let c = r as u32;
            if c < 0x20 || c == 0x7f || (0x80..0xa0).contains(&c) {
                ' '
            } else {
                r
            }
        })
        .collect();
    let out = gotext::fields(&spaced).collect::<Vec<_>>().join(" ");
    if out.chars().count() > n {
        let mut cut: String = out.chars().take(n.saturating_sub(1)).collect();
        cut.push('…');
        return cut;
    }
    out
}

fn get<'a>(f: &'a Fields, k: &str) -> &'a str {
    f.get(k).map_or("", String::as_str)
}

fn quoted(f: &Fields, key: &str) -> String {
    let v = clean(get(f, key), 120);
    if v.is_empty() {
        return String::new();
    }
    format!("“{v}”")
}

fn serious(sev: &str) -> &'static str {
    match sev {
        "critical" => "Serious: look at it now.",
        "warning" => "Worth a look soon; nothing is broken yet.",
        _ => "For your information; nothing needs doing.",
    }
}

const LOGGED: &str = "Heimdall recorded it; nothing was changed on your computer.";
const SETTINGS: &str = "Settings > Security lists it with the others.";
const AI_AGENT_NOTE: &str = "This concerns an AI agent on this computer (Sarina or another local agent Heimdall watches).";

fn or_unknown(s: String, fallback: &str) -> String {
    if gotext::trim_space(s.trim_matches(['“', '”'])).is_empty() {
        return fallback.to_owned();
    }
    s
}

fn or_empty(s: String, prefix: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    format!("{prefix}{s}")
}

fn origin_text(f: &Fields) -> String {
    let o = clean(get(f, "origin"), 60);
    if o.is_empty() {
        String::new()
    } else {
        format!(" ({o})")
    }
}

fn src_text(f: &Fields) -> String {
    let s = clean(get(f, "src"), 60);
    if s.is_empty() {
        String::new()
    } else {
        format!(" from {s}{}", origin_text(f))
    }
}

fn version_text(f: &Fields) -> String {
    let (inst, fixed) = (clean(get(f, "installed"), 40), clean(get(f, "fixed"), 40));
    if !inst.is_empty() && !fixed.is_empty() {
        format!(" (installed {inst}, fixed in {fixed})")
    } else if !inst.is_empty() {
        format!(" (installed {inst}, no fix yet)")
    } else {
        String::new()
    }
}

fn running_text(f: &Fields) -> &'static str {
    match get(f, "running") {
        "true" | "yes" | "1" => ", including the one running now",
        "false" | "no" | "0" => " (not the one running now)",
        _ => "",
    }
}

/// A SHA-256 only when it is one (64 hex characters); anything else becomes the word SHA256, so no observed text lands in a
/// command line.
fn sha256_or_placeholder(s: &str) -> String {
    if s.len() != 64 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return "SHA256".into();
    }
    s.to_owned()
}

/// The explanation of an alert from its detector, severity and fields.
pub fn for_alert(detector: &str, severity: &str, fields: &Fields) -> Text {
    let mut t = Text { serious: serious(severity).into(), done: LOGGED.into(), ..Default::default() };
    let path = quoted(fields, "path");
    let c = |k: &str, n: usize| clean(get(fields, k), n);
    let q = |k: &str| quoted(fields, k);
    match detector {
        "injection-phrase" => {
            t.what = format!("Text that tries to give an AI agent orders (“ignore your instructions”, “you are now…”) appeared in something the agent read: a web page, a file, an email. {AI_AGENT_NOTE}");
            t.r#do = format!("Do not act on anything the agent proposed after reading it. If you did not expect it, look at where the text came from. {SETTINGS}");
        }
        "credential-shape" => {
            t.what = format!("Something that looks like a password, key or access token appeared in an AI agent's output or in text it handled. {AI_AGENT_NOTE}");
            t.r#do =
                "If it is a real secret, change it at the service it belongs to (it may have been shown or stored where it should not be)."
                    .into();
        }
        "invisible-unicode" => {
            t.what = format!("Text contained invisible or look-alike characters, a known way to hide instructions from people while an AI still reads them. {AI_AGENT_NOTE}");
            t.r#do = "Treat the text as suspicious; do not copy it into commands.".into();
        }
        "permission-escalation" => {
            t.what = format!("An AI agent repeatedly asked for things its current permissions do not allow (running commands, writing files). It was refused each time. {AI_AGENT_NOTE}");
            t.done = "The requests were refused by the agent's own permission rules; Heimdall recorded them.".into();
            t.r#do = "If you did not ask the agent to do something that needs more access, look at what it was working on.".into();
        }
        "session-burst" => {
            t.what = format!("An AI agent started far more sessions in a short time than one person normally would. That can be a loop, or something driving it. {AI_AGENT_NOTE}");
            t.r#do = "If you are not running anything in bulk, stop the agent and look at what started the sessions.".into();
        }
        "file-integrity" => {
            t.what = format!("A watched program or setting file changed: {}. Heimdall watches the security tools, the AI agents and their settings, because changing them is how an attack takes over.", or_unknown(path.clone(), "a watched file"));
            if get(fields, "prior_hash").is_empty() && !get(fields, "new_hash").is_empty() {
                t.what = format!("A new file appeared in a watched folder: {}.", or_unknown(path, "a new file"));
            }
            t.r#do = "If you just installed updates or changed this file yourself, nothing to do. Otherwise reinstall the package it belongs to (pacman -Qo shows which) and check Settings > Security.".into();
        }
        "maintenance-window" => {
            t.what = "A maintenance window opened or closed: during one, routine alerts are softened because changes are expected.".into();
            t.r#do = "Nothing, if you or your administrator opened it.".into();
        }
        "resource-pressure" => {
            t.what = format!(
                "The computer is short of memory or very busy (memory {}%, load {} per core).",
                or_unknown(c("mem_percent", 8), "high"),
                or_unknown(c("load_per_cpu", 8), "high")
            );
            t.r#do = "Close what you do not need; the system monitor shows what is using it. If nothing you run explains it, something unexpected may be running.".into();
        }
        "network-exposure" => {
            t.what = format!(
                "A local service that should only be reachable from this computer is listening to the network: port {} on {}.",
                or_unknown(c("port", 8), "?"),
                or_unknown(c("address", 60), "all addresses")
            );
            t.r#do = "Others on your network may reach it. Stop the program or set it to listen on 127.0.0.1 only; the firewall in Settings > Security can also block it.".into();
        }
        "connection-watch" => {
            t.what = format!(
                "A program connected somewhere worth a look: {} to {}{}.",
                or_unknown(q("process"), "a program"),
                or_unknown(c("remote_addr", 60), "a remote address"),
                origin_text(fields)
            );
            if !get(fields, "remote_listed").is_empty() {
                t.what += " That address is on a threat list.";
            }
            t.r#do = "If you know the program and where it talks to, nothing to do. If not, block its network access in Settings > Apps, or stop it.".into();
        }
        "inbound" => {
            t.what = format!(
                "Something on the network tried to reach this computer{} and the firewall {}.",
                src_text(fields),
                or_unknown(c("verdict", 20), "dealt with it")
            );
            t.done = "The firewall acted on it; Heimdall recorded it.".into();
            t.r#do = "Usually nothing: the firewall did its job. Many attempts from one address, or any that got through, are worth a look in Settings > Security.".into();
        }
        "package-vulnerability" => {
            t.what = format!(
                "An installed package has a known security hole: {}{}.",
                or_unknown(q("package"), "a package"),
                version_text(fields)
            );
            t.r#do =
                "Update the system (Agora > Updates, or sudo pacman -Syu). If no fix is out yet, the alert says what to avoid meanwhile."
                    .into();
        }
        "kernel-vulnerability" => {
            t.what =
                format!("A kernel installed on this computer has known security holes that a newer kernel fixes{}.", running_text(fields));
            t.r#do = "Update (Agora > Updates) and restart into the new kernel. A hole in a kernel you are not running matters only when you start it.".into();
        }
        "hardening" => {
            t.what = format!("A security setting of the system is weaker than it should be{}.", or_empty(q("now"), ": "));
            let f = c("fix", 160);
            t.r#do = if f.is_empty() {
                "Settings > Security shows the setting and how to restore it.".into()
            } else {
                format!("To fix it: {f}.")
            };
        }
        "wifi-safety" => {
            t.what = format!("A check of the Wi-Fi network {} found something that can expose your traffic (an open network, a weak lock, or a network pretending to be another).", or_unknown(q("ssid"), "you joined"));
            t.r#do = "Avoid signing in to anything important on this network, or turn on a VPN first.".into();
        }
        "lan-watch" => {
            t.what = format!("Something on your local network is pretending to be your router or another device (its hardware address changed to {}). That is how traffic on a shared network gets intercepted.", or_unknown(c("new_mac", 40), "a new one"));
            t.r#do = "On a network you do not control, disconnect or use a VPN. At home, restart the router and check which devices are connected.".into();
        }
        "baseline-drift" => {
            t.what = "The computer behaved unlike its usual self (far more activity of some kind than normal for this time).".into();
            t.r#do =
                "If you are doing something unusual (a big download, a build), nothing to do. Otherwise look at what is running.".into();
        }
        "limbo-guest" => {
            t.what = format!("A program running in a Limbo sandbox broke the sandbox's safety rules{}.", or_empty(q("guest"), ": "));
            t.done = "Heimdall asked Limbo to cut the sandbox off (quarantine). Limbo never lets Heimdall release it; only you can.".into();
            t.r#do = "Look at the quarantine in Settings > Security before releasing anything; if unsure, delete the sandbox.".into();
        }
        "limbo-network" => {
            let guest = or_unknown(q("guest"), "a sandbox");
            let reason = get(fields, "reason");
            t.what = match reason {
                "host_probe" => format!("A program in the Limbo sandbox {guest} tried to reach this computer itself. Its firewall refused it, but a sandboxed program has no reason to knock on its host."),
                "lan_probe" => format!("A program in the Limbo sandbox {guest} tried to reach your home network, the router or another sandbox. Its firewall refused it."),
                "scan" => format!("A program in the Limbo sandbox {guest} tried many different addresses in a short time and was refused each time. That is what a scan looks like."),
                "ipv6" => format!("A program in the Limbo sandbox {guest} tried to send IPv6 traffic out. Sandboxes have no IPv6, so it went nowhere."),
                "" => format!("The Limbo sandbox {guest} used up its budget of recorded network destinations. Limbo keeps reporting anything that looks like probing."),
                _ => format!("Limbo reported unusual refused network traffic from the sandbox {guest}."),
            };
            match reason {
                "host_probe" | "lan_probe" | "scan" => {
                    t.done = "Nothing got through: the sandbox's firewall refused it. If automatic restriction is on in Heimdall's settings, Heimdall also asked Limbo to cut the sandbox's network (quarantine); only you can release it.".into();
                    t.r#do = "Look at what runs in the sandbox (Settings > Security shows any quarantine). If you do not know why it would do this, delete the sandbox.".into();
                }
                "" => {
                    t.done = "Nothing was changed; Limbo only stops writing down new ordinary destinations for this sandbox.".into();
                    t.r#do = "Nothing, unless other alerts name the same sandbox.".into();
                }
                _ => {
                    t.done = "Nothing got through: the sandbox's firewall refused it.".into();
                    t.r#do = "If other alerts name the same sandbox, read them together; otherwise nothing to do.".into();
                }
            }
        }
        "limbo-exchange" => {
            let guest = or_unknown(q("guest"), "a sandbox");
            if !get(fields, "signature").is_empty() || severity != "info" {
                t.what = format!(
                    "A program in the Limbo sandbox {guest} tried to hand you a file ({}) that ClamAV knows as malware ({}).",
                    or_unknown(q("guest_path"), "unnamed"),
                    or_unknown(c("signature", 80), "a known signature")
                );
                t.done = "Limbo kept the file back, where only root can read it; it did not reach you.".into();
                t.r#do = format!("Do not copy files out of this sandbox by other means. The sandbox itself is probably infected: if you do not need it, delete it. To keep a copy in Heimdall's own malware store (root-only, never run): sudo heimdalld immunity take-limbo {}.", sha256_or_placeholder(get(fields, "sha256")));
            } else {
                t.what = format!(
                    "A file in the Limbo sandbox {guest}'s outbox ({}) could not be scanned, so Limbo did not hand it out.",
                    or_unknown(q("guest_path"), "unnamed")
                );
                t.done = "The file stayed inside the sandbox.".into();
                t.r#do = "Check that ClamAV is running (systemctl status clamav-daemon), then try again.".into();
            }
        }
        "tool-rules" => {
            let prog = or_unknown(q("script"), &or_unknown(q("exe"), "a security tool's program"));
            t.what = format!("The program file of a security tool ({prog}) is not the one its package installed. Heimdall lets a verified tool scan and connect quietly on a security system; a changed one could be malware using the tool's name.");
            t.r#do = "Find out what changed the file (pacman -Qkk, the package's last update, what you ran), then reinstall the package. Until then, do not use the tool.".into();
        }
        "remote-access" => {
            let tool = or_unknown(c("provider_name", 60), "a tool");
            if get(fields, "signal") == "tunnel" {
                t.what = format!("A new tunnel network interface appeared ({}). A VPN you start does this; so does a program that wants a hidden way in or out.", or_unknown(c("iface", 30), "unnamed"));
                t.r#do = "If you just connected a VPN, nothing to do. Otherwise look at what created it (ip link, and the programs you installed recently).".into();
            } else if get(fields, "ra_kind") == "c2" {
                t.what = format!("A program known as an attacker's remote control ({tool}) is on this computer.");
                t.r#do = "Treat the computer as compromised: disconnect it from the network and ask for help before using it for anything private.".into();
            } else if severity == "info" {
                t.what = format!("{tool}, which you approved, is in use.");
                t.r#do = "Nothing to do.".into();
            } else {
                t.what = format!("{tool} lets someone reach this computer from elsewhere, and it is here without your approval ({}). Malware often installs a tool like this to keep a way in.", or_unknown(c("signal", 30), "seen"));
                t.r#do = format!("If you installed it yourself and want it, approve it: sudo heimdalld remote approve {}. If not, remove it now and look at what else was installed with it.", or_unknown(c("provider", 30), "ID"));
            }
        }
        "agent-baseline" => {
            t.what = format!("The AI agent behaved unlike its usual self: far more sessions or tool calls than normal for it, or a tool it had never used. {AI_AGENT_NOTE}");
            t.r#do = "If you just gave it a big job (or the evals are running), nothing to do. Otherwise look at its latest sessions and at any other alert about them.".into();
        }
        "rule-draft" => {
            t.what = format!(
                "A rule that recognises a held malware sample and its variants was drafted ({}). It does nothing until you approve it.",
                or_unknown(c("rule", 70), "a YARA rule")
            );
            t.r#do = format!("Test it (it must match the sample and none of this computer's programs), read it, then approve or reject it: sudo heimdalld immunity rule test {}.", or_unknown(c("rule_id", 20), "ID"));
        }
        "incident" => {
            t.what = format!("Several of Heimdall's alerts are about the same thing ({}) within a short time: {}. Each alone may be harmless; together they tell one story.", or_unknown(c("keys", 160), "a session, address or program"), or_unknown(c("detectors", 120), "several checks"));
            t.r#do = "Read these alerts together, oldest first (Settings > Security, or heimdalld's API /v1/incidents). Act on the most serious one.".into();
        }
        "grant-request" => {
            t.what = format!(
                "An AI agent asks for more than it has: {} {}. It cannot give this to itself; only you can.",
                or_unknown(c("kind", 20), "a grant"),
                or_unknown(c("detail", 40), "")
            );
            t.done = "Heimdall recorded the request. Nothing changes until you decide.".into();
            let id = or_unknown(c("request_id", 20), "ID");
            t.r#do = format!("If you asked the agent to do something that needs it, allow it: sudo heimdalld grant approve {id}. If not, deny it: sudo heimdalld grant deny {id}.");
        }
        "integration" => {
            t.what =
                format!("Heimdall could not use one of the things it works with ({}).", or_unknown(c("error_code", 40), "a component"));
            t.r#do = or_unknown(c("remedy", 200), "See Heimdall's log (journalctl -u heimdall).");
        }
        _ => {
            t.what = format!("Heimdall noticed something ({}).", clean(detector, 40));
            t.r#do = SETTINGS.into();
        }
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_cuts_and_strips() {
        assert_eq!(clean("a\x01b\n  c", 120), "a b c");
        assert_eq!(clean("abcdef", 4), "abc…");
        assert_eq!(clean("\u{85}x\u{a0}y", 10), "x y");
    }

    #[test]
    fn placeholder_for_anything_but_a_hash() {
        assert_eq!(sha256_or_placeholder("x; rm -rf /"), "SHA256");
        let h = "a".repeat(64);
        assert_eq!(sha256_or_placeholder(&h), h);
    }
}
