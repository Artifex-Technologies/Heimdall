//! The owner's choices: `/etc/heimdall/multilink.json` (root's, readable by all: it holds no secret).
//!
//! ```json
//! {"new_links": "use",
//!  "links": {"wlan0": {"role": "use"},
//!            "usb0":  {"role": "use", "share": 30, "data_cap_mb": 2000, "period": "month"}}}
//! ```
//!
//! A link is a network interface that has a default route in the main table (NetworkManager puts one there for every
//! connection). Links are named by their interface, as NetworkManager and Settings show them.

use std::collections::BTreeMap;
use std::path::Path;

/// What a link is used for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// New connections are spread over it.
    Use,
    /// Only while no link set to Use works.
    Backup,
    /// Never: it keeps NetworkManager's normal routing and nothing of ours touches it.
    Off,
}

impl Role {
    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "use" => Some(Role::Use),
            "backup" => Some(Role::Backup),
            "off" => Some(Role::Off),
            _ => None,
        }
    }
    pub fn id(self) -> &'static str {
        match self {
            Role::Use => "use",
            Role::Backup => "backup",
            Role::Off => "off",
        }
    }
}

/// How long a data cap counts before it starts again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Period {
    Day,
    Month,
}

impl Period {
    pub fn id(self) -> &'static str {
        match self {
            Period::Day => "day",
            Period::Month => "month",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct LinkConf {
    pub role: Role,
    /// At most this share of new connections (percent, 1-99); None: no limit.
    pub share: Option<u8>,
    /// At most this much data (sent and received) per period; past it the link is kept for backup only.
    pub data_cap_mb: Option<u64>,
    pub period: Period,
}

impl Default for LinkConf {
    fn default() -> Self {
        LinkConf { role: Role::Use, share: None, data_cap_mb: None, period: Period::Month }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    /// The role of a link that is not in `links` (a phone plugged in for the first time).
    pub new_links: Role,
    pub links: BTreeMap<String, LinkConf>,
    /// Where the health checks connect (TCP, IP:port). A refused connection counts as reached: something on the internet
    /// answered.
    pub probe4: Vec<String>,
    pub probe6: Vec<String>,
    /// How often each link is checked, in milliseconds.
    pub probe_every_ms: u64,
}

pub const DEFAULT_PROBE4: [&str; 2] = ["1.1.1.1:443", "9.9.9.9:443"];
pub const DEFAULT_PROBE6: [&str; 2] = ["[2606:4700:4700::1111]:443", "[2620:fe::fe]:443"];

impl Default for Config {
    fn default() -> Self {
        Config {
            new_links: Role::Use,
            links: BTreeMap::new(),
            probe4: DEFAULT_PROBE4.iter().map(|s| s.to_string()).collect(),
            probe6: DEFAULT_PROBE6.iter().map(|s| s.to_string()).collect(),
            probe_every_ms: 2000,
        }
    }
}

/// An interface name as the kernel allows it (at most 15 bytes, no slash, no space); anything else is refused, so a
/// name never becomes a second argument of `ip`.
pub fn valid_ifname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 15
        && s != "."
        && s != ".."
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@'))
        && !s.starts_with('-')
}

impl Config {
    pub fn link(&self, name: &str) -> LinkConf {
        self.links.get(name).cloned().unwrap_or(LinkConf { role: self.new_links, ..LinkConf::default() })
    }

    pub fn parse(text: &str) -> Result<Config, String> {
        let v: serde_json::Value = serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))?;
        let mut c = Config::default();
        if let Some(r) = v.get("new_links").and_then(|r| r.as_str()) {
            c.new_links = Role::parse(r).ok_or(format!("new_links: unknown role {r}"))?;
        }
        if let Some(m) = v.get("links").and_then(|l| l.as_object()) {
            for (name, l) in m {
                if !valid_ifname(name) {
                    return Err(format!("links: {name:?} is not an interface name"));
                }
                let mut lc = LinkConf::default();
                if let Some(r) = l.get("role").and_then(|r| r.as_str()) {
                    lc.role = Role::parse(r).ok_or(format!("{name}: unknown role {r}"))?;
                }
                if let Some(s) = l.get("share").and_then(|s| s.as_u64()) {
                    if !(1..=99).contains(&s) {
                        return Err(format!("{name}: share must be 1 to 99"));
                    }
                    lc.share = Some(s as u8);
                }
                lc.data_cap_mb = l.get("data_cap_mb").and_then(|s| s.as_u64()).filter(|&n| n > 0);
                lc.period = match l.get("period").and_then(|p| p.as_str()) {
                    Some("day") => Period::Day,
                    None | Some("month") => Period::Month,
                    Some(p) => return Err(format!("{name}: unknown period {p}")),
                };
                c.links.insert(name.clone(), lc);
            }
        }
        let list = |k: &str| -> Option<Vec<String>> {
            v.get(k).and_then(|a| a.as_array()).map(|a| a.iter().filter_map(|s| s.as_str()).map(String::from).collect())
        };
        if let Some(p) = list("probe4") {
            c.probe4 = p;
        }
        if let Some(p) = list("probe6") {
            c.probe6 = p;
        }
        if let Some(ms) = v.get("probe_every_ms").and_then(|n| n.as_u64()) {
            c.probe_every_ms = ms.clamp(200, 60_000);
        }
        Ok(c)
    }

    pub fn to_json(&self) -> serde_json::Value {
        let links: serde_json::Map<String, serde_json::Value> = self
            .links
            .iter()
            .map(|(n, l)| {
                let mut o = serde_json::json!({"role": l.role.id()});
                if let Some(s) = l.share {
                    o["share"] = s.into();
                }
                if let Some(c) = l.data_cap_mb {
                    o["data_cap_mb"] = c.into();
                    o["period"] = l.period.id().into();
                }
                (n.clone(), o)
            })
            .collect();
        let mut v = serde_json::json!({"new_links": self.new_links.id(), "links": links});
        if self.probe4 != Config::default().probe4 {
            v["probe4"] = self.probe4.clone().into();
        }
        if self.probe6 != Config::default().probe6 {
            v["probe6"] = self.probe6.clone().into();
        }
        if self.probe_every_ms != Config::default().probe_every_ms {
            v["probe_every_ms"] = self.probe_every_ms.into();
        }
        v
    }

    /// The file, or the defaults when there is none; a broken file is an error (the service then keeps what it had).
    pub fn load(path: &Path) -> Result<Config, String> {
        match std::fs::read_to_string(path) {
            Ok(t) => Config::parse(&t),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    /// Written whole to a new file and renamed over the old one, so the service never reads half a file.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let tmp = path.with_extension("json.new");
        let text = serde_json::to_string_pretty(&self.to_json()).map_err(|e| e.to_string())? + "\n";
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
        }
        std::fs::write(&tmp, text).map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_round_trips_and_unknown_links_get_new_links() {
        let c = Config::parse(
            r#"{"new_links":"backup","links":{"wlan0":{"role":"use"},"usb0":{"role":"use","share":30,"data_cap_mb":2000,"period":"day"}}}"#,
        )
        .unwrap();
        assert_eq!(c.link("wlan0").role, Role::Use);
        assert_eq!(c.link("usb0").share, Some(30));
        assert_eq!(c.link("usb0").period, Period::Day);
        assert_eq!(c.link("eth9").role, Role::Backup);
        assert_eq!(Config::parse(&c.to_json().to_string()).unwrap(), c);
    }

    #[test]
    fn bad_values_are_refused() {
        assert!(Config::parse(r#"{"links":{"wlan0":{"role":"fast"}}}"#).is_err());
        assert!(Config::parse(r#"{"links":{"wlan0":{"share":100}}}"#).is_err());
        assert!(Config::parse(r#"{"links":{"-x y":{}}}"#).is_err());
        assert!(Config::parse("{").is_err());
    }

    #[test]
    fn interface_names() {
        for ok in ["wlan0", "enp0s20f0u1", "usb0", "eth0.5", "wwan0"] {
            assert!(valid_ifname(ok), "{ok}");
        }
        for bad in ["", "-a", "a b", "a/b", "..", "sixteen-letters!", "abcdefghijklmnop"] {
            assert!(!valid_ifname(bad), "{bad}");
        }
    }
}
