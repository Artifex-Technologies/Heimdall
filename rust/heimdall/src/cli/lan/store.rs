//! The device list's files (Go: internal/lan/lan.go): devices.json (read as Go's json.Unmarshal reads it, written as
//! json.MarshalIndent with one space, through a .tmp file and a rename), events.jsonl (one line per new device), the merge of
//! one scan into a network's list, and the guess of what a device is.

use crate::gostruct::{self, Field, Ty, Val};
use crate::gotime::Time;

/// One device on a network, keyed by its hardware address.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Device {
    pub mac: String,
    pub ip: String,
    pub name: String,
    pub names: Vec<String>,
    pub vendor: String,
    pub model: String,
    pub kind: String,
    pub services: Vec<String>,
    pub private_mac: bool,
    pub first_seen: Time,
    pub last_seen: Time,
}

/// One trusted network's devices. `devices` None is Go's nil slice (written as null).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Network {
    pub uuid: String,
    pub ssid: String,
    pub first_scan: Time,
    pub last_scan: Time,
    pub devices: Option<Vec<Device>>,
}

/// The whole file. `networks` None is Go's nil slice.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Store {
    pub networks: Option<Vec<Network>>,
    pub status: String,
    pub status_uuid: String,
    pub status_time: Time,
}

/// One network's list is bounded; the devices seen longest ago go first.
pub const MAX_DEVICES: usize = 512;

static STRS: Ty = Ty::Slice(&Ty::Str);
pub static DEVICE: Ty = Ty::Struct(
    "lan.Device",
    &[
        Field("mac", &Ty::Str, false),
        Field("ip", &Ty::Str, false),
        Field("name", &Ty::Str, true),
        Field("names", &STRS, true),
        Field("vendor", &Ty::Str, true),
        Field("model", &Ty::Str, true),
        Field("kind", &Ty::Str, false),
        Field("services", &STRS, true),
        Field("private_mac", &Ty::Bool, true),
        Field("first_seen", &Ty::Time, false),
        Field("last_seen", &Ty::Time, false),
    ],
);
pub static NETWORK: Ty = Ty::Struct(
    "lan.Network",
    &[
        Field("uuid", &Ty::Str, false),
        Field("ssid", &Ty::Str, false),
        Field("first_scan", &Ty::Time, false),
        Field("last_scan", &Ty::Time, false),
        Field("devices", &Ty::Slice(&DEVICE), false),
    ],
);
pub static STORE: Ty = Ty::Struct(
    "lan.Store",
    &[
        Field("networks", &Ty::Slice(&NETWORK), false),
        Field("status", &Ty::Str, false),
        Field("status_uuid", &Ty::Str, true),
        Field("status_time", &Ty::Time, false),
    ],
);
/// A line of events.jsonl (Go: lan.NewDevice).
pub static NEW_DEVICE: Ty =
    Ty::Struct("lan.NewDevice", &[Field("time", &Ty::Time, false), Field("ssid", &Ty::Str, false), Field("device", &DEVICE, false)]);

fn s(v: &Val) -> String {
    match v {
        Val::Str(s) => s.clone(),
        Val::Bytes(b) => crate::gotext::lossy(b),
        _ => String::new(),
    }
}
fn t(v: &Val) -> Time {
    match v {
        Val::Time(t) => *t,
        _ => Time::default(),
    }
}
fn strs(v: &Val) -> Vec<String> {
    match v {
        Val::Slice(Some(x)) => x.iter().map(s).collect(),
        _ => Vec::new(),
    }
}
fn fields(v: &Val) -> &[Val] {
    match v {
        Val::Struct(f) => f,
        _ => &[],
    }
}
fn strs_val(x: &[String]) -> Val {
    // omitempty: an empty list is never written, so nil and empty are alike
    if x.is_empty() {
        Val::Slice(None)
    } else {
        Val::Slice(Some(x.iter().map(|y| Val::Str(y.clone())).collect()))
    }
}

impl Device {
    fn from_val(v: &Val) -> Device {
        let f = fields(v);
        Device {
            mac: s(&f[0]),
            ip: s(&f[1]),
            name: s(&f[2]),
            names: strs(&f[3]),
            vendor: s(&f[4]),
            model: s(&f[5]),
            kind: s(&f[6]),
            services: strs(&f[7]),
            private_mac: matches!(f[8], Val::Bool(true)),
            first_seen: t(&f[9]),
            last_seen: t(&f[10]),
        }
    }
    pub fn to_val(&self) -> Val {
        Val::Struct(vec![
            Val::Str(self.mac.clone()),
            Val::Str(self.ip.clone()),
            Val::Str(self.name.clone()),
            strs_val(&self.names),
            Val::Str(self.vendor.clone()),
            Val::Str(self.model.clone()),
            Val::Str(self.kind.clone()),
            strs_val(&self.services),
            Val::Bool(self.private_mac),
            Val::Time(self.first_seen),
            Val::Time(self.last_seen),
        ])
    }
}

impl Network {
    fn from_val(v: &Val) -> Network {
        let f = fields(v);
        Network {
            uuid: s(&f[0]),
            ssid: s(&f[1]),
            first_scan: t(&f[2]),
            last_scan: t(&f[3]),
            devices: match &f[4] {
                Val::Slice(Some(d)) => Some(d.iter().map(Device::from_val).collect()),
                _ => None,
            },
        }
    }
    fn to_val(&self) -> Val {
        Val::Struct(vec![
            Val::Str(self.uuid.clone()),
            Val::Str(self.ssid.clone()),
            Val::Time(self.first_scan),
            Val::Time(self.last_scan),
            Val::Slice(self.devices.as_ref().map(|d| d.iter().map(Device::to_val).collect())),
        ])
    }

    /// Records the devices one scan saw and returns those that are new. The first scan of a network only learns: every device
    /// already there is the owner's own or was there before Heimdall looked.
    pub fn merge(&mut self, seen: Vec<Device>, now: Time) -> Vec<Device> {
        let first = self.first_scan.is_zero();
        if first {
            self.first_scan = now;
        }
        self.last_scan = now;
        let was_nil = self.devices.is_none();
        let devices = self.devices.get_or_insert_with(Vec::new);
        let mut index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for (i, d) in devices.iter().enumerate() {
            index.insert(d.mac.clone(), i);
        }
        let mut fresh = Vec::new();
        let mut appended = false;
        for mut d in seen {
            d.last_seen = now;
            if let Some(&i) = index.get(&d.mac) {
                let old = &devices[i];
                d.first_seen = old.first_seen;
                // a scan that missed an announcement keeps what earlier scans found
                if d.name.is_empty() {
                    d.name = old.name.clone();
                    d.names = old.names.clone();
                }
                if d.vendor.is_empty() {
                    d.vendor = old.vendor.clone();
                }
                if d.model.is_empty() {
                    d.model = old.model.clone();
                }
                if d.services.is_empty() {
                    d.services = old.services.clone();
                }
                if (d.kind == "other" || d.kind == "private") && old.kind != "other" && old.kind != "private" && !old.kind.is_empty() {
                    d.kind = old.kind.clone();
                }
                devices[i] = d;
                continue;
            }
            d.first_seen = now;
            devices.push(d.clone());
            appended = true;
            index.insert(d.mac.clone(), devices.len() - 1);
            if !first && d.kind != "this" {
                fresh.push(d);
            }
        }
        if was_nil && !appended {
            self.devices = None; // Go appended nothing to a nil slice: it stays nil
            return fresh;
        }
        let devices = self.devices.as_mut().expect("set above");
        devices.sort_by_key(|d| std::cmp::Reverse(d.last_seen)); // stable, newest first
        devices.truncate(MAX_DEVICES);
        fresh
    }
}

impl Store {
    pub fn from_val(v: &Val) -> Store {
        let f = fields(v);
        Store {
            networks: match &f[0] {
                Val::Slice(Some(n)) => Some(n.iter().map(Network::from_val).collect()),
                _ => None,
            },
            status: s(&f[1]),
            status_uuid: s(&f[2]),
            status_time: t(&f[3]),
        }
    }
    pub fn to_val(&self) -> Val {
        Val::Struct(vec![
            Val::Slice(self.networks.as_ref().map(|n| n.iter().map(Network::to_val).collect())),
            Val::Str(self.status.clone()),
            Val::Str(self.status_uuid.clone()),
            Val::Time(self.status_time),
        ])
    }

    /// The network with this connection, made when missing; a non-empty SSID given renames it.
    pub fn network(&mut self, uuid: &str, ssid: &str) -> &mut Network {
        let nets = self.networks.get_or_insert_with(Vec::new);
        if let Some(i) = nets.iter().position(|n| n.uuid == uuid) {
            if !ssid.is_empty() {
                nets[i].ssid = ssid.to_string();
            }
            return &mut nets[i];
        }
        nets.push(Network { uuid: uuid.to_string(), ssid: ssid.to_string(), ..Network::default() });
        nets.last_mut().expect("pushed")
    }

    /// The file as Go writes it (json.MarshalIndent, one space), or Go's error when a time cannot be written.
    pub fn marshal(&self) -> Result<String, String> {
        gostruct::to_json_indented(&STORE, &self.to_val(), " ")
            .ok_or_else(|| "json: error calling MarshalJSON for type time.Time: Time.MarshalJSON: year outside of range [0,9999]".into())
    }

    /// Writes the store whole: a .tmp file (0640) and a rename, so a reader never sees half a file.
    pub fn save(&self, path: &str) -> Result<(), String> {
        let b = self.marshal()?;
        let tmp = format!("{path}.tmp");
        crate::gopath::write_file(&tmp, b.as_bytes(), 0o640)?;
        crate::gopath::rename(&tmp, path)
    }
}

/// Go's lan.Load: a missing file is an empty store; the error otherwise is Go's text. Like Go, a store that read only in part
/// comes back with the error.
pub fn load(path: &str) -> (Store, Option<String>) {
    match std::fs::read(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (Store::default(), None),
        Err(e) => (Store::default(), Some(crate::gopath::read_err(path, &e))),
        Ok(b) => {
            let (v, err) = gostruct::unmarshal(&STORE, &b);
            (Store::from_val(&v), err.map(|e| go_char_names(&e.0)))
        }
    }
}

/// The JSON reader names a byte it did not expect as Go's quoteChar does: `'\x01'`, `' '`, `'\''`, `'\\'`, `'\xff'` (gojson
/// writes "byte 0x01" for those that are not printable ASCII and does not escape the quote and the backslash).
fn go_char_names(msg: &str) -> String {
    const LEAD: &str = "invalid character ";
    let Some(i) = msg.find(LEAD) else { return msg.to_string() };
    let rest = &msg[i + LEAD.len()..];
    let (named, tail) = if let Some(h) = rest.strip_prefix("byte 0x") {
        let Ok(c) = u8::from_str_radix(&h[..2.min(h.len())], 16) else { return msg.to_string() };
        let q = match c {
            0x07 => "\\a".to_string(),
            0x08 => "\\b".to_string(),
            0x09 => "\\t".to_string(),
            0x0a => "\\n".to_string(),
            0x0b => "\\v".to_string(),
            0x0c => "\\f".to_string(),
            0x0d => "\\r".to_string(),
            0x20 => " ".to_string(),
            c => format!("\\x{c:02x}"),
        };
        (format!("'{q}'"), &h[2..])
    } else if let Some(t) = rest.strip_prefix("'''") {
        ("'\\''".to_string(), t)
    } else if let Some(t) = rest.strip_prefix("'\\'") {
        ("'\\\\'".to_string(), t)
    } else {
        return msg.to_string();
    };
    format!("{}{LEAD}{named}{tail}", &msg[..i])
}

/// Adds one line per new device to events.jsonl (which heimdalld follows).
pub fn append_events(path: &str, ssid: &str, devs: &[Device], now: Time) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if devs.is_empty() {
        return Ok(());
    }
    let mut f =
        std::fs::OpenOptions::new().create(true).append(true).mode(0o640).open(path).map_err(|e| crate::goerr::path("open", path, &e))?;
    for d in devs {
        let v = Val::Struct(vec![Val::Time(now), Val::Str(ssid.to_string()), d.to_val()]);
        let mut line = gostruct::to_json(&NEW_DEVICE, &v).unwrap_or_default();
        line.push('\n');
        f.write_all(line.as_bytes()).map_err(|e| crate::goerr::path("write", path, &e))?;
    }
    Ok(())
}

/// A list of devices from Go's JSON (`[]lan.Device`; null is an empty list).
pub fn devices_from_json(b: &[u8]) -> Vec<Device> {
    static DEVICES: Ty = Ty::Slice(&DEVICE);
    match gostruct::unmarshal(&DEVICES, b).0 {
        Val::Slice(Some(d)) => d.iter().map(Device::from_val).collect(),
        _ => Vec::new(),
    }
}

/// Go's `json.Marshal` of a `[]lan.Device` (an empty list is Go's nil slice: null).
pub fn devices_to_json(d: &[Device]) -> String {
    static DEVICES: Ty = Ty::Slice(&DEVICE);
    let v = if d.is_empty() { Val::Slice(None) } else { Val::Slice(Some(d.iter().map(Device::to_val).collect())) };
    gostruct::to_json(&DEVICES, &v).unwrap_or_default()
}

impl Network {
    /// A network from Go's JSON.
    pub fn from_json(b: &[u8]) -> Network {
        Network::from_val(&gostruct::unmarshal(&NETWORK, b).0)
    }
    /// Go's `json.MarshalIndent(n, "", " ")`.
    pub fn marshal_indent(&self) -> String {
        gostruct::to_json_indented(&NETWORK, &self.to_val(), " ").unwrap_or_default()
    }
}

/// What a device is, guessed from what it offers and who made it (Settings shows it as an icon and a word).
pub fn kind_of(d: &Device) -> &'static str {
    let has = |t: &[&str]| d.services.iter().any(|s| t.contains(&s.as_str()));
    let text = crate::gotext::to_lower(&format!("{} {} {}", d.name, d.model, d.vendor));
    let c = |x: &str| text.contains(x);
    let tv_maker = ["samsung", "lg electronics", "sony", "tcl", "vizio", "roku", "hisense", "amazon", "nvidia", "philips", "sharp"]
        .iter()
        .any(|m| c(m));
    if has(&["_ipp._tcp", "_printer._tcp", "_ipps._tcp", "_pdl-datastream._tcp"]) {
        return "printer";
    }
    if has(&["_googlecast._tcp", "_amzn-wplay._tcp", "_androidtvremote2._tcp"])
        || c(" tv")
        || text.starts_with("tv")
        || c("fire tv")
        || c("roku")
        || (has(&["_airplay._tcp"]) && tv_maker)
    {
        if has(&["_googlecast._tcp"]) && c("speaker") || c("nest audio") || c("home mini") {
            return "speaker";
        }
        return "tv";
    }
    if has(&["_sonos._tcp", "_spotify-connect._tcp", "_raop._tcp"]) && !has(&["_workstation._tcp", "_companion-link._tcp", "_smb._tcp"]) {
        return "speaker";
    }
    if c("iphone") || c("ipad") || c("android") || c("galaxy") || c("pixel") {
        return "phone";
    }
    if has(&["_workstation._tcp", "_smb._tcp", "_ssh._tcp", "_companion-link._tcp"]) || c("macbook") || c("desktop") || c("laptop") {
        return "computer";
    }
    if c("xbox") || c("playstation") || c("nintendo") {
        return "console";
    }
    if c("espressif")
        || c("tuya")
        || c("shelly")
        || c("wyze")
        || c("ring")
        || c("ecobee")
        || c("nest labs")
        || c("signify")
        || has(&["_hap._tcp", "_matter._tcp"])
    {
        return "smart"; // smart-home gadgets: plugs, bulbs, clocks, cameras, thermostats
    }
    if d.private_mac {
        return "private"; // a made-up address: almost always a phone, tablet or laptop
    }
    "other"
}
