//! What the measurements mean (internal/wifihealth/judge.go): the networks sharing our channel, quieter channels, the
//! findings, the verdict and the summary, word for word; and the report written as Go's `json.Encoder` writes it.

use super::gostr::json as js;
use super::parse::{overlaps, Link, Neighbour, Ping};
use crate::gojson::write_f64;
use crate::gotext::fixed;
use crate::gotime::Time;

/// One check's result.
#[derive(Clone, Debug, PartialEq)]
pub struct Finding {
    pub check: String,
    pub status: String,
    pub title: String,
    pub detail: String,
}

/// The optional speed test.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Speed {
    pub down_mbps: f64,
    pub server: String,
    pub loaded: Option<Ping>,
    pub error: String,
}

/// Everything one check measured and what it means.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Report {
    pub time: Time,
    pub iface: String,
    pub connected: bool,
    pub link: Link,
    pub retries_pct: f64,
    pub retries_span: String,
    /// None: Go's nil slice (written as null)
    pub neighbours: Option<Vec<Neighbour>>,
    pub heard: i64,
    pub better: Vec<i64>,
    pub own_5ghz: bool,
    pub from_router: Vec<String>,
    pub router: Ping,
    pub internet: Ping,
    pub devices_here: i64,
    pub power_save: bool,
    pub speed: Option<Speed>,
    pub findings: Option<Vec<Finding>>,
    pub verdict: String,
    pub summary: String,
}

/// NetworkManager's signal above which a neighbour takes airtime from us.
const HEARD_AT: i64 = 40;

fn rank(s: &str) -> i32 {
    match s {
        "warn" => 1,
        "bad" => 2,
        _ => 0,
    }
}

fn candidates(band: &str) -> &'static [i64] {
    match band {
        "2.4 GHz" => &[1, 6, 11],
        "5 GHz" => &[36, 149, 52, 100, 116, 132],
        _ => &[],
    }
}

impl Report {
    /// `Neighbourhood`.
    pub fn neighbourhood(&mut self, all: &[Neighbour]) {
        let l = self.link.clone();
        let mut neighbours: Option<Vec<Neighbour>> = None;
        self.from_router = Vec::new();
        self.heard = 0;
        for n in all {
            if n.same_router {
                if !n.ssid.is_empty() && !self.from_router.contains(&n.ssid) {
                    self.from_router.push(n.ssid.clone());
                }
                continue;
            }
            if n.own && n.band == "5 GHz" && l.band == "2.4 GHz" {
                self.own_5ghz = true;
            }
            if n.own || n.band != l.band || !overlaps(&l.band, l.channel, l.width, n.channel) {
                continue;
            }
            neighbours.get_or_insert_with(Vec::new).push(n.clone());
            if n.signal >= HEARD_AT {
                self.heard += 1;
            }
        }
        if let Some(v) = neighbours.as_mut() {
            super::gosort::slice(v, |a, b| a.signal > b.signal);
        }
        self.neighbours = neighbours;
        let load = |ch: i64| -> i64 {
            all.iter()
                .filter(|n| {
                    !n.own && !n.same_router && n.band == l.band && n.signal >= HEARD_AT && overlaps(&l.band, ch, l.width, n.channel)
                })
                .fold(0i64, |s, n| s.wrapping_add(n.signal))
        };
        let here = load(l.channel);
        let mut cs: Vec<(i64, i64)> = Vec::new();
        for &ch in candidates(&l.band) {
            if overlaps(&l.band, l.channel, l.width, ch) {
                continue;
            }
            let ld = load(ch);
            if ld.wrapping_add(60) < here {
                cs.push((ch, ld));
            }
        }
        cs.sort_by_key(|c| c.1); // stable, as sort.SliceStable
        self.better = cs.iter().take(2).map(|c| c.0).collect();
    }

    /// `Judge`.
    pub fn judge(&mut self) {
        let mut f: Vec<Finding> = Vec::new();
        let add = |f: &mut Vec<Finding>, check: &str, status: &str, title: &str, detail: &str| {
            f.push(Finding { check: check.into(), status: status.into(), title: title.into(), detail: detail.into() })
        };
        if !self.connected {
            add(&mut f, "signal", "bad", "Not connected to Wi-Fi", "Connect to a network first.");
            self.findings = Some(f);
            self.verdict = "bad".into();
            self.summary = "Not connected to Wi-Fi".into();
            return;
        }
        let l = self.link.clone();
        let sig = l.signal_dbm;
        let place = format!("{sig} dBm on {} channel {}", l.band, l.channel);
        if sig >= -60 {
            add(&mut f, "signal", "good", "Strong signal", &format!("{place}."));
        } else if sig >= -67 {
            add(&mut f, "signal", "good", "Good signal", &format!("{place}. Enough for streaming and video calls."));
        } else if sig >= -75 {
            add(
                &mut f,
                "signal",
                "warn",
                "Fair signal",
                &format!("{place}. Speed drops and calls may stutter. Closer to the router, or fewer walls and floors between, helps."),
            );
        } else {
            add(&mut f, "signal", "bad", "Weak signal", &format!("{place}. This alone makes Wi-Fi slow and unreliable. Move closer to the router, or add a mesh point or extender between."));
        }
        if l.band == "2.4 GHz" && self.own_5ghz {
            add(&mut f, "band", "warn", "On 2.4 GHz", "Your network also offers 5 GHz, which is much faster and less crowded at this distance. Forgetting and rejoining, or giving 5 GHz its own network name on the router, moves this computer there.");
        }

        let busy: [i64; 2] = match l.band.as_str() {
            "2.4 GHz" => [3, 6],
            "5 GHz" | "6 GHz" => [2, 4],
            _ => [0, 0],
        };
        let names = || {
            let mut s = Vec::new();
            for (i, n) in self.neighbours.iter().flatten().enumerate() {
                if i == 4 || n.signal < HEARD_AT {
                    break;
                }
                let name = if n.ssid.is_empty() { "a hidden network".to_string() } else { n.ssid.clone() };
                s.push(format!("{name} ({}%)", n.signal));
            }
            s.join(", ")
        };
        let better = if self.better.is_empty() {
            String::new()
        } else {
            let s: Vec<String> = self.better.iter().map(|c| c.to_string()).collect();
            format!(" Channel {} is quieter here; the channel is set on the router.", s.join(" or "))
        };
        if busy[1] > 0 && self.heard >= busy[1] {
            add(
                &mut f,
                "channel",
                "bad",
                "Crowded channel",
                &format!(
                    "{} other networks share channel {} loudly enough to take turns with yours: {}.{better}",
                    self.heard,
                    l.channel,
                    names()
                ),
            );
        } else if busy[0] > 0 && self.heard >= busy[0] {
            add(
                &mut f,
                "channel",
                "warn",
                "Busy channel",
                &format!("{} other networks share channel {}: {}.{better}", self.heard, l.channel, names()),
            );
        } else if self.heard > 0 {
            add(
                &mut f,
                "channel",
                "good",
                "Channel mostly clear",
                &format!("{} other network on channel {}: {}.", self.heard, l.channel, names()),
            );
        } else {
            add(&mut f, "channel", "good", "Channel clear", &format!("No other network is heard on channel {}.", l.channel));
        }
        if !self.from_router.is_empty() {
            let last = f.last_mut().expect("a finding");
            last.detail.push_str(&format!(
                " {} also comes from your own router (a second network on the same radio); it is not counted.",
                self.from_router.join(" and ")
            ));
        }

        if !self.retries_span.is_empty() {
            let span = if self.retries_span == "connection" { "since connecting" } else { "during the check" };
            let p = self.retries_pct;
            if p >= 25.0 {
                add(
                    &mut f,
                    "retries",
                    "bad",
                    "Much resending",
                    &format!(
                        "{}% of what this computer sent had to be sent again {span}: interference, a crowded channel or a weak signal.",
                        fixed(p, 0)
                    ),
                );
            } else if p >= 10.0 {
                add(
                    &mut f,
                    "retries",
                    "warn",
                    "Some resending",
                    &format!("{}% sent again {span}. A little is normal; this much slows things down.", fixed(p, 0)),
                );
            } else {
                add(&mut f, "retries", "good", "Little resending", &format!("{}% sent again {span}.", fixed(p, 1)));
            }
        }

        let rt = self.router.clone();
        let mut router_bad = false;
        if !rt.ok && self.internet.ok {
            add(
                &mut f,
                "router",
                "info",
                "The router does not answer ping",
                "Some routers ignore it; the internet answers, so the link works.",
            );
        } else if !rt.ok {
            add(
                &mut f,
                "router",
                "bad",
                "No answer from the router",
                "The router did not answer at all. Restarting it, or rejoining the network, is the first thing to try.",
            );
            router_bad = true;
        } else if rt.loss_pct >= 5.0 || rt.median_ms >= 40.0 {
            add(
                &mut f,
                "router",
                "bad",
                "Poor link to the router",
                &format!(
                    "{}% lost, typically {} ms (good is a few ms with nothing lost). The problem is between this computer and the router.",
                    fixed(rt.loss_pct, 0),
                    fixed(rt.median_ms, 0)
                ),
            );
            router_bad = true;
        } else if rt.loss_pct >= 2.0 || rt.median_ms >= 15.0 {
            add(
                &mut f,
                "router",
                "warn",
                "Slow link to the router",
                &format!("{}% lost, typically {} ms (good is a few ms).", fixed(rt.loss_pct, 0), fixed(rt.median_ms, 0)),
            );
            router_bad = true;
        } else {
            add(&mut f, "router", "good", "Good link to the router", &format!("Typically {} ms, nothing lost.", fixed(rt.median_ms, 1)));
        }
        if rt.ok && self.power_save && rt.max_ms > 30.0 && rt.max_ms > 5.0 * rt.median_ms {
            add(&mut f, "powersave", "info", "Power saving makes some answers late", &format!("The Wi-Fi adapter naps between the router's beacons, so a few answers took up to {} ms. Downloads do not suffer; online games may feel it as a hitch now and then.", fixed(rt.max_ms, 0)));
        }
        let inet = self.internet.clone();
        let mut beyond = false;
        if !inet.ok {
            add(
                &mut f,
                "internet",
                "bad",
                "No answer from the internet",
                "The internet did not answer. If the router answers, the problem is the router's own connection or the internet provider.",
            );
            beyond = rt.ok;
        } else if inet.loss_pct >= 5.0 || inet.median_ms >= 100.0 {
            add(
                &mut f,
                "internet",
                "bad",
                "Poor internet connection",
                &format!("{}% lost, typically {} ms.", fixed(inet.loss_pct, 0), fixed(inet.median_ms, 0)),
            );
            beyond = !router_bad;
        } else if inet.loss_pct >= 2.0 || inet.median_ms >= 60.0 {
            add(
                &mut f,
                "internet",
                "warn",
                "Slow answers from the internet",
                &format!("{}% lost, typically {} ms.", fixed(inet.loss_pct, 0), fixed(inet.median_ms, 0)),
            );
            beyond = !router_bad;
        } else {
            add(
                &mut f,
                "internet",
                "good",
                "Internet answers quickly",
                &format!("Typically {} ms, nothing lost.", fixed(inet.median_ms, 0)),
            );
        }

        let signal_ok = sig >= -67;
        let quiet = self.heard < busy[0] && self.retries_pct < 10.0;
        let busy_net = router_bad && signal_ok && quiet && rt.ok;
        if busy_net && self.devices_here > 0 {
            add(&mut f, "devices", "warn", "Busy network", &format!("The signal is good and the channel quiet, yet the router answers slowly: other devices are probably using the Wi-Fi heavily (a download, a game update, video). {} devices are on now (Wi-Fi & Network > Devices).", self.devices_here));
        } else if busy_net {
            add(&mut f, "devices", "warn", "Busy network", "The signal is good and the channel quiet, yet the router answers slowly: other devices are probably using the Wi-Fi heavily (a download, a game update, video).");
        } else if self.devices_here > 0 {
            add(
                &mut f,
                "devices",
                "info",
                &format!("{} devices on now", self.devices_here),
                "How many is not a problem by itself; what they are doing is.",
            );
        }

        if let Some(s) = &self.speed {
            if !s.error.is_empty() {
                add(&mut f, "speed", "info", "Speed test did not run", &s.error);
            } else if s.down_mbps < 10.0 {
                add(&mut f, "speed", "warn", &format!("{} Mbps download", fixed(s.down_mbps, 0)), &format!("Slow: video in HD needs about 5-10 Mbps per stream. Measured from {}; a busy server can make it look slower than the line is.", s.server));
            } else {
                add(
                    &mut f,
                    "speed",
                    "good",
                    &format!("{} Mbps download", fixed(s.down_mbps, 0)),
                    &format!(
                        "Measured from {} (the update server this computer uses); a busy server can make it look slower than the line is.",
                        s.server
                    ),
                );
            }
            if let Some(loaded) = &s.loaded {
                if loaded.ok && inet.ok {
                    let rise = loaded.median_ms - inet.median_ms;
                    if rise >= 100.0 {
                        add(&mut f, "bufferbloat", "warn", "Slow answers while the line is full", &format!("Answers took {} ms longer during the download. When one device fills the connection, everything else waits: games lag and calls stutter. Routers with \"smart queue\" (SQM) settings fix this.", fixed(rise, 0)));
                    } else if rise >= 30.0 {
                        add(
                            &mut f,
                            "bufferbloat",
                            "info",
                            "Some delay while the line is full",
                            &format!("Answers took {} ms longer during the download.", fixed(rise, 0)),
                        );
                    }
                }
            }
        }

        let mut verdict = "good";
        for x in &f {
            if rank(&x.status) > rank(verdict) {
                verdict = match x.status.as_str() {
                    "warn" => "warn",
                    _ => "bad",
                };
            }
        }
        self.verdict = verdict.into();
        const ORDER: [&str; 9] = ["signal", "channel", "retries", "devices", "router", "band", "internet", "bufferbloat", "speed"];
        self.summary = "Your Wi-Fi looks healthy".into();
        'outer: for want in ["bad", "warn"] {
            for c in ORDER {
                if let Some(x) = f.iter().find(|x| x.check == c && x.status == want) {
                    self.summary = summary_for(x, beyond);
                    break 'outer;
                }
            }
        }
        self.findings = Some(f);
    }

    /// Every number in the report is finite (Go's encoder refuses NaN and the infinities, and then writes nothing).
    fn finite(&self) -> bool {
        let p = |x: &Ping| [x.loss_pct, x.avg_ms, x.jitter_ms, x.max_ms, x.median_ms].iter().all(|f| f.is_finite());
        let l = &self.link;
        [l.rx_mbps, l.tx_mbps, l.expected_mbps, self.retries_pct].iter().all(|f| f.is_finite())
            && p(&self.router)
            && p(&self.internet)
            && self.speed.as_ref().is_none_or(|s| s.down_mbps.is_finite() && s.loaded.as_ref().is_none_or(p))
    }

    /// `json.NewEncoder(os.Stdout).Encode(r)`: the line, or None where Go's encoder fails (a NaN or infinite number).
    pub fn to_json(&self) -> Option<String> {
        if !self.finite() {
            return None;
        }
        let mut o = String::from("{\"time\":\"");
        o.push_str(&self.time.rfc3339_nano());
        o.push_str("\",\"iface\":");
        js(&mut o, &self.iface);
        o.push_str(",\"connected\":");
        o.push_str(if self.connected { "true" } else { "false" });
        let l = &self.link;
        o.push_str(",\"link\":{\"ssid\":");
        js(&mut o, &l.ssid);
        o.push_str(&format!(",\"freq_mhz\":{},\"channel\":{},\"band\":", l.freq_mhz, l.channel));
        js(&mut o, &l.band);
        o.push_str(&format!(",\"width\":{},\"signal_dbm\":{},\"rx_mbps\":", l.width, l.signal_dbm));
        write_f64(&mut o, l.rx_mbps);
        o.push_str(",\"tx_mbps\":");
        write_f64(&mut o, l.tx_mbps);
        if l.expected_mbps != 0.0 {
            o.push_str(",\"expected_mbps\":");
            write_f64(&mut o, l.expected_mbps);
        }
        o.push_str("},\"retries_pct\":");
        write_f64(&mut o, self.retries_pct);
        o.push_str(",\"retries_span\":");
        js(&mut o, &self.retries_span);
        o.push_str(",\"neighbours\":");
        match &self.neighbours {
            None => o.push_str("null"),
            Some(v) => {
                o.push('[');
                for (i, n) in v.iter().enumerate() {
                    if i > 0 {
                        o.push(',');
                    }
                    o.push_str("{\"ssid\":");
                    js(&mut o, &n.ssid);
                    o.push_str(&format!(",\"channel\":{},\"band\":", n.channel));
                    js(&mut o, &n.band);
                    o.push_str(&format!(",\"signal\":{}", n.signal));
                    if n.in_use {
                        o.push_str(",\"in_use\":true");
                    }
                    if n.own {
                        o.push_str(",\"own\":true");
                    }
                    if n.same_router {
                        o.push_str(",\"same_router\":true");
                    }
                    o.push('}');
                }
                o.push(']');
            }
        }
        o.push_str(&format!(",\"heard\":{}", self.heard));
        if !self.better.is_empty() {
            let s: Vec<String> = self.better.iter().map(|c| c.to_string()).collect();
            o.push_str(&format!(",\"better_channels\":[{}]", s.join(",")));
        }
        o.push_str(&format!(",\"own_5ghz\":{}", self.own_5ghz));
        if !self.from_router.is_empty() {
            o.push_str(",\"from_router\":[");
            for (i, s) in self.from_router.iter().enumerate() {
                if i > 0 {
                    o.push(',');
                }
                js(&mut o, s);
            }
            o.push(']');
        }
        o.push_str(",\"router\":");
        ping_json(&mut o, &self.router);
        o.push_str(",\"internet\":");
        ping_json(&mut o, &self.internet);
        o.push_str(&format!(",\"devices_here\":{},\"power_save\":{}", self.devices_here, self.power_save));
        if let Some(s) = &self.speed {
            o.push_str(",\"speed\":{\"down_mbps\":");
            write_f64(&mut o, s.down_mbps);
            if !s.server.is_empty() {
                o.push_str(",\"server\":");
                js(&mut o, &s.server);
            }
            if let Some(p) = &s.loaded {
                o.push_str(",\"loaded\":");
                ping_json(&mut o, p);
            }
            if !s.error.is_empty() {
                o.push_str(",\"error\":");
                js(&mut o, &s.error);
            }
            o.push('}');
        }
        o.push_str(",\"findings\":");
        match &self.findings {
            None => o.push_str("null"),
            Some(v) => {
                o.push('[');
                for (i, x) in v.iter().enumerate() {
                    if i > 0 {
                        o.push(',');
                    }
                    o.push_str("{\"check\":");
                    js(&mut o, &x.check);
                    o.push_str(",\"status\":");
                    js(&mut o, &x.status);
                    o.push_str(",\"title\":");
                    js(&mut o, &x.title);
                    o.push_str(",\"detail\":");
                    js(&mut o, &x.detail);
                    o.push('}');
                }
                o.push(']');
            }
        }
        o.push_str(",\"verdict\":");
        js(&mut o, &self.verdict);
        o.push_str(",\"summary\":");
        js(&mut o, &self.summary);
        o.push_str("}\n");
        Some(o)
    }

    /// The text cmd/heimdalld/wifihealth.go prints, as bytes (a name that is not UTF-8 is written as it came).
    pub fn to_text(&self) -> Vec<u8> {
        let mut o = String::new();
        o.push_str(&self.summary);
        o.push('\n');
        if self.connected {
            let l = &self.link;
            o.push_str(&format!(
                "{}, {} channel {} ({} MHz), {} dBm, {}/{} Mbps\n",
                l.ssid,
                l.band,
                l.channel,
                l.width,
                l.signal_dbm,
                fixed(l.rx_mbps, 0),
                fixed(l.tx_mbps, 0)
            ));
        }
        for x in self.findings.iter().flatten() {
            let mark = match x.status.as_str() {
                "good" => "ok  ",
                "info" => "    ",
                "warn" => "WARN",
                "bad" => "BAD ",
                _ => "",
            };
            o.push_str(&format!("  {mark} {}", x.title));
            if !x.detail.is_empty() {
                o.push_str(&format!(": {}", x.detail));
            }
            o.push('\n');
        }
        super::gostr::encode(&o)
    }
}

/// A Ping as Go's encoder writes it.
pub fn ping_json(o: &mut String, p: &Ping) {
    o.push_str("{\"target\":");
    js(o, &p.target);
    o.push_str(&format!(",\"sent\":{},\"loss_pct\":", p.sent));
    write_f64(o, p.loss_pct);
    o.push_str(",\"avg_ms\":");
    write_f64(o, p.avg_ms);
    o.push_str(",\"jitter_ms\":");
    write_f64(o, p.jitter_ms);
    o.push_str(",\"max_ms\":");
    write_f64(o, p.max_ms);
    o.push_str(",\"median_ms\":");
    write_f64(o, p.median_ms);
    o.push_str(&format!(",\"ok\":{}}}", p.ok));
}

fn summary_for(f: &Finding, beyond: bool) -> String {
    match f.check.as_str() {
        "signal" => "A weak signal is the likely cause".into(),
        "channel" | "retries" => "A crowded channel is the likely cause".into(),
        "devices" => "Other devices using the network are the likely cause".into(),
        "router" => "The link to the router is the problem".into(),
        "internet" if beyond => {
            "Your Wi-Fi is fine; the problem is past the router (the internet provider or the router's connection)".into()
        }
        "internet" => "The internet connection is slow".into(),
        "band" => "Faster on 5 GHz".into(),
        _ => f.title.clone(),
    }
}
