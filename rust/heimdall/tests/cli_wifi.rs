//! `heimdalld wifi-health` against the Go code: the parsers, the judge and whole reports from testdata/parity/cli-wifi.json
//! (written by internal/parity/cli_wifi.go), byte for byte; then the Go and the Rust binaries in fake roots with a made-up
//! Wi-Fi (fake iw, ping and nmcli, a dummy interface in a network namespace, a fake Heimdall API and a fake mirror).

mod common;
#[allow(unused_imports)]
use common::*;
use heimdall::cli::wifihealth::{gosort, gostr, judge, parse, run};
use heimdall::gojson::write_f64;
use serde_json::Value;

fn fixture() -> Value {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/parity/cli-wifi.json");
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

/// A text field of a case, with the bytes Go saw when it was not UTF-8.
fn text(c: &Value, name: &str) -> String {
    if let Some(Value::String(b64)) = c.get("raw").and_then(|r| r.get(name)) {
        return gostr::decode(&b64decode(b64));
    }
    c[name].as_str().unwrap_or("").to_string()
}

fn b64decode(s: &str) -> Vec<u8> {
    let val = |c: u8| match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        _ => 63,
    };
    let b: Vec<u8> = s.bytes().filter(|&c| c != b'=').collect();
    let mut out = Vec::new();
    for ch in b.chunks(4) {
        let n = ch.iter().enumerate().fold(0u32, |n, (i, &c)| n | (val(c) as u32) << (18 - 6 * i));
        out.push((n >> 16) as u8);
        if ch.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if ch.len() > 3 {
            out.push(n as u8);
        }
    }
    out
}

fn link_json(l: &parse::Link) -> String {
    let mut o = String::from("{\"ssid\":");
    gostr::json(&mut o, &l.ssid);
    o.push_str(&format!(",\"freq_mhz\":{},\"channel\":{},\"band\":", l.freq_mhz, l.channel));
    gostr::json(&mut o, &l.band);
    o.push_str(&format!(",\"width\":{},\"signal_dbm\":{},\"rx_mbps\":", l.width, l.signal_dbm));
    write_f64(&mut o, l.rx_mbps);
    o.push_str(",\"tx_mbps\":");
    write_f64(&mut o, l.tx_mbps);
    if l.expected_mbps != 0.0 {
        o.push_str(",\"expected_mbps\":");
        write_f64(&mut o, l.expected_mbps);
    }
    o.push_str(&format!(",\"tx_packets\":{},\"tx_retries\":{},\"tx_failed\":{}}}", l.tx_packets, l.tx_retries, l.tx_failed));
    o
}

fn scan_json(v: &[parse::Neighbour]) -> String {
    if v.is_empty() {
        return "null".into();
    }
    let mut o = String::from("[");
    for (i, n) in v.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        o.push_str("{\"ssid\":");
        gostr::json(&mut o, &n.ssid);
        o.push_str(&format!(",\"channel\":{},\"band\":", n.channel));
        gostr::json(&mut o, &n.band);
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
        o.push_str(",\"bssid\":");
        gostr::json(&mut o, &n.bssid);
        o.push('}');
    }
    o.push(']');
    o
}

#[test]
fn parsers_as_go() {
    let f = fixture();
    let mut n = 0;
    for c in f["links"].as_array().unwrap() {
        let l = parse::parse_link(&text(c, "in"));
        assert_eq!(l.is_some(), c["ok"].as_bool().unwrap(), "{c}");
        assert_eq!(link_json(&l.unwrap_or_default()), c["out"].as_str().unwrap(), "{c}");
        n += 1;
    }
    for c in f["scans"].as_array().unwrap() {
        let v = parse::parse_scan(&text(c, "in"), &text(c, "own"));
        assert_eq!(scan_json(&v), c["out"].as_str().unwrap(), "{c}");
        n += 1;
    }
    for c in f["pings"].as_array().unwrap() {
        let p = parse::parse_ping(c["target"].as_str().unwrap(), c["in"].as_str().unwrap());
        let mut o = String::new();
        judge::ping_json(&mut o, &p);
        assert_eq!(o, c["out"].as_str().unwrap(), "{c}");
        n += 1;
    }
    for c in f["channels"].as_array().unwrap() {
        let (ch, band) = parse::channel(c[0].as_i64().unwrap());
        assert_eq!((ch, band.as_str()), (c[1].as_i64().unwrap(), c[2].as_str().unwrap()));
        n += 1;
    }
    for c in f["overlaps"].as_array().unwrap() {
        let got = parse::overlaps(c[0].as_str().unwrap(), c[1].as_i64().unwrap(), c[2].as_i64().unwrap(), c[3].as_i64().unwrap());
        assert_eq!(got, c[4].as_bool().unwrap(), "{c}");
        n += 1;
    }
    for c in f["sorts"].as_array().unwrap() {
        let keys: Vec<i64> = c["keys"].as_array().unwrap().iter().map(|k| k.as_i64().unwrap()).collect();
        let mut v: Vec<(i64, i64)> = keys.iter().enumerate().map(|(i, &k)| (k, i as i64)).collect();
        gosort::slice(&mut v, |a, b| a.0 > b.0);
        let order: Vec<i64> = v.iter().map(|x| x.1).collect();
        let want: Vec<i64> = c["order"].as_array().unwrap().iter().map(|k| k.as_i64().unwrap()).collect();
        assert_eq!(order, want, "keys {keys:?}");
        n += 1;
    }
    assert!(n > 3000, "{n} cases");
}

/// The situation through the Rust code as Run would take it (the mirror of internal/parity's WifiJudge).
fn judge_case(c: &Value) -> judge::Report {
    let mut r = judge::Report {
        time: heimdall::gotime::Time::parse_rfc3339("2026-11-10T20:00:00Z").unwrap(),
        devices_here: c["devices"].as_i64().unwrap(),
        power_save: c["power_save"].as_bool().unwrap(),
        ..Default::default()
    };
    if c["connected"].as_bool().unwrap() {
        r.iface = "wlan0".into();
        if let Some(before) = parse::parse_link(&text(c, "before")) {
            r.connected = true;
            r.router = parse::parse_ping("192.0.2.1", c["router"].as_str().unwrap());
            r.internet = parse::parse_ping("1.1.1.1", c["internet"].as_str().unwrap());
            if let Some(s) = c["speed"].as_object() {
                r.speed = Some(judge::Speed {
                    down_mbps: s["down_mbps"].as_f64().unwrap(),
                    server: s["server"].as_str().unwrap().into(),
                    error: s["error"].as_str().unwrap().into(),
                    loaded: Some(s["loaded"].as_str().unwrap()).filter(|l| !l.is_empty()).map(|l| parse::parse_ping("1.1.1.1", l)),
                });
            }
            let after = parse::parse_link(&text(c, "after")).unwrap_or_else(|| before.clone());
            r.link = after.clone();
            let sent = after.tx_packets.wrapping_sub(before.tx_packets);
            if after.tx_packets >= before.tx_packets && sent >= 300 {
                r.retries_pct = parse::round1(100.0 * after.tx_retries.wrapping_sub(before.tx_retries) as f64 / sent as f64);
                r.retries_span = "check".into();
            } else if after.tx_packets >= 1000 {
                r.retries_pct = parse::round1(100.0 * after.tx_retries as f64 / after.tx_packets as f64);
                r.retries_span = "connection".into();
            }
            r.neighbourhood(&parse::parse_scan(&text(c, "scan"), &after.ssid));
        }
    }
    r.judge();
    r
}

#[test]
fn reports_as_go() {
    let f = fixture();
    let reports = f["reports"].as_array().unwrap();
    for c in reports {
        let r = judge_case(c);
        assert_eq!(r.to_json().unwrap_or_default(), c["json"].as_str().unwrap(), "{c}");
        assert_eq!(gostr::decode(&r.to_text()), text(c, "text"), "{c}");
    }
    assert_eq!(reports.len(), 160);
}

#[test]
fn reports_with_numbers_go_cannot_write_are_left_out() {
    // a gigantic number in ping's output reads as +Inf in Go, whose encoder then writes nothing
    let mut r = judge::Report { connected: true, ..Default::default() };
    r.router = parse::parse_ping(
        "x",
        &format!("1 packets transmitted, 1 received, 0% packet loss\nrtt min/avg/max/mdev = 1/{}/1/1 ms", "9".repeat(400)),
    );
    r.judge();
    assert!(r.to_json().is_none());
}

#[test]
fn device_counts_from_the_api() {
    let ok = r#"{"networks":[{"uuid":"a","ssid":"Home","first_scan":"2026-11-10T19:00:00Z","last_scan":"2026-11-10T20:00:00Z","devices":[{"mac":"02:00:00:00:00:01","ip":"192.0.2.2","kind":"tv","first_seen":"2026-11-10T19:00:00Z","last_seen":"2026-11-10T20:00:00Z"},{"mac":"02:00:00:00:00:02","ip":"192.0.2.3","kind":"phone","first_seen":"2026-11-10T19:00:00Z","last_seen":"2026-11-10T19:58:00Z"},{"mac":"02:00:00:00:00:03","ip":"192.0.2.4","kind":"other","first_seen":"2026-11-10T19:00:00Z","last_seen":"2026-11-10T19:59:30+00:00"}]},{"uuid":"b","devices":[]}],"status":"scanned","status_uuid":"a","status_time":"2026-11-10T20:00:00Z"}"#;
    assert_eq!(run::count_devices(ok.as_bytes()), 2);
    assert_eq!(run::count_devices(format!("{ok} trailing words").as_bytes()), 2, "Go's decoder reads the first value only");
    assert_eq!(run::count_devices(ok.replace("\"scanned\"", "\"offline\"").as_bytes()), -1);
    assert_eq!(run::count_devices(ok.replace("\"status_uuid\":\"a\"", "\"status_uuid\":\"c\"").as_bytes()), -1);
    assert_eq!(run::count_devices(ok.replace("\"kind\":\"tv\"", "\"kind\":5").as_bytes()), -1, "a type error anywhere");
    assert_eq!(run::count_devices(&ok.as_bytes()[..100]), -1);
    assert_eq!(run::count_devices(b""), -1);
}
