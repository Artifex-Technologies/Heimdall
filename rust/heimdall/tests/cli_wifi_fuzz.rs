//! The Wi-Fi commands' fuzz targets (src/cli/wifihealth/fuzzing.rs, src/cli/wifitools/fuzzing.rs) on their seeds and on
//! random input, and properties of the parsers, the judge and Go's sort, so they run in the ordinary test suite too.

use heimdall::cli::wifihealth::{fuzzing as wf, gosort, gostr, judge, parse};
use proptest::prelude::*;

type Target = fn(&[u8]);

fn targets() -> Vec<(&'static str, Target)> {
    let mut v: Vec<(&'static str, Target)> =
        vec![("wifi_link", wf::link), ("wifi_scan", wf::scan), ("wifi_ping", wf::ping), ("wifi_devices", wf::devices)];
    v.extend(heimdall::cli::wifitools::fuzz_targets());
    v
}

#[test]
fn every_wifi_target_survives_its_seeds() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../fuzz/seeds");
    for (name, f) in targets() {
        let d = format!("{dir}/{name}");
        let seeds = std::fs::read_dir(&d).unwrap_or_else(|_| panic!("no seeds in {d}"));
        for s in seeds.flatten() {
            f(&std::fs::read(s.path()).unwrap());
        }
    }
}

fn texty() -> impl Strategy<Value = Vec<u8>> {
    let words = prop::sample::select(vec![
        &b"Connected to x\n"[..],
        b"\tSSID: ",
        b"freq: ",
        b"signal: -",
        b"rx bitrate: ",
        b"tx bitrate: ",
        b" MBit/s ",
        b"80MHz",
        b"tx packets: ",
        b"tx retries: ",
        b"expected throughput: ",
        b"Mbps",
        b"packets transmitted, ",
        b" received, ",
        b"% packet loss",
        b"time=",
        b" ms",
        b"= 1.5/2.5/3.5/0.5 ms",
        b"*:",
        b"\\:",
        b":",
        b" MHz:",
        b"\n",
        b"2412",
        b"5180",
        b"999999999999999999999",
        b".",
        b"\xff",
        b"\xe2\x80",
        b"\"status\":\"scanned\"",
        b"{",
        b"}",
    ]);
    prop::collection::vec(prop_oneof![words.prop_map(|w| w.to_vec()), prop::collection::vec(any::<u8>(), 0..6)], 0..40)
        .prop_map(|parts| parts.concat())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 400, ..ProptestConfig::default() })]

    #[test]
    fn wifi_targets_survive_random_input(data in texty()) {
        for (_, f) in targets() {
            f(&data);
        }
    }

    #[test]
    fn bytes_go_back_as_they_came(data in prop::collection::vec(any::<u8>(), 0..64)) {
        prop_assert_eq!(gostr::encode(&gostr::decode(&data)), data);
    }

    #[test]
    fn go_sort_sorts_and_keeps_every_element(keys in prop::collection::vec(0i64..8, 0..120)) {
        let mut v: Vec<(i64, usize)> = keys.iter().copied().zip(0..).collect();
        gosort::slice(&mut v, |a, b| a.0 > b.0);
        prop_assert!(v.windows(2).all(|w| w[0].0 >= w[1].0));
        let mut idx: Vec<usize> = v.iter().map(|x| x.1).collect();
        idx.sort();
        prop_assert_eq!(idx, (0..keys.len()).collect::<Vec<_>>());
    }

    #[test]
    fn a_judged_report_has_a_verdict_its_findings_justify(sig in -100i64..-20, heard in 0i64..9, loss in 0f64..100.0, med in 0f64..300.0, devices in -1i64..20) {
        let mut r = judge::Report { connected: true, devices_here: devices, ..Default::default() };
        r.link = parse::Link { signal_dbm: sig, channel: 36, band: "5 GHz".into(), width: 80, ..Default::default() };
        r.heard = heard;
        r.router = parse::Ping { ok: loss < 100.0, loss_pct: loss, median_ms: med, sent: 30, ..Default::default() };
        r.internet = r.router.clone();
        r.judge();
        let fs = r.findings.clone().unwrap();
        let worst = fs.iter().map(|f| match f.status.as_str() { "bad" => 2, "warn" => 1, _ => 0 }).max().unwrap();
        prop_assert_eq!(r.verdict.as_str(), ["good", "warn", "bad"][worst]);
        prop_assert!(serde_json::from_str::<serde_json::Value>(&r.to_json().unwrap()).is_ok());
    }
}

/// The Kani harnesses' claims, checked over a range here (Kani is not installed on every computer).
#[test]
fn channels_and_overlaps_exhaustively() {
    for mhz in -10..8000 {
        let (ch, band) = parse::channel(mhz);
        assert_eq!(ch == 0, band.is_empty(), "{mhz}");
    }
    for a in -5..200 {
        for b in -5..200 {
            for w in [20, 40, 80] {
                assert_eq!(parse::overlaps("2.4 GHz", a, w, b), parse::overlaps("2.4 GHz", b, w, a));
            }
        }
    }
}
