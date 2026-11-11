//! The fuzz targets' bodies for wifi-health's parsers (rust/fuzz/fuzz_targets/wifi_*.rs; run on seeds and random input by
//! tests/cli_wifi_fuzz.rs), and the Kani harnesses.

use super::{gostr, judge, parse, run};

/// iw's link and station text: parsed, then judged; the report Go could write is valid JSON.
pub fn link(data: &[u8]) {
    let text = gostr::decode(data);
    if let Some(l) = parse::parse_link(&text) {
        let (ch, band) = parse::channel(l.freq_mhz);
        assert_eq!((ch, band), (l.channel, l.band.clone()));
        assert!(l.width != 0);
        let mut r = judge::Report { connected: true, link: l, ..Default::default() };
        r.judge();
        if let Some(j) = r.to_json() {
            assert!(crate::gojson::parse(j.trim_end().as_bytes()).is_ok());
        }
    }
}

/// NetworkManager's scan list, our own network named by the first line.
pub fn scan(data: &[u8]) {
    let text = gostr::decode(data);
    let (own, list) = text.split_once('\n').unwrap_or(("", &text));
    let all = parse::parse_scan(list, own);
    for n in &all {
        assert!(n.channel != 0 && !n.band.is_empty());
    }
    let mut r = judge::Report { connected: true, ..Default::default() };
    r.link.channel = all.first().map(|n| n.channel).unwrap_or(6);
    r.link.band = all.first().map(|n| n.band.clone()).unwrap_or_default();
    r.link.width = 80;
    r.neighbourhood(&all);
    r.judge();
    assert!(r.better.len() <= 2);
}

/// ping's output.
pub fn ping(data: &[u8]) {
    let p = parse::parse_ping("192.0.2.1", &gostr::decode(data));
    assert!(p.sent != 0 || p.loss_pct == 100.0);
}

/// The API's device list.
pub fn devices(data: &[u8]) {
    assert!(run::count_devices(data) >= -1);
}

#[cfg(kani)]
mod proofs {
    use super::parse;

    /// Every frequency has a channel and a band together, or neither.
    #[kani::proof]
    fn channel_and_band_go_together() {
        let mhz: i64 = kani::any();
        let (ch, band) = parse::channel(mhz);
        assert_eq!(ch == 0, band.is_empty());
    }

    /// On 2.4 GHz, sharing airtime is symmetric.
    #[kani::proof]
    fn overlap_is_symmetric_on_2_4() {
        let (a, b, w): (i64, i64, i64) = (kani::any(), kani::any(), kani::any());
        kani::assume(a.abs() < 1 << 40 && b.abs() < 1 << 40);
        assert_eq!(parse::overlaps("2.4 GHz", a, w, b), parse::overlaps("2.4 GHz", b, w, a));
    }
}
