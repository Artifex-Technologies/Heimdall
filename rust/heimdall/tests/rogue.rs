//! The rogue-router watch replays the Go watcher's scenarios (testdata/netsource/rogue-router.json, written by
//! `go test ./internal/sources/netsource -run Rogue -update`): the same alerts, field for field, at every step.

use heimdall::sources::rogue::{hex_ipv6, RogueSource};
use std::collections::BTreeMap;
use std::io::Write;

#[test]
fn rogue_router_scenarios_match_go() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/netsource/rogue-router.json");
    let fixture: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let mut steps_run = 0;
    for (n, sc) in fixture.as_array().unwrap().iter().enumerate() {
        let dir = std::env::temp_dir().join(format!("heimdall-rogue-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("proc/net")).unwrap();
        let p = |s: &str| dir.join(s).to_string_lossy().into_owned();
        let mut w = RogueSource::new(&p("netid.jsonl"), &p("current.json"), &p("routers.json"), &p("proc"));
        w.trusted = p("wifi-trusted.json");
        w.sys_root = p("sys");
        for (i, st) in sc["steps"].as_array().unwrap().iter().enumerate() {
            // a phone's USB link: its driver ipheth, as Go's runRogue lays it out
            for iface in st["phone_usb"].as_array().into_iter().flatten() {
                let iface = iface.as_str().unwrap();
                std::fs::create_dir_all(dir.join("sys/bus/usb/drivers/ipheth")).unwrap();
                std::fs::create_dir_all(dir.join(format!("sys/class/net/{iface}/device"))).unwrap();
                let _ = std::os::unix::fs::symlink(
                    dir.join("sys/bus/usb/drivers/ipheth"),
                    dir.join(format!("sys/class/net/{iface}/device/driver")),
                );
            }
            if let Some(lines) = st["netid"].as_array() {
                let mut f = std::fs::OpenOptions::new().append(true).create(true).open(p("netid.jsonl")).unwrap();
                for l in lines {
                    writeln!(f, "{}", l.as_str().unwrap()).unwrap();
                }
            }
            let _ = std::fs::remove_file(p("current.json"));
            if let Some(c) = st["current"].as_str() {
                std::fs::write(p("current.json"), c).unwrap();
            }
            std::fs::write(p("proc/net/ipv6_route"), st["ipv6_route"].as_str().unwrap_or("")).unwrap();
            std::fs::write(
                p("proc/net/arp"),
                format!(
                    "IP address       HW type     Flags       HW address            Mask     Device\n{}",
                    st["arp"].as_str().unwrap_or("")
                ),
            )
            .unwrap();
            let _ = std::fs::remove_file(p("wifi-trusted.json"));
            if let Some(t) = st["trusted"].as_str() {
                std::fs::write(p("wifi-trusted.json"), t).unwrap();
            }
            let got: Vec<BTreeMap<String, String>> = w
                .poll_at(st["now"].as_i64().unwrap())
                .into_iter()
                .map(|e| {
                    let mut m: BTreeMap<String, String> = e.fields.into_iter().collect();
                    m.insert("kind".into(), e.kind);
                    m.insert("text".into(), e.text);
                    m
                })
                .collect();
            let want: Vec<BTreeMap<String, String>> = serde_json::from_value(st["want"].clone()).unwrap_or_default();
            assert_eq!(got, want, "{}, step {i}", sc["name"]);
            steps_run += 1;
        }
        if let Ok(m) = std::fs::metadata(p("routers.json")) {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(m.permissions().mode() & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
    assert!(steps_run > 10);
}

#[test]
fn hex_ipv6_short_form() {
    for (i, w) in [
        ("fe800000000000000000000000000001", "fe80::1"),
        ("20010db8000100000000000000000000", "2001:db8:1::"),
        ("00000000000000000000000000000000", "::"),
        ("20010db8000000010000000000000001", "2001:db8:0:1::1"),
        ("20010db8000000000001000000000001", "2001:db8::1:0:0:1"),
    ] {
        assert_eq!(hex_ipv6(i), w);
    }
}
