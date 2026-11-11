//! `heimdalld lan` against the Go heimdalld: the pure parts on the shared fixture (testdata/parity/cli-lan.json, written by
//! internal/lan's TestRustFixture), the commands in fake roots, and a whole scan in network namespaces with made-up devices
//! answering (documentation addresses, documentation and locally administered hardware addresses), every packet each binary
//! sent compared.

mod common;
#[allow(unused_imports)]
use common::*;
use heimdall::cli::lan::{discover, dns, oui, resolver, scan, store, text};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn fixture() -> Value {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/parity/cli-lan.json");
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}
fn arr<'a>(f: &'a Value, k: &str) -> &'a Vec<Value> {
    f[k].as_array().unwrap_or_else(|| panic!("{k}"))
}
fn st(v: &Value) -> &str {
    v.as_str().unwrap_or_default()
}

#[test]
fn the_dns_codec_reads_what_go_reads() {
    let f = fixture();
    let mut n = 0;
    for c in arr(&f, "messages") {
        let m = unhex(st(&c["m"]));
        let (recs, err) = dns::parse(&m);
        let got: Vec<Value> = recs
            .iter()
            .map(|r| {
                serde_json::json!({"name": hex(&r.name), "type": r.rtype, "ptr": hex(&r.ptr), "ip": hex(r.ip.as_deref().unwrap_or_default()),
                    "txt": r.txt.iter().map(|t| hex(t)).collect::<Vec<_>>(), "port": r.port})
            })
            .collect();
        assert_eq!(Value::Array(got), c["recs"], "{}", st(&c["m"]));
        assert_eq!(err.map(|e| e.to_string()).unwrap_or_default(), st(&c["err"]), "{}", st(&c["m"]));
        n += 1;
    }
    for c in arr(&f, "names") {
        let m = unhex(st(&c["M"]));
        let off = c["Off"].as_u64().unwrap() as usize;
        let (name, end, err) = match dns::read_name(&m, off) {
            Ok((n, e)) => (n, e, String::new()),
            Err(e) => (Vec::new(), 0, e.to_string()),
        };
        assert_eq!((hex(&name), end as u64, err.as_str()), (st(&c["Name"]).to_string(), c["End"].as_u64().unwrap(), st(&c["Err"])));
        n += 1;
    }
    for c in arr(&f, "queries") {
        let names: Vec<&str> = c["names"].as_array().unwrap().iter().map(st).collect();
        assert_eq!(hex(&dns::query(&names)), st(&c["q"]));
        n += 1;
    }
    assert!(n > 900, "{n} cases");
}

#[test]
fn discovery_learns_what_go_learns() {
    let f = fixture();
    for c in arr(&f, "absorb") {
        let (mut found, mut types) = (BTreeMap::new(), BTreeSet::new());
        for a in c["answers"].as_array().unwrap() {
            let (recs, _) = dns::parse(&unhex(st(&a["m"])));
            if let Ok(ip) = st(&a["from"]).parse::<std::net::Ipv4Addr>() {
                discover::absorb(&mut found, &mut types, ip, &recs);
            }
        }
        let got: BTreeMap<String, Value> = found
            .iter()
            .map(|(ip, x)| {
                (ip.clone(), serde_json::json!({"names": x.names, "model": x.model, "services": x.services.iter().collect::<Vec<_>>()}))
            })
            .collect();
        assert_eq!(serde_json::to_value(got).unwrap(), c["found"], "{c}");
        assert_eq!(serde_json::to_value(&types).unwrap(), c["types"]);
    }
    for c in arr(&f, "service_type") {
        assert_eq!(discover::service_type(st(&c["In"])), st(&c["Out"]));
    }
    for c in arr(&f, "instance") {
        let got = discover::instance_name(&unhex(st(&c["Full"])), st(&c["Typ"]));
        if c["Panic"].as_bool().unwrap() {
            assert_eq!(got, None, "Go panics here; Rust leaves the name out");
        } else {
            assert_eq!(got.map(|g| hex(&g)), Some(st(&c["Out"]).to_string()), "{c}");
        }
    }
    for c in arr(&f, "clean") {
        assert_eq!(text::clean(&unhex(st(&c["In"]))), st(&c["Out"]));
    }
    for c in arr(&f, "generated") {
        assert_eq!(discover::looks_generated(st(&c["N"]), st(&c["IP"])), c["Out"].as_bool().unwrap(), "{c}");
    }
    for c in arr(&f, "id") {
        assert_eq!(discover::looks_id(st(&c["N"])), c["Out"].as_bool().unwrap(), "{c}");
    }
    for c in arr(&f, "nbname") {
        assert_eq!(discover::nb_name(&unhex(st(&c["In"]))), st(&c["Out"]));
    }
    for c in arr(&f, "fold") {
        assert_eq!(text::equal_fold(st(&c["A"]), st(&c["B"])), c["Out"].as_bool().unwrap(), "{c}");
    }
}

#[test]
fn the_list_and_its_files_as_go_keeps_them() {
    let f = fixture();
    for c in arr(&f, "kind") {
        let d = &store::devices_from_json(format!("[{}]", c["device"]).as_bytes())[0];
        assert_eq!(store::kind_of(d), st(&c["out"]), "{c}");
    }
    for c in arr(&f, "merge") {
        let mut n = store::Network::from_json(c["network"].to_string().as_bytes());
        let seen = store::devices_from_json(c["seen"].to_string().as_bytes());
        let now = heimdall::gotime::Time::parse_rfc3339(st(&c["now"])).unwrap();
        let fresh = n.merge(seen, now);
        assert_eq!(n.marshal_indent(), st(&c["after"]), "{c}");
        assert_eq!(store::devices_to_json(&fresh), st(&c["fresh"]), "{c}");
    }
    let dir = std::env::temp_dir().join(format!("heimdall-cli-lan-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("devices.json").to_string_lossy().into_owned();
    for c in arr(&f, "store") {
        std::fs::write(&p, unhex(st(&c["In"]))).unwrap();
        let (s, err) = store::load(&p);
        let (err, want) = (err.unwrap_or_default(), st(&c["Err"]));
        if want.starts_with("parsing time ") {
            // a time Go cannot read: Go also names the element of its layout where reading stopped; the port says the
            // same up to there (both commands fail with it, exit 1)
            let head = &want[..want.find(" as ").unwrap()];
            assert!(err.starts_with(head), "{err} / {want}");
        } else {
            assert_eq!(err, want, "{c}");
        }
        assert_eq!(s.marshal().unwrap(), st(&c["Out"]), "{c}");
    }
    for c in arr(&f, "trusted") {
        let got: BTreeMap<String, Value> = scan::parse_trusted(st(&c["in"]).as_bytes())
            .into_iter()
            .map(|(k, t)| (k, serde_json::json!({"ssid": t.ssid, "routers": if t.routers.is_empty() { Value::Null } else { serde_json::json!(t.routers) }})))
            .collect();
        // Go writes a nil list of routers as null and an empty one as []; both are "no routers" to the scan
        let empty = serde_json::Map::new(); // Go's nil map (from "null") is no networks too
        let want: BTreeMap<String, Value> = c["out"]
            .as_object()
            .unwrap_or(&empty)
            .iter()
            .map(|(k, v)| {
                let r = if v["routers"].as_array().is_some_and(|a| a.is_empty()) { Value::Null } else { v["routers"].clone() };
                (k.clone(), serde_json::json!({"ssid": v["ssid"], "routers": r}))
            })
            .collect();
        assert_eq!(got, want, "{c}");
    }
    for c in arr(&f, "nmcli") {
        assert_eq!(scan::parse_nmcli(st(&c["Out"]), st(&c["Iface"])), (st(&c["UUID"]).to_string(), st(&c["Name"]).to_string()));
    }
    let proc = dir.to_string_lossy().into_owned();
    std::fs::create_dir_all(dir.join("net")).unwrap();
    for c in arr(&f, "route") {
        std::fs::write(dir.join("net/route"), st(&c["Text"])).unwrap();
        let got = scan::default_route(&proc).map(|(i, g)| (i, g.to_string())).unwrap_or_default();
        assert_eq!(got, (st(&c["Iface"]).to_string(), st(&c["GW"]).to_string()), "{c}");
    }
    for c in arr(&f, "arp") {
        std::fs::write(dir.join("net/arp"), st(&c["Text"])).unwrap();
        let got = scan::arp_table(&proc, st(&c["Iface"]));
        let want: BTreeMap<String, String> = serde_json::from_value(c["Out"].clone()).unwrap();
        assert_eq!(got, want, "{c}");
    }
    for c in arr(&f, "oui") {
        std::fs::write(dir.join("oui.txt"), st(&c["text"])).unwrap();
        let macs: Vec<String> = c["macs"].as_array().unwrap().iter().map(|m| st(m).to_string()).collect();
        let got = oui::vendors(&dir.join("oui.txt").to_string_lossy(), &macs);
        let want: BTreeMap<String, String> = serde_json::from_value(c["out"].clone()).unwrap();
        assert_eq!(got, want);
    }
    for c in arr(&f, "private") {
        assert_eq!(oui::private_mac(st(&c["N"])), c["Out"].as_bool().unwrap(), "{c}");
    }
    for c in arr(&f, "short") {
        assert_eq!(oui::short_vendor(st(&c["In"])), st(&c["Out"]), "{c}");
    }
    // events.jsonl
    let ev = dir.join("events.jsonl").to_string_lossy().into_owned();
    let _ = std::fs::remove_file(&ev);
    let t0 = heimdall::gotime::Time::parse_rfc3339("2026-11-07T10:00:00Z").unwrap();
    let a = store::Device {
        mac: "06:00:00:00:00:05".into(),
        ip: "192.0.2.5".into(),
        kind: "private".into(),
        private_mac: true,
        first_seen: t0,
        last_seen: t0,
        ..Default::default()
    };
    let b = store::Device {
        mac: "00:00:5E:00:53:02".into(),
        names: vec!["TV\u{2028}".into()],
        name: "TV\u{2028}".into(),
        ..Default::default()
    };
    store::append_events(&ev, "Home <&>", &[a, b], t0).unwrap();
    assert_eq!(std::fs::read_to_string(&ev).unwrap(), st(&f["events"]));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_resolver_question_is_gos() {
    // what Go's resolver sent for 192.0.2.5 (id 0x1234), taken from a Go run against a fake router
    let q = resolver::question(0x1234, "5.2.0.192.in-addr.arpa.", false);
    assert_eq!(
        hex(&q),
        "123401000001000000000001013501320130033139320769\
         6e2d61646472046172706100000c000100002904d0000000000000"
    );
}

/// A device list with three networks, odd text and times written with offsets (as a hand-edited or older file may have).
const DEVICES: &str = r#"{
 "networks": [
  {
   "uuid": "u1",
   "ssid": "Home <&>",
   "first_scan": "2026-11-07T10:00:00Z",
   "last_scan": "2026-11-10T19:55:00+01:00",
   "devices": [
    {"mac": "00:00:5E:00:53:01", "ip": "192.0.2.1", "name": "router", "kind": "router", "first_seen": "2026-11-07T10:00:00Z", "last_seen": "2026-11-10T18:55:00Z"},
    {"mac": "06:00:00:00:00:05", "ip": "192.0.2.5", "name": "Living Room TV ünï", "names": ["Living Room TV ünï", "tv"], "vendor": "Example", "kind": "tv", "services": ["_googlecast._tcp"], "first_seen": "2026-03-29T00:59:00Z", "last_seen": "2026-11-01T06:30:00Z"},
    {"mac": "00:00:5E:00:53:0A", "ip": "192.0.2.10", "kind": "this", "first_seen": "0001-01-01T00:00:00Z", "last_seen": "2026-11-10T18:55:00Z"},
    {"mac": "06:00:00:00:00:07", "ip": "192.0.2.7", "name": "a\tb", "vendor": "宽 width", "kind": "other", "first_seen": "2026-07-01T12:00:00-07:00", "last_seen": "2026-07-01T12:00:00.999Z"}
   ]
  },
  {"uuid": "u2", "ssid": "", "first_scan": "0001-01-01T00:00:00Z", "last_scan": "0001-01-01T00:00:00Z", "devices": null},
  {"uuid": "u3", "ssid": "Cabin", "first_scan": "2026-01-01T00:00:00Z", "last_scan": "2026-01-01T00:00:00Z", "devices": []}
 ],
 "status": "scanned",
 "status_uuid": "u1",
 "status_time": "2026-11-10T18:55:00Z"
}"#;

#[test]
fn lan_list_as_go() {
    let cases: Vec<(&str, Vec<&str>, Option<&str>)> = vec![
        ("full", vec!["lan", "list"], Some(DEVICES)),
        ("missing", vec!["lan", "list"], None),
        ("empty", vec!["lan", "list"], Some("{}")),
        ("broken", vec!["lan", "list"], Some("{\"networks\": [")),
        ("wrong type", vec!["lan", "list"], Some("{\"networks\": [{\"devices\": [{\"mac\": 5}]}]}")),
        ("bad byte", vec!["lan", "list"], Some("\u{1}")),
        ("dir flag", vec!["lan", "list", "--dir", "/srv//lan/"], Some(DEVICES)),
        ("dir flag =", vec!["lan", "list", "-dir=/srv/lan", "extra"], Some(DEVICES)),
        ("no command", vec!["lan"], None),
        ("bad command", vec!["lan", "show"], None),
        ("unknown flag", vec!["lan", "list", "--json"], None),
        ("help", vec!["lan", "scan", "-h"], None),
        ("missing value", vec!["lan", "list", "--dir"], None),
    ];
    let mut n = 0;
    for (what, args, doc) in &cases {
        let build = |r: &Root| {
            if let Some(d) = doc {
                let dir = if args.iter().any(|a| a.contains("/srv")) { "/srv/lan" } else { "/var/lib/heimdall/lan" };
                r.write(&format!("{dir}/devices.json"), d);
            }
        };
        let Some(((g, _), (r, _))) = both("lan-list", build, args, &Opts::user().env("HEIMDALL_RUST_LAN_SCAN", "1")) else { return };
        assert_same(what, &g, &r);
        n += 1;
    }
    // a store that is a folder, and one that cannot be read
    for (what, mode) in [("folder", 0), ("unreadable", 0o000)] {
        let build = |r: &Root| {
            if mode == 0 {
                r.mkdir("/var/lib/heimdall/lan/devices.json", 0o755);
            } else {
                r.write_mode("/var/lib/heimdall/lan/devices.json", DEVICES, mode);
            }
        };
        let Some(((g, _), (r, _))) = both("lan-list", build, &["lan", "list"], &Opts::user()) else { return };
        assert_same(what, &g, &r);
        n += 1;
    }
    // other time zones: the times are shown in local time
    for tz in ["UTC", "Asia/Kolkata", "Pacific/Chatham", "Europe/Berlin"] {
        let build = |r: &Root| {
            r.write("/var/lib/heimdall/lan/devices.json", DEVICES);
        };
        let Some(((g, _), (r, _))) = both("lan-list", build, &["lan", "list"], &Opts::user().env("TZ", tz)) else { return };
        assert_same(tz, &g, &r);
        n += 1;
    }
    eprintln!("lan list: {n} runs compared with Go");
}

/// A network namespace with one interface (a dummy: no neighbour ever answers) and a default route through it.
const DUMMY_NET: &str = "ip link add lan0 type dummy\nip link set lan0 address 00:00:5e:00:53:0a\nip addr add 192.0.2.10/28 dev lan0\n\
                         ip link set lan0 up\nip route add default via 192.0.2.1 dev lan0\n";

#[test]
fn lan_scan_without_a_scan_as_go() {
    let trusted = r#"{"u1": {"ssid": "Home", "routers": ["00:00:5e:00:53:01"]}}"#;
    let nmcli = "printf 'u0:wlan0:Other\\nu1:lan0:Ho\\\\:me\\n'\n";
    // (what, setup, trusted file, nmcli script, store before, args, as root)
    type Case<'a> = (&'a str, &'a str, Option<&'a str>, &'a str, Option<&'a str>, Vec<&'a str>, bool);
    let cases: Vec<Case> = vec![
        ("offline", "", None, nmcli, None, vec!["lan", "scan"], false),
        ("offline, the old list kept", "", None, nmcli, Some(DEVICES), vec!["lan", "scan"], false),
        ("not trusted: no file", DUMMY_NET, None, nmcli, Some(DEVICES), vec!["lan", "scan"], false),
        (
            "not trusted: another network",
            DUMMY_NET,
            Some(r#"{"u9": {"ssid": "x", "routers": []}}"#),
            nmcli,
            None,
            vec!["lan", "scan"],
            false,
        ),
        ("not trusted: nmcli fails", DUMMY_NET, Some(trusted), "exit 1\n", None, vec!["lan", "scan"], false),
        ("not trusted: broken file", DUMMY_NET, Some("{"), nmcli, None, vec!["lan", "scan"], false),
        ("router changed", DUMMY_NET, Some(trusted), nmcli, Some(DEVICES), vec!["lan", "scan"], false),
        ("router changed, as root, own dir", DUMMY_NET, Some(trusted), nmcli, None, vec!["lan", "scan", "--dir", "/srv//new/lan/"], true),
        ("store unreadable", DUMMY_NET, None, nmcli, Some("{\"status\": 5}"), vec!["lan", "scan"], false),
        ("dir not makeable", "", None, nmcli, None, vec!["lan", "scan", "--dir", "/proc/nope"], false),
        ("store not writable", "", None, nmcli, None, vec!["lan", "scan", "--dir", "/etc/heimdall"], false),
    ];
    let mut n = 0;
    for (what, setup, trust, nm, before, args, root) in &cases {
        let build = |r: &Root| {
            r.tool("nmcli", nm);
            r.mkdir("/etc/heimdall", 0o755);
            if let Some(t) = trust {
                r.write("/etc/heimdall/wifi-trusted.json", t);
            }
            if let Some(b) = before {
                r.write("/var/lib/heimdall/lan/devices.json", b);
            }
        };
        // the heimdall account's folder, as the unit has it (the test user stands in for it)
        let chown = if *root { "" } else { "mkdir -p \"$R/var/lib/heimdall/lan\"\nchown -R 1000:1000 \"$R/var/lib/heimdall\"\n" };
        let base = if *root { Opts::default() } else { Opts::user() };
        let o = Opts { net: true, setup: format!("{chown}{setup}"), ..base.env("HEIMDALL_RUST_LAN_SCAN", "1") };
        let Some(((g, rg), (r, rr))) = both("lan-scan", build, args, &o) else { return };
        assert_same(what, &g, &r);
        eprintln!("{what}: exit {}, {:?} {:?}", g.code, g.stdout, g.stderr);
        let dirs = ["/var/lib/heimdall", "/srv"];
        let norm = |t: BTreeMap<String, String>| t.into_iter().map(|(k, v)| (k, normalize(&v))).collect::<BTreeMap<_, _>>();
        assert_eq!(norm(rg.tree(&dirs)), norm(rr.tree(&dirs)), "{what}: the files");
        assert_eq!(rg.calls(), rr.calls(), "{what}: the tools called");
        n += 1;
    }
    eprintln!("lan scan statuses: {n} runs compared with Go");
}
