//! `heimdalld lan` against the Go heimdalld: the pure parts on the shared fixture (testdata/parity/cli-lan.json, written by
//! internal/lan's TestRustFixture), the commands in fake roots, and a whole scan in network namespaces with made-up devices
//! answering (documentation addresses, documentation and locally administered hardware addresses), every packet each binary
//! sent compared.

mod common;
#[allow(unused_imports)]
use common::*;
use heimdall::cli::lan::{discover, dns, resolver, scan, store, text};
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
        let tk: Vec<String> = store::takeovers(&n, &seen)
            .iter()
            .map(|x| [x.device.ip.as_str(), &x.device.mac, &x.was_mac, &x.was_name, &x.other_ip].join(" "))
            .collect();
        assert_eq!(tk.join("|"), st(&c["takeovers"]), "{c}");
        let nm: Vec<String> =
            store::name_moves(&n, &seen).iter().map(|x| [x.change, &x.device.mac, &x.was_mac, &x.was_name].join(" ")).collect();
        assert_eq!(nm.join("|"), st(&c["names"]), "{c}");
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
        let levels: BTreeMap<String, Value> =
            scan::parse_trusted(st(&c["in"]).as_bytes()).into_iter().map(|(k, t)| (k, Value::String(t.level))).collect();
        let want: BTreeMap<String, Value> = c["levels"].as_object().unwrap().clone().into_iter().collect();
        assert_eq!(levels, want, "levels of {}", c["in"]);
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
fn the_owners_kinds_as_go_reads_and_writes_them() {
    let f = fixture();
    let dir = std::env::temp_dir().join(format!("heimdall-cli-lan-kinds-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let kp = dir.join(store::KINDS_FILE).to_string_lossy().into_owned();
    let dev = |mac: &str, kind: &str, owner: &str| store::Device {
        mac: mac.into(),
        kind: kind.into(),
        owner_kind: owner.into(),
        ..Default::default()
    };
    let listed = store::Store {
        networks: Some(vec![
            store::Network {
                uuid: "u".into(),
                devices: Some(vec![
                    dev("00:00:5E:00:53:01", "router", ""),
                    dev("06:00:00:00:00:0a", "private", "tv"),
                    dev("0A:00:00:00:00:0B", "other", ""),
                    dev("\u{17f}0:00:00:00:00:0C", "other", ""),
                ]),
                ..Default::default()
            },
            store::Network { uuid: "v".into(), ..Default::default() },
        ]),
        ..Default::default()
    };
    for c in arr(&f, "kinds") {
        let _ = std::fs::remove_file(&kp);
        let doc = unhex(st(&c["in"]));
        if !doc.is_empty() {
            std::fs::write(&kp, &doc).unwrap();
        }
        let k = store::load_kinds(&kp);
        let want: Option<BTreeMap<String, String>> = serde_json::from_value(c["out"].clone()).unwrap();
        assert_eq!(k, want, "{c}");
        let mut s = listed.clone();
        s.apply_kinds(k.as_ref());
        assert_eq!(s.marshal().unwrap(), st(&c["list"]), "{c}");
    }
    std::fs::write(&kp, r#"{"06:00:00:00:00:0A": "tv", "bad": "tv", "0A:00:00:00:00:0B": 1}"#).unwrap();
    for c in arr(&f, "set_kind") {
        let r = store::set_kind(&kp, st(&c["Mac"]), st(&c["Kind"]));
        let (ret, err) = match r {
            Ok(m) => (m, String::new()),
            Err(e) => (String::new(), e),
        };
        assert_eq!((ret.as_str(), err.as_str()), (st(&c["Ret"]), st(&c["Err"])), "{c}");
        assert_eq!(std::fs::read_to_string(&kp).unwrap(), st(&c["After"]), "{c}");
    }
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
    // the owner's kinds: shown in the list, and written by `lan kind`
    let kinds = r#"{"06:00:00:00:00:05": "speaker", "06:00:00:00:00:07": "console", "00:00:5E:00:53:0A": "nonsense"}"#;
    for (what, doc) in [("kinds", kinds), ("kinds damaged", "{\"06:00:00:00:00:05\": "), ("kinds wrong type", "[\"tv\"]")] {
        let build = |r: &Root| {
            r.write("/var/lib/heimdall/lan/devices.json", DEVICES);
            r.write("/var/lib/heimdall/lan/kinds.json", doc);
        };
        let Some(((g, _), (r, _))) = both("lan-list", build, &["lan", "list"], &Opts::user()) else { return };
        assert_same(what, &g, &r);
        n += 1;
    }
    let kind_cases: Vec<(&str, Vec<&str>, Option<&str>)> = vec![
        ("kind set", vec!["lan", "kind", "06:00:00:00:00:07", "tv"], Some(kinds)),
        ("kind set, lower case, no file", vec!["lan", "kind", "0a:00:00:00:00:0b", "printer"], None),
        ("kind guess", vec!["lan", "kind", "06:00:00:00:00:05", "guess"], Some(kinds)),
        ("kind dir flag", vec!["lan", "kind", "--dir", "/srv/lan", "06:00:00:00:00:05", "phone"], None),
        ("kind bad address", vec!["lan", "kind", "06-00-00-00-00-05", "tv"], Some(kinds)),
        ("kind bad word", vec!["lan", "kind", "06:00:00:00:00:05", "private"], Some(kinds)),
        ("kind one word", vec!["lan", "kind", "06:00:00:00:00:05"], Some(kinds)),
        ("kind three words", vec!["lan", "kind", "06:00:00:00:00:05", "tv", "x"], Some(kinds)),
        ("kind no folder", vec!["lan", "kind", "--dir", "/nowhere/lan", "06:00:00:00:00:05", "tv"], None),
    ];
    for (what, args, doc) in &kind_cases {
        let build = |r: &Root| {
            r.mkdir("/var/lib/heimdall/lan", 0o755);
            r.mkdir("/srv/lan", 0o755);
            if let Some(d) = doc {
                r.write("/var/lib/heimdall/lan/kinds.json", d);
            }
        };
        let Some(((g, rg), (r, rr))) = both("lan-kind", build, args, &Opts::user()) else { return };
        assert_same(what, &g, &r);
        for f in ["/var/lib/heimdall/lan/kinds.json", "/srv/lan/kinds.json"] {
            assert_eq!(rg.read_str(f), rr.read_str(f), "{what}: {f}");
        }
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
        // trusted by heimdall-wifi-guard, but not as the home network: nothing is swept
        (
            "trusted, not home",
            DUMMY_NET,
            Some(r#"{"u1": {"ssid": "Home", "level": "trusted", "key_mgmt": "sae", "routers": []}}"#),
            nmcli,
            Some(DEVICES),
            vec!["lan", "scan"],
            false,
        ),
        (
            "a level that is not one",
            DUMMY_NET,
            Some(r#"{"u1": {"ssid": "Home", "level": null, "routers": ["00:00:5e:00:53:01"]}}"#),
            nmcli,
            None,
            vec!["lan", "scan"],
            false,
        ),
        (
            "home, router changed",
            DUMMY_NET,
            Some(r#"{"u1": {"ssid": "Home", "level": "home", "routers": ["00:00:5e:00:53:01"]}}"#),
            nmcli,
            None,
            vec!["lan", "scan"],
            false,
        ),
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

/// The made-up network: this computer at 192.0.2.10 on a bridge (br0); on the bridge, each in a network namespace of its own
/// joined by a veth pair, the router (192.0.2.1, reverse lookups), a TV (.20, multicast DNS), a Windows computer (.30,
/// NetBIOS) and a thermostat (.40, ARP only), each with a locally administered hardware address;
/// rust/parity/harness/lan-responder.py answers and logs every question.
fn made_up_network(log: &str) -> String {
    bridge(
        log,
        "dev 02:00:00:00:00:01 1 router\ndev 02:00:00:00:00:20 20 tv\ndev 02:00:00:00:00:30 30 pc\ndev 02:00:00:00:00:40 40 ''\n",
        3,
    )
}

/// The bridge and `devs` ("dev MAC LAST-OCTET ROLE" lines, ROLE '' for a device that runs nothing), then a wait for `ready`
/// responders and the default route through 192.0.2.1.
fn bridge(log: &str, devs: &str, ready: usize) -> String {
    let resp = repo().join("rust/parity/harness/lan-responder.py");
    format!(
        "ip link add br0 address 02:00:00:00:00:10 type bridge
ip addr add 192.0.2.10/24 dev br0
ip link set br0 up
dev() {{
  unshare --net sleep 60 &
  P=$!
  sleep 0.1
  ip link add h$2 type veth peer name e$2
  ip link set h$2 master br0
  ip link set h$2 up
  ip link set e$2 netns \"$R/proc/$P/ns/net\"
  N=\"nsenter --net=$R/proc/$P/ns/net\"
  $N ip link set lo up
  $N ip link set e$2 address $1 name eth0
  $N ip addr add 192.0.2.$2/24 dev eth0
  $N ip link set eth0 up
  $N ip route add 224.0.0.0/4 dev eth0
  if [ -n \"$3\" ]; then $N python3 -I '{resp}' '{log}' $3 192.0.2.$2 & fi
}}
{devs}ip route add default via 192.0.2.1 dev br0
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do [ \"$(grep -c ready '{log}' 2>/dev/null)\" = {ready} ] && break; sleep 0.2; done
sleep 1
",
        resp = resp.display()
    )
}

#[test]
fn lan_scan_on_a_made_up_network_as_go() {
    let trusted = r#"{"u1": {"ssid": "Home", "routers": ["02:00:00:00:00:01"]}}"#;
    // a list from an earlier scan: the router and the thermostat known, so the TV and the computer are new
    let before = r#"{"networks":[{"uuid":"u1","ssid":"Home","first_scan":"2026-11-01T10:00:00Z","last_scan":"2026-11-01T10:00:00Z","devices":[
{"mac":"02:00:00:00:00:01","ip":"192.0.2.1","name":"router","kind":"router","first_seen":"2026-11-01T10:00:00Z","last_seen":"2026-11-01T10:00:00Z"},
{"mac":"02:00:00:00:00:40","ip":"192.0.2.40","kind":"smart","first_seen":"2026-11-01T10:00:00Z","last_seen":"2026-11-01T10:00:00Z"}]}],
"status":"scanned","status_uuid":"u1","status_time":"2026-11-01T10:00:00Z"}"#;
    let Some(go) = go_or_skip("lan-net") else { return };
    let mk = |tag: &str| {
        let r = Root::new(tag);
        r.write("/etc/heimdall/wifi-trusted.json", trusted);
        r.write("/var/lib/heimdall/lan/devices.json", before);
        // names from the router: the resolver asks DNS only where nsswitch says so
        r.write("/etc/nsswitch.conf", "passwd: files\ngroup: files\nhosts: files dns\n");
        r.tool("nmcli", "printf 'u1:br0:Home\\n'\n");
        r
    };
    let (rg, rr) = (mk("lan-net-go"), mk("lan-net-rs"));
    let o = |r: &Root| Opts {
        net: true,
        pid: true,
        setup: made_up_network(&r.host("/packets.log").display().to_string()),
        ..Opts::default().env("HEIMDALL_RUST_LAN_SCAN", "1")
    };
    let (g, r) = std::thread::scope(|s| {
        let a = s.spawn(|| rg.run(&go, &["lan", "scan"], &o(&rg)));
        let b = s.spawn(|| rr.run(&rust_bin(), &["lan", "scan"], &o(&rr)));
        (a.join().unwrap(), b.join().unwrap())
    });
    assert_same("lan scan", &g, &r);
    assert_eq!(g.stdout, "5 devices, 2 new\n", "{g:?}");
    for f in ["/var/lib/heimdall/lan/devices.json", "/var/lib/heimdall/lan/events.jsonl"] {
        assert_eq!(normalize(&rg.read_str(f)), normalize(&rr.read_str(f)), "{f}");
    }
    let dev = rg.read_str("/var/lib/heimdall/lan/devices.json");
    assert!(dev.contains("Living TV") && dev.contains("DESKTOP-ABC") && dev.contains("thermostat-7"), "{dev}");
    // every question each binary asked, in any order
    let asked = |r: &Root| {
        let mut l: Vec<String> = r.read_str("/packets.log").lines().map(String::from).collect();
        l.sort();
        l
    };
    assert_eq!(asked(&rg), asked(&rr), "the packets sent");
    assert!(asked(&rg).iter().any(|l| l.starts_with("mdns")) && asked(&rg).iter().any(|l| l.starts_with("netbios")));
    eprintln!("lan scan on a made-up network: {} questions compared", asked(&rg).len());
}

/// `lan look` (HEI-74) on a network that is not home: it lists the router (from the neighbour table) and a TV that announces
/// itself over multicast DNS, and sends nothing: br0's transmit counter is the same before and after, and the TV hears no
/// question. Without this computer in the multicast DNS group it does not join one, and lists only the neighbour table. Run
/// as the owner (no root), the way Settings runs it.
#[test]
fn lan_look_listens_and_sends_nothing() {
    let resp = repo().join("rust/parity/harness/lan-responder.py");
    for joined in [true, false] {
        let r = Root::new(if joined { "lan-look" } else { "lan-look-alone" });
        r.tool("nmcli", "printf 'u1:br0:Cafe\\n'\n");
        let log = r.host("/packets.log").display().to_string();
        let member = if joined { format!("python3 -I '{}' '{log}' member 192.0.2.10 &\n", resp.display()) } else { String::new() };
        let devs = format!("dev 02:00:00:00:00:01 1 ''\ndev 02:00:00:00:00:20 20 announcer\n{member}");
        let tx = "awk '$1 == \"br0:\" {print $11}' \"$R/proc/net/dev\"";
        let setup = format!(
            "sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1\n{}\
             ip neigh replace 192.0.2.1 lladdr 02:00:00:00:00:01 dev br0 nud permanent\n\
             sleep 2\n{tx} > \"$R/tx-before\"\n\
             (while :; do {tx} > \"$R/tx.tmp\" && mv \"$R/tx.tmp\" \"$R/tx-after\"; sleep 0.1; done) &\n",
            bridge(&log, &devs, if joined { 2 } else { 1 })
        );
        let o = Opts { net: true, pid: true, setup, ..Opts::user() };
        let out = r.run(&rust_bin(), &["lan", "look", "--wait", "2", "u1"], &o);
        assert_eq!(out.code, 0, "{out:?}");
        let j: Value = serde_json::from_str(out.stdout.trim()).unwrap_or_else(|e| panic!("{e}: {out:?}"));
        let ips: Vec<&str> = j["devices"].as_array().unwrap().iter().map(|d| d["ip"].as_str().unwrap()).collect();
        assert_eq!((j["status"].as_str(), j["interface"].as_str(), j["name"].as_str()), (Some("looked"), Some("br0"), Some("Cafe")));
        assert_eq!(j["devices"][0]["kind"], "router");
        assert_eq!(j["devices"][1]["kind"], "this");
        if joined {
            assert_eq!(j["mdns"], "listened", "{j}");
            assert_eq!(ips, ["192.0.2.1", "192.0.2.10", "192.0.2.20"]);
            let tv = &j["devices"][2];
            assert_eq!((tv["name"].as_str(), tv["kind"].as_str(), tv["mac"].as_str()), (Some("Living TV"), Some("tv"), Some("")), "{tv}");
        } else {
            assert_eq!(j["mdns"], "not_member", "{j}");
            assert_eq!(ips, ["192.0.2.1", "192.0.2.10"]);
        }
        let (before, after) = (r.read_str("/tx-before"), r.read_str("/tx-after"));
        assert!(!before.trim().is_empty() && !after.trim().is_empty(), "the counter was read: {before:?} {after:?}");
        assert_eq!(before, after, "br0 sent nothing during the look");
        let heard = std::fs::read_to_string(&log).unwrap_or_default();
        assert!(!heard.lines().any(|l| l.starts_with("mdns")), "the TV was asked nothing: {heard}");
        eprintln!(
            "lan look ({}): {} devices, br0 sent {} packets before and none during",
            if joined { "in the group" } else { "alone" },
            ips.len(),
            before.trim()
        );
    }
}

/// HEI-21, Go's TestNameMoves table: a hardware address that never had a known device's name and now announces it is reported
/// once, as moved when the device that had it is gone and as shared when it is still there.
#[test]
fn a_known_name_on_other_hardware_is_reported_once() {
    let t = |m: i64| heimdall::gotime::Time::parse_rfc3339("2026-11-16T10:00:00Z").unwrap().add(m * 60_000_000_000);
    let dev = |mac: &str, ip: &str, name: &str| store::Device {
        mac: mac.into(),
        ip: ip.into(),
        name: name.into(),
        names: if name.is_empty() { Vec::new() } else { vec![name.into()] },
        ..Default::default()
    };
    let printer = dev("00:11:22:00:00:30", "192.0.2.30", "Office-Printer");
    let phone = dev("06:00:00:00:00:40", "192.0.2.40", "Phone");
    let known = || {
        let mut n = store::Network { uuid: "u".into(), ..Default::default() };
        n.merge(vec![printer.clone(), phone.clone()], t(0));
        n
    };
    let other = "02:00:00:00:00:77";
    let mut me = dev(other, "192.0.2.77", "Phone");
    me.kind = "this".into();
    let first = store::Network { uuid: "u".into(), devices: Some(vec![printer.clone()]), ..Default::default() };
    let cases: Vec<(&str, store::Network, Vec<store::Device>, &str)> = vec![
        (
            "another device takes the printer's name while it is away",
            known(),
            vec![dev(other, "192.0.2.77", "office-printer"), phone.clone()],
            "name_moved 02:00:00:00:00:77 00:11:22:00:00:30 Office-Printer",
        ),
        (
            "beside it",
            known(),
            vec![dev(other, "192.0.2.77", "Office-Printer"), printer.clone(), phone.clone()],
            "name_shared 02:00:00:00:00:77 00:11:22:00:00:30 Office-Printer",
        ),
        (
            "the printer seen without its announcement",
            known(),
            vec![dev(other, "192.0.2.77", "Office-Printer"), dev(&printer.mac, &printer.ip, "")],
            "name_shared 02:00:00:00:00:77 00:11:22:00:00:30 Office-Printer",
        ),
        (
            "the printer renamed meanwhile",
            known(),
            vec![dev(other, "192.0.2.77", "Office-Printer"), dev(&printer.mac, &printer.ip, "Hall-Printer")],
            "name_moved 02:00:00:00:00:77 00:11:22:00:00:30 Office-Printer",
        ),
        (
            "the phone with a new private address",
            known(),
            vec![dev("06:00:00:00:00:41", "192.0.2.41", "Phone")],
            "name_moved 06:00:00:00:00:41 06:00:00:00:00:40 Phone",
        ),
        ("each device with its own name", known(), vec![printer.clone(), phone.clone()], ""),
        ("a new name", known(), vec![dev(other, "192.0.2.77", "Laptop")], ""),
        ("no name", known(), vec![dev(other, "192.0.2.77", "")], ""),
        ("this computer", known(), vec![me], ""),
        ("the first scan", first, vec![dev(other, "192.0.2.77", "Office-Printer")], ""),
    ];
    for (name, n, seen, want) in cases {
        let got: Vec<String> =
            store::name_moves(&n, &seen).iter().map(|x| [x.change, &x.device.mac, &x.was_mac, &x.was_name].join(" ")).collect();
        assert_eq!(got.join("|"), want, "{name}");
    }
    let mut n = known();
    let seen = vec![dev(other, "192.0.2.77", "Office-Printer"), printer.clone()];
    assert_eq!(store::name_moves(&n, &seen).len(), 1, "the first time");
    n.merge(seen.clone(), t(5));
    assert!(store::name_moves(&n, &seen).is_empty(), "once");
}
