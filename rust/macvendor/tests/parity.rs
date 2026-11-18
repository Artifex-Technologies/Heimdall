//! The Go twin's answers (internal/macvendor, `go test ./internal/macvendor -update` writes testdata/parity/macvendor.json):
//! the same registry files, read in the same order, give the same table and the same answer for every address; addresses as
//! text, cleaned names and short names agree too.

use heimdall_macvendor::{clean, parse_mac, short, Answer, Builder, Registry};
use serde_json::Value;

fn fixture() -> Value {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/parity/macvendor.json");
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn st(v: &Value) -> &str {
    v.as_str().unwrap_or_default()
}

fn arr<'a>(f: &'a Value, k: &str) -> &'a Vec<Value> {
    f[k].as_array().unwrap_or_else(|| panic!("{k}"))
}

#[test]
fn tables_and_lookups_match_go() {
    let f = fixture();
    assert_eq!(st(&f["format"]), "heimdall-macvendor/1");
    let mut n = 0;
    for t in arr(&f, "tables") {
        let mut b = Builder::new();
        for file in arr(t, "files") {
            b.read(&unhex(st(&file["hex"]))[..], Registry::from_name(st(&file["registry"])).unwrap());
        }
        let table = b.finish();
        assert_eq!(table.len() as u64, t["len"].as_u64().unwrap(), "{t}");
        for l in arr(t, "lookups") {
            let a = table.lookup_str(st(&l["mac"]));
            let (name, short, registry, bits) = match a {
                Answer::Vendor(v) => (v.name, v.short, v.registry.name(), v.bits),
                Answer::Special(s) => (s.name, s.short, "", 0),
                _ => ("", "", "", 0),
            };
            let got = (a.kind(), name, short, registry, bits as u64);
            let want = (st(&l["kind"]), st(&l["name"]), st(&l["short"]), st(&l["registry"]), l["bits"].as_u64().unwrap());
            assert_eq!(got, want, "{l}");
            n += 1;
        }
    }
    assert!(n > 3000, "{n}");
}

#[test]
fn addresses_and_names_match_go() {
    let f = fixture();
    for c in arr(&f, "parse") {
        let got = parse_mac(st(&c["in"]))
            .map(|m| format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5]))
            .unwrap_or_default();
        assert_eq!(got, st(&c["out"]), "{c}");
    }
    for c in arr(&f, "clean") {
        assert_eq!(clean(&unhex(st(&c["in"]))), st(&c["out"]), "{c}");
    }
    for c in arr(&f, "short") {
        assert_eq!(short(st(&c["in"])), st(&c["out"]), "{c}");
    }
}
