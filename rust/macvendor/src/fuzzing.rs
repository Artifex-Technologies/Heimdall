//! The body of the `macvendor` fuzz target (rust/fuzz/fuzz_targets/macvendor.rs): the file readers, the name rules and the
//! address reader on any bytes must never panic, and what they produce must keep the table's promises. tests/props.rs runs
//! it on the made-up samples, their damaged versions and random bytes in the ordinary tests.

use crate::{clean, parse_mac, short, Answer, Builder, Registry};

/// Reads `data` as a registry file of each kind, then checks every block it gave and a few lookups.
pub fn parsers(data: &[u8]) {
    for hint in [Registry::MaL, Registry::Iab] {
        let mut b = Builder::new();
        let n = b.read(data, hint);
        let t = b.finish();
        assert!(t.len() <= n);
        assert_eq!(t.is_empty(), n == 0);
        // every 6-byte window of the input as an address, and the address text itself
        for w in data.windows(6).take(256) {
            let mac: [u8; 6] = w.try_into().unwrap();
            check(t.lookup(&mac));
        }
        if let Ok(s) = std::str::from_utf8(data) {
            for part in s.split(|c: char| c.is_whitespace() || c == ',').take(256) {
                check(t.lookup_str(part));
            }
        }
    }
    let c = clean(data);
    assert!(c.len() <= crate::name::MAX_NAME);
    assert_eq!(c, c.trim_matches(' '));
    assert!(!c.contains("  "));
    assert!(!c.chars().any(|ch| crate::name::is_dropped(ch) || (crate::name::is_space(ch) && ch != ' ')));
    // cleaning is idempotent, and the short name of a name is never empty and never longer
    assert_eq!(clean(c.as_bytes()), c);
    let s = short(&c);
    assert_eq!(s.is_empty(), c.is_empty());
    assert!(s.len() <= c.len());
    if let Ok(text) = std::str::from_utf8(data) {
        if let Some(m) = parse_mac(text) {
            let again = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5]);
            assert_eq!(parse_mac(&again), Some(m));
        }
    }
}

fn check(a: Answer<'_>) {
    if let Answer::Vendor(v) = a {
        assert!(!v.name.is_empty() && v.name.len() <= crate::name::MAX_NAME);
        assert!(!v.short.is_empty() && v.short.len() <= v.name.len());
        assert!(matches!(v.bits, 24..=47));
    }
}
