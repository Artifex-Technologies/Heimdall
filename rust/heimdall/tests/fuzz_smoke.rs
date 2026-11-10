//! The fuzz targets' bodies (src/fuzzing.rs) on random inputs and on the seed corpus (rust/fuzz/seeds), so every target runs
//! in the ordinary test suite too. The real fuzzing is `cargo +nightly fuzz run TARGET` in rust/fuzz.

use heimdall::fuzzing;
use proptest::prelude::*;

type Target = fn(&[u8]);

const TARGETS: &[(&str, Target)] = &[
    ("json", fuzzing::json),
    ("config", fuzzing::config),
    ("rule_file", fuzzing::rule_file),
    ("event_line", fuzzing::event_line),
    ("alert_line", fuzzing::alert_line),
    ("text", fuzzing::text),
];

#[test]
fn every_target_survives_its_seeds() {
    let seeds = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fuzz/seeds");
    let mut n = 0;
    for (name, f) in TARGETS {
        let dir = seeds.join(name);
        let Ok(entries) = std::fs::read_dir(&dir) else { panic!("no seeds for {name} in {}", dir.display()) };
        for e in entries {
            let b = std::fs::read(e.unwrap().path()).unwrap();
            f(&b);
            // and every prefix of it: a file cut short is the commonest damage
            for cut in (0..b.len()).step_by((b.len() / 16).max(1)) {
                f(&b[..cut]);
            }
            n += 1;
        }
    }
    assert!(n >= TARGETS.len());
}

/// Structured garbage: JSON-ish bytes, so the readers get past the first character.
fn jsonish() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(
        prop_oneof![
            Just(b"{".to_vec()),
            Just(b"}".to_vec()),
            Just(b"[".to_vec()),
            Just(b"]".to_vec()),
            Just(b",".to_vec()),
            Just(b":".to_vec()),
            Just(b"\"".to_vec()),
            Just(b"\\u".to_vec()),
            Just(b"\\ud800".to_vec()),
            Just(b"null".to_vec()),
            Just(b"\"time\":".to_vec()),
            Just(b"\"fields\":".to_vec()),
            Just(b"\"rules\":".to_vec()),
            Just(b"\"kind\":".to_vec()),
            Just(b"\"format\":\"heimdall-text-rules/1\"".to_vec()),
            Just(b"\"pattern\":\"(?i)a\\\\s\"".to_vec()),
            Just(b"1e400".to_vec()),
            Just(b"-0".to_vec()),
            Just(b"2026-11-10T01:02:03.5+01:00".to_vec()),
            Just(vec![0xff]),
            proptest::collection::vec(any::<u8>(), 0..4),
        ],
        0..40,
    )
    .prop_map(|parts| parts.concat())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 3000, ..ProptestConfig::default() })]

    #[test]
    fn every_target_survives_random_input(b in prop_oneof![jsonish(), proptest::collection::vec(any::<u8>(), 0..256)]) {
        for (_, f) in TARGETS {
            f(&b);
        }
    }
}
