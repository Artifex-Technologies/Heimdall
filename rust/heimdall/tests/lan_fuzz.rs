//! The device list's fuzz targets (rust/fuzz/fuzz_targets/lan_dns.rs, lan_answer.rs; bodies in src/cli/lan/fuzz.rs) where
//! cargo-fuzz does not run: their seeds and every cut of them, random bytes, and the Kani harness body exhaustively over small
//! messages.

use proptest::prelude::*;

/// The fuzz targets' bodies on their seeds (and every cut of them) and on random bytes, where cargo-fuzz does not run.
#[test]
fn the_fuzz_targets_survive_seeds() {
    use heimdall::cli::lan::fuzz;
    let seeds = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fuzz/seeds");
    let mut n = 0;
    for (name, f) in [("lan_dns", fuzz::lan_dns as fn(&[u8])), ("lan_answer", fuzz::lan_answer)] {
        for e in std::fs::read_dir(seeds.join(name)).unwrap() {
            let b = std::fs::read(e.unwrap().path()).unwrap();
            for cut in 0..=b.len() {
                f(&b[..cut]);
            }
            n += 1;
        }
    }
    assert!(n >= 5);
}

/// The Kani harness body (src/cli/lan/fuzz.rs), exhaustively where it is small: every message of up to two bytes, and every
/// three-byte message over the bytes that matter to a name (ends, labels, pointers, the reserved kinds), at every offset.
#[test]
fn read_name_stays_in_bounds_exhaustively() {
    use heimdall::cli::lan::fuzz::read_name_bounds;
    let mut n = 0u64;
    for len in 0..=2usize {
        for v in 0..(1u32 << (8 * len)) {
            let m: Vec<u8> = (0..len).map(|i| (v >> (8 * i)) as u8).collect();
            for off in 0..len + 2 {
                read_name_bounds(&m, off);
                n += 1;
            }
        }
    }
    let alphabet = [0u8, 1, 2, 3, 0x3f, 0x40, 0x80, 0xc0, 0xc1, 0xff, b'a'];
    for a in alphabet {
        for b in alphabet {
            for c in alphabet {
                for d in alphabet {
                    let m = [a, b, c, d];
                    for off in 0..6 {
                        read_name_bounds(&m, off);
                        n += 1;
                    }
                }
            }
        }
    }
    assert!(n > 300_000);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 300, ..ProptestConfig::default() })]

    /// Random bytes never stop the readers, and keep their invariants.
    #[test]
    fn random_answers(b in proptest::collection::vec(any::<u8>(), 0..300)) {
        heimdall::cli::lan::fuzz::lan_dns(&b);
        heimdall::cli::lan::fuzz::lan_answer(&b);
    }
}
