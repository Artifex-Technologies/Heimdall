//! Property tests: the readers and the name rules on random and damaged input (the fuzz target's body, src/fuzzing.rs, runs
//! here on stable; the real fuzzing is `cargo +nightly fuzz run macvendor` in rust/fuzz), and lookups against a plain list.

use heimdall_macvendor::{fuzzing, parse_mac, Answer, Builder, Registry};
use proptest::prelude::*;

const SEEDS: &[&[u8]] = &[
    b"OUI/MA-L\n\n0C-00-01   (hex)\t\tEXAMPLE NETWORKS CORP\n0C0001     (base 16)\t\tEXAMPLE NETWORKS CORP\n",
    b"0C-00-03                      (hex)                         Tiny Sensors Inc.\nABC000-ABCFFF                 (base 16)                     Tiny Sensors Inc.\n",
    b"\xef\xbb\xbfRegistry,Assignment,Organization Name,Organization Address\r\nMA-M,0C00030,\"Middle Block Devices, Inc.\",\"1 Way\r\nTown\"\r\n",
    b"Registry,Assignment,Organization Name\nMA-S,0C0003ABD,Smallest Things GmbH,Somewhere\nMA-L,0C0011,\"open",
    b"0C:00:01:00:00:01",
    b"Good\xe2\x80\xae Name\x07 \xc9cole",
];

#[test]
fn the_fuzz_body_on_the_seeds_and_every_cut() {
    for s in SEEDS {
        for end in 0..=s.len() {
            fuzzing::parsers(&s[..end]);
            fuzzing::parsers(&s[end..]);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn random_bytes(data in prop::collection::vec(any::<u8>(), 0..512)) {
        fuzzing::parsers(&data);
    }

    #[test]
    fn mutated_seeds(i in 0..SEEDS.len(), flips in prop::collection::vec((any::<usize>(), any::<u8>()), 1..8)) {
        let mut d = SEEDS[i].to_vec();
        for (at, v) in flips {
            let n = d.len();
            d[at % n] = v;
        }
        fuzzing::parsers(&d);
    }

    /// Random blocks written as a CSV file are found again, longest first, as a plain search through the list finds them.
    #[test]
    fn lookups_match_a_plain_search(
        blocks in prop::collection::vec((prop::sample::select(vec![6usize, 7, 9]), any::<u64>()), 1..40),
        probes in prop::collection::vec(any::<[u8; 6]>(), 1..40),
    ) {
        let mut csv = String::from("Registry,Assignment,Organization Name\n");
        let mut list: Vec<(u8, u64, String)> = Vec::new();
        for (i, (digits, v)) in blocks.iter().enumerate() {
            // clear the group and local bits, so the probes below can reach the blocks
            let bits = 4 * *digits as u32;
            let key = (v & ((1u64 << bits) - 1)) & !(0x03u64 << (bits - 8));
            let reg = match digits { 6 => "MA-L", 7 => "MA-M", _ => "MA-S" };
            let name = format!("Maker {i}");
            csv.push_str(&format!("{reg},{key:0w$X},{name}\n", w = *digits));
            if !list.iter().any(|(b, k, _)| *b as u32 == bits && *k == key) {
                list.push((bits as u8, key, name));
            }
        }
        let mut b = Builder::new();
        b.read(csv.as_bytes(), Registry::MaL);
        let t = b.finish();
        // the probes, and each block's own first address
        let mut macs: Vec<[u8; 6]> = probes;
        for (bits, key, _) in &list {
            let v = key << (48 - *bits as u32);
            macs.push(std::array::from_fn(|i| (v >> (40 - 8 * i)) as u8));
        }
        for m in macs {
            let v = m.iter().fold(0u64, |a, &x| a << 8 | x as u64);
            let want = list
                .iter()
                .filter(|(bits, key, _)| v >> (48 - *bits as u32) == *key)
                .max_by_key(|(bits, _, _)| *bits)
                .map(|(_, _, n)| n.as_str());
            let got = t.lookup(&m);
            match got {
                Answer::Vendor(x) => prop_assert_eq!(Some(x.name), want),
                Answer::Unknown => prop_assert_eq!(None, want),
                // special, group and local addresses are never a maker's, whatever the list says
                _ => prop_assert!(m[0] & 0x03 != 0 || got.kind() == "special"),
            }
        }
    }

    /// Any address written in any of the three forms reads back the same.
    #[test]
    fn addresses_round_trip(m in any::<[u8; 6]>(), upper in any::<bool>()) {
        let h: Vec<String> = m.iter().map(|b| if upper { format!("{b:02X}") } else { format!("{b:02x}") }).collect();
        prop_assert_eq!(parse_mac(&h.join(":")), Some(m));
        prop_assert_eq!(parse_mac(&h.join("-")), Some(m));
        prop_assert_eq!(parse_mac(&h.concat()), Some(m));
        let c = h.concat();
        prop_assert_eq!(parse_mac(&format!("{}.{}.{}", &c[..4], &c[4..8], &c[8..])), Some(m));
    }
}
