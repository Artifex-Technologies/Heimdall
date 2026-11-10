//! Properties of the audits' rules (proptest): pacman's version comparison is an order and agrees with pacman's own
//! `vercmp` where it is installed; kernel versions order totally; a reported hole is always one a newer kernel fixes; the
//! package matcher only reports installed packages older than the fix.

use heimdall::audit::{kernel, pkg, vercmp};
use proptest::prelude::*;
use std::collections::BTreeMap;

fn version() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        prop_oneof![
            Just("0"),
            Just("1"),
            Just("2"),
            Just("10"),
            Just("01"),
            Just("a"),
            Just("rc"),
            Just("beta"),
            Just("."),
            Just("-"),
            Just(":"),
            Just("_"),
            Just("+"),
            Just("~"),
        ],
        0..8,
    )
    .prop_map(|p| p.concat())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2000, ..ProptestConfig::default() })]

    #[test]
    fn vercmp_is_antisymmetric_and_reflexive(a in version(), b in version()) {
        prop_assert_eq!(vercmp::vercmp(a.as_bytes(), b.as_bytes()), -vercmp::vercmp(b.as_bytes(), a.as_bytes()));
        prop_assert_eq!(vercmp::vercmp(a.as_bytes(), a.as_bytes()), 0);
    }

    #[test]
    fn kernel_versions_order_totally(a in proptest::collection::vec(0i64..5, 0..5), b in proptest::collection::vec(0i64..5, 0..5),
                                     c in proptest::collection::vec(0i64..5, 0..5)) {
        prop_assert_eq!(kernel::compare(&a, &b), -kernel::compare(&b, &a));
        if kernel::compare(&a, &b) <= 0 && kernel::compare(&b, &c) <= 0 {
            prop_assert!(kernel::compare(&a, &c) <= 0);
        }
    }

    #[test]
    fn a_reported_hole_is_one_a_newer_kernel_fixes(k in (5i64..8, 0i64..20, 0i64..60),
                                                   ranges in proptest::collection::vec(((5i64..8, 0i64..20, 0i64..60), proptest::option::of((5i64..8, 0i64..20, 0i64..60))), 1..5)) {
        let v = |t: (i64, i64, i64)| format!("{}.{}.{}", t.0, t.1, t.2);
        let f = kernel::File {
            vulns: vec![kernel::Vuln {
                id: "CVE-1".into(),
                ranges: ranges.iter().map(|(i, x)| kernel::Range { introduced: v(*i), fixed: x.map(v).unwrap_or_default() }).collect(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let kv = v(k) + "-1-lts";
        let (holes, fix_all) = kernel::check(&f, &kv);
        prop_assert!(holes.len() <= 1);
        for h in &holes {
            prop_assert!(kernel::compare(&kernel::version(&kv), &kernel::version(&h.fixed_in)) < 0);
            prop_assert_eq!(&h.fixed_in, &fix_all);
            // never when the fix reached its own line at or before it
            prop_assert!(!f.vulns[0].ranges.iter().any(|r| !r.fixed.is_empty()
                && kernel::line(&kernel::version(&r.fixed)) == kernel::line(&kernel::version(&kv))
                && kernel::compare(&kernel::version(&kv), &kernel::version(&r.fixed)) >= 0));
        }
    }

    #[test]
    fn a_package_is_reported_only_when_installed_and_older_than_the_fix(installed in version(), fixed in version(), name in "[a-c]") {
        let inst = BTreeMap::from([(b"a".to_vec(), installed.clone().into_bytes())]);
        let g = pkg::Group { name: "AVG-1".into(), packages: vec![name.clone()], status: "Fixed".into(), fixed: fixed.clone(), ..Default::default() };
        let found = pkg::check(&[g], &inst);
        let want = name == "a" && !fixed.is_empty() && vercmp::vercmp(installed.as_bytes(), fixed.as_bytes()) < 0;
        prop_assert_eq!(!found.is_empty(), want);
    }
}

/// pacman's own `vercmp` is the oracle (Go's test does the same); skipped where pacman is not installed.
#[test]
fn vercmp_agrees_with_pacman() {
    let bin = "/usr/bin/vercmp";
    if !std::path::Path::new(bin).exists() {
        return;
    }
    let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig { cases: 300, ..ProptestConfig::default() });
    runner
        .run(&(version(), version()), |(a, b)| {
            // Go's Vercmp (and so the port) differs from pacman on an empty release ("1-" against "1-0": pacman compares
            // "" with "0", Go treats an empty release as none); pacman never writes such a version (docs/RUST_PORT.md)
            if a.ends_with('-') || b.ends_with('-') {
                return Ok(());
            }
            let out = std::process::Command::new(bin).arg(&a).arg(&b).output().unwrap();
            let want: i32 = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap();
            prop_assert_eq!(vercmp::vercmp(a.as_bytes(), b.as_bytes()), want.signum(), "{:?} {:?}", a, b);
            Ok(())
        })
        .unwrap();
}

/// The Kani harnesses' claim over every version of up to three characters from a small alphabet, without Kani.
#[test]
fn vercmp_is_antisymmetric_exhaustively() {
    let alpha = *b"01a.-:";
    let mut all = vec![Vec::new()];
    for len in 1..=3 {
        let mut idx = vec![0usize; len];
        loop {
            all.push(idx.iter().map(|&i| alpha[i]).collect::<Vec<u8>>());
            let mut k = 0;
            while k < len {
                idx[k] += 1;
                if idx[k] < alpha.len() {
                    break;
                }
                idx[k] = 0;
                k += 1;
            }
            if k == len {
                break;
            }
        }
    }
    for a in &all {
        for b in &all {
            assert_eq!(vercmp::vercmp(a, b), -vercmp::vercmp(b, a), "{a:?} {b:?}");
        }
    }
}
