//! `heimdalld mesh` against the Go command, step by step in fake roots: the key made by each read by the other (`init` again
//! and `id` print the same fingerprint), a known key giving the same fingerprint byte for byte, the peers file edited the same
//! way (enrol, replace, forget, flags after the words), and every refusal (not root, no terminal, an agent's sudo, a peers
//! file that is not root's, writable by others, a link, damaged, in a missing folder).

mod common;
use common::*;
use heimdall::mesh;

const FP1: &str = "hm1-copdsqhgjnkjc4rardm2bv2bmkh4qjxa"; // the zero seed's (testdata/parity/cli-trust.json)

struct Step {
    args: Vec<&'static str>,
    opts: Opts,
    before: &'static str,
}

fn root(args: &[&'static str]) -> Step {
    Step { args: args.to_vec(), opts: Opts::default(), before: "" }
}
fn user(args: &[&'static str]) -> Step {
    Step { args: args.to_vec(), opts: Opts::user(), before: "" }
}
fn after(before: &'static str, args: &[&'static str]) -> Step {
    Step { args: args.to_vec(), opts: Opts::default(), before }
}

/// What two runs with keys made at random differ in: the fingerprint and the key file.
fn norm(s: &str, random_keys: bool) -> String {
    if !random_keys {
        return normalize(s);
    }
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find("hm1-") {
        out.push_str(&rest[..i]);
        let tail = &rest[i + 4..];
        let n = tail.bytes().take_while(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(c)).count();
        out.push_str(if n == 32 { "<FP>" } else { "hm1-" });
        rest = if n == 32 { &tail[32..] } else { tail };
    }
    out.push_str(rest);
    normalize(&out)
}

/// The random digits of Go's (and the port's) temporary peers file name.
fn no_temp_digits(s: &str) -> String {
    match s.find(".mesh-peers-") {
        Some(i) => {
            let tail = &s[i + 12..];
            let n = tail.bytes().take_while(u8::is_ascii_digit).count();
            format!("{}.mesh-peers-<N>{}", &s[..i], &tail[n..])
        }
        None => s.to_string(),
    }
}

fn steps(test: &str, build: impl Fn(&Root), random_keys: bool, list: &[Step]) -> usize {
    let Some(go) = go_or_skip(test) else { return 0 };
    let rg = Root::new(&format!("{test}-go"));
    let rr = Root::new(&format!("{test}-rs"));
    build(&rg);
    build(&rr);
    let dirs = ["/etc/heimdall", "/var/lib/heimdall"];
    let tree = |r: &Root| {
        use std::os::unix::fs::MetadataExt;
        r.tree(&dirs)
            .into_iter()
            .map(|(k, v)| {
                let v =
                    if random_keys && k.ends_with("/key.pem") { v.split_once(' ').unwrap().0.to_string() } else { norm(&v, random_keys) };
                let m = std::fs::symlink_metadata(r.host(k.trim_end_matches('/'))).unwrap();
                (k, v, m.uid(), m.gid())
            })
            .collect::<Vec<_>>()
    };
    for (i, s) in list.iter().enumerate() {
        let mut o = s.opts.clone();
        o.setup = s.before.to_string();
        let g = rg.run(&go, &s.args, &o);
        let r = rr.run(&rust_bin(), &s.args, &o);
        let what = format!("{test} step {i}: {:?}", s.args);
        if std::env::var_os("HEIMDALL_SHOW_STEPS").is_some() {
            eprintln!("== {what}: exit {}\n{}{}", r.code, r.stdout, r.stderr);
        }
        let n = |x: &Out| Out { code: x.code, stdout: norm(&x.stdout, random_keys), stderr: no_temp_digits(&norm(&x.stderr, random_keys)) };
        assert_same(&what, &n(&g), &n(&r));
        assert_eq!(tree(&rg), tree(&rr), "{what}: files");
    }
    // each reads the key the other made: init (kept) and id print the fingerprint the maker printed
    if std::path::Path::new(&rg.host("/var/lib/heimdall/mesh/key.pem")).exists() {
        for args in [&["mesh", "init"][..], &["mesh", "id"]] {
            let o = Opts::default();
            assert_same(&format!("{test}: Rust reading Go's key: {args:?}"), &rg.run(&go, args, &o), &rg.run(&rust_bin(), args, &o));
            assert_same(&format!("{test}: Go reading Rust's key: {args:?}"), &rr.run(&rust_bin(), args, &o), &rr.run(&go, args, &o));
        }
    }
    list.len()
}

#[test]
fn mesh_keys_as_go() {
    let n = steps(
        "mesh-keys",
        |_| {},
        true,
        &[
            root(&["mesh"]),
            root(&["mesh", "bogus"]),
            root(&["mesh", "bogus", "--nope"]),
            root(&["mesh", "id"]),
            user(&["mesh", "init"]),
            root(&["mesh", "init", "--nope"]),
            root(&["mesh", "init", "--dir"]),
            root(&["mesh", "init"]),
            root(&["mesh", "init"]),
            root(&["mesh", "id"]),
            user(&["mesh", "id"]),
            user(&["mesh", "init", "--dir", "/tmp/mine"]),
            user(&["mesh", "id", "--dir=/tmp/mine"]),
            after("mkdir -p \"$R/tmp/file\"; : > \"$R/tmp/file/key.pem\"", &["mesh", "init", "--dir", "/tmp/file"]),
            after(
                "printf -- '-----BEGIN PUBLIC KEY-----\\nAAAA\\n-----END PUBLIC KEY-----\\n' > \"$R/tmp/file/key.pem\"",
                &["mesh", "init", "--dir", "/tmp/file"],
            ),
        ],
    );
    eprintln!("{n} steps");
}

#[test]
fn mesh_peers_as_go() {
    let known_key = |r: &Root| {
        r.write_mode("/var/lib/heimdall/mesh/key.pem", mesh::key_pem(&[0; 32]), 0o600);
        r.mkdir("/etc/heimdall", 0o755);
    };
    let test_peers = "/etc/heimdall/test-peers.json";
    let fp2 = "HM1-72ASYEXTVNGONVTT6ZRTQZHU5R5K3PXQ"; // upper case: enrol writes it lower case
    let _ = fp2;
    let n = steps(
        "mesh-peers",
        known_key,
        false,
        &[
            root(&["mesh", "init"]),
            root(&["mesh", "id"]),
            root(&["mesh", "list"]),
            root(&["mesh", "enroll"]),
            root(&["mesh", "enroll", "pc", FP1]),
            root(&["mesh", "forget"]),
            user(&["mesh", "enroll", "pc", FP1, "100.64.0.2:8931"]),
            root(&["mesh", "enroll", "pc", FP1, "100.64.0.2:8931"]),
            root(&["mesh", "enroll", "pc", FP1, "100.64.0.2:8931", "--peers", test_peers]),
            root(&["mesh", "enroll", "desk", "HM1-72ASYEXTVNGONVTT6ZRTQZHU5R5K3PXQ", "[fd00::2]:8931", "--peers", test_peers]),
            root(&["mesh", "enroll", "--peers", test_peers, "pc", FP1, "100.64.0.3:8931"]),
            root(&["mesh", "enroll", "--peers", test_peers, "Bad", FP1, "100.64.0.3:8931"]),
            root(&["mesh", "enroll", "--peers", test_peers, "x", "hm1-short", "100.64.0.3:8931"]),
            root(&["mesh", "enroll", "--peers", test_peers, "x", FP1, "laptop.lan:8931"]),
            root(&["mesh", "enroll", "--peers", test_peers, "x", FP1, "0.0.0.0:8931"]),
            root(&["mesh", "list", "--peers", test_peers]),
            user(&["mesh", "list", "--peers", test_peers]),
            Step {
                args: vec!["mesh", "forget", "pc", "--peers", "/etc/heimdall/test-peers.json"],
                opts: Opts::default().env("SUDO_USER", "sarina"),
                before: "",
            },
            root(&["mesh", "forget", "pc", "--peers", test_peers]),
            root(&["mesh", "forget", "nobody", "--peers", test_peers]),
            root(&["mesh", "forget", "desk", "--peers", test_peers]),
            root(&["mesh", "list", "--peers", test_peers]),
            after("chown 1000:1000 \"$R/etc/heimdall/test-peers.json\"", &["mesh", "list", "--peers", test_peers]),
            after(
                "chown 0:0 \"$R/etc/heimdall/test-peers.json\"; chmod 664 \"$R/etc/heimdall/test-peers.json\"",
                &["mesh", "enroll", "a", FP1, "1.2.3.4:5", "--peers", test_peers],
            ),
            after(
                "chmod 644 \"$R/etc/heimdall/test-peers.json\"; ln -sf test-peers.json \"$R/etc/heimdall/link.json\"",
                &["mesh", "list", "--peers", "/etc/heimdall/link.json"],
            ),
            after("printf '[{\"name\":5}]' > \"$R/etc/heimdall/test-peers.json\"", &["mesh", "list", "--peers", test_peers]),
            after(
                "printf '{\"x\":' > \"$R/etc/heimdall/test-peers.json\"",
                &["mesh", "enroll", "a", FP1, "1.2.3.4:5", "--peers", test_peers],
            ),
            root(&["mesh", "enroll", "a", FP1, "1.2.3.4:5", "--peers", "/nowhere/peers.json"]),
            root(&["mesh", "list", "--peers", "/nowhere/peers.json"]),
        ],
    );
    eprintln!("{n} steps");
}

mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 200, ..ProptestConfig::default() })]

        /// The owner's rule with messages and the detectors' yes-or-no rule always agree.
        #[test]
        fn the_two_peer_rules_agree(name in "[a-zA-Z0-9 -]{0,34}", fp in "(hm1-|HM1-|x)[a-z2-9]{30,33}", addr in "[0-9a-f.:\\[\\]%a-z]{0,24}") {
            let p = heimdall::detect::Peer { name, fingerprint: fp, address: addr };
            prop_assert_eq!(mesh::validate_peer(&p).is_ok(), heimdall::detect::valid_peer(&p));
        }

        /// A key file from any seed reads back as the same key.
        #[test]
        fn a_key_file_reads_back(seed in any::<[u8; 32]>()) {
            let d = std::env::temp_dir().join(format!("heimdall-cli-mesh-p{}-{}", std::process::id(), seed[0]));
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("key.pem"), mesh::key_pem(&seed)).unwrap();
            let id = mesh::load_or_create(d.to_str().unwrap()).unwrap();
            let key = heimdall::trust::OwnerKey::from_seed(&seed);
            prop_assert_eq!(id.fingerprint, mesh::fingerprint(&key.public()));
            std::fs::remove_dir_all(&d).unwrap();
        }
    }
}
