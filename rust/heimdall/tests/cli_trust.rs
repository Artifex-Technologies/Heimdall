//! `heimdalld trust` against the Go command: the fixture of what Go writes (testdata/parity/cli-trust.json: keys from seeds,
//! signed lists and their signatures byte for byte, the watch list, the mode), then the real binaries run step by step in
//! fake roots (every subcommand and error path, as root and as a user, files owned by the user restored as the user, links
//! refused), each binary reading what the other wrote, and properties of the signer.

mod common;
use common::*;
use heimdall::trust::{self, OwnerKey, SignedList, Store, WatchList};
use serde_json::Value;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn seed(s: &str) -> [u8; 32] {
    unhex(s).try_into().unwrap()
}

#[test]
fn the_owner_side_writes_what_go_writes() {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/parity/cli-trust.json");
    let fx: Value = serde_json::from_slice(&std::fs::read(p).expect("go test ./internal/parity -update")).unwrap();
    let mut n = 0;
    for k in fx["keys"].as_array().unwrap() {
        let s = seed(k["seed"].as_str().unwrap());
        let key = OwnerKey::from_seed(&s);
        assert_eq!(format!("{}\n", trust::std_base64_encode(&key.go_bytes(&s))), k["key"].as_str().unwrap());
        assert_eq!(format!("{}\n", trust::std_base64_encode(&key.public())), k["pub"].as_str().unwrap());
        // and Go's 64 bytes read back as the same key
        let go = trust::std_base64(k["key"].as_str().unwrap().trim()).unwrap();
        assert_eq!(OwnerKey::from_go(&go).unwrap().public(), key.public());
        n += 1;
    }
    for l in fx["lists"].as_array().unwrap() {
        let key = OwnerKey::from_seed(&seed(l["seed"].as_str().unwrap()));
        let mut m = SignedList {
            signed_at: heimdall::gotime::Time::parse_rfc3339(l["signed_at"].as_str().unwrap()).unwrap(),
            ..Default::default()
        };
        for f in l["files"].as_array().into_iter().flatten() {
            m.files.insert(unhex(f[0].as_str().unwrap()), f[1].as_str().unwrap().to_string());
        }
        let body = m.body();
        assert_eq!(body, l["body"].as_str().unwrap());
        assert_eq!(format!("{}\n", trust::std_base64_encode(&key.sign(body.as_bytes()))), l["sig"].as_str().unwrap());
        // the daemon's reader takes it as Go's would
        let d = std::env::temp_dir().join(format!("heimdall-cli-trust-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let st = Store::new(d.to_str().unwrap());
        std::fs::write(d.join("owner.pub"), format!("{}\n", trust::std_base64_encode(&key.public()))).unwrap();
        st.write_signed(&m, &key).unwrap();
        assert_eq!(std::fs::read_to_string(d.join("manifest.json")).unwrap(), l["body"].as_str().unwrap());
        assert_eq!(std::fs::read_to_string(d.join("manifest.sig")).unwrap(), l["sig"].as_str().unwrap());
        assert_eq!(st.load().unwrap().files.len(), m.files.len());
        std::fs::remove_dir_all(&d).unwrap();
        n += 1;
    }
    for w in fx["watch"].as_array().unwrap() {
        let list = |v: &Value| v.as_array().map(|a| a.iter().map(|x| x.as_str().unwrap().to_string()).collect());
        let wl = WatchList { files: list(&w["files"]), dirs: list(&w["dirs"]) };
        let d = std::env::temp_dir().join(format!("heimdall-cli-trust-w{}-{n}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let st = Store::new(d.to_str().unwrap());
        st.set_watch(&wl).unwrap();
        assert_eq!(std::fs::read_to_string(d.join("watch.json")).unwrap(), w["json"].as_str().unwrap());
        assert_eq!(st.watch(), wl, "read back");
        std::fs::remove_dir_all(&d).unwrap();
        n += 1;
    }
    for m in fx["modes"].as_array().unwrap() {
        let input = m["in"].as_str().unwrap();
        match trust::parse_mode(input) {
            Ok(mode) => {
                assert_eq!(mode, m["mode"].as_str().unwrap(), "{input:?}");
                let d = std::env::temp_dir().join(format!("heimdall-cli-trust-m{}-{n}", std::process::id()));
                std::fs::create_dir_all(&d).unwrap();
                Store::new(d.to_str().unwrap()).set_mode(mode).unwrap();
                assert_eq!(std::fs::read_to_string(d.join("mode")).unwrap(), m["file"].as_str().unwrap());
                std::fs::remove_dir_all(&d).unwrap();
            }
            Err(e) => assert_eq!(e, m["error"].as_str().unwrap(), "{input:?}"),
        }
        n += 1;
    }
    // the mesh: identities from seeds, the peer rule, the owner's edits of the peers file
    let m = &fx["mesh"];
    for id in m["identities"].as_array().unwrap() {
        let s = seed(id["seed"].as_str().unwrap());
        assert_eq!(heimdall::mesh::key_pem(&s), id["key_pem"].as_str().unwrap());
        let d = std::env::temp_dir().join(format!("heimdall-cli-mesh-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("key.pem"), id["key_pem"].as_str().unwrap()).unwrap();
        assert_eq!(heimdall::mesh::load_or_create(d.to_str().unwrap()).unwrap().fingerprint, id["fingerprint"].as_str().unwrap());
        std::fs::remove_dir_all(&d).unwrap();
        n += 1;
    }
    let peer = |v: &Value| heimdall::detect::Peer {
        name: v["name"].as_str().unwrap().into(),
        fingerprint: v["fingerprint"].as_str().unwrap().into(),
        address: v["address"].as_str().unwrap().into(),
    };
    for v in m["validate"].as_array().unwrap() {
        let p = peer(&v["peer"]);
        let want = v["error"].as_str().unwrap();
        assert_eq!(heimdall::mesh::validate_peer(&p).err().unwrap_or_default(), want, "{p:?}");
        assert_eq!(heimdall::detect::valid_peer(&p), want.is_empty(), "the detectors' rule agrees: {p:?}");
        n += 1;
    }
    for (i, sq) in m["sequences"].as_array().unwrap().iter().enumerate() {
        let d = std::env::temp_dir().join(format!("heimdall-cli-mesh-s{}-{i}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let path = d.join(format!("peers-{i}.json"));
        let p = path.to_str().unwrap();
        let start = sq["start"].as_str().unwrap();
        if start != "\0none" {
            std::fs::write(&path, start).unwrap();
        }
        for st in sq["steps"].as_array().unwrap() {
            let r = heimdall::mesh::set_peer(p, &peer(&st["peer"]), st["remove"].as_bool().unwrap_or(false));
            let names: Vec<String> = r.as_ref().map(|ps| ps.iter().map(|x| x.name.clone()).collect()).unwrap_or_default();
            let want: Vec<String> = st["names"].as_array().into_iter().flatten().map(|x| x.as_str().unwrap().to_string()).collect();
            assert_eq!(r.as_ref().err().map(|e| e.replace(d.to_str().unwrap(), "TMP")).unwrap_or_default(), st["error"].as_str().unwrap());
            assert_eq!(names, want);
            assert_eq!(std::fs::read_to_string(&path).unwrap_or_default(), st["file"].as_str().unwrap());
            assert_eq!(std::fs::read_dir(&d).unwrap().count(), usize::from(path.exists()), "no temporary file left");
            n += 1;
        }
        std::fs::remove_dir_all(&d).unwrap();
    }
    for b in fx["base64"].as_array().unwrap() {
        let bytes = unhex(b["hex"].as_str().unwrap());
        assert_eq!(trust::std_base64_encode(&bytes), b["text"].as_str().unwrap());
        assert_eq!(trust::std_base64(b["text"].as_str().unwrap()).unwrap(), bytes);
        n += 1;
    }
    assert!(n > 90, "{n} cases");
}

// ---- the real binaries, step by step in fake roots

const KEY_SEED: [u8; 32] = [7; 32];

/// A system with Sarina's files for the owner (uid 1000), Heimdall's config and /etc/sarina.
fn system(r: &Root) {
    r.write("/home/owner/.sarina/policy.json", "{\"allow\":[]}\n");
    r.write("/home/owner/.sarina/mcp.json", "{}\n");
    r.write("/home/owner/.sarina/skills/a.md", "skill a\n");
    r.write("/home/owner/.sarina/skills/sub/b.md", "skill b\n");
    r.write("/home/owner/.sarina/skills/c.md", "skill c <&> ünï\n");
    r.symlink("/etc/passwd", "/home/owner/.sarina/skills/link.md");
    r.write("/home/owner/.sarina/agents/x.md", "agent x\n");
    r.write("/etc/heimdall/config.json", "{\"agent_session_dir\":\"/var/lib/sarina/sessions\"}\n");
    r.write("/etc/sarina/service.conf", "port=8765\n");
    r.write("/srv/notes.txt", "not watched\n");
}

/// The owner's key from a fixed seed and an empty signed list, as `trust init` would leave them (signed at a known time).
fn planted_key(r: &Root) {
    let key = OwnerKey::from_seed(&KEY_SEED);
    r.write_mode("/etc/heimdall/trust/owner.key", format!("{}\n", trust::std_base64_encode(&key.go_bytes(&KEY_SEED))), 0o600);
    r.write("/etc/heimdall/trust/owner.pub", format!("{}\n", trust::std_base64_encode(&key.public())));
    r.write("/etc/heimdall/trust/mode", "off\n");
    let st = Store::new(r.host("/etc/heimdall/trust").to_str().unwrap());
    let m = SignedList { signed_at: heimdall::gotime::Time::parse_rfc3339("2026-11-10T08:00:00Z").unwrap(), ..Default::default() };
    st.write_signed(&m, &key).unwrap();
}

/// The user's files belong to the user (uid 1000) inside.
const CHOWN: &str = "chown -R 1000:1000 \"$R/home/owner\"\n";

/// One step: arguments, how it runs, and a shell line run as root inside first (changing files between steps).
struct Step {
    args: Vec<&'static str>,
    opts: Opts,
    before: &'static str,
}

fn step(args: &[&'static str]) -> Step {
    Step { args: args.to_vec(), opts: Opts::default(), before: "" }
}
fn user_step(args: &[&'static str]) -> Step {
    Step { args: args.to_vec(), opts: Opts::user(), before: "" }
}
fn after(before: &'static str, args: &[&'static str]) -> Step {
    Step { args: args.to_vec(), opts: Opts::default(), before }
}

/// What two runs may differ in: the time a list was signed (and so its signature) and, after `trust init`, the key.
fn norm_tree(t: std::collections::BTreeMap<String, String>, keys_differ: bool) -> std::collections::BTreeMap<String, String> {
    t.into_iter()
        .map(|(k, v)| {
            let v = if k.ends_with("/manifest.sig") || (keys_differ && (k.ends_with("/owner.key") || k.ends_with("/owner.pub"))) {
                v.split_once(' ').map(|(m, _)| format!("{m} <VARIES>")).unwrap_or(v)
            } else {
                normalize(&v)
            };
            (k, v)
        })
        .collect()
}

/// The owners of everything under the folders (the user's files must stay the user's).
fn owners(r: &Root, dirs: &[&str]) -> Vec<(String, u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    r.tree(dirs)
        .keys()
        .filter_map(|p| {
            // (a name that is not UTF-8 is in the tree under its lossy spelling, which names no file)
            let m = std::fs::symlink_metadata(r.host(p.trim_end_matches('/'))).ok()?;
            Some((p.clone(), m.uid(), m.gid()))
        })
        .collect()
}

/// Runs the steps in a Go root and a Rust root built alike, comparing every step's output, the calls to outside tools and
/// the files; then each binary reads what the other wrote (status and verify in the other's root).
fn steps(test: &str, build: impl Fn(&Root), keys_differ: bool, list: &[Step]) -> usize {
    let Some(go) = go_or_skip(test) else { return 0 };
    let rg = Root::new(&format!("{test}-go"));
    let rr = Root::new(&format!("{test}-rs"));
    build(&rg);
    build(&rr);
    let dirs = ["/etc/heimdall", "/home/owner", "/etc/sarina", "/srv"];
    for (i, s) in list.iter().enumerate() {
        let mut o = s.opts.clone();
        o.setup = format!("{CHOWN}{}", s.before);
        let g = rg.run(&go, &s.args, &o);
        let r = rr.run(&rust_bin(), &s.args, &o);
        let what = format!("{test} step {i}: {:?}", s.args);
        if std::env::var_os("HEIMDALL_SHOW_STEPS").is_some() {
            eprintln!("== {what}: exit {}\n{}{}", r.code, r.stdout, r.stderr);
        }
        let n = |x: &Out| Out { code: x.code, stdout: normalize(&x.stdout), stderr: normalize(&x.stderr) };
        assert_same(&what, &n(&g), &n(&r));
        assert_eq!(rg.calls(), rr.calls(), "{what}: calls");
        assert_eq!(norm_tree(rg.tree(&dirs), keys_differ), norm_tree(rr.tree(&dirs), keys_differ), "{what}: files");
        assert_eq!(owners(&rg, &dirs), owners(&rr, &dirs), "{what}: owners");
    }
    // each reads the other's files
    for args in [&["trust", "status"][..], &["trust", "verify"]] {
        let o = Opts::user();
        let own_go = rg.run(&go, args, &o);
        let rust_on_go = rg.run(&rust_bin(), args, &o);
        assert_same(&format!("{test}: Rust reading Go's files: {args:?}"), &own_go, &rust_on_go);
        let own_rs = rr.run(&rust_bin(), args, &o);
        let go_on_rust = rr.run(&go, args, &o);
        assert_same(&format!("{test}: Go reading Rust's files: {args:?}"), &own_rs, &go_on_rust);
    }
    list.len()
}

#[test]
fn trust_from_init_as_go() {
    let sudo = |s: Step| Step { opts: s.opts.env("SUDO_USER", "owner"), ..s };
    let n = steps(
        "trust-init",
        system,
        true,
        &[
            step(&["trust"]),
            step(&["trust", "nonsense"]),
            step(&["trust", "status"]),
            user_step(&["trust", "verify"]),
            step(&["trust", "mode", "watch"]),
            user_step(&["trust", "init"]),
            step(&["trust", "init", "--user", "nobody-here"]),
            step(&["trust", "init", "--nope"]),
            sudo(step(&["trust", "init"])),
            sudo(step(&["trust", "init"])),
            step(&["trust", "status"]),
            step(&["trust", "mode"]),
            step(&["trust", "mode", "loud"]),
            user_step(&["trust", "mode", "watch"]),
            step(&["trust", "mode", " watch "]),
            step(&["trust", "sign", "--watched"]),
            step(&["trust", "status"]),
            user_step(&["trust", "verify"]),
            step(&["trust", "mode", "enforce"]),
            step(&["trust", "mode", "off"]),
        ],
    );
    eprintln!("{n} steps");
}

#[test]
fn trust_signing_restoring_and_forgetting_as_go() {
    let build = |r: &Root| {
        system(r);
        planted_key(r);
        r.write(
            "/etc/heimdall/trust/watch.json",
            "{\"files\":[\"/home/owner/.sarina/policy.json\",\"/home/owner/.sarina/mcp.json\",\"/etc/heimdall/config.json\",\"/home/owner/.sarina/gone.json\"],\"dirs\":[\"/home/owner/.sarina/skills\",\"/etc/sarina\",\"/nowhere\"]}",
        );
    };
    let n = steps(
        "trust-sign",
        build,
        false,
        &[
            user_step(&["trust", "verify"]),
            user_step(&["trust", "sign", "/srv/notes.txt"]),
            step(&["trust", "sign"]),
            step(&["trust", "sign", "/nonexistent"]),
            step(&["trust", "sign", "/dev/null"]),
            step(&["trust", "sign", "srv/notes.txt"]),
            step(&["trust", "sign", "--watched"]),
            step(&["trust", "sign", "/home/owner/.sarina/agents", "/home/owner/.sarina/agents/x.md"]),
            step(&["trust", "status"]),
            user_step(&["trust", "verify"]),
            user_step(&["trust", "verify", "/home/owner/.sarina/skills", "/srv"]),
            user_step(&["trust", "verify", "/missing"]),
            step(&["trust", "restore"]),
            after("echo changed > \"$R/home/owner/.sarina/policy.json\"; rm \"$R/home/owner/.sarina/skills/sub/b.md\"; echo planted > \"$R/home/owner/.sarina/skills/new.md\"; echo edited > \"$R/etc/sarina/service.conf\"", &["trust", "verify"]),
            step(&["trust", "restore", "/home/owner/.sarina/skills"]),
            step(&["trust", "restore"]),
            step(&["trust", "restore"]),
            after("rm -r \"$R/home/owner/.sarina/skills/sub\"; mkdir \"$R/elsewhere\"; ln -s /elsewhere \"$R/home/owner/.sarina/skills/sub\"", &["trust", "restore"]),
            after("rm \"$R/home/owner/.sarina/skills/sub\"; rm \"$R/etc/heimdall/trust/approved/\"*", &["trust", "restore"]),
            step(&["trust", "forget"]),
            step(&["trust", "forget", "/home/owner/.sarina/skills/", "/home/owner/.sarina/agents/x.md", "/not/signed"]),
            step(&["trust", "status"]),
            user_step(&["trust", "verify"]),
            step(&["trust", "watch"]),
            step(&["trust", "watch", "add"]),
            step(&["trust", "watch", "touch", "/a"]),
            user_step(&["trust", "watch", "add", "/a"]),
            step(&["trust", "watch", "add", "/srv", "/srv/notes.txt", "rel/x", "/home/owner/.sarina/skills"]),
            step(&["trust", "watch", "remove", "/srv", "/srv/notes.txt", "/rel/x", "/home/owner/.sarina/policy.json", "/home/owner/.sarina/mcp.json", "/etc/heimdall/config.json", "/home/owner/.sarina/gone.json"]),
            step(&["trust", "watch", "remove", "/home/owner/.sarina/skills", "/etc/sarina", "/nowhere"]),
            step(&["trust", "status"]),
            after("mkdir -p \"$R/big\"; i=0; while [ $i -le 5000 ]; do : > \"$R/big/f$i\"; i=$((i+1)); done", &["trust", "sign", "/big"]),
            after("rm -r \"$R/big\"; echo tampered >> \"$R/etc/heimdall/trust/manifest.json\"", &["trust", "status"]),
            user_step(&["trust", "verify"]),
            step(&["trust", "sign", "/srv/notes.txt"]),
            step(&["trust", "restore"]),
            after("rm \"$R/etc/heimdall/trust/owner.key\"", &["trust", "forget", "/srv"]),
        ],
    );
    eprintln!("{n} steps");
}

#[test]
fn trust_with_names_that_are_not_utf8_as_go() {
    // Go keeps such a name's bytes (signed, printed as they are) and writes U+FFFD for each bad byte in the list
    let bad = "echo x > \"$R/srv/name-$(printf '\\377\\376')-cut-$(printf '\\342\\204')\"";
    steps(
        "trust-bytes",
        |r: &Root| {
            system(r);
            planted_key(r);
        },
        false,
        &[
            Step { args: vec!["trust", "sign", "/srv"], opts: Opts::default(), before: Box::leak(bad.to_string().into_boxed_str()) },
            user_step(&["trust", "verify", "/srv"]),
            user_step(&["trust", "verify"]),
            step(&["trust", "status"]),
            step(&["trust", "restore"]),
            step(&["trust", "forget", "/srv"]),
        ],
    );
}

#[test]
fn trust_with_a_test_folder_as_go() {
    // HEIMDALL_TRUST_DIR: Go's tests' folder, no root needed and no restart asked for
    let o = |args: &[&'static str]| Step { args: args.to_vec(), opts: Opts::user().env("HEIMDALL_TRUST_DIR", "/tmp/t"), before: "" };
    steps(
        "trust-dir",
        |r: &Root| {
            system(r);
            r.mkdir("/tmp/t", 0o777);
        },
        true,
        &[o(&["trust", "init"]), o(&["trust", "mode", "watch"]), o(&["trust", "sign", "/srv/notes.txt"]), o(&["trust", "status"])],
    );
}

mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 200, ..ProptestConfig::default() })]

        /// Go's base64 reader takes back what the writer wrote, for any bytes.
        #[test]
        fn base64_round_trips(b in proptest::collection::vec(any::<u8>(), 0..100)) {
            prop_assert_eq!(trust::std_base64(&trust::std_base64_encode(&b)).unwrap(), b);
        }

        /// Any list signed by the owner's key reads back with the same entries (paths that are UTF-8), and a change of one
        /// byte of the body is refused.
        #[test]
        fn a_signed_list_reads_back(seed in any::<[u8; 32]>(), files in proptest::collection::btree_map("/[ -~]{0,12}", "[0-9a-f]{0,64}", 0..6), flip in any::<usize>()) {
            let key = OwnerKey::from_seed(&seed);
            let m = SignedList { signed_at: heimdall::gotime::Time::parse_rfc3339("2026-11-10T08:00:00Z").unwrap(), files: files.iter().map(|(k, v)| (k.as_bytes().to_vec(), v.clone())).collect() };
            let d = std::env::temp_dir().join(format!("heimdall-cli-trust-p{}-{}", std::process::id(), flip));
            std::fs::create_dir_all(&d).unwrap();
            let st = Store::new(d.to_str().unwrap());
            std::fs::write(d.join("owner.pub"), format!("{}\n", trust::std_base64_encode(&key.public()))).unwrap();
            st.write_signed(&m, &key).unwrap();
            let back = st.load().unwrap();
            prop_assert_eq!(back.files, files);
            let mut body = std::fs::read(d.join("manifest.json")).unwrap();
            let i = flip % body.len();
            body[i] ^= 1;
            std::fs::write(d.join("manifest.json"), &body).unwrap();
            prop_assert!(st.load().is_err());
            std::fs::remove_dir_all(&d).unwrap();
        }
    }
}
