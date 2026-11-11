//! The command line as a whole against the Go heimdalld, in fake roots (tests/common): version, help, a missing or unknown
//! command, the hidden write-as-owner command; and the fake root itself (what the commands under test can and cannot reach).

mod common;
use common::*;

#[test]
fn version_help_and_unknown_commands_as_go() {
    for args in [&["version"][..], &[], &["help"], &["-h"], &["--help"]] {
        let Some(((g, _), (r, _))) = both("cli-basic", |_| {}, args, &Opts::default()) else { return };
        assert_eq!(g.code, r.code, "{args:?}");
        assert_eq!(g.stdout, r.stdout, "{args:?}");
        // help: Go's text, then the Rust-only commands
        assert!(r.stderr.starts_with(&g.stderr), "{args:?}: {}", r.stderr);
    }
    // an unknown command, with no Go binary beside to hand it to
    let Some(((g, _), (r, _))) = both("cli-unknown", |_| {}, &["frobnicate", "x"], &Opts::default()) else { return };
    assert_eq!((g.code, r.code), (2, 2));
    assert!(r.stderr.starts_with(&g.stderr[..g.stderr.find("Usage").unwrap()]));
}

#[test]
fn write_as_owner_child_as_go() {
    for (args, stdin) in [
        (&["__write-as-owner"][..], &b""[..]),
        (&["__write-as-owner", "/tmp/x", "9", "0", "false"], b""),
        (&["__write-as-owner", "/tmp/x", "640", "x", "false"], b""),
        (&["__write-as-owner", "/tmp/a/b/new", "640", "1700000000123456789", "false"], b"hello"),
        (&["__write-as-owner", "/tmp/a/b/new", "600", "0", "true"], b"again"),
        (&["__write-as-owner", "/tmp/link/x", "644", "0", "false"], b"through a link"),
    ] {
        let build = |r: &Root| {
            r.mkdir("/tmp/real", 0o755);
            r.symlink("/tmp/real", "/tmp/link");
            if args.len() == 5 && args[4] == "true" {
                r.write("/tmp/a/b/new", "already");
            }
        };
        let o = Opts::user().stdin(stdin);
        let Some(((g, rg), (r, rr))) = both("cli-writeas", build, args, &o) else { return };
        assert_same(&format!("{args:?}"), &g, &r);
        assert_eq!(rg.tree(&["/tmp"]), rr.tree(&["/tmp"]), "{args:?}");
        if args.len() == 5 && args[3] != "0" && g.code == 0 {
            let m = |root: &Root| std::fs::metadata(root.host("/tmp/a/b/new")).unwrap();
            use std::os::unix::fs::MetadataExt;
            assert_eq!((m(&rg).mtime(), m(&rg).mtime_nsec()), (m(&rr).mtime(), m(&rr).mtime_nsec()));
        }
    }
}

#[test]
fn the_fake_root_keeps_the_command_in() {
    let r = Root::new("cli-fence");
    r.tool("frob", "echo frobbed \"$@\"\n");
    // the shell stands in for the binary under test here: what can a command in the root see and do?
    let sh = std::path::PathBuf::from("/usr/bin/sh");
    let o = r.run_as(
        "/usr/bin/probe",
        &sh,
        &[
            "-c",
            "id -u; systemctl stop sarina-service; echo $?; frob a; cat /etc/hostname; ls /home; touch /usr/lib/x 2>/dev/null || echo ro",
        ],
        &Opts::default(),
    );
    assert_eq!(o.stdout, "0\n1\nfrobbed a\ntesthost\nowner\nro\n", "{}", o.stderr);
    assert_eq!(r.calls(), "systemctl stop sarina-service\nfrob a\n");
    let o = r.run_as("/usr/bin/probe", &sh, &["-c", "id -u; ip -o link 2>&1 | wc -l"], &Opts { net: true, ..Opts::user() });
    assert!(o.stdout.starts_with("1000\n"), "{o:?}");
}

#[test]
fn normalize_hides_times() {
    assert_eq!(normalize("at 2026-11-10T20:01:02.5+01:00 and 2026/11/10 20:01:02 x"), "at <TIME> and <STAMP> x");
    assert_eq!(normalize("last scan 2026-11-10 20:01:02, seen 2026-11-10 20:01"), "last scan <TIME>, seen <TIME>");
}
