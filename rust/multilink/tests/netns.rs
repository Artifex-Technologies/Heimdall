//! The service in a made-up network (tests/netns.sh): spreading, weights, failover, backup, share limit, data cap, the VPN
//! pause, and the clean restore after a stop or a crash, in IPv4 and IPv6. It runs in a user + network + mount namespace
//! of its own (`unshare -rnm`), so it never touches this computer's real network. Where such namespaces are not allowed
//! (some containers), it says so and passes; CI allows them.

use std::process::Command;

#[test]
fn the_service_in_a_made_up_network() {
    let here = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let probe = Command::new("unshare").args(["-rnm", "ip", "link", "add", "t0", "type", "veth", "peer", "name", "t1"]).output();
    if !probe.as_ref().is_ok_and(|o| o.status.success()) {
        eprintln!("skipped: no user and network namespaces with veth here ({probe:?})");
        return;
    }
    let dir = std::env::temp_dir().join(format!("multilink-netns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let out = Command::new("unshare")
        .args(["-rnm", "sh"])
        .arg(here.join("netns.sh"))
        .arg(env!("CARGO_BIN_EXE_heimdall-multilink"))
        .arg(here.join("netns_helper.py"))
        .arg(&dir)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    println!("{text}");
    eprintln!("{}", String::from_utf8_lossy(&out.stderr));
    let _ = std::fs::remove_dir_all(&dir);
    assert!(out.status.success() && text.contains("passed"), "the namespace test failed");
}
