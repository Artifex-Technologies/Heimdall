//! `heimdalld ipdb-check`, `intel-check`, `origin` and `kernel-check` against the Go binary, in fake roots: the same files in,
//! the same output, exit codes and files out (the kernel list's time aside).

mod common;
use common::*;
use std::io::Write;

fn parity(name: &str) -> Vec<u8> {
    std::fs::read(repo().join("testdata/parity").join(name)).unwrap()
}

fn same(test: &str, build: impl Fn(&Root), args: &[&str], o: &Opts, trees: &[&str]) -> Option<(Out, Out)> {
    let ((g, rg), (r, rr)) = both(test, build, args, o)?;
    let norm = |o: &Out| Out { code: o.code, stdout: normalize(&o.stdout), stderr: normalize(&o.stderr) };
    assert_same(&format!("{test} {args:?}"), &norm(&g), &norm(&r));
    let t = |root: &Root| -> Vec<(String, String)> { root.tree(trees).into_iter().map(|(k, v)| (k, normalize(&v))).collect() };
    assert_eq!(t(&rg), t(&rr), "{test} {args:?}: files differ");
    Some((g, r))
}

#[test]
fn ipdb_check_as_go() {
    let country = parity("synthetic-country.mmdb");
    let asn = parity("synthetic-asn.mmdb");
    let build = |r: &Root| {
        r.write("/db/country.mmdb", &country);
        r.write("/db/asn.mmdb", &asn);
        r.write("/db/half.mmdb", &country[..country.len() / 2]);
        r.write("/db/tail.mmdb", &country[country.len() / 2..]);
        r.write("/db/empty.mmdb", b"");
        r.write("/db/junk.mmdb", b"<html>not found</html>\n");
        let mut marker = b"\xab\xcd\xefMaxMind.com".to_vec();
        marker.extend_from_slice(b"\x01\x02");
        r.write("/db/marker.mmdb", &marker);
        r.mkdir("/db/folder.mmdb", 0o755);
        r.write_mode("/db/locked.mmdb", &country, 0o000);
    };
    for args in [
        &["ipdb-check"][..],
        &["ipdb-check", "/db/country.mmdb"],
        &["ipdb-check", "/db/asn.mmdb", "/db/country.mmdb"],
        &["ipdb-check", "/db/half.mmdb", "/db/tail.mmdb", "/db/empty.mmdb", "/db/junk.mmdb", "/db/marker.mmdb"],
        &["ipdb-check", "/db/missing.mmdb", "/db/folder.mmdb", "/db/country.mmdb"],
    ] {
        same("ipdb", build, args, &Opts::default(), &[]);
        same("ipdb-user", build, args, &Opts::user(), &[]);
    }
    // a file the user cannot read
    same("ipdb-locked", build, &["ipdb-check", "/db/locked.mmdb"], &Opts::user(), &[]);
}

/// A threat list of `n` made-up public networks (documentation-free: plain public ranges, nothing real meant).
fn list(n: usize, start: u32) -> String {
    let mut s = String::from("# made up\n; comment\n\n");
    for i in 0..n {
        let a = start + i as u32;
        match i % 5 {
            0 => s += &format!("{}.{}.{}.0/24 ; SBL{i}\n", 11 + a / 65536 % 200, a / 256 % 256, a % 256),
            1 => s += &format!("{}.{}.{}.7\n", 11 + a / 65536 % 200, a / 256 % 256, a % 256),
            2 => s += &format!("{{\"cidr\":\"{}.{}.{}.0/25\",\"sblid\":\"x\"}}\n", 11 + a / 65536 % 200, a / 256 % 256, a % 256),
            3 => s += &format!("2a0{}:{:x}::/48 # v6\n", i % 9, a % 65536),
            _ => s += &format!("  {}.{}.{}.0/26\tx y\n", 11 + a / 65536 % 200, a / 256 % 256, a % 256),
        }
    }
    s += "10.0.0.0/8\n192.168.1.1\n1.0.0.0/4\nnot-an-address\n{\"type\":\"metadata\",\"timestamp\":1}\n";
    s
}

#[test]
fn intel_check_lists_and_trackers_as_go() {
    let tracker = |n: usize| -> String {
        let g: Vec<String> = (0..n)
            .map(|i| {
                format!(
                    r#"{{"name":"AVG-{i}","packages":["pkg{i}"],"status":"Fixed","severity":"High","type":"x","affected":"1.0-1","fixed":"1.1-1","issues":["CVE-2026-{i}"]}}"#
                )
            })
            .collect();
        format!("[{}]", g.join(","))
    };
    let build = |r: &Root| {
        r.write("/in/good.list", list(40, 100));
        r.write("/in/prev.list", list(40, 100));
        r.write("/in/grown.list", format!("{}{}", list(40, 100), "12.0.0.0/8\n13.0.0.0/8\n"));
        r.write("/in/shrunk.list", list(12, 100));
        r.write("/in/small.list", list(5, 100));
        r.write("/in/empty.list", "# nothing\n");
        r.write("/in/html.list", "<html><body>503</body></html>\n");
        let mut long = list(20, 300);
        long += &"x".repeat(1 << 20);
        long += "\n";
        long += &list(20, 900);
        r.write("/in/longline.list", long);
        r.write("/in/crlf.list", list(30, 500).replace('\n', "\r\n"));
        r.write("/in/tracker.json", tracker(120));
        r.write("/in/short.json", tracker(99));
        r.write("/in/bad.json", "{\"not\":\"a list\"}");
        r.write("/in/typo.json", "[{\"name\":1}]");
        r.write("/in/syntax.json", "[{\"name\":");
        r.mkdir("/in/folder", 0o755);
    };
    for args in [
        &["intel-check"][..],
        &["intel-check", "list"],
        &["intel-check", "list", "/in/good.list"],
        &["intel-check", "list", "/in/good.list", "/in/prev.list"],
        &["intel-check", "list", "/in/grown.list", "/in/prev.list"],
        &["intel-check", "list", "/in/shrunk.list", "/in/prev.list"],
        &["intel-check", "list", "/in/good.list", "/in/missing.list"],
        &["intel-check", "list", "/in/good.list", "/in/html.list"],
        &["intel-check", "list", "/in/small.list"],
        &["intel-check", "list", "/in/empty.list"],
        &["intel-check", "list", "/in/html.list"],
        &["intel-check", "list", "/in/longline.list"],
        &["intel-check", "list", "/in/crlf.list"],
        &["intel-check", "list", "/in/missing.list"],
        &["intel-check", "list", "/in/folder"],
        &["intel-check", "tracker", "/in/tracker.json"],
        &["intel-check", "tracker", "/in/short.json"],
        &["intel-check", "tracker", "/in/bad.json"],
        &["intel-check", "tracker", "/in/typo.json"],
        &["intel-check", "tracker", "/in/syntax.json"],
        &["intel-check", "tracker", "/in/missing.json"],
        &["intel-check", "tracker", "/in/tracker.json", "x"],
        &["intel-check", "other", "/in/good.list"],
        &["intel-check", "other", "/in/missing"],
        &["intel-check", "kernel", "/in/good.list"],
        &["intel-check", "a", "b", "c", "d", "e"],
    ] {
        let (g, _) = same("intel", build, args, &Opts::default(), &[]).unwrap_or_default();
        if matches!(args.get(1), Some(&"list" | &"tracker"))
            && matches!(args.get(2), Some(&"/in/good.list" | &"/in/tracker.json"))
            && args.len() == 3
        {
            assert_eq!(g.code, 0, "{args:?}: {g:?}");
        }
    }
}

/// A zip archive as Go's writer makes one (stored or deflated entries, a central directory, the end record).
fn zip(entries: &[(&str, Vec<u8>, bool)], zip64: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data, deflate) in entries {
        let body = if *deflate {
            let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(data).unwrap();
            e.finish().unwrap()
        } else {
            data.clone()
        };
        let crc = crc32(data);
        let off = out.len() as u32;
        let method: u16 = if *deflate { 8 } else { 0 };
        let mut h = Vec::new();
        h.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        h.extend_from_slice(&20u16.to_le_bytes());
        h.extend_from_slice(&0u16.to_le_bytes());
        h.extend_from_slice(&method.to_le_bytes());
        h.extend_from_slice(&[0, 0, 0, 0]);
        h.extend_from_slice(&crc.to_le_bytes());
        h.extend_from_slice(&(body.len() as u32).to_le_bytes());
        h.extend_from_slice(&(data.len() as u32).to_le_bytes());
        h.extend_from_slice(&(name.len() as u16).to_le_bytes());
        h.extend_from_slice(&0u16.to_le_bytes());
        h.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&h);
        out.extend_from_slice(&body);
        let mut c = Vec::new();
        c.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        c.extend_from_slice(&20u16.to_le_bytes());
        c.extend_from_slice(&20u16.to_le_bytes());
        c.extend_from_slice(&0u16.to_le_bytes());
        c.extend_from_slice(&method.to_le_bytes());
        c.extend_from_slice(&[0, 0, 0, 0]);
        c.extend_from_slice(&crc.to_le_bytes());
        c.extend_from_slice(&(body.len() as u32).to_le_bytes());
        c.extend_from_slice(&(data.len() as u32).to_le_bytes());
        c.extend_from_slice(&(name.len() as u16).to_le_bytes());
        c.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        c.extend_from_slice(&off.to_le_bytes());
        c.extend_from_slice(name.as_bytes());
        central.extend_from_slice(&c);
    }
    let cd_off = out.len() as u64;
    out.extend_from_slice(&central);
    let n = entries.len() as u64;
    if zip64 {
        let end64 = out.len() as u64;
        out.extend_from_slice(&0x0606_4b50u32.to_le_bytes());
        out.extend_from_slice(&44u64.to_le_bytes());
        out.extend_from_slice(&[45, 0, 45, 0]);
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&(central.len() as u64).to_le_bytes());
        out.extend_from_slice(&cd_off.to_le_bytes());
        out.extend_from_slice(&0x0706_4b50u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&end64.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
    }
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    let cnt: u16 = if zip64 { 0xffff } else { n as u16 };
    out.extend_from_slice(&cnt.to_le_bytes());
    out.extend_from_slice(&cnt.to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    let o: u32 = if zip64 { 0xffff_ffff } else { cd_off as u32 };
    out.extend_from_slice(&o.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn crc32(b: &[u8]) -> u32 {
    let mut c = !0u32;
    for &x in b {
        c ^= x as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 };
        }
    }
    !c
}

/// osv records, made up: ranges open and closed, scores, odd shapes, records Go refuses or skips.
fn records(n: usize) -> Vec<(String, Vec<u8>, bool)> {
    let mut out = Vec::new();
    for i in 0..n {
        let id = format!("CVE-2026-{:05}", (i * 7919) % 100000);
        let body = match i % 13 {
            0 => format!(
                r#"{{"id":"{id}","summary":"A hole in   the\nnet code {i}","severity":[{{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}],"affected":[{{"package":{{"name":"Kernel","ecosystem":"Linux"}},"ranges":[{{"type":"ECOSYSTEM","events":[{{"introduced":"0"}},{{"fixed":"6.1.{i}"}},{{"introduced":"6.2"}},{{"fixed":"6.6.{i}"}}]}}]}}]}}"#
            ),
            1 => format!(
                r#"{{"ID":"{id}","Summary":"{}","affected":[{{"package":{{"name":"Kernel","ecosystem":"Linux"}},"ranges":[{{"type":"ECOSYSTEM","events":[{{"introduced":"5.10"}}]}},{{"type":"GIT","events":[{{"introduced":"abc"}}]}}]}}]}}"#,
                "é".repeat(150)
            ),
            2 => format!(
                r#"{{"id":"{id}","summary":"x","affected":[{{"package":{{"name":"Kernel","ecosystem":"Debian"}},"ranges":[{{"type":"ECOSYSTEM","events":[{{"introduced":"0"}},{{"fixed":"1"}}]}}]}}]}}"#
            ),
            3 => format!(r#"{{"id":"{id}","summary":5,"affected":[]}}"#),
            4 => format!(
                r#"{{"id":"{id}","summary":"<b> & </b>","severity":[{{"type":"CVSS_V3","score":"bogus"}},{{"type":"CVSS_V4","score":"CVSS:4.0/AV:N"}}],"affected":[{{"package":{{"name":"Kernel","ecosystem":"Linux"}},"ranges":[{{"type":"ECOSYSTEM","events":[null,{{"introduced":"4.19","x":null}},{{"fixed":"4.19.{i}","introduced":"5.0"}}]}}]}}]}} trailing"#
            ),
            5 => format!(
                r#"{{"id":"{id}","affected":[{{"package":{{"name":"Kernel","ecosystem":"Linux"}},"ranges":[{{"type":"ECOSYSTEM","events":[{{"introduced":1}}]}}]}}]}}"#
            ),
            6 => format!("[\"{id}\"]"),
            7 => format!(
                r#"{{"id":"{id}","summary":"dup keys","summary":"second","affected":[{{"package":{{"name":"Kernel","ecosystem":"Linux"}},"ranges":[{{"type":"ECOSYSTEM","events":[{{"introduced":"0","introduced":"3.1"}},{{"fixed":"3.2"}}]}}]}}]}}"#
            ),
            8 => format!(r#"{{"id":"{id}","summary":"truncated","affected":[{{"package""#),
            _ => format!(
                r#"{{"id":"{id}","summary":"Exploited maybe {i}   sep","severity":[{{"type":"CVSS_V3","score":"CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:N"}}],"affected":[{{"package":{{"name":"Kernel","ecosystem":"Linux"}},"ranges":[{{"type":"ECOSYSTEM","events":[{{"introduced":"0"}},{{"fixed":"6.12.{i}"}}]}}]}}],"unknown":{{"a":[1,2]}}}}"#
            ),
        };
        let name = if i % 31 == 0 { format!("{id}.txt") } else { format!("{id}.json") };
        out.push((name, body.into_bytes(), i % 3 != 0));
    }
    out
}

fn kev(n: usize) -> String {
    let v: Vec<String> =
        (0..n).map(|i| format!(r#"{{"cveID":"CVE-2026-{:05}","vendorProject":"Linux"}}"#, (i * 7919 * 13) % 100000)).collect();
    format!(r#"{{"title":"made up","vulnerabilities":[{}]}}"#, v.join(","))
}

#[test]
fn intel_check_kernel_as_go() {
    let recs = records(2200);
    let good: Vec<(&str, Vec<u8>, bool)> = recs.iter().map(|(n, b, d)| (n.as_str(), b.clone(), *d)).collect();
    let few: Vec<(&str, Vec<u8>, bool)> = good[..1300].to_vec();
    let z = zip(&good, false);
    let z64 = zip(&good, true);
    let zfew = zip(&few, false);
    let build = |r: &Root| {
        r.write("/in/linux.zip", &z);
        r.write("/in/linux64.zip", &z64);
        r.write("/in/few.zip", &zfew);
        r.write("/in/cut.zip", &z[..z.len() - 30]);
        r.write("/in/headless.zip", &z[z.len() / 2..]);
        r.write("/in/notzip.zip", b"<html>rate limited</html>");
        r.write("/in/empty.zip", b"");
        r.write("/in/kev.json", kev(150));
        r.write("/in/kev-short.json", kev(20));
        r.write("/in/kev-bad.json", "{\"vulnerabilities\":[{\"cveID\":5}]}");
        r.write("/in/kev-html.json", "<html>");
        r.mkdir("/out", 0o755);
    };
    for args in [
        &["intel-check", "kernel", "/in/linux.zip", "/out/linux-kernel.json"][..],
        &["intel-check", "kernel", "/in/linux.zip", "/out/linux-kernel.json", "/in/kev.json"],
        &["intel-check", "kernel", "/in/linux64.zip", "/out/linux-kernel.json", "/in/kev.json"],
        &["intel-check", "kernel", "/in/linux.zip", "/out/linux-kernel.json", "/in/kev-short.json"],
        &["intel-check", "kernel", "/in/linux.zip", "/out/linux-kernel.json", "/in/kev-bad.json"],
        &["intel-check", "kernel", "/in/linux.zip", "/out/linux-kernel.json", "/in/kev-html.json"],
        &["intel-check", "kernel", "/in/linux.zip", "/out/linux-kernel.json", "/in/missing.json"],
        &["intel-check", "kernel", "/in/few.zip", "/out/linux-kernel.json"],
        &["intel-check", "kernel", "/in/cut.zip", "/out/linux-kernel.json"],
        &["intel-check", "kernel", "/in/headless.zip", "/out/linux-kernel.json"],
        &["intel-check", "kernel", "/in/notzip.zip", "/out/linux-kernel.json"],
        &["intel-check", "kernel", "/in/empty.zip", "/out/linux-kernel.json"],
        &["intel-check", "kernel", "/in/missing.zip", "/out/linux-kernel.json"],
        &["intel-check", "kernel", "/in", "/out/linux-kernel.json"],
        &["intel-check", "kernel", "/in/linux.zip", "/nowhere/linux-kernel.json"],
    ] {
        let (g, _) = same("kernel", build, args, &Opts::default(), &["/out"]).unwrap_or_default();
        if args[2].starts_with("/in/linux") && args[3].starts_with("/out") && go_bin().is_some() {
            assert!(g.code == 0 && g.stdout.contains("kernel CVE records"), "{args:?}: {g:?}");
        }
    }
}

#[test]
fn origin_and_kernel_check_as_go() {
    let country = parity("synthetic-country.mmdb");
    let asn = parity("synthetic-asn.mmdb");
    let kernel_list = r#"{"generated":"2026-11-01T03:00:00Z","source":"made up","vulns":[
{"id":"CVE-2026-00001","summary":"net: a hole","score":9.8,"ranges":[{"introduced":"0","fixed":"6.12.30"},{"introduced":"6.13","fixed":"7.1.2"}],"exploited":true},
{"id":"CVE-2026-00002","summary":"fs: another","score":5.5,"ranges":[{"introduced":"6.0"}]},
{"id":"CVE-2026-00003","summary":"mm: Ünïcode summary","ranges":[{"introduced":"0","fixed":"7.3.1"}]}
]}"#;
    let mut many = String::from(r#"{"generated":"2026-11-01T03:00:00+02:00","source":"made up","vulns":["#);
    for i in 0..14 {
        if i > 0 {
            many.push(',');
        }
        many += &format!(
            r#"{{"id":"CVE-2026-1{i:04}","summary":"hole {i}","score":{}.{i},"ranges":[{{"introduced":"0","fixed":"7.3.{}"}}]}}"#,
            i % 10,
            i + 2
        );
    }
    many += "]}";
    let build = |r: &Root| {
        r.write("/db/country.mmdb", &country);
        r.write("/db/asn.mmdb", &asn);
        r.write("/intel/drop.list", list(30, 100));
        r.write("/intel/bad.list", "nothing\n");
        r.write("/intel/doc.list", "203.0.113.0/24\n198.51.100.7\n");
        r.write(
            "/etc/heimdall/config.json",
            r#"{"ip_databases":["/db/country.mmdb","/db/asn.mmdb"],"threat_list_dir":"/intel","kernel_vulns":"/k/list.json"}"#,
        );
        r.write("/etc/heimdall/other.json", r#"{"ip_databases":["/db/missing.mmdb"]}"#);
        r.write("/etc/heimdall/broken.json", "{");
        r.write("/k/list.json", kernel_list);
        r.write("/k/many.json", &many);
        r.write("/k/bad.json", "[1]");
        r.write("/k/badfield.json", r#"{"vulns":[{"id":"x","ranges":[{"introduced":3}]}]}"#);
        r.write("/k/badtime.json", r#"{"generated":"yesterday","vulns":[]}"#);
        for k in ["6.12.25-1-lts", "7.3.0-4-cachy", "7.3.5-1"] {
            r.write(&format!("/m/{k}/vmlinuz"), "x");
        }
        r.mkdir("/m/no-vmlinuz", 0o755);
        r.write("/m2/7.0.0/vmlinuz", "x");
    };
    let ips =
        ["203.0.113.9", "198.51.100.7", "11.0.100.7", "10.1.2.3", "::ffff:203.0.113.9", "2001:db8::5", "fe80::1", "nonsense", "1.2.3.4"];
    let mut origin: Vec<Vec<&str>> = vec![vec!["origin"], vec!["origin", "--config"], vec!["origin", "-x", "1.2.3.4"]];
    for cfg in ["/etc/heimdall/config.json", "/etc/heimdall/other.json", "/etc/heimdall/broken.json", "/nope.json"] {
        let mut a = vec!["origin", "--config", cfg];
        a.extend_from_slice(&ips);
        origin.push(a);
    }
    let mut d = vec!["origin"];
    d.extend_from_slice(&ips);
    origin.push(d);
    for args in &origin {
        same("origin", build, args, &Opts::default(), &[]);
    }
    for args in [
        &["kernel-check"][..],
        &["kernel-check", "--modules", "/m"],
        &["kernel-check", "--modules", "/m", "--list", "/k/many.json"],
        &["kernel-check", "--modules", "/m", "--list", "/k/many.json", "--all"],
        &["kernel-check", "--modules", "/m2", "--list", "/k/list.json"],
        &["kernel-check", "--modules", "/none", "--list", "/k/list.json"],
        &["kernel-check", "--list", "/k/bad.json"],
        &["kernel-check", "--list", "/k/badfield.json"],
        &["kernel-check", "--list", "/k/missing.json"],
        &["kernel-check", "--frob"],
    ] {
        same("kcheck", build, args, &Opts::default(), &[]);
        same("kcheck-user", build, args, &Opts::user().env("TZ", "Asia/Kolkata"), &[]);
    }
}
