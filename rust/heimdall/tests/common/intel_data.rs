//! Made-up downloads for the intel tests (`cli_intel.rs` against Go, `cli_shtools.rs` against the shell script): threat
//! lists, Arch's tracker, osv.dev's kernel archive and CISA's catalog.

use std::io::Write;

/// A threat list of `n` made-up public networks (documentation-free: plain public ranges, nothing real meant).
pub fn list(n: usize, start: u32) -> String {
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

/// Arch's security tracker with `n` made-up advisory groups.
pub fn tracker(n: usize) -> String {
    let g: Vec<String> = (0..n)
        .map(|i| {
            format!(
                r#"{{"name":"AVG-{i}","packages":["pkg{i}"],"status":"Fixed","severity":"High","type":"x","affected":"1.0-1","fixed":"1.1-1","issues":["CVE-2026-{i}"]}}"#
            )
        })
        .collect();
    format!("[{}]", g.join(","))
}

/// A zip archive as Go's writer makes one (stored or deflated entries, a central directory, the end record).
pub fn zip(entries: &[(&str, Vec<u8>, bool)], zip64: bool) -> Vec<u8> {
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

pub fn crc32(b: &[u8]) -> u32 {
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
pub fn records(n: usize) -> Vec<(String, Vec<u8>, bool)> {
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

pub fn kev(n: usize) -> String {
    let v: Vec<String> =
        (0..n).map(|i| format!(r#"{{"cveID":"CVE-2026-{:05}","vendorProject":"Linux"}}"#, (i * 7919 * 13) % 100000)).collect();
    format!(r#"{{"title":"made up","vulnerabilities":[{}]}}"#, v.join(","))
}

/// A small IP database in the MaxMind DB format that knows 8.8.8.0/24 (and nothing else): the record `kind` gives
/// (`country`: its country; `asn`: its network), for checks that must pass (`heimdalld ipdb-check` asks about 8.8.8.8).
pub fn mmdb(kind: &str, db_type: &str) -> Vec<u8> {
    fn ctrl(out: &mut Vec<u8>, typ: u8, size: usize) {
        let first = if typ <= 7 { typ << 5 } else { 0 };
        let (s, extra): (u8, Vec<u8>) = if size < 29 { (size as u8, vec![]) } else { (29, vec![(size - 29) as u8]) };
        out.push(first | s);
        if typ > 7 {
            out.push(typ - 7);
        }
        out.extend(extra);
    }
    fn s(out: &mut Vec<u8>, v: &str) {
        ctrl(out, 2, v.len());
        out.extend_from_slice(v.as_bytes());
    }
    fn uint(out: &mut Vec<u8>, typ: u8, v: u64) {
        let b: Vec<u8> = v.to_be_bytes().iter().copied().skip_while(|&x| x == 0).collect();
        ctrl(out, typ, b.len());
        out.extend(b);
    }
    let ip = [8u8, 8, 8, 0];
    let nodes = 24usize;
    let mut tree = Vec::new();
    for i in 0..nodes {
        let bit = (ip[i / 8] >> (7 - i % 8)) & 1;
        let next = if i + 1 == nodes { nodes + 16 } else { i + 1 };
        let (l, r) = if bit == 0 { (next, nodes) } else { (nodes, next) };
        tree.extend_from_slice(&(l as u32).to_be_bytes()[1..]);
        tree.extend_from_slice(&(r as u32).to_be_bytes()[1..]);
    }
    let mut data = Vec::new();
    if kind == "country" {
        ctrl(&mut data, 7, 1);
        s(&mut data, "country");
        ctrl(&mut data, 7, 1);
        s(&mut data, "iso_code");
        s(&mut data, "US");
    } else {
        ctrl(&mut data, 7, 2);
        s(&mut data, "autonomous_system_number");
        uint(&mut data, 6, 15169);
        s(&mut data, "autonomous_system_organization");
        s(&mut data, "Made Up Networks");
    }
    let mut meta = b"\xab\xcd\xefMaxMind.com".to_vec();
    ctrl(&mut meta, 7, 9);
    s(&mut meta, "node_count");
    uint(&mut meta, 6, nodes as u64);
    s(&mut meta, "record_size");
    uint(&mut meta, 5, 24);
    s(&mut meta, "ip_version");
    uint(&mut meta, 5, 4);
    s(&mut meta, "database_type");
    s(&mut meta, db_type);
    s(&mut meta, "build_epoch");
    uint(&mut meta, 9, 1_790_000_000);
    s(&mut meta, "binary_format_major_version");
    uint(&mut meta, 5, 2);
    s(&mut meta, "binary_format_minor_version");
    uint(&mut meta, 5, 0);
    s(&mut meta, "languages");
    ctrl(&mut meta, 11, 0);
    s(&mut meta, "description");
    ctrl(&mut meta, 7, 0);
    [tree, vec![0; 16], data, meta].concat()
}
