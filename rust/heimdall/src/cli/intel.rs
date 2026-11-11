//! `heimdalld origin`, `ipdb-check`, `intel-check`, `kernel-check` (Go: cmd/heimdalld/origin.go, kernel.go; internal/ipintel,
//! internal/pkgaudit, internal/kernelaudit). The `heimdall-intel-update` helper stays the shell script that calls them.

mod zip;

use crate::audit::kernel;
use crate::cli::goflag::FlagSet;
use crate::config::Config;
use crate::gojson::{self, Value};
use crate::gotext;
use crate::gotime::Time;
use crate::ipintel;
use std::collections::BTreeSet;
use std::net::IpAddr;

/// Go's `net.IP.String()`: an IPv4 (or IPv4-mapped) address dotted, IPv6 in its shortest form.
fn ip_string(ip: &IpAddr) -> String {
    crate::gonet::canonical(*ip).to_string()
}

/// `heimdalld origin [--config PATH] IP...`
pub fn origin(args: &[String]) -> Option<i32> {
    let mut fs = FlagSet::new("origin");
    fs.string("config", "/etc/heimdall/config.json", "config file (for ip_databases)");
    if fs.parse(args).is_err() || fs.narg() == 0 {
        eprintln!("usage: heimdalld origin [--config PATH] IP...");
        return Some(2);
    }
    let cfg = Config::load_go(&fs.get_str("config")).unwrap_or_default();
    let mut r = ipintel::Resolver::new(&cfg.ip_databases);
    let mut threats = ipintel::Lists::new(&cfg.threat_list_dir);
    if !r.available() {
        eprintln!("heimdalld: no IP database yet (run heimdall-intel-update); only private and reserved addresses can be named");
    }
    let mut rc = 0;
    for a in fs.args() {
        let Some(ip) = crate::gonet::parse_ip(a) else {
            eprintln!("{a}: not an IP address");
            rc = 1;
            continue;
        };
        let mut line = format!("{}  {}", ip_string(&ip), r.lookup(&ip).text());
        let l = threats.matching(&ip);
        if !l.is_empty() {
            line += &format!("  [on threat lists: {}]", l.join(", "));
        }
        println!("{line}");
    }
    Some(rc)
}

/// Go's `ipintel.Open`, with Go's error texts for a file that cannot be read.
fn open_db(p: &str) -> Result<ipintel::Db, String> {
    match std::fs::metadata(p) {
        Err(e) => return Err(crate::goerr::path("open", p, &e)),
        Ok(m) if m.is_dir() => {
            return Err(crate::goerr::path("read", p, &std::io::Error::from_raw_os_error(libc::EISDIR)));
        }
        Ok(_) => {}
    }
    if let Err(e) = std::fs::File::open(p) {
        return Err(crate::goerr::path("open", p, &e));
    }
    ipintel::Db::open(p)
}

/// `heimdalld ipdb-check FILE...`
pub fn ipdb_check(args: &[String]) -> Option<i32> {
    if args.is_empty() {
        eprintln!("usage: heimdalld ipdb-check FILE...");
        return Some(2);
    }
    let mut rc = 0;
    let probe: IpAddr = "8.8.8.8".parse().unwrap();
    for p in args {
        let db = match open_db(p) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("{p}: {e}");
                rc = 1;
                continue;
            }
        };
        match db.lookup(&probe) {
            Ok(Some(m)) => {
                let built = Time::from_unix(db.build_epoch as i64, 0).format("2006-01-02");
                println!("{p}: {}, built {built}, 8.8.8.8 is {}", db.db_type, ipintel::Origin::from_record(&m).text());
            }
            Ok(None) => {
                eprintln!("{p}: opens, but knows nothing about 8.8.8.8 (<nil>)");
                rc = 1;
            }
            Err(e) => {
                eprintln!("{p}: opens, but knows nothing about 8.8.8.8 ({e})");
                rc = 1;
            }
        }
    }
    Some(rc)
}

/// Go's bufio.Scanner with a 1 MiB limit stops at the first longer line: the list is what came before it.
fn scanner_prefix(b: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < b.len() {
        let end = b[start..].iter().position(|&c| c == b'\n').map_or(b.len(), |i| start + i);
        let has_newline = end < b.len();
        if end - start >= 1 << 20 && (has_newline || end - start > 1 << 20) {
            return &b[..start];
        }
        start = end + 1;
    }
    b
}

fn parse_list(name: &str, b: &[u8]) -> Result<ipintel::List, String> {
    ipintel::parse_list(name, scanner_prefix(b)).ok_or_else(|| "no addresses in the list".to_string())
}

/// `heimdalld intel-check list FILE [LAST-GOOD] | tracker FILE | kernel ARCHIVE OUT [EXPLOITED]`
pub fn intel_check(args: &[String]) -> Option<i32> {
    if (args.len() == 3 || args.len() == 4) && args[0] == "kernel" {
        let mut exploited = BTreeSet::new();
        if args.len() == 4 {
            match read_exploited(&args[3]) {
                Ok(e) => exploited = e,
                Err(e) => eprintln!("{}: {e} (the list is made without it)", args[3]),
            }
        }
        let res = compact(&args[1], &exploited).and_then(|(json, n)| {
            let tmp = format!("{}.tmp", args[2]);
            crate::gopath::write_file(&tmp, json.as_bytes(), 0o640)?;
            crate::gopath::rename(&tmp, &args[2])?;
            Ok(n)
        });
        return Some(match res {
            Ok(n) => {
                println!("{}: {n} kernel CVE records", args[2]);
                0
            }
            Err(e) => {
                eprintln!("{}: {e}", args[1]);
                1
            }
        });
    }
    if args.len() != 2 && !(args.len() == 3 && args[0] == "list") {
        eprintln!("usage: heimdalld intel-check list FILE [LAST-GOOD] | tracker FILE | kernel ARCHIVE OUT [EXPLOITED]");
        return Some(2);
    }
    let res: Result<(), String> = match std::fs::read(&args[1]) {
        Err(e) => Err(crate::gopath::read_err(&args[1], &e)),
        Ok(b) => match args[0].as_str() {
            "list" => (|| {
                let l = parse_list("check", &b)?;
                if l.entries < 10 {
                    return Err("fewer than 10 entries: probably an error page, not a list".to_string());
                }
                if args.len() == 3 {
                    if let Ok(pb) = std::fs::read(&args[2]) {
                        if let Ok(prev) = parse_list("last", &pb) {
                            let (pv, nv) = (prev.v4_addresses(), l.v4_addresses());
                            if nv > 2 * pv + 65536 {
                                return Err(format!("covers {nv} IPv4 addresses, the last good copy {pv}: too big a change for an update"));
                            }
                            if l.entries < prev.entries / 2 {
                                return Err(format!(
                                    "{} entries, the last good copy {}: too many gone for an update",
                                    l.entries, prev.entries
                                ));
                            }
                        }
                    }
                }
                println!("{}: {} entries", args[1], l.entries);
                Ok(())
            })(),
            "tracker" => match crate::audit::pkg::load_tracker(&args[1]) {
                Err(e) => {
                    Err(go_json_error(&GROUPS, &b).map_or(e.to_string(), |g| format!("the security tracker file is not readable: {g}")))
                }
                Ok(g) if g.len() < 100 => Err("fewer than 100 entries: not the full tracker".to_string()),
                Ok(g) => {
                    println!("{}: {} advisory groups", args[1], g.len());
                    Ok(())
                }
            },
            _ => Err("give list or tracker".to_string()),
        },
    };
    Some(match res {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{}: {e}", args[1]);
            1
        }
    })
}

use crate::gostruct::{Field, Ty};
static STRS: Ty = Ty::Slice(&Ty::Str);
static GROUP: Ty = Ty::Struct(
    "pkgaudit.Group",
    &[
        Field("name", &Ty::Str, false),
        Field("packages", &STRS, false),
        Field("status", &Ty::Str, false),
        Field("severity", &Ty::Str, false),
        Field("type", &Ty::Str, false),
        Field("affected", &Ty::Str, false),
        Field("fixed", &Ty::Str, false),
        Field("issues", &STRS, false),
    ],
);
static GROUPS: Ty = Ty::Slice(&GROUP);
static KRANGE: Ty = Ty::Struct("kernelaudit.Range", &[Field("introduced", &Ty::Str, false), Field("fixed", &Ty::Str, true)]);
static KRANGES: Ty = Ty::Slice(&KRANGE);
static KVULN: Ty = Ty::Struct(
    "kernelaudit.Vuln",
    &[
        Field("id", &Ty::Str, false),
        Field("summary", &Ty::Str, false),
        Field("score", &Ty::Float, true),
        Field("vector", &Ty::Str, true),
        Field("ranges", &KRANGES, false),
        Field("exploited", &Ty::Bool, true),
    ],
);
static KVULNS: Ty = Ty::Slice(&KVULN);
static KFILE: Ty = Ty::Struct(
    "kernelaudit.File",
    &[Field("generated", &Ty::Time, false), Field("source", &Ty::Str, false), Field("vulns", &KVULNS, false)],
);

/// The error Go's `json.Unmarshal` gives for `b` into `t`, in Go's words (the daemon's readers word type errors their own way).
fn go_json_error(t: &Ty, b: &[u8]) -> Option<String> {
    crate::gostruct::unmarshal(t, b).1.map(|e| e.0)
}

/// Go's `kernelaudit.Exploited`: the CVE ids of CISA's catalog.
fn read_exploited(path: &str) -> Result<BTreeSet<String>, String> {
    use crate::gostruct::{self, Field, Ty, Val};
    static ITEM: Ty = Ty::Struct("", &[Field("cveID", &Ty::Str, false)]);
    static ITEMS: Ty = Ty::Slice(&ITEM);
    static CATALOG: Ty = Ty::Struct("", &[Field("vulnerabilities", &ITEMS, false)]);
    let b = std::fs::read(path).map_err(|e| crate::gopath::read_err(path, &e))?;
    let (v, err) = gostruct::unmarshal(&CATALOG, &b);
    if let Some(e) = err {
        return Err(e.0);
    }
    let items = match gostruct::field(&CATALOG, &v, "vulnerabilities") {
        Some(Val::Slice(Some(items))) => items.clone(),
        _ => Vec::new(),
    };
    if items.len() < 100 {
        return Err(format!("only {} entries: not the catalog", items.len()));
    }
    Ok(items.iter().map(|i| gostruct::str_field(&ITEM, i, "cveID").to_string()).collect())
}

/// Go's `oneLine`: spaces collapsed, cut at `n` bytes (possibly inside a character) with an ellipsis.
fn one_line(s: &str, n: usize) -> Vec<u8> {
    let joined = gotext::fields(s).collect::<Vec<_>>().join(" ");
    let mut b = joined.into_bytes();
    if b.len() > n {
        b.truncate(n);
        b.extend_from_slice("…".as_bytes());
    }
    b
}

#[derive(Default)]
struct Range {
    introduced: String,
    fixed: String,
}

/// A range of an affected package: its type and its events (None: a null event; each event its keys and values).
type OsvRange = (String, Vec<Option<Vec<(String, String)>>>);

#[derive(Default)]
struct Osv {
    id: String,
    summary: String,
    severity: Vec<(String, String)>,
    /// (name, ecosystem, ranges: (type, events))
    affected: Vec<(String, String, Vec<OsvRange>)>,
}

/// A string field: Go's string, null leaving it as it was; anything else a type error (Some(Err)).
fn str_into(v: &Value, into: &mut String) -> Result<(), ()> {
    match v {
        Value::Null => Ok(()),
        Value::String(s) => {
            *into = s.clone();
            Ok(())
        }
        _ => Err(()),
    }
}

/// An array for a Go slice: null makes it nil (empty), anything but an array is a type error.
fn arr(v: &Value) -> Result<&[Value], ()> {
    match v {
        Value::Null => Ok(&[]),
        Value::Array(a) => Ok(a),
        _ => Err(()),
    }
}

fn members<'v>(v: &'v Value, fields: &[&str]) -> Result<Vec<(usize, &'v Value)>, ()> {
    match gojson::struct_members(v, fields, "") {
        Ok(Some(m)) => Ok(m),
        Ok(None) => Ok(Vec::new()),
        Err(_) => Err(()),
    }
}

/// Go's decoding of an osv record into `osvRecord`: any type error anywhere makes the whole record unread (Go's Decode error).
fn read_osv(v: &Value) -> Result<Osv, ()> {
    let mut r = Osv::default();
    for (i, val) in members(v, &["id", "summary", "severity", "affected"])? {
        match i {
            0 => str_into(val, &mut r.id)?,
            1 => str_into(val, &mut r.summary)?,
            2 => {
                r.severity = Vec::new();
                for s in arr(val)? {
                    let (mut t, mut sc) = (String::new(), String::new());
                    for (j, x) in members(s, &["type", "score"])? {
                        str_into(x, if j == 0 { &mut t } else { &mut sc })?;
                    }
                    r.severity.push((t, sc));
                }
            }
            _ => {
                r.affected = Vec::new();
                for a in arr(val)? {
                    let (mut name, mut eco, mut ranges) = (String::new(), String::new(), Vec::new());
                    for (j, x) in members(a, &["package", "ranges"])? {
                        if j == 0 {
                            for (k, y) in members(x, &["name", "ecosystem"])? {
                                str_into(y, if k == 0 { &mut name } else { &mut eco })?;
                            }
                        } else {
                            ranges = Vec::new();
                            for rg in arr(x)? {
                                let (mut ty, mut events) = (String::new(), Vec::new());
                                for (k, y) in members(rg, &["type", "events"])? {
                                    if k == 0 {
                                        str_into(y, &mut ty)?;
                                    } else {
                                        events = Vec::new();
                                        for ev in arr(y)? {
                                            match ev {
                                                Value::Null => events.push(None),
                                                Value::Object(m) => {
                                                    let mut kv: Vec<(String, String)> = Vec::new();
                                                    for (key, val) in m {
                                                        let mut s = String::new();
                                                        str_into(val, &mut s)?;
                                                        kv.retain(|(k2, _)| k2 != key);
                                                        kv.push((key.clone(), s));
                                                    }
                                                    events.push(Some(kv));
                                                }
                                                _ => return Err(()),
                                            }
                                        }
                                    }
                                }
                                ranges.push((ty, events));
                            }
                        }
                    }
                    r.affected.push((name, eco, ranges));
                }
            }
        }
    }
    Ok(r)
}

struct Vuln {
    id: String,
    summary: Vec<u8>,
    score: f64,
    vector: String,
    ranges: Vec<Range>,
    exploited: bool,
}

/// Go's `kernelaudit.Compact` and `json.Marshal` of its result: the file's JSON and the number of records.
fn compact(zip_path: &str, exploited: &BTreeSet<String>) -> Result<(String, usize), String> {
    let z = zip::open(zip_path)?;
    let generated = Time::now().utc().truncate(1_000_000_000);
    let mut vulns: Vec<Vuln> = Vec::new();
    for e in &z.entries {
        if !e.name.ends_with(b".json") || e.uncompressed > 8 << 20 {
            continue;
        }
        let Ok(data) = z.read(e, 8 << 20) else { continue };
        let Ok(v) = gojson::parse_first(&data) else { continue };
        let Ok(r) = read_osv(&v) else { continue };
        if r.id.is_empty() {
            continue;
        }
        let mut v = Vuln {
            summary: one_line(&r.summary, 200),
            exploited: exploited.contains(&r.id),
            id: r.id,
            score: 0.0,
            vector: String::new(),
            ranges: Vec::new(),
        };
        for (t, s) in &r.severity {
            if t.starts_with("CVSS_V3") {
                if let Some(sc) = kernel::cvss3(s) {
                    v.score = sc;
                    v.vector = s.clone();
                }
            }
        }
        for (name, eco, ranges) in &r.affected {
            if eco != "Linux" || name != "Kernel" {
                continue;
            }
            for (ty, events) in ranges {
                if ty != "ECOSYSTEM" {
                    continue;
                }
                let mut cur = Range::default();
                for ev in events.iter().flatten() {
                    let get = |k: &str| ev.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
                    if let Some(x) = get("introduced") {
                        cur = Range { introduced: x, fixed: String::new() };
                    }
                    if let Some(x) = get("fixed") {
                        cur.fixed = x;
                        v.ranges.push(std::mem::take(&mut cur));
                    }
                }
                if !cur.introduced.is_empty() {
                    v.ranges.push(cur);
                }
            }
        }
        if !v.ranges.is_empty() {
            vulns.push(v);
        }
    }
    if vulns.len() < 1000 {
        return Err(format!("only {} kernel records: not the full archive", vulns.len()));
    }
    vulns.sort_by(|a, b| a.id.cmp(&b.id));
    let mut out = String::from("{\"generated\":\"");
    out.push_str(&generated.rfc3339_nano());
    out.push_str("\",\"source\":");
    gojson::write_str(&mut out, "osv.dev, Linux ecosystem (the kernel CVE team's records)");
    out.push_str(",\"vulns\":[");
    for (i, v) in vulns.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"id\":");
        gojson::write_str(&mut out, &v.id);
        out.push_str(",\"summary\":");
        gojson::write_str(&mut out, &gotext::lossy(&v.summary));
        if v.score != 0.0 {
            out.push_str(",\"score\":");
            gojson::write_f64(&mut out, v.score);
        }
        if !v.vector.is_empty() {
            out.push_str(",\"vector\":");
            gojson::write_str(&mut out, &v.vector);
        }
        out.push_str(",\"ranges\":[");
        for (j, r) in v.ranges.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            out.push_str("{\"introduced\":");
            gojson::write_str(&mut out, &r.introduced);
            if !r.fixed.is_empty() {
                out.push_str(",\"fixed\":");
                gojson::write_str(&mut out, &r.fixed);
            }
            out.push('}');
        }
        out.push(']');
        if v.exploited {
            out.push_str(",\"exploited\":true");
        }
        out.push('}');
    }
    out.push_str("]}");
    Ok((out, vulns.len()))
}

/// `heimdalld kernel-check [--list FILE] [--all] [--modules DIR]`
pub fn kernel_check(args: &[String]) -> Option<i32> {
    let mut fs = FlagSet::new("kernel-check");
    fs.string("list", "", "the kernel CVE list (default: kernel_vulns from the config)");
    fs.bool("all", false, "every hole, not only the ten worst");
    fs.string("modules", "/usr/lib/modules", "where the kernels are");
    if fs.parse(args).is_err() {
        return Some(2);
    }
    let mut list = fs.get_str("list");
    if list.is_empty() {
        list = Config::load_go("/etc/heimdall/config.json").unwrap_or_default().kernel_vulns;
    }
    let f = match kernel::load(&list) {
        Ok(f) => f,
        Err(e) => {
            let e = std::fs::read(&list).ok().and_then(|b| go_json_error(&KFILE, &b)).unwrap_or(e.to_string());
            eprintln!("heimdalld kernel-check: no kernel CVE list yet (heimdall-intel-update fetches it): {e}");
            return Some(2);
        }
    };
    let all = fs.get_bool("all");
    let mut bad = 0;
    let mut out = String::new();
    for k in kernel::installed(&fs.get_str("modules")) {
        let (holes, fix) = kernel::check(&f, &k);
        if holes.is_empty() {
            out += &format!("{k}: no known hole that an update fixes\n");
            continue;
        }
        bad += 1;
        let same = holes.iter().filter(|h| h.same_line).count();
        out += &format!(
            "{k}: {} known hole(s): {same} fixed on its own line, the rest only in newer lines ({fix} or later fixes all; ! = exploited in the wild)\n",
            holes.len()
        );
        for (i, h) in holes.iter().enumerate() {
            if i == 10 && !all {
                out += &format!("  … and {} more (--all)\n", holes.len() - 10);
                break;
            }
            let mark = if h.vuln.exploited { "!" } else { " " };
            out += &format!(
                "  {mark} {} {:>4}  fixed in {} {}\n",
                pad(&h.vuln.id, 16),
                gotext::fixed(h.vuln.score, 1),
                pad(&h.fixed_in, 9),
                h.vuln.summary
            );
        }
    }
    out += &format!("(list from {}, {} records)\n", f.generated.local().format("2006-01-02"), f.vulns.len());
    print!("{out}");
    Some(if bad > 0 { 1 } else { 0 })
}

/// Go's `%-Ns`: padded with spaces to N characters.
fn pad(s: &str, n: usize) -> String {
    let c = s.chars().count();
    if c >= n {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(n - c))
    }
}

/// `heimdall-intel-update`: stays the shell script (packaging/arch/heimdall-intel-update) that calls the checks above.
pub fn update_tool(_args: &[String]) -> Option<i32> {
    None
}
