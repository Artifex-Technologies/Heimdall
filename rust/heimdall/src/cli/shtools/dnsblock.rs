//! `heimdall-dns-blocklist`, ported from the shell script (packaging/net/heimdall-dns-blocklist): block known malware,
//! phishing, scam and botnet domains for every program on this computer.
//!
//! NetworkManager runs a small local DNS cache (dnsmasq); this keeps a list of bad domains in that cache, so a lookup of one
//! (and of every name under it) fails at once, before any connection is made. Nothing about the sites visited leaves this
//! computer; the lists are downloaded. A downloaded list is never used as configuration: only lines that are plain domain
//! names are kept, and the dnsmasq lines are written here (a hostile list cannot add directives).
//!
//! The same commands, environment, files (paths, modes: umask 022), output and exit codes as the script, its text tools'
//! steps carried over byte for byte in the C locale (`domains`), proved against it in fake roots (tests/cli_shtools.rs).

use super::coreutils::{cp, lines, mkdir_p, mktemp_d, mv_f, quote, rm_rf, say, sort_u, strerror, subst, warn, wc_l};
use super::fetch;
use std::collections::HashSet;
use std::io::Write;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The lists: (name, URL). HaGeZi's Threat Intelligence Feeds, mini (GPL-3.0) and the URLhaus malware filter (CC0).
pub const LISTS: [(&str, &str); 2] = [
    ("hagezi-tif-mini", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt"),
    ("urlhaus-filter", "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts-online.txt"),
];
/// `--max-filesize 100000000`.
pub const MAX_FILESIZE: u64 = 100_000_000;

/// The usage the script printed (its lines 2 to 15, the comment marks taken off).
pub const USAGE: &str = "heimdall-dns-blocklist: block known malware, phishing, scam and botnet domains for every program on this computer.

How: NetworkManager runs a small local DNS cache (dnsmasq). This keeps a list of bad domains in that cache, so a lookup of one
(and of every name under it) fails at once, before any connection is made: a hacked website that tries to send the browser to a
malware or phishing page simply does not resolve. Nothing about the sites you visit leaves this computer; the lists are downloaded.

  heimdall-dns-blocklist update     fetch the lists and build the block file (daily, by heimdall-dns-blocklist.timer)
  heimdall-dns-blocklist apply      make the DNS cache load it, and undo it if names stop resolving (root)
  heimdall-dns-blocklist allow DOMAIN    never block DOMAIN (and names under it), then apply (root)
  heimdall-dns-blocklist status     what is blocked, from which lists, and when they were fetched
  heimdall-dns-blocklist test DOMAIN     is DOMAIN blocked?

Lists (free): HaGeZi's Threat Intelligence Feeds, mini (github.com/hagezi/dns-blocklists, GPL-3.0) and the URLhaus malware
filter (malware-filter.gitlab.io, from abuse.ch URLhaus data, CC0). A downloaded list is never used as configuration: only lines
";

const NM_CONF: [&str; 2] = ["/usr/lib/NetworkManager/conf.d/heimdall-dns.conf", "/etc/NetworkManager/conf.d/heimdall-dns.conf"];

/// The paths and limits, from the environment as the script read them.
struct Ctx {
    dir: PathBuf,
    allow: PathBuf,
    conf: PathBuf,
    min: std::ffi::OsString,
}

fn env_or(name: &str, default: &str) -> std::ffi::OsString {
    std::env::var_os(name).filter(|v| !v.is_empty()).unwrap_or_else(|| default.into())
}

/// How the script ended early: `exit CODE`.
type Exit = i32;

// ---- the text steps

/// `[[:space:]]` in the C locale.
fn space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

fn domain_re() -> &'static regex::bytes::Regex {
    static RE: OnceLock<regex::bytes::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::bytes::Regex::new(
            r"(?-u)^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z][a-z0-9-]{0,61}[a-z0-9]$",
        )
        .expect("the domain pattern")
    })
}

/// One line through the script's sed: the comment off, a hosts file's address before the name off, spaces at the end off.
fn clean_line(l: &[u8]) -> &[u8] {
    let mut l = match l.iter().position(|&c| c == b'#') {
        Some(i) => &l[..i],
        None => l,
    };
    // s/^[[:space:]]*(0\.0\.0\.0|127\.0\.0\.1|::)[[:space:]]+//
    let lead = l.iter().take_while(|&&c| space(c)).count();
    for addr in [&b"0.0.0.0"[..], b"127.0.0.1", b"::"] {
        if l[lead..].starts_with(addr) {
            let after = lead + addr.len();
            let sp = l[after..].iter().take_while(|&&c| space(c)).count();
            if sp > 0 {
                l = &l[after + sp..];
            }
            break;
        }
    }
    let end = l.len() - l.iter().rev().take_while(|&&c| space(c)).count();
    &l[..end]
}

/// The script's `domains`: plain domain names, one per line (hosts lines and comments understood; anything else dropped).
pub fn domains(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for l in lines(text) {
        let c: Vec<u8> = clean_line(l).iter().map(u8::to_ascii_lowercase).collect();
        if domain_re().is_match(&c) && !matches!(&c[..], b"localhost" | b"localhost.localdomain" | b"local" | b"broadcasthost") {
            out.extend_from_slice(&c);
            out.push(b'\n');
        }
    }
    out
}

/// The script's `allowed`: the allow list, cleaned the same way (nothing when it is not readable).
fn allowed(ctx: &Ctx) -> Vec<u8> {
    if !readable(&ctx.allow) {
        return Vec::new();
    }
    match std::fs::read(&ctx.allow) {
        Ok(b) => sort_u(&domains(&b)),
        Err(e) => {
            if e.raw_os_error() == Some(libc::EISDIR) {
                warn(&format!("sed: read error on {}: {}", ctx.allow.to_string_lossy(), strerror(&e)));
            } else {
                warn(&format!("sed: can't read {}: {}", ctx.allow.to_string_lossy(), strerror(&e)));
            }
            Vec::new()
        }
    }
}

fn readable(p: &Path) -> bool {
    let Ok(c) = std::ffi::CString::new(p.as_os_str().as_bytes()) else { return false };
    unsafe { libc::faccessat(libc::AT_FDCWD, c.as_ptr(), libc::R_OK, libc::AT_EACCESS) == 0 }
}

/// `> FILE`: created (0666 less the umask) or emptied, then written.
fn redirect(p: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o666).open(p)?;
    f.write_all(data)
}

fn is_file(p: &Path) -> bool {
    std::fs::metadata(p).is_ok_and(|m| m.is_file())
}

/// `date -u +%Y-%m-%dT%H:%MZ`.
fn stamp() -> String {
    let (y, mo, d, h, mi, _) = crate::gotime::Time::now().utc().civil();
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}Z")
}

/// The awk step: drop allowed names and everything under them.
fn drop_allowed(all: &[u8], allow: &[u8]) -> Vec<u8> {
    let a: HashSet<&[u8]> = lines(allow).into_iter().collect();
    let mut out = Vec::new();
    for d in lines(all) {
        let mut x = d;
        let mut keep = true;
        while !x.is_empty() {
            if a.contains(x) {
                keep = false;
                break;
            }
            match x.iter().position(|&c| c == b'.') {
                Some(i) => x = &x[i + 1..],
                None => break,
            }
        }
        if keep {
            out.extend_from_slice(d);
            out.push(b'\n');
        }
    }
    out
}

// ---- update

/// The script's `update`. `errexit`: whether `set -e` holds; `quiet`: its standard output thrown away; `skip`: no downloads
/// (all three as `allow` calls it: `HEIMDALL_DNS_SKIP_FETCH=1 update >/dev/null || true`).
fn update(ctx: &Ctx, errexit: bool, quiet: bool, skip: bool) -> Result<(), Exit> {
    let out = |s: &str| {
        if !quiet {
            say(s)
        }
    };
    if let Err(e) = mkdir_p(&ctx.dir) {
        warn(&e);
        if errexit {
            return Err(1);
        }
    }
    let tmp = match mktemp_d(&ctx.dir) {
        Ok(t) => t,
        Err(e) => {
            warn(&e);
            return Err(1);
        }
    };
    struct Gone(PathBuf);
    impl Drop for Gone {
        fn drop(&mut self) {
            rm_rf(&self.0);
        }
    }
    let _gone = Gone(tmp.clone());
    let test_sources = std::env::var_os("HEIMDALL_DNS_TEST_SOURCES").filter(|v| !v.is_empty());
    for (name, url) in LISTS {
        let raw = tmp.join(format!("{name}.raw"));
        let txt = tmp.join(format!("{name}.txt"));
        let keep = ctx.dir.join(format!("{name}.txt"));
        if let Some(src) = &test_sources {
            // tests: the lists come from files, never the network
            if cp(&PathBuf::from(src).join(format!("{name}.raw")), &raw).is_ok() {
                let cleaned = domains(&std::fs::read(&raw).unwrap_or_default());
                if redirect(&txt, &cleaned).is_ok() {
                    if let Err(e) = cp(&txt, &keep) {
                        warn(&e);
                    }
                }
            }
            continue;
        }
        if !skip && fetch::curl(&fetch::Request { url, out: &raw, max_filesize: MAX_FILESIZE, auth: None, max_time: fetch::MAX_TIME }) == 0
        {
            let cleaned = domains(&std::fs::read(&raw).unwrap_or_default());
            if let Err(e) = redirect(&txt, &cleaned) {
                warn(&format!("grep: write error: {}", strerror(&e)));
            }
            out(&format!("{name}: {} domains", wc_l(&std::fs::read(&txt).unwrap_or_default())));
            if let Err(e) = cp(&txt, &keep) {
                warn(&e);
                if errexit {
                    return Err(1);
                }
            }
        } else {
            if !skip {
                warn(&format!("{name}: not fetched; using the last copy"));
            }
            if is_file(&keep) {
                if let Err(e) = cp(&keep, &txt) {
                    warn(&e);
                }
            }
        }
    }
    // cat "$tmp"/*.txt | sort -u >"$tmp/all": the lists in the glob's order; none at all fails the pipeline
    let mut names: Vec<Vec<u8>> = std::fs::read_dir(&tmp)
        .map(|rd| rd.flatten().map(|e| e.file_name().into_vec()).filter(|n| n.ends_with(b".txt") && !n.starts_with(b".")).collect())
        .unwrap_or_default();
    names.sort();
    let mut cat = Vec::new();
    for n in &names {
        if let Ok(b) = std::fs::read(tmp.join(std::ffi::OsStr::from_bytes(n))) {
            cat.extend_from_slice(&b);
        }
    }
    let mut all = sort_u(&cat);
    let all_path = tmp.join("all");
    let wrote = redirect(&all_path, &all);
    if let Err(e) = &wrote {
        warn(&format!("sort: write failed: {}: {}", quote(all_path.as_os_str()), strerror(e)));
    }
    if errexit && (names.is_empty() || wrote.is_err()) {
        return Err(if names.is_empty() { 1 } else { 2 });
    }
    let allow = allowed(ctx);
    let _ = redirect(&tmp.join("allow"), &allow);
    if !allow.is_empty() {
        all = drop_allowed(&all, &allow);
        let _ = redirect(&tmp.join("all2"), &all).and_then(|_| std::fs::rename(tmp.join("all2"), &all_path));
    }
    let n = wc_l(&all) as i64;
    // (( n < min_entries )): a number (bash would evaluate any arithmetic here; docs/RUST_CLI.md)
    let Some(min) = ctx.min.to_str().map(str::trim).and_then(|m| m.parse::<i64>().ok()) else {
        warn(&format!("heimdall-dns-blocklist: HEIMDALL_DNS_MIN is not a number: {}", ctx.min.to_string_lossy()));
        return Err(1);
    };
    if n < min {
        warn(&format!("only {n} domains: something went wrong; the last good block file stays"));
        return Err(1);
    }
    let mut conf = format!(
        "# Written by heimdall-dns-blocklist on {}: {n} blocked domains (and the names under them).\n\
         # Do not edit: add domains to {} instead, then run: sudo heimdall-dns-blocklist allow DOMAIN\n",
        stamp(),
        ctx.allow.to_string_lossy()
    )
    .into_bytes();
    for d in lines(&all) {
        conf.extend_from_slice(b"local=/");
        conf.extend_from_slice(d);
        conf.extend_from_slice(b"/\n");
    }
    // an allowed name under a blocked one still resolves normally
    for d in lines(&allow) {
        conf.extend_from_slice(b"server=/");
        conf.extend_from_slice(d);
        conf.extend_from_slice(b"/#\n");
    }
    let new = tmp.join("blocklist.conf");
    let _ = redirect(&new, &conf);
    // a block file cut short (a full disk) never replaces the good one: every line must be there
    if wc_l(&std::fs::read(&new).unwrap_or_default()) as i64 != n + 2 + wc_l(&allow) as i64 {
        warn("the block file could not be written in full; the last good block file stays");
        return Err(1);
    }
    if let Err(e) = mv_f(&new, &ctx.conf) {
        warn(&e);
        if errexit {
            return Err(1);
        }
    }
    if let Err(e) = redirect(&ctx.dir.join("updated"), format!("{}\n", stamp()).as_bytes()) {
        warn(&format!("{}: {}", ctx.dir.join("updated").to_string_lossy(), strerror(&e)));
        if errexit {
            return Err(1);
        }
    }
    out(&format!("{n} domains blocked"));
    Ok(())
}

// ---- apply

/// The script's `works`: do ordinary names resolve?
fn works() -> bool {
    use std::net::ToSocketAddrs;
    ["archlinux.org", "wikipedia.org"].iter().any(|d| (*d, 0).to_socket_addrs().is_ok_and(|mut a| a.next().is_some()))
}

/// nmcli with the arguments, its output passed through; under `set -e` its failure ends the script with its code.
fn nmcli(args: &[&str]) -> Result<(), Exit> {
    use std::os::unix::process::ExitStatusExt;
    match std::process::Command::new("nmcli").args(args).status() {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(s.code().unwrap_or_else(|| 128 + s.signal().unwrap_or(0))),
        Err(e) => {
            warn(&format!("heimdall-dns-blocklist: nmcli: {}", strerror(&e)));
            Err(127)
        }
    }
}

fn root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn apply(ctx: &Ctx) -> Result<(), Exit> {
    if !root() {
        warn("apply needs root (sudo)");
        return Err(1);
    }
    if !NM_CONF.iter().any(|p| is_file(Path::new(p))) {
        warn("the DNS cache is not switched on (no heimdall-dns.conf in NetworkManager/conf.d)");
        return Err(1);
    }
    let before = works();
    // re-read the settings (the first time this switches the DNS cache on) and restart the cache
    nmcli(&["general", "reload", "conf,dns-full"])?;
    for _ in 0..10 {
        if works() {
            say("DNS cache reloaded with the block list; names resolve");
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    if before {
        // it worked before and not now: the new block file is the suspect; go back to an empty one so the computer stays
        // online
        let broken = PathBuf::from({
            let mut b = ctx.conf.clone().into_os_string();
            b.push(".broken");
            b
        });
        warn(&format!("names stopped resolving after the reload: the block list is set aside (moved to {})", broken.to_string_lossy()));
        if let Err(e) = mv_f(&ctx.conf, &broken) {
            warn(&e);
            return Err(1);
        }
        if let Err(e) = redirect(&ctx.conf, b"") {
            warn(&format!("{}: {}", ctx.conf.to_string_lossy(), strerror(&e)));
            return Err(1);
        }
        nmcli(&["general", "reload", "dns-full"])?;
        return Err(1);
    }
    warn("names did not resolve before or after the reload (offline?); left as it is");
    Ok(())
}

// ---- the commands

fn allow_cmd(ctx: &Ctx, arg: &str) -> Result<(), Exit> {
    if !root() {
        warn("allow needs root (sudo)");
        return Err(1);
    }
    let d: Vec<u8> = subst(arg.as_bytes()).iter().map(u8::to_ascii_lowercase).collect();
    let mut probe = d.clone();
    probe.push(b'\n');
    if domains(&probe).is_empty() {
        warn(&format!("not a domain name: {arg}"));
        return Err(2);
    }
    let mut new = ctx.allow.clone().into_os_string();
    new.push(".new");
    let new = PathBuf::from(new);
    // install -Dm644 /dev/null "$allow.new"
    if let Some(parent) = new.parent().filter(|p| !p.as_os_str().is_empty()) {
        if let Err(e) = mkdir_p(parent) {
            warn(&e.replacen("mkdir:", "install:", 1));
        }
    }
    let _ = std::fs::remove_file(&new);
    if let Err(e) = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&new) {
        warn(&format!("install: cannot create regular file {}: {}", super::coreutils::quoteaf(new.as_os_str()), strerror(&e)));
        return Err(1);
    } else {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o644));
    }
    let mut all = Vec::new();
    if is_file(&ctx.allow) {
        match std::fs::read(&ctx.allow) {
            Ok(b) => all = b,
            Err(e) => warn(&format!("cat: {}: {}", ctx.allow.to_string_lossy(), strerror(&e))),
        }
    }
    all.extend_from_slice(&d);
    all.push(b'\n');
    match redirect(&new, &sort_u(&all)) {
        Ok(()) => {
            if let Err(e) = mv_f(&new, &ctx.allow) {
                warn(&e);
                return Err(1);
            }
        }
        Err(e) => warn(&format!("{}: {}", new.to_string_lossy(), strerror(&e))),
    }
    // a failed rebuild only ends the command when update itself exits
    update(ctx, false, true, true)?;
    apply(ctx)?;
    say(&format!("{} is allowed", String::from_utf8_lossy(&d)));
    Ok(())
}

fn status(ctx: &Ctx) {
    if is_file(&ctx.conf) {
        let count = match std::fs::read(&ctx.conf) {
            Ok(b) => lines(&b).iter().filter(|l| l.starts_with(b"local=")).count().to_string(),
            Err(e) => {
                warn(&format!("grep: {}: {}", ctx.conf.to_string_lossy(), strerror(&e)));
                String::new()
            }
        };
        let updated = match std::fs::read(ctx.dir.join("updated")) {
            Ok(b) => String::from_utf8_lossy(subst(&b)).into_owned(),
            Err(_) => "never".into(),
        };
        say(&format!("blocked domains: {count} (updated {updated})"));
        let mut names: Vec<Vec<u8>> = std::fs::read_dir(&ctx.dir)
            .map(|rd| rd.flatten().map(|e| e.file_name().into_vec()).filter(|n| n.ends_with(b".txt") && !n.starts_with(b".")).collect())
            .unwrap_or_default();
        names.sort();
        for n in names {
            let p = ctx.dir.join(std::ffi::OsStr::from_bytes(&n));
            if is_file(&p) {
                let base = String::from_utf8_lossy(&n[..n.len() - 4]).into_owned();
                let lines = std::fs::read(&p).map(|b| wc_l(&b).to_string()).unwrap_or_default();
                say(&format!("  {base}: {lines}"));
            }
        }
    } else {
        say("no block list yet");
    }
    say(&format!("allowed by you: {} ({})", wc_l(&allowed(ctx)), ctx.allow.to_string_lossy()));
    say(if NM_CONF.iter().any(|p| is_file(Path::new(p))) { "DNS cache: on" } else { "DNS cache: off" });
}

fn test_cmd(ctx: &Ctx, arg: &str) {
    let d: Vec<u8> = subst(arg.as_bytes()).iter().map(u8::to_ascii_lowercase).collect();
    let conf = std::fs::read(&ctx.conf).ok();
    let conf_lines: HashSet<&[u8]> = conf.as_deref().map(lines).unwrap_or_default().into_iter().collect();
    let mut hit: Option<&[u8]> = None;
    let mut x: &[u8] = &d;
    while !x.is_empty() {
        // grep -qxF "local=/$x/": a pattern with newlines is several patterns, any whole line equal to one of them
        let mut pat = b"local=/".to_vec();
        pat.extend_from_slice(x);
        pat.push(b'/');
        if conf.is_some() && pat.split(|&c| c == b'\n').any(|p| conf_lines.contains(p)) {
            hit = Some(x);
            break;
        }
        match x.iter().position(|&c| c == b'.') {
            Some(i) => x = &x[i + 1..],
            None => break,
        }
    }
    let ds = String::from_utf8_lossy(&d);
    match hit {
        Some(h) => say(&format!("{ds} is blocked (listed: {})", String::from_utf8_lossy(h))),
        None => say(&format!("{ds} is not blocked")),
    }
}

pub fn main(args: &[String]) -> i32 {
    unsafe { libc::umask(0o022) };
    let dir = PathBuf::from(env_or("HEIMDALL_DNS_DIR", "/var/lib/heimdall-dns"));
    let allow = PathBuf::from(env_or("HEIMDALL_DNS_ALLOW", "/etc/heimdall/dns-allow.txt"));
    // a list that suddenly shrinks this far is an error page, not a list: the last good file stays
    let min = env_or("HEIMDALL_DNS_MIN", "20000");
    let ctx = Ctx { conf: dir.join("blocklist.conf"), dir, allow, min };
    let arg = |i: usize| args.get(i).cloned().unwrap_or_default();
    let r = match args.first().map(String::as_str) {
        Some("update") => {
            let skip = std::env::var_os("HEIMDALL_DNS_SKIP_FETCH").is_some_and(|v| v.as_bytes() == b"1");
            update(&ctx, true, false, skip)
        }
        Some("apply") => apply(&ctx),
        Some("allow") => allow_cmd(&ctx, &arg(1)),
        Some("status") => {
            status(&ctx);
            Ok(())
        }
        Some("test") => {
            test_cmd(&ctx, &arg(1));
            Ok(())
        }
        _ => {
            let _ = std::io::stdout().write_all(USAGE.as_bytes());
            Err(2)
        }
    };
    match r {
        Ok(()) => 0,
        Err(code) => code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_is_the_scripts() {
        let script = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../packaging/net/heimdall-dns-blocklist")).unwrap();
        let want: String = script
            .lines()
            .skip(1)
            .take(14)
            .map(|l| {
                let l = l.strip_prefix('#').unwrap_or(l);
                format!("{}\n", l.strip_prefix(' ').unwrap_or(l))
            })
            .collect();
        assert_eq!(USAGE, want);
    }

    #[test]
    fn lines_cleaned_as_sed_and_grep() {
        let got = domains(b"# c\n0.0.0.0 Evil.Example\n  127.0.0.1\tx.test # c\n:: y.test\n::1 z.test\nlocalhost.localdomain\nok.example \r\n  lead.example\nbad_x.example\n0.0.0.0\na.b");
        assert_eq!(got, b"evil.example\nx.test\ny.test\nok.example\n");
    }

    #[test]
    fn allowed_names_and_under() {
        assert_eq!(drop_allowed(b"a.example\nb.a.example\nc.example\n", b"a.example\n"), b"c.example\n");
    }
}
