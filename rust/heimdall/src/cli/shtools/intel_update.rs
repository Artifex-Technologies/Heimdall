//! `heimdall-intel-update`, ported from the shell script (packaging/arch/heimdall-intel-update): fetch the files Heimdall
//! checks against, all used offline on this computer:
//!
//! - threat lists of known malware, botnet and criminal addresses (Spamhaus DROP, FireHOL Level 1, Emerging Threats) and Arch
//!   Linux's security tracker, daily;
//! - the Linux kernel's CVE records (osv.dev) with CISA's known-exploited list, weekly;
//! - the IP databases that say where an address belongs (IPinfo Lite with the owner's token, else DB-IP Lite), monthly.
//!
//! Only these files are downloaded; no address Heimdall has seen and nothing about this computer is sent anywhere. Each
//! download is checked before it replaces the file in use (`heimdalld ipdb-check` and `intel-check`, called here
//! directly): a broken or tampered download is thrown away and the last good file stays. The same URLs, curl's rules
//! (`fetch.rs`), files, modes (umask 027), output and exit codes as the script, proved against it in fake roots
//! (tests/cli_shtools.rs, docs/RUST_CLI.md).

use super::coreutils::{find_fresh, mkdir_p, mktemp_d, mv_f, rm_rf, strerror, warn};
use super::fetch;
use crate::cli::intel;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// The daily lists: (URL, the check's kind, the file name).
pub const LISTS: [(&str, &str, &str); 5] = [
    ("https://www.spamhaus.org/drop/drop_v4.json", "list", "spamhaus-drop.list"),
    ("https://www.spamhaus.org/drop/drop_v6.json", "list", "spamhaus-dropv6.list"),
    ("https://iplists.firehol.org/files/firehol_level1.netset", "list", "firehol-level1.list"),
    ("https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "list", "et-compromised.list"),
    ("https://security.archlinux.org/issues/all.json", "tracker", "arch-security.json"),
];
pub const KEV_URL: &str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
pub const OSV_URL: &str = "https://osv-vulnerabilities.storage.googleapis.com/Linux/all.zip";
pub const IPINFO_URL: &str = "https://ipinfo.io/data/ipinfo_lite.mmdb";
/// `--max-filesize 200000000`.
pub const MAX_FILESIZE: u64 = 200_000_000;

const ME: &str = "heimdall-intel-update";

/// `${NAME:-default}`: unset and empty are the same.
fn env_or(name: &str, default: &str) -> PathBuf {
    std::env::var_os(name).filter(|v| !v.is_empty()).map_or_else(|| PathBuf::from(default), PathBuf::from)
}

fn env_is_1(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|v| v.as_bytes() == b"1")
}

fn s(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// The script's `fetch URL FILE`.
fn fetch(url: &str, out: &Path, auth: Option<&str>) -> bool {
    fetch::curl(&fetch::Request { url, out, max_filesize: MAX_FILESIZE, auth, max_time: fetch::MAX_TIME }) == 0
}

/// The folders made for this run, removed at the end however it ends (the script's `trap ... EXIT`).
struct Temps(Vec<PathBuf>);

impl Drop for Temps {
    fn drop(&mut self) {
        for p in &self.0 {
            rm_rf(p);
        }
    }
}

/// This month and the one before it, as `date -u +%Y-%m` and `date -u -d "$(date -u +%Y-%m-01) -1 day" +%Y-%m` give them.
pub fn months() -> [String; 2] {
    let (y, m, ..) = crate::gotime::Time::now().utc().civil();
    let (py, pm) = if m == 1 { (y - 1, 12) } else { (y, m - 1) };
    [format!("{y:04}-{m:02}"), format!("{py:04}-{pm:02}")]
}

/// `[[ -r FILE ]]`: readable by this program's effective user.
fn readable(p: &Path) -> bool {
    let Ok(c) = std::ffi::CString::new(p.as_os_str().as_bytes()) else { return false };
    unsafe { libc::faccessat(libc::AT_FDCWD, c.as_ptr(), libc::R_OK, libc::AT_EACCESS) == 0 }
}

pub fn main(_args: &[String]) -> i32 {
    unsafe { libc::umask(0o027) };
    let dir = env_or("HEIMDALL_IPDB_DIR", "/var/lib/heimdall/ipdb");
    let intel = env_or("HEIMDALL_INTEL_DIR", "/var/lib/heimdall/intel");
    for d in [&intel, &dir] {
        if let Err(e) = mkdir_p(d) {
            warn(&e);
            return 1;
        }
    }
    let mut temps = Temps(Vec::new());
    let tmp = match mktemp_d(&dir) {
        Ok(t) => t,
        Err(e) => {
            warn(&e);
            return 1;
        }
    };
    temps.0.push(tmp.clone());

    // the script's install_checked: the database checked, then moved into place
    let install_checked = |file: &Path, name: &str| -> bool {
        if intel::ipdb_check(&[s(file)]) == Some(0) {
            match mv_f(file, &dir.join(name)) {
                Ok(()) => true,
                Err(e) => {
                    warn(&e);
                    false
                }
            }
        } else {
            warn(&format!("{ME}: {name} failed the check; the old file stays"));
            false
        }
    };

    // ---- threat lists and the security tracker (daily)
    let itmp = match mktemp_d(&intel) {
        Ok(t) => t,
        Err(e) => {
            warn(&e);
            return 1;
        }
    };
    temps.0.push(itmp.clone());
    let mut intel_ok = false;
    for (url, kind, name) in LISTS {
        // a list is also compared with its last good copy (a sudden wide range or a list emptied is refused)
        let last = intel.join(name);
        let mut args = vec![kind.to_string(), s(&itmp.join(name))];
        if kind == "list" && std::fs::metadata(&last).is_ok_and(|m| m.is_file()) {
            args.push(s(&last));
        }
        if fetch(url, &itmp.join(name), None) && intel::intel_check(&args) == Some(0) {
            if let Err(e) = mv_f(&itmp.join(name), &last) {
                warn(&e);
                return 1;
            }
            intel_ok = true;
        } else {
            warn(&format!("{ME}: {name} not updated; the last good copy stays"));
        }
    }

    // ---- the kernel's own CVE records (weekly: about 60 MB) and CISA's list of vulnerabilities exploited in the wild, made
    // into one small file (linux-kernel.json) that heimdalld matches against the installed kernels
    if !find_fresh(&intel, |n| n == b"linux-kernel.json", 6) || env_is_1("HEIMDALL_KERNEL_FORCE") {
        let kev = itmp.join("kev.json");
        let zip = itmp.join("linux.zip");
        let mut args = vec!["kernel".to_string(), s(&zip), s(&intel.join("linux-kernel.json"))];
        if fetch(KEV_URL, &kev, None) {
            args.push(s(&kev));
        }
        if fetch(OSV_URL, &zip, None) && intel::intel_check(&args) == Some(0) {
            intel_ok = true;
        } else {
            warn(&format!("{ME}: the kernel CVE list not updated; the last good copy stays"));
        }
        let _ = std::fs::remove_file(&zip);
        let _ = std::fs::remove_file(&kev);
    }

    // ---- IP databases (monthly is enough: they change slowly)
    let fresh = find_fresh(&dir, |n| n.ends_with(b".mmdb"), 25);
    if fresh && !env_is_1("HEIMDALL_IPDB_FORCE") {
        if !intel_ok {
            warn(&format!("{ME}: nothing could be fetched"));
            return 1;
        }
        return 0;
    }
    let mut ok = false;
    let token_file = env_or("HEIMDALL_IPINFO_TOKEN_FILE", "/etc/heimdall/ipinfo-token");
    let token = if readable(&token_file) {
        match std::fs::read(&token_file) {
            Ok(b) => b.into_iter().filter(u8::is_ascii_alphanumeric).map(char::from).collect::<String>(),
            Err(e) => {
                // tr's read of a folder
                if e.raw_os_error() == Some(libc::EISDIR) {
                    warn(&format!("tr: read error: {}", strerror(&e)));
                }
                String::new()
            }
        }
    } else {
        String::new()
    };
    if !token.is_empty() {
        // the token goes in a header, not the URL, so it does not end up in a log line
        let f = tmp.join("ipinfo_lite.mmdb");
        if fetch(IPINFO_URL, &f, Some(&format!("Bearer {token}"))) && install_checked(&f, "ipinfo_lite.mmdb") {
            ok = true;
        } else {
            warn(&format!("{ME}: IPinfo Lite download failed; trying DB-IP Lite"));
        }
    }
    if !ok {
        for kind in ["country", "asn"] {
            let mut got = false;
            // this month's file appears on the 1st; early in the month last month's is still the newest
            for month in months() {
                let gz = tmp.join(format!("{kind}.mmdb.gz"));
                if fetch(&format!("https://download.db-ip.com/free/dbip-{kind}-lite-{month}.mmdb.gz"), &gz, None) {
                    let out = tmp.join(format!("dbip-{kind}-lite.mmdb"));
                    let mut f = match std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o666).open(&out) {
                        Ok(f) => f,
                        Err(e) => {
                            warn(&format!("{ME}: {}: {}", s(&out), strerror(&e)));
                            continue;
                        }
                    };
                    if super::gunzip::gzip_dc(&gz, &mut f) == 0 {
                        got = true;
                        break;
                    }
                }
            }
            let name = format!("dbip-{kind}-lite.mmdb");
            if got && install_checked(&tmp.join(&name), &name) {
                ok = true;
            }
        }
    }
    if !(ok || intel_ok) {
        warn(&format!("{ME}: nothing could be fetched"));
        return 1;
    }
    0
}
