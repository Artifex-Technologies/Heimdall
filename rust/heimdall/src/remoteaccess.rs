//! Remote-access, tunnel and command-and-control tools (Go: internal/remoteaccess): the Go daemon's catalog, compiled in from
//! the same file, and recognition by program name or by the Go module paths in a program's own build info (so a renamed Go
//! binary is still known).

use crate::gojson::{self, FromGo};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};

pub const CATALOG: &str = include_str!("../../../internal/remoteaccess/remote-access.json");

#[derive(Clone, Debug, Default)]
pub struct Provider {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub packages: Vec<String>,
    pub exes: Vec<String>,
    pub go_modules: Vec<String>,
    pub units: Vec<String>,
    pub ifaces: Vec<String>,
    pub ports: Vec<i64>,
}
crate::go_struct!(Provider {
    id: "id",
    name: "name",
    kind: "kind",
    packages: "packages",
    exes: "exes",
    go_modules: "go_modules",
    units: "units",
    ifaces: "ifaces",
    ports: "ports",
});

#[derive(Default)]
struct CatalogFile {
    providers: Vec<Provider>,
}
crate::go_struct!(CatalogFile { providers: "providers" });

#[derive(Clone, Debug, Default)]
pub struct Catalog {
    pub providers: Vec<Provider>,
}

/// Go's filepath.Match for the catalog's interface patterns (`*` and `?`; brackets are not used there and match literally).
fn glob(pat: &[u8], s: &[u8]) -> bool {
    match (pat.first(), s.first()) {
        (None, None) => true,
        (Some(b'*'), _) => glob(&pat[1..], s) || (!s.is_empty() && s[0] != b'/' && glob(pat, &s[1..])),
        (Some(b'?'), Some(c)) if *c != b'/' => glob(&pat[1..], &s[1..]),
        (Some(p), Some(c)) if p == c => glob(&pat[1..], &s[1..]),
        _ => false,
    }
}

impl Catalog {
    pub fn builtin() -> Catalog {
        let mut f = CatalogFile::default();
        f.read_into(&gojson::parse(CATALOG.as_bytes()).expect("the built-in catalog is JSON"), "").expect("the built-in catalog reads");
        Catalog { providers: f.providers }
    }

    fn find(&self, m: impl Fn(&Provider) -> bool) -> Option<&Provider> {
        self.providers.iter().find(|p| m(p))
    }

    pub fn match_package(&self, name: &str) -> Option<&Provider> {
        self.find(|p| p.packages.iter().any(|x| x == name))
    }

    pub fn match_iface(&self, name: &str) -> Option<&Provider> {
        self.find(|p| p.ifaces.iter().any(|pat| glob(pat.as_bytes(), name.as_bytes())))
    }

    pub fn match_exe(&self, exe: &str, comm: &str) -> Option<&Provider> {
        let path = exe.strip_suffix(" (deleted)").unwrap_or(exe);
        let base = base(path);
        self.find(|p| p.exes.iter().any(|x| x == base) || (!comm.is_empty() && p.exes.iter().any(|x| x == comm)))
    }

    pub fn match_go_modules(&self, mods: &[String]) -> Option<&Provider> {
        self.find(|p| p.go_modules.iter().any(|want| mods.iter().any(|m| m == want || m.starts_with(&format!("{want}/")))))
    }
}

/// Go's filepath.Base.
pub fn base(p: &str) -> &str {
    let t = p.trim_end_matches('/');
    if t.is_empty() {
        return if p.is_empty() { "." } else { "/" };
    }
    t.rsplit('/').next().unwrap_or(t)
}

/// The Go module paths in an ELF program's build info (Go 1.18+ format): (main: [main module, main package path], deps).
/// None when it is not a Go program (or not one this reader understands), as Go's debug/buildinfo reports an error.
pub fn go_modules(path: &str) -> Option<(Vec<String>, Vec<String>)> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut h = [0u8; 64];
    f.read_exact(&mut h).ok()?;
    if &h[..4] != b"\x7fELF" || h[4] != 2 || h[5] != 1 {
        return None; // 64-bit little-endian ELF only (what runs here)
    }
    let u16_at = |b: &[u8], o: usize| u16::from_le_bytes([b[o], b[o + 1]]) as u64;
    let u32_at = |b: &[u8], o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) as u64;
    let u64_at = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    let (phoff, shoff) = (u64_at(&h, 32), u64_at(&h, 40));
    let (phentsize, phnum, shentsize, shnum, shstrndx) = (u16_at(&h, 54), u16_at(&h, 56), u16_at(&h, 58), u16_at(&h, 60), u16_at(&h, 62));
    let read = |f: &mut std::fs::File, off: u64, n: usize| -> Option<Vec<u8>> {
        let mut b = vec![0u8; n];
        f.seek(SeekFrom::Start(off)).ok()?;
        let got = f.by_ref().take(n as u64).read(&mut b).ok()?;
        b.truncate(got);
        Some(b)
    };
    // the .go.buildinfo section, else the first writable loaded segment (as Go's reader looks)
    let mut start: Option<u64> = None;
    if shnum > 0 && shentsize >= 64 && shnum < 4096 {
        let sh = read(&mut f, shoff, (shnum * shentsize) as usize)?;
        if sh.len() == (shnum * shentsize) as usize && shstrndx < shnum {
            let s = &sh[(shstrndx * shentsize) as usize..];
            let names = read(&mut f, u64_at(s, 24), u64_at(s, 32).min(1 << 20) as usize)?;
            for i in 0..shnum {
                let s = &sh[(i * shentsize) as usize..];
                let n = u32_at(s, 0) as usize;
                if names.get(n..).is_some_and(|r| r.starts_with(b".go.buildinfo\0")) {
                    start = Some(u64_at(s, 24));
                }
            }
        }
    }
    if start.is_none() && phnum > 0 && phentsize >= 56 && phnum < 4096 {
        let ph = read(&mut f, phoff, (phnum * phentsize) as usize)?;
        for i in 0..phnum as usize {
            let p = &ph[i * phentsize as usize..];
            if p.len() >= 56 && u32_at(p, 0) == 1 && u32_at(p, 4) & 2 != 0 {
                start = Some(u64_at(p, 8));
                break;
            }
        }
    }
    let data = read(&mut f, start?, 64 << 10)?;
    const MAGIC: &[u8] = b"\xff Go buildinf:";
    let at = (0..data.len().saturating_sub(32)).step_by(16).find(|&i| data[i..].starts_with(MAGIC))?;
    let hdr = &data[at..];
    if hdr[15] & 2 == 0 {
        return None; // the pre-1.18 pointer format
    }
    let mut rest = &hdr[32..];
    let mut string = || -> Option<Vec<u8>> {
        let (mut n, mut shift, mut i) = (0u64, 0u32, 0usize);
        loop {
            let b = *rest.get(i)?;
            n |= ((b & 0x7f) as u64) << shift;
            i += 1;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift > 63 {
                return None;
            }
        }
        let s = rest.get(i..i + n as usize)?.to_vec();
        rest = &rest[i + n as usize..];
        Some(s)
    };
    let _version = string()?;
    let raw = string()?;
    // the module info is wrapped in 16-byte sentinels (bytes, not text: they are cut before reading it as text)
    let modinfo =
        if raw.len() >= 33 && raw[raw.len() - 17] == b'\n' { crate::gotext::lossy(&raw[16..raw.len() - 16]) } else { String::new() };
    let (mut path_, mut main, mut deps) = (String::new(), String::new(), Vec::new());
    for line in modinfo.lines() {
        let mut f = line.split('\t');
        match f.next() {
            Some("path") => path_ = f.next().unwrap_or("").to_owned(),
            Some("mod") => main = f.next().unwrap_or("").to_owned(),
            Some("dep") => deps.push(f.next().unwrap_or("").to_owned()),
            _ => {}
        }
    }
    Some((vec![main, path_], deps))
}

/// Recognises the remote-access tool a program is, by name or build info (cached by path, size and time).
#[derive(Default)]
pub struct Identifier {
    pub catalog: Catalog,
    cache: HashMap<String, Option<(usize, &'static str)>>,
}

impl Identifier {
    pub fn new(catalog: Catalog) -> Identifier {
        Identifier { catalog, cache: HashMap::new() }
    }

    /// (provider, signal): signal "exe", "gomod" or "gomod-dep".
    pub fn identify(&mut self, exe: &str, comm: &str) -> Option<(Provider, &'static str)> {
        if let Some(p) = self.catalog.match_exe(exe, comm) {
            return Some((p.clone(), "exe"));
        }
        let path = exe.strip_suffix(" (deleted)").unwrap_or(exe);
        let md = std::fs::metadata(path).ok().filter(|m| m.is_file())?;
        let key = format!("{path}|{}|{}", md.len(), crate::sources::mtime(&md).unix_nanos());
        if let Some(r) = self.cache.get(&key) {
            return r.map(|(i, s)| (self.catalog.providers[i].clone(), s));
        }
        let (main, deps) = go_modules(path).unwrap_or_default();
        let idx =
            |mods: &[String]| self.catalog.match_go_modules(mods).and_then(|p| self.catalog.providers.iter().position(|x| x.id == p.id));
        let r = idx(&main).map(|i| (i, "gomod")).or_else(|| idx(&deps).map(|i| (i, "gomod-dep")));
        self.cache.insert(key, r);
        r.map(|(i, s)| (self.catalog.providers[i].clone(), s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_catalog_reads_and_matches() {
        let c = Catalog::builtin();
        assert!(c.providers.len() >= 20);
        assert_eq!(c.match_exe("/usr/bin/tailscaled", "").map(|p| p.id.as_str()), Some("tailscale"));
        assert_eq!(c.match_iface("tailscale0").map(|p| p.id.as_str()), Some("tailscale"));
        assert!(c.match_iface("eth0").is_none());
        assert!(glob(b"zt*", b"ztabc") && !glob(b"zt*", b"xzt"));
    }

    #[test]
    fn reads_a_go_programs_modules() {
        // the Go toolchain itself is a Go program: its main module is cmd
        if let Ok(go) = std::process::Command::new("go").args(["env", "GOROOT"]).output() {
            let root = String::from_utf8_lossy(&go.stdout).trim().to_string();
            if let Some((main, _)) = go_modules(&format!("{root}/bin/go")) {
                assert!(main.iter().any(|m| m.starts_with("cmd")), "{main:?}");
            }
        }
        assert!(go_modules("/bin/sh").is_none() || go_modules("/bin/sh").is_some_and(|(m, _)| m.iter().all(String::is_empty)));
    }
}
