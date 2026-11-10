//! Trust (Go: internal/trust), the daemon's half: the signed list of the files that decide how the AI agents behave, read
//! and checked, and the judge the file watch asks about a change to one of them. Signing, restoring and the key stay with
//! the Go one-shot command (`heimdalld trust ...`, root); this reads what it wrote in `/etc/heimdall/trust`:
//!
//!   owner.pub      the public key (base64 of 32 bytes)
//!   manifest.json  `{"version":1,"signed_at":...,"files":{"/abs/path":"sha256"}}`
//!   manifest.sig   base64 Ed25519 signature over the exact bytes of manifest.json
//!   mode           off | watch | enforce
//!   watch.json     `{"files":[...],"dirs":[...]}`
//!
//! A list that does not verify trusts nothing: every watched change is then "unsigned". Every file is read again on each
//! question, as in Go, so a new signature counts at once.

use crate::detect::TrustJudge;
use crate::gojson::{self, Value};
use crate::gostruct::{self, Field, Ty, Val};
use crate::gotime::Time;
use std::collections::BTreeMap;

pub const DEFAULT_DIR: &str = "/etc/heimdall/trust";

/// One trust folder (Go: Store).
#[derive(Clone, Debug)]
pub struct Store {
    pub dir: String,
}

/// The signed list (Go: Manifest).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Manifest {
    pub version: i64,
    pub signed_at: Time,
    pub files: BTreeMap<String, String>,
}

impl Manifest {
    /// Whether `path` is approved with exactly this content hash.
    pub fn matches(&self, path: &str, sha: &str) -> bool {
        !sha.is_empty() && self.files.get(path).is_some_and(|h| h == sha)
    }
    /// Whether `path` is on the list at all.
    pub fn has(&self, path: &str) -> bool {
        self.files.contains_key(path)
    }
}

/// What the file watch looks at besides fim_paths (Go: WatchList).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct WatchList {
    /// None: Go's nil (written as null)
    pub files: Option<Vec<String>>,
    pub dirs: Option<Vec<String>>,
}

impl WatchList {
    /// Whether `path` is one of the files or under one of the folders (Go: watches).
    pub fn watches(&self, path: &str) -> bool {
        self.files.iter().flatten().any(|f| f == path)
            || self.dirs.iter().flatten().any(|d| path.starts_with(&format!("{}/", d.strip_suffix('/').unwrap_or(d))))
    }

    /// The list as Go's json.Marshal writes it.
    pub fn to_json(&self) -> String {
        let v = Val::Struct(vec![
            Val::Slice(self.files.as_ref().map(|f| f.iter().map(|s| Val::Str(s.clone())).collect())),
            Val::Slice(self.dirs.as_ref().map(|f| f.iter().map(|s| Val::Str(s.clone())).collect())),
        ]);
        gostruct::to_json(&WATCH, &v).unwrap_or_default()
    }
}

static WATCH: Ty =
    Ty::Struct("trust.WatchList", &[Field("files", &Ty::Slice(&Ty::Str), false), Field("dirs", &Ty::Slice(&Ty::Str), false)]);

/// Go's base64.StdEncoding.DecodeString: padding required, newlines (\r, \n) skipped, anything else outside the alphabet
/// refused.
pub fn std_base64(s: &str) -> Option<Vec<u8>> {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let b: Vec<u8> = s.bytes().filter(|c| *c != b'\r' && *c != b'\n').collect();
    if b.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    for (i, q) in b.chunks(4).enumerate() {
        let last = i == b.len() / 4 - 1;
        let pad = q.iter().rev().take_while(|c| **c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for (j, c) in q.iter().enumerate() {
            let v = if j >= 4 - pad { 0 } else { A.iter().position(|a| a == c)? as u32 };
            n = n << 6 | v;
        }
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..3 - pad]);
    }
    Some(out)
}

fn read(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| crate::sources::go_path_error("open", path, &e))
}

impl Store {
    pub fn new(dir: &str) -> Store {
        Store { dir: dir.to_string() }
    }

    fn path(&self, name: &str) -> String {
        format!("{}/{name}", self.dir.trim_end_matches('/'))
    }

    /// The mode; a missing, unreadable or unknown one is "off" (Go: Mode).
    pub fn mode(&self) -> &'static str {
        let Ok(b) = std::fs::read(self.path("mode")) else { return "off" };
        match std::str::from_utf8(&b).map(crate::gotext::trim_space) {
            Ok("watch") => "watch",
            Ok("enforce") => "enforce",
            _ => "off",
        }
    }

    /// The watch list; missing or unreadable is nothing extra, a document that reads in part keeps that part (Go: Watch).
    pub fn watch(&self) -> WatchList {
        let Ok(b) = std::fs::read(self.path("watch.json")) else { return WatchList::default() };
        let (v, _) = gostruct::unmarshal(&WATCH, &b);
        let list = |k: &str| match gostruct::field(&WATCH, &v, k) {
            Some(Val::Slice(Some(items))) => {
                Some(items.iter().map(|x| if let Val::Str(s) = x { s.clone() } else { String::new() }).collect())
            }
            _ => None,
        };
        WatchList { files: list("files"), dirs: list("dirs") }
    }

    fn key(&self, name: &str, size: usize) -> Result<Vec<u8>, String> {
        let path = self.path(name);
        let b = read(&path)?;
        match std::str::from_utf8(&b).ok().and_then(|s| std_base64(crate::gotext::trim_space(s))) {
            Some(k) if k.len() == size => Ok(k),
            _ => Err(format!("{path} is not a key")),
        }
    }

    /// Reads the list and checks its signature (Go: Load). A list that does not verify is an error: nothing in it can be
    /// trusted.
    pub fn load(&self) -> Result<Manifest, String> {
        let public = self.key("owner.pub", 32)?;
        let body = read(&self.path("manifest.json"))?;
        let sig_text = read(&self.path("manifest.sig"))?;
        let sig = std::str::from_utf8(&sig_text).ok().and_then(|s| std_base64(crate::gotext::trim_space(s)));
        let ok = sig.is_some_and(|s| ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &public).verify(&body, &s).is_ok());
        if !ok {
            return Err("the signed list of approved files does not match its signature (changed by someone without the key)".into());
        }
        parse_manifest(&body)
    }
}

/// Go's json.Unmarshal into a Manifest: keys without regard to case, the first type error reported (the rest still read,
/// but Load then refuses the list), duplicate `files` objects merged, a null file entry kept as "".
pub fn parse_manifest(body: &[u8]) -> Result<Manifest, String> {
    static VERSION: Ty = Ty::Int;
    let v = gojson::parse(body).map_err(|e| e.0)?;
    let mut m = Manifest::default();
    let members = match v {
        Value::Null => return Ok(m),
        Value::Object(members) => members,
        other => return Err(format!("json: cannot unmarshal {} into Go value of type trust.Manifest", gojson::kind(&other))),
    };
    let mut first: Option<String> = None;
    for (k, x) in &members {
        // Go matches an exact field name first, else one without regard to case (the three names differ in more than case)
        if gojson::key_matches(k, "version") {
            let mut cx = gostruct::Ctx { top: "Manifest", first: None };
            let mut val = Val::Int(m.version);
            gostruct::read(&VERSION, x, &mut val, "version", &mut cx);
            if let Val::Int(n) = val {
                m.version = n;
            }
            if let Some(e) = cx.first {
                first.get_or_insert(e.0);
            }
        } else if gojson::key_matches(k, "signed_at") {
            match x {
                Value::Null => {}
                Value::String(s) => match Time::parse_rfc3339(s) {
                    Some(t) => m.signed_at = t,
                    None => {
                        first.get_or_insert(format!(
                            "parsing time {} as \"2006-01-02T15:04:05Z07:00\": cannot parse",
                            crate::gotext::quote(s)
                        ));
                    }
                },
                _ => {
                    first.get_or_insert("Time.UnmarshalJSON: input is not a JSON string".into());
                }
            }
        } else if gojson::key_matches(k, "files") {
            match x {
                Value::Null => m.files.clear(),
                Value::Object(entries) => {
                    for (path, h) in entries {
                        match h {
                            Value::String(s) => {
                                m.files.insert(path.clone(), s.clone());
                            }
                            Value::Null => {
                                m.files.insert(path.clone(), String::new());
                            }
                            other => {
                                let what = gojson::kind(other);
                                let field = path.replace('~', "~0").replace('/', "~1");
                                first.get_or_insert(format!(
                                    "json: cannot unmarshal {what} into Go struct field Manifest.files.{field} of type string"
                                ));
                            }
                        }
                    }
                }
                other => {
                    let what = gojson::kind(other);
                    first.get_or_insert(format!(
                        "json: cannot unmarshal {what} into Go struct field Manifest.files of type map[string]string"
                    ));
                }
            }
        }
    }
    match first {
        Some(e) => Err(e),
        None => Ok(m),
    }
}

/// The file watch's question (Go: Judge): whether a change to a watched behaviour file was approved. ("", "") when trust
/// has no say (off, or not a watched path).
#[derive(Clone, Debug)]
pub struct Judge {
    pub store: Store,
}

impl Judge {
    pub fn judge(&self, path: &str, new_hash: &str, deleted: bool) -> (String, String) {
        if self.store.mode() == "off" || !self.store.watch().watches(path) {
            return (String::new(), String::new());
        }
        let m = match self.store.load() {
            Ok(m) => m,
            Err(e) => return ("unsigned".into(), format!("the signed list cannot be checked: {e}")),
        };
        let (v, why) = match () {
            _ if deleted && m.has(path) => ("unsigned", "the signed list still expects it"),
            _ if deleted => ("approved", ""),
            _ if m.matches(path, new_hash) => ("approved", ""),
            _ if m.has(path) => ("unsigned", "its content differs from the signed version"),
            _ => ("unsigned", "it is not on the signed list"),
        };
        (v.into(), why.into())
    }
}

impl TrustJudge for Judge {
    fn judge(&self, path: &str, new_hash: &str, deleted: bool) -> (String, String) {
        Judge::judge(self, path, new_hash, deleted)
    }
}

/// The fuzz target's body: any bytes as a signed list (read or refused, never a panic; an empty hash never matches)
/// and as a key or signature file (Go's base64: at most 3 bytes out for 4 in).
pub fn fuzz_list(data: &[u8]) {
    if let Ok(m) = parse_manifest(data) {
        assert!(m.files.keys().all(|k| m.has(k) && !m.matches(k, "")), "an empty hash never matches");
    }
    if let Ok(s) = std::str::from_utf8(data) {
        if let Some(b) = std_base64(s) {
            assert!(b.len() * 4 <= s.len() * 3);
        }
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Go's base64 reader never panics and never makes more than 3 bytes of 4 (inputs up to 8 bytes).
    #[kani::proof]
    #[kani::unwind(10)]
    fn base64_never_panics() {
        let b: [u8; 8] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= 8);
        if let Ok(s) = std::str::from_utf8(&b[..len]) {
            if let Some(out) = std_base64(s) {
                assert!(out.len() * 4 <= len * 3);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Kani claim over every input of up to 4 characters from a mixed alphabet, without Kani.
    #[test]
    fn base64_never_panics() {
        let alphabet = b"Aa0+/=\r\n-.";
        let mut n = 0;
        for len in 0..=4u32 {
            for i in 0..alphabet.len().pow(len) {
                let s: String = (0..len).map(|k| alphabet[i / alphabet.len().pow(k) % alphabet.len()] as char).collect();
                if let Some(out) = std_base64(&s) {
                    assert!(out.len() * 4 <= s.len() * 3, "{s:?}");
                }
                n += 1;
            }
        }
        assert!(n > 11_000);
    }

    #[test]
    fn base64_as_go_reads_it() {
        assert_eq!(std_base64("aGk=").unwrap(), b"hi");
        assert_eq!(std_base64("aG\r\nk=").unwrap(), b"hi");
        assert!(std_base64("aGk").is_none(), "padding is required");
        assert!(std_base64("aG k=").is_none());
        assert!(std_base64("a-_=").is_none());
        assert!(std_base64("aGk=aGk=").is_none(), "padding only at the end");
        assert_eq!(std_base64("").unwrap(), b"");
    }
}
