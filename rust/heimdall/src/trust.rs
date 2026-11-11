//! Trust (Go: internal/trust): the signed list of the files that decide how the AI agents behave, read and checked, and the
//! judge the file watch asks about a change to one of them (the daemon's half); and, below, the owner's side for
//! `heimdalld trust ...` (root): the key, signing, forgetting, restoring. The files in `/etc/heimdall/trust` are Go's:
//!
//!   owner.key      the signing key (base64 of Go's 64-byte ed25519 private key: the seed, then the public key; root, 0600)
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

// ---- the owner's side (Go: the rest of internal/trust), for `heimdalld trust ...`: the key, signing, forgetting, restoring

/// The largest number of files signed or watched under one folder (Go: MaxDirFiles).
pub const MAX_DIR_FILES: usize = 5000;

/// Go's `ParseMode`: off, watch or enforce (spaces around trimmed); anything else is Go's error.
pub fn parse_mode(s: &str) -> Result<&'static str, String> {
    match crate::gotext::trim_space(s) {
        "off" => Ok("off"),
        "watch" => Ok("watch"),
        "enforce" => Ok("enforce"),
        _ => Err(format!("unknown trust mode {} (off, watch or enforce)", crate::gotext::quote(s))),
    }
}

/// Go's base64.StdEncoding.EncodeToString.
pub fn std_base64_encode(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The signed list as the owner's side works on it: paths as bytes (a file found in a signed folder may have a name that is
/// not UTF-8, which Go keeps as it is and writes as U+FFFD), sorted as Go sorts a map's keys.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SignedList {
    pub signed_at: Time,
    pub files: BTreeMap<Vec<u8>, String>,
}

impl SignedList {
    pub fn from_manifest(m: &Manifest) -> SignedList {
        SignedList { signed_at: m.signed_at, files: m.files.iter().map(|(k, v)| (k.as_bytes().to_vec(), v.clone())).collect() }
    }
    pub fn has(&self, path: &[u8]) -> bool {
        self.files.contains_key(path)
    }
    pub fn matches(&self, path: &[u8], sha: &str) -> bool {
        !sha.is_empty() && self.files.get(path).is_some_and(|h| h == sha)
    }

    /// The exact bytes Go signs: `json.MarshalIndent(Manifest{Version: 1, ...}, "", "  ")` and a newline.
    pub fn body(&self) -> String {
        let mut out = String::from("{\n  \"version\": 1,\n  \"signed_at\": ");
        gojson::write_str(&mut out, &self.signed_at.rfc3339_nano());
        out.push_str(",\n  \"files\": {");
        for (i, (k, v)) in self.files.iter().enumerate() {
            out.push_str(if i == 0 { "\n    " } else { ",\n    " });
            // the Go that builds heimdalld (1.27, json v2 underneath) writes each byte that is not UTF-8 as U+FFFD itself
            gojson::write_str(&mut out, &crate::gotext::lossy(k));
            out.push_str(": ");
            gojson::write_str(&mut out, v);
        }
        out.push_str(if self.files.is_empty() { "}\n}\n" } else { "\n  }\n}\n" });
        out
    }
}

/// The owner's signing key: Go's 64-byte ed25519.PrivateKey (the seed, then the public key).
pub struct OwnerKey {
    pair: ring::signature::Ed25519KeyPair,
}

impl OwnerKey {
    /// The key Go would make from this seed (`ed25519.NewKeyFromSeed`).
    pub fn from_seed(seed: &[u8; 32]) -> OwnerKey {
        OwnerKey { pair: ring::signature::Ed25519KeyPair::from_seed_unchecked(seed).expect("a 32-byte seed is a key") }
    }
    /// From Go's 64 bytes: the public half must be the seed's (Go would sign with a mismatched half and make a list that
    /// never verifies; that is refused here instead).
    pub fn from_go(b: &[u8]) -> Option<OwnerKey> {
        if b.len() != 64 {
            return None;
        }
        ring::signature::Ed25519KeyPair::from_seed_and_public_key(&b[..32], &b[32..]).ok().map(|pair| OwnerKey { pair })
    }
    pub fn generate() -> Result<OwnerKey, String> {
        use ring::rand::SecureRandom;
        let mut seed = [0u8; 32];
        ring::rand::SystemRandom::new().fill(&mut seed).map_err(|_| "no random numbers from the kernel".to_string())?;
        Ok(OwnerKey::from_seed(&seed))
    }
    pub fn public(&self) -> Vec<u8> {
        use ring::signature::KeyPair;
        self.pair.public_key().as_ref().to_vec()
    }
    /// Go's 64 bytes, as owner.key holds them (base64).
    pub fn go_bytes(&self, seed: &[u8; 32]) -> Vec<u8> {
        let mut b = seed.to_vec();
        b.extend_from_slice(&self.public());
        b
    }
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.pair.sign(msg).as_ref().to_vec()
    }
}

/// Go's trust `writeFile`: through PATH.tmp (written with the mode, then chmod-ed to it) and a rename.
pub fn write_file(path: &str, data: &[u8], mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let tmp = format!("{path}.tmp");
    crate::gopath::write_file(&tmp, data, mode)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)).map_err(|e| crate::goerr::path("chmod", &tmp, &e))?;
    crate::gopath::rename(&tmp, path)
}

/// One file put back by `restore`: its path and "changed" or "deleted".
#[derive(Clone, Debug, PartialEq)]
pub struct Restored {
    pub path: String,
    pub why: &'static str,
}

fn os(p: &[u8]) -> &std::path::Path {
    use std::os::unix::ffi::OsStrExt;
    std::path::Path::new(std::ffi::OsStr::from_bytes(p))
}

/// Go's `HashFile`: the hex SHA-256 of a file's content ("open P: ..." or "read P: ..." when it cannot be read).
pub fn hash_file(path: &[u8]) -> Result<String, std::io::Error> {
    use sha2::Digest;
    use std::io::Read;
    let mut f = std::fs::File::open(os(path))?;
    let mut h = sha2::Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(|e| std::io::Error::new(e.kind(), ReadErr(e)))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(crate::state::hex(&h.finalize()))
}

/// A read error (not an open one), so the text says "read" as Go's does.
#[derive(Debug)]
struct ReadErr(std::io::Error);
impl std::fmt::Display for ReadErr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
impl std::error::Error for ReadErr {}

/// Go's text for a `hash_file` error on `path`.
pub fn hash_err(path: &[u8], e: &std::io::Error) -> String {
    let p = crate::gotext::lossy(path);
    match e.get_ref().and_then(|x| x.downcast_ref::<ReadErr>()) {
        Some(ReadErr(inner)) => crate::goerr::path("read", &p, inner),
        None => crate::goerr::path("open", &p, e),
    }
}

/// Whether a hash_file error is Go's os.IsNotExist.
pub fn not_exist(e: &std::io::Error) -> bool {
    e.get_ref().is_none_or(|x| x.downcast_ref::<ReadErr>().is_none()) && e.kind() == std::io::ErrorKind::NotFound
}

/// Go's `Expand`: a path as the regular files it names (itself, or every regular file under a folder, links not followed,
/// at most MAX_DIR_FILES), sorted. The files found before an error come back with it.
pub fn expand(p: &str) -> (Vec<Vec<u8>>, Option<String>) {
    let abs = match crate::gopath::abs(p) {
        Ok(a) => a,
        Err(e) => return (Vec::new(), Some(e)),
    };
    let info = match std::fs::symlink_metadata(&abs) {
        Ok(i) => i,
        Err(e) => return (Vec::new(), Some(crate::goerr::path("lstat", &abs, &e))),
    };
    if info.file_type().is_file() {
        return (vec![abs.into_bytes()], None);
    }
    if !info.is_dir() {
        return (Vec::new(), Some(format!("{abs} is not a regular file or a folder")));
    }
    let mut out = Vec::new();
    let err = walk(abs.as_bytes(), &abs, &mut out);
    out.sort();
    (out, err)
}

/// filepath.WalkDir's order (names sorted in each folder), regular files only, unreadable folders skipped.
fn walk(dir: &[u8], top: &str, out: &mut Vec<Vec<u8>>) -> Option<String> {
    use std::os::unix::ffi::OsStrExt;
    let Ok(rd) = std::fs::read_dir(os(dir)) else { return None };
    let mut names: Vec<(Vec<u8>, std::fs::FileType)> =
        rd.flatten().filter_map(|e| e.file_type().ok().map(|t| (e.file_name().as_bytes().to_vec(), t))).collect();
    names.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, t) in names {
        let mut p = dir.to_vec();
        if !p.ends_with(b"/") {
            p.push(b'/');
        }
        p.extend_from_slice(&name);
        if t.is_file() {
            if out.len() >= MAX_DIR_FILES {
                return Some(format!("{top} has more than {MAX_DIR_FILES} files"));
            }
            out.push(p);
        } else if t.is_dir() {
            if let Some(e) = walk(&p, top, out) {
                return Some(e);
            }
        }
    }
    None
}

impl Store {
    /// Go's `SetMode` (root).
    pub fn set_mode(&self, m: &str) -> Result<(), String> {
        let m = parse_mode(m)?;
        write_file(&self.path("mode"), format!("{m}\n").as_bytes(), 0o644)
    }

    /// Go's `SetWatch`: `json.MarshalIndent(w, "", "  ")` and a newline (root).
    pub fn set_watch(&self, w: &WatchList) -> Result<(), String> {
        let v = Val::Struct(vec![
            Val::Slice(w.files.as_ref().map(|f| f.iter().map(|s| Val::Str(s.clone())).collect())),
            Val::Slice(w.dirs.as_ref().map(|f| f.iter().map(|s| Val::Str(s.clone())).collect())),
        ]);
        let body = gostruct::to_json_indented(&WATCH, &v, "  ").unwrap_or_default() + "\n";
        write_file(&self.path("watch.json"), body.as_bytes(), 0o644)
    }

    /// Go's `Init`: the key pair, made once (an existing key is never replaced: that would void every signature), the mode
    /// off unless one is there, and an empty signed list. True when the key was made now.
    pub fn init(&self) -> Result<bool, String> {
        if std::fs::metadata(self.path("owner.key")).is_ok() {
            return Ok(false);
        }
        crate::gopath::mkdir_all(&self.dir, 0o755)?;
        use ring::rand::SecureRandom;
        let mut seed = [0u8; 32];
        ring::rand::SystemRandom::new().fill(&mut seed).map_err(|_| "no random numbers from the kernel".to_string())?;
        let key = OwnerKey::from_seed(&seed);
        write_file(&self.path("owner.key"), format!("{}\n", std_base64_encode(&key.go_bytes(&seed))).as_bytes(), 0o600)?;
        write_file(&self.path("owner.pub"), format!("{}\n", std_base64_encode(&key.public())).as_bytes(), 0o644)?;
        if std::fs::metadata(self.path("mode")).is_err() {
            self.set_mode("off").map_err(|e| e.to_string())?;
        }
        self.write(&mut SignedList::default(), &key)?;
        Ok(true)
    }

    /// The signing key (Go: key).
    pub fn owner_key(&self) -> Result<OwnerKey, String> {
        let why = |e: String| format!("the signing key cannot be read (run as root, after heimdalld trust init): {e}");
        let b = self.key("owner.key", 64).map_err(why)?;
        OwnerKey::from_go(&b).ok_or_else(|| why(format!("{} is not a key", self.path("owner.key"))))
    }

    /// Go's `write`: signed now (UTC, whole seconds), the list then its signature written under new names and both renamed.
    pub fn write(&self, m: &mut SignedList, key: &OwnerKey) -> Result<(), String> {
        m.signed_at = Time::now().utc().truncate(1_000_000_000);
        self.write_signed(m, key)
    }

    /// `write` with the time already set (the fixtures sign at a known time).
    pub fn write_signed(&self, m: &SignedList, key: &OwnerKey) -> Result<(), String> {
        let body = m.body();
        let sig = key.sign(body.as_bytes());
        write_file(&self.path("manifest.json.new"), body.as_bytes(), 0o644)?;
        write_file(&self.path("manifest.sig.new"), format!("{}\n", std_base64_encode(&sig)).as_bytes(), 0o644)?;
        crate::gopath::rename(&self.path("manifest.json.new"), &self.path("manifest.json"))?;
        crate::gopath::rename(&self.path("manifest.sig.new"), &self.path("manifest.sig"))
    }

    /// Go's `Sign`: approves the current content of each path (a folder: every file under it). The paths signed come back,
    /// with the error that stopped it, if any.
    pub fn sign(&self, paths: &[String]) -> (Vec<Vec<u8>>, Option<String>) {
        let key = match self.owner_key() {
            Ok(k) => k,
            Err(e) => return (Vec::new(), Some(e)),
        };
        let mut m = match self.load() {
            Ok(m) => SignedList::from_manifest(&m),
            Err(e) => return (Vec::new(), Some(e)),
        };
        let mut done = Vec::new();
        for p in paths {
            let (files, err) = expand(p);
            if let Some(e) = err {
                return (done, Some(e));
            }
            for f in files {
                let sum = match hash_file(&f) {
                    Ok(s) => s,
                    Err(e) => return (done, Some(hash_err(&f, &e))),
                };
                if let Err(e) = self.keep_copy(&f, &sum) {
                    return (done, Some(e));
                }
                m.files.insert(f.clone(), sum);
                done.push(f);
            }
        }
        if let Err(e) = self.write(&mut m, &key) {
            return (done, Some(e));
        }
        self.prune_copies(&m);
        (done, None)
    }

    /// Go's `keepCopy`: the approved content under approved/<sha256> (root only), unless it is there already.
    fn keep_copy(&self, path: &[u8], sum: &str) -> Result<(), String> {
        use sha2::Digest;
        let dir = self.path("approved");
        crate::gopath::mkdir_all(&dir, 0o700)?;
        let dst = format!("{dir}/{sum}");
        if std::fs::metadata(&dst).is_ok() {
            return Ok(());
        }
        let p = crate::gotext::lossy(path);
        let b = std::fs::read(os(path)).map_err(|e| crate::gopath::read_err(&p, &e))?;
        if crate::state::hex(&sha2::Sha256::digest(&b)) != sum {
            return Err(format!("{p} changed while it was being signed; sign it again"));
        }
        write_file(&dst, &b, 0o600)
    }

    /// Go's `pruneCopies`: the copies no entry needs any more are removed.
    fn prune_copies(&self, m: &SignedList) {
        use std::os::unix::ffi::OsStrExt;
        let need: std::collections::HashSet<&[u8]> = m.files.values().map(|s| s.as_bytes()).collect();
        let Ok(rd) = std::fs::read_dir(self.path("approved")) else { return };
        for e in rd.flatten() {
            let n = e.file_name();
            if !need.contains(n.as_bytes()) && n.len() == 64 {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }

    /// Go's `Restore`: the approved content of listed files that were changed or deleted put back (only those under
    /// `paths`, or all), written as their folder's owner and never through a link. Files the list does not know are left.
    pub fn restore(&self, paths: &[String]) -> (Vec<Restored>, Option<String>) {
        let m = match self.load() {
            Ok(m) => m,
            Err(e) => return (Vec::new(), Some(e)),
        };
        let mut abs = Vec::new();
        for p in paths {
            match crate::gopath::abs(p) {
                Ok(a) => abs.push(a),
                Err(e) => return (Vec::new(), Some(e)),
            }
        }
        let within = |f: &str| abs.is_empty() || abs.iter().any(|a| f == a || f.starts_with(&format!("{a}/")));
        let mut out = Vec::new();
        for (f, want) in &m.files {
            if !within(f) {
                continue;
            }
            let why = match hash_file(f.as_bytes()) {
                Err(e) if not_exist(&e) => "deleted",
                Ok(have) if &have == want => continue,
                _ => "changed",
            };
            let copy = format!("{}/{want}", self.path("approved"));
            let b = match std::fs::read(&copy) {
                Ok(b) => b,
                Err(e) => return (out, Some(format!("no approved copy of {f}: {}", crate::gopath::read_err(&copy, &e)))),
            };
            if let Err(e) = crate::safefs::put(f, &crate::safefs::File { data: b, mode: 0o644, mtime: None, exclusive: false }) {
                return (out, Some(e));
            }
            out.push(Restored { path: f.clone(), why });
        }
        (out, None)
    }

    /// Go's `Forget`: entries removed (a folder: every entry under it), the paths removed sorted.
    pub fn forget(&self, paths: &[String]) -> (Vec<String>, Option<String>) {
        let key = match self.owner_key() {
            Ok(k) => k,
            Err(e) => return (Vec::new(), Some(e)),
        };
        let mut m = match self.load() {
            Ok(m) => SignedList::from_manifest(&m),
            Err(e) => return (Vec::new(), Some(e)),
        };
        let mut gone = Vec::new();
        for p in paths {
            let a = match crate::gopath::abs(p) {
                Ok(a) => a,
                Err(e) => return (gone, Some(e)),
            };
            let prefix = format!("{a}/");
            let hit: Vec<Vec<u8>> =
                m.files.keys().filter(|f| f.as_slice() == a.as_bytes() || f.starts_with(prefix.as_bytes())).cloned().collect();
            for f in hit {
                m.files.remove(&f);
                gone.push(crate::gotext::lossy(&f));
            }
        }
        gone.sort();
        let err = self.write(&mut m, &key).err();
        (gone, err)
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
            // a key file: 64 bytes whose halves agree, or refused
            if let Some(k) = OwnerKey::from_go(&b) {
                assert_eq!(k.public(), b[32..]);
            }
        }
    }
    // the owner's side: any bytes as a path in a list the owner signs; the list written reads back with each path spelled
    // as Go spells it (each byte that is not UTF-8 as U+FFFD), and the base64 writer reads back
    assert_eq!(std_base64(&std_base64_encode(data)).as_deref(), Some(data));
    let mut m = SignedList::default();
    m.files.insert(data.to_vec(), "0".repeat(64));
    let back = parse_manifest(m.body().as_bytes()).expect("the owner's list always reads back");
    assert!(back.has(&crate::gotext::lossy(data)));
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

    /// The base64 writer of the owner's key and signature files reads back exactly, for any bytes up to 5.
    #[kani::proof]
    #[kani::unwind(8)]
    fn base64_round_trips() {
        let b: [u8; 5] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= 5);
        let text = std_base64_encode(&b[..len]);
        assert_eq!(text.len(), len.div_ceil(3) * 4);
        assert_eq!(std_base64(&text).as_deref(), Some(&b[..len]));
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

    /// The second Kani claim without Kani: every input of up to 2 bytes, and lengths up to 5 with a few byte values.
    #[test]
    fn base64_round_trips() {
        let mut n = 0;
        for len in 0..=5usize {
            let values: &[u8] = if len <= 2 { &[] } else { &[0, 1, 0x7f, 0x80, 0xfe, 0xff] };
            let count = if len <= 2 { 256usize.pow(len as u32) } else { values.len().pow(len as u32) };
            for i in 0..count {
                let b: Vec<u8> = (0..len)
                    .map(|k| if len <= 2 { (i >> (8 * k)) as u8 } else { values[i / values.len().pow(k as u32) % values.len()] })
                    .collect();
                let text = std_base64_encode(&b);
                assert_eq!(text.len(), len.div_ceil(3) * 4);
                assert_eq!(std_base64(&text).as_deref(), Some(&b[..]));
                n += 1;
            }
        }
        assert!(n > 60_000);
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
