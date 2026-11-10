//! What the daemon needs of immunity (Go: internal/immunity): the index of what is held (read for GET /v1/quarantine and to
//! know a sample a rule draft names) and the rule drafts file (GET and POST /v1/rules/drafts). The rest (keeping, testing,
//! approving, releasing samples) is root's, through `heimdalld immunity`, and stays in Go.

use crate::gostruct::{self, Field, Ty, Val};
use crate::gotime::Time;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::sync::Mutex;

/// The root-only store's folder (HEIMDALL_IMMUNITY_DIR in tests); its index is readable by heimdalld's group.
pub const DEFAULT_DIR: &str = "/var/lib/heimdall-immunity";
pub const DEFAULT_RULE_DRAFTS: &str = "/var/lib/heimdall/rule-drafts.json";
const MAX_RULE: usize = 16 << 10;
const MAX_DRAFTS: usize = 100;

static STRS: Ty = Ty::Slice(&Ty::Str);
static ELF: Ty = Ty::Struct(
    "immunity.ELFInfo",
    &[
        Field("class", &Ty::Str, false),
        Field("machine", &Ty::Str, false),
        Field("type", &Ty::Str, false),
        Field("interp", &Ty::Str, true),
        Field("needed", &STRS, true),
        Field("stripped", &Ty::Bool, false),
        Field("static", &Ty::Bool, false),
    ],
);
static REPORT: Ty = Ty::Struct(
    "immunity.Report",
    &[
        Field("entropy", &Ty::Float, false),
        Field("head", &Ty::Str, true),
        Field("strings", &STRS, true),
        Field("elf", &Ty::Ptr(&ELF), true),
    ],
);
static ANALYSIS: Ty = Ty::Struct(
    "immunity.Analysis",
    &[
        Field("time", &Ty::Time, false),
        Field("profile", &Ty::Str, false),
        Field("run_id", &Ty::Str, true),
        Field("status", &Ty::Str, false),
        Field("output", &Ty::Str, true),
        Field("error", &Ty::Str, true),
    ],
);
/// One held sample (Go: immunity.Entry).
pub static ENTRY: Ty = Ty::Struct(
    "immunity.Entry",
    &[
        Field("sha256", &Ty::Str, false),
        Field("size", &Ty::Int, false),
        Field("kind", &Ty::Str, false),
        Field("original", &Ty::Str, false),
        Field("reason", &Ty::Str, false),
        Field("source", &Ty::Str, false),
        Field("added", &Ty::Time, false),
        Field("status", &Ty::Str, false),
        Field("confirmed", &Ty::Time, true),
        Field("clamav", &Ty::Str, true),
        Field("held_at", &Ty::Time, true),
        Field("uid", &Ty::Int, true),
        Field("gid", &Ty::Int, true),
        Field("mode", &Ty::Uint32, true),
        Field("mtime", &Ty::Int, true),
        Field("seen_since", &Ty::Time, true),
        Field("released", &Ty::Time, true),
        Field("released_by", &Ty::Str, true),
        Field("copies", &STRS, true),
        Field("report", &Ty::Ptr(&REPORT), true),
        Field("analysis", &Ty::Ptr(&ANALYSIS), true),
    ],
);
pub static ENTRIES: Ty = Ty::Slice(&ENTRY);

static RULE_TEST: Ty = Ty::Struct(
    "immunity.RuleTest",
    &[
        Field("time", &Ty::Time, false),
        Field("text_sha256", &Ty::Str, false),
        Field("matched_sample", &Ty::Bool, false),
        Field("false_positives", &STRS, true),
        Field("fp_count", &Ty::Int, false),
        Field("scanned", &STRS, false),
        Field("error", &Ty::Str, true),
    ],
);
/// One rule draft (Go: immunity.Rule).
pub static RULE: Ty = Ty::Struct(
    "immunity.Rule",
    &[
        Field("id", &Ty::Str, false),
        Field("name", &Ty::Str, false),
        Field("sample_sha256", &Ty::Str, false),
        Field("text", &Ty::Str, false),
        Field("text_sha256", &Ty::Str, false),
        Field("note", &Ty::Str, true),
        Field("uid", &Ty::Uint32, false),
        Field("time", &Ty::Time, false),
        Field("status", &Ty::Str, false),
        Field("test", &Ty::Ptr(&RULE_TEST), true),
        Field("decided", &Ty::Time, true),
        Field("by", &Ty::Str, true),
        Field("installed", &Ty::Str, true),
    ],
);
pub static RULES: Ty = Ty::Slice(&RULE);

/// The index of what is held, newest first (Go: Store.Load): None for no file; Err for anything else that went wrong.
pub fn load_entries(dir: &str) -> Result<Option<Val>, String> {
    let path = format!("{dir}/immunity.json");
    let b = match std::fs::read(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(crate::sources::go_path_error("open", &path, &e)),
        Ok(b) => b,
    };
    match gostruct::unmarshal(&ENTRIES, &b) {
        (_, Some(e)) => Err(e.0),
        (Val::Slice(None), None) => Ok(None),
        (v, None) => Ok(Some(v)),
    }
}

/// The SHA-256s of what is held (errors: none).
pub fn held_hashes(dir: &str) -> Vec<String> {
    match load_entries(dir) {
        Ok(Some(Val::Slice(Some(es)))) => es.iter().map(|e| gostruct::str_field(&ENTRY, e, "sha256").to_string()).collect(),
        _ => Vec::new(),
    }
}

/// The drafts file (Go: immunity.Rules).
pub struct Rules {
    pub path: String,
}

static LOCK: Mutex<()> = Mutex::new(());

/// Go's CheckRule: one rule named Heimdall_..., with a condition, no import or include, at most 16 KiB of printable text;
/// the rule's name. The patterns are Go's with its ASCII `\s` and `\b`.
pub fn check_rule(text: &str) -> Result<String, String> {
    use std::sync::OnceLock;
    static RX: OnceLock<(regex::Regex, regex::Regex, regex::Regex)> = OnceLock::new();
    let (name_rx, good, forbidden) = RX.get_or_init(|| {
        let s = r"[\t\n\x0C\r ]";
        (
            regex::Regex::new(&format!(r"(?m)^{s}*(?:private{s}+|global{s}+)*rule{s}+([A-Za-z_][A-Za-z0-9_]*)"))
                .expect("rule name pattern"),
            regex::Regex::new(r"^Heimdall_[A-Za-z0-9_]{1,64}$").expect("good name pattern"),
            regex::Regex::new(&format!(r"(?m)^{s}*(import|include)(?-u:\b)")).expect("forbidden pattern"),
        )
    });
    if text.is_empty() || text.len() > MAX_RULE {
        return Err("a rule is 1 byte to 16 KiB".into());
    }
    if text.chars().any(|c| c == '\0' || (c < ' ' && !matches!(c, '\n' | '\t' | '\r'))) {
        return Err("a rule is printable text".into());
    }
    if forbidden.is_match(text) {
        return Err("no import or include: a rule stands alone".into());
    }
    let names: Vec<regex::Captures> = name_rx.captures_iter(text).collect();
    if names.len() != 1 {
        return Err(format!("exactly one rule per draft (found {})", names.len()));
    }
    let name = names[0][1].to_string();
    if !good.is_match(&name) {
        return Err("the rule's name starts with Heimdall_ (letters, digits and _ after it, at most 64), so ClamAV's report says where it came from".into());
    }
    if !text.contains("condition:") {
        return Err("a rule needs a condition".into());
    }
    Ok(name)
}

fn sha_ok(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// What a draft request kept (or found already kept).
#[derive(Clone, Debug, PartialEq)]
pub struct Drafted {
    pub id: String,
    pub name: String,
    pub sample: String,
    pub status: String,
}

impl Rules {
    /// The drafts, newest last (Go: Rules.Load: never through a link, at most 8 MiB read). None: no file, or `null`.
    pub fn load(&self) -> Result<Option<Val>, String> {
        let f = match std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(&self.path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(crate::sources::go_path_error("open", &self.path, &e)),
            Ok(f) => f,
        };
        let mut b = Vec::new();
        f.take(8 << 20).read_to_end(&mut b).map_err(|e| crate::sources::go_path_error("read", &self.path, &e))?;
        match gostruct::unmarshal(&RULES, &b) {
            (_, Some(e)) => Err(e.0),
            (Val::Slice(None), None) => Ok(None),
            (v, None) => Ok(Some(v)),
        }
    }

    /// Keeps a new draft (Go: Rules.Draft); the same text for the same sample is not kept twice.
    pub fn draft(&self, sample: &str, text: &str, note: &str, uid: u32, now: Time) -> Result<Drafted, String> {
        if !sha_ok(sample) {
            return Err("sample_sha256: the held sample's 64-character SHA-256".into());
        }
        let name = check_rule(text)?;
        // Go cuts the note at 2000 bytes, inside a letter if it falls there
        let note = if note.len() > 2000 { Val::Bytes(note.as_bytes()[..2000].to_vec()) } else { Val::Str(note.to_string()) };
        let _g = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut rs = match self.load()? {
            Some(Val::Slice(Some(rs))) => rs,
            _ => Vec::new(),
        };
        let sum = crate::state::hex(&<sha2::Sha256 as sha2::Digest>::digest(text.as_bytes()));
        let s = |r: &Val, k: &str| gostruct::str_field(&RULE, r, k).to_string();
        if let Some(o) = rs.iter().find(|o| s(o, "sample_sha256") == sample && s(o, "text_sha256") == sum) {
            return Ok(Drafted { id: s(o, "id"), name: s(o, "name"), sample: s(o, "sample_sha256"), status: s(o, "status") });
        }
        let mut id = [0u8; 4];
        crate::grants::random(&mut id);
        let id = crate::state::hex(&id);
        let mut d = gostruct::zero(&RULE);
        if let Val::Struct(f) = &mut d {
            f[0] = Val::Str(id.clone());
            f[1] = Val::Str(name.clone());
            f[2] = Val::Str(sample.to_string());
            f[3] = Val::Str(text.to_string());
            f[4] = Val::Str(sum);
            f[5] = note;
            f[6] = Val::Uint(uid as u64);
            f[7] = Val::Time(now.utc());
            f[8] = Val::Str("draft".into());
        }
        rs.push(d);
        if rs.len() > MAX_DRAFTS {
            let cut = rs.len() - MAX_DRAFTS;
            rs.drain(..cut);
        }
        self.save(&Val::Slice(Some(rs)))?;
        Ok(Drafted { id, name, sample: sample.to_string(), status: "draft".into() })
    }

    /// Go's save: MarshalIndent with two spaces, a temporary file beside it (0640, the folder's owner when root writes),
    /// renamed into place.
    fn save(&self, rs: &Val) -> Result<(), String> {
        let b =
            gostruct::to_json_indented(&RULES, rs, "  ").ok_or_else(|| "json: error calling MarshalJSON for type time.Time".to_string())?;
        let dir = std::path::Path::new(&self.path).parent().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|| ".".into());
        let mut r = [0u8; 5];
        crate::grants::random(&mut r);
        let tmp = format!("{dir}/.rule-drafts-{}", u64::from_le_bytes([r[0], r[1], r[2], r[3], r[4], 0, 0, 0]));
        let res = (|| -> std::io::Result<()> {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o640).open(&tmp)?;
            f.write_all(b.as_bytes())?;
            let _ = std::fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(0o640));
            // SAFETY: geteuid has no preconditions.
            if unsafe { libc::geteuid() } == 0 {
                if let Ok(m) = std::fs::metadata(&dir) {
                    let _ = std::os::unix::fs::chown(&tmp, Some(m.uid()), Some(m.gid()));
                }
            }
            drop(f);
            std::fs::rename(&tmp, &self.path)
        })();
        if res.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        res.map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cut_note_is_written_as_go_writes_it() {
        let mut s = String::new();
        gostruct::write_bytes(&mut s, &"aé".as_bytes()[..2]);
        assert_eq!(s, r#""a\ufffd""#);
        let mut s = String::new();
        gostruct::write_bytes(&mut s, b"<\xe2\x82x\xff");
        assert_eq!(s, r#""\u003c\ufffd\ufffdx\ufffd""#);
    }
}
