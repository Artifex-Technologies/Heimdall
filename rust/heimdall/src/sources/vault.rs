//! The AI agent's vault notes at rest (Go: internal/sources/vaultsource): every note checked when it appears or changes
//! (inotify, no polling), its SHA-256 kept in vault-notes.json (the Go daemon's file) so a restart reports only what changed.

use super::inotify::{self, Inotify, Mask};
use super::{Msg, Source};
use crate::event::{Event, Fields};
use crate::gojson::{self, FromGo};
use crate::gotime::Time;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::os::fd::BorrowedFd;
use std::os::unix::fs::OpenOptionsExt;
use std::time::Instant;

const MAX_NOTE: u64 = 1 << 20;
const MAX_NOTES: usize = 20_000;

fn skip_dir(name: &str) -> bool {
    matches!(name, ".git" | ".obsidian" | ".trash" | ".port_sessions")
}

fn is_note(name: &str) -> bool {
    name.to_lowercase().ends_with(".md")
}

pub struct Watcher {
    pub roots: Vec<String>,
    pub state_path: String,
    seen: Option<BTreeMap<String, String>>,
    /// Problems to log (the Go daemon logs them, "vault watch: ...").
    pub issues: Vec<String>,
}

impl Watcher {
    pub fn new(roots: Vec<String>, state_path: &str) -> Watcher {
        Watcher { roots, state_path: state_path.into(), seen: None, issues: Vec::new() }
    }

    fn seen(&mut self) -> &mut BTreeMap<String, String> {
        if self.seen.is_none() {
            let mut m = BTreeMap::new();
            if !self.state_path.is_empty() {
                if let Ok(b) = std::fs::read(&self.state_path) {
                    if let Ok(v) = gojson::parse(&b) {
                        let _ = m.read_into(&v, "");
                    }
                }
            }
            self.seen = Some(m);
        }
        self.seen.as_mut().expect("loaded")
    }

    pub fn hashes(&mut self) -> &BTreeMap<String, String> {
        self.seen()
    }

    fn save(&mut self) {
        if self.state_path.is_empty() {
            return;
        }
        let mut out = String::from("{");
        for (i, (k, v)) in self.seen().iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            gojson::write_str(&mut out, k);
            out.push(':');
            gojson::write_str(&mut out, v);
        }
        out.push('}');
        let tmp = format!("{}.tmp", self.state_path);
        if crate::state::write_private(&tmp, out.as_bytes()).is_ok() {
            let _ = std::fs::rename(&tmp, &self.state_path);
        }
    }

    fn check(&mut self, root: &str, path: &str) -> Option<Event> {
        let b = read_note(path)?;
        let h = crate::state::hex(&Sha256::digest(&b));
        if self.seen().get(path) == Some(&h) {
            return None;
        }
        self.seen().insert(path.to_owned(), h);
        let rel = path.strip_prefix(root).map(|r| r.trim_start_matches('/')).unwrap_or(path).to_owned();
        let rel = if rel.is_empty() { ".".to_owned() } else { rel };
        Some(Event {
            source: "agent-vault".into(),
            session_id: String::new(),
            time: Time::now(),
            kind: "vault_note".into(),
            text: crate::gotext::lossy_owned(b),
            fields: Fields::from([
                ("vault".to_string(), root.to_string()),
                ("note".to_string(), rel),
                ("path".to_string(), path.to_string()),
                ("role".to_string(), "vault".to_string()),
            ]),
        })
    }

    /// Every note of every vault (and every folder, for the watches), in Go's walk order.
    pub fn scan(&mut self) -> (Vec<Event>, Vec<String>) {
        let mut events = Vec::new();
        let mut dirs = Vec::new();
        for root in self.roots.clone() {
            let mut n = 0;
            self.walk(&root, &root, true, &mut n, &mut events, &mut dirs);
            if let Err(e) = std::fs::metadata(&root) {
                self.issues.push(super::go_path_error("stat", &root, &e));
            }
        }
        self.save();
        (events, dirs)
    }

    fn walk(&mut self, root: &str, dir: &str, top: bool, n: &mut usize, events: &mut Vec<Event>, dirs: &mut Vec<String>) -> bool {
        let Ok(md) = std::fs::symlink_metadata(dir) else { return true };
        if !md.is_dir() {
            return true;
        }
        if !top && skip_dir(dir.rsplit('/').next().unwrap_or("")) {
            return true;
        }
        dirs.push(dir.to_owned());
        let Ok(rd) = std::fs::read_dir(dir) else { return true };
        let mut entries: Vec<(Vec<u8>, std::fs::FileType)> = rd
            .filter_map(|e| e.ok())
            .filter_map(|e| Some((std::os::unix::ffi::OsStrExt::as_bytes(e.file_name().as_os_str()).to_vec(), e.file_type().ok()?)))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, ft) in entries {
            let name = crate::gotext::lossy(&name);
            let p = format!("{dir}/{name}");
            if ft.is_dir() {
                if !self.walk(root, &p, false, n, events, dirs) {
                    return false;
                }
                continue;
            }
            if !ft.is_file() || !is_note(&name) {
                continue; // links are never followed
            }
            *n += 1;
            if *n > MAX_NOTES {
                return false;
            }
            if let Some(e) = self.check(root, &p) {
                events.push(e);
            }
        }
        true
    }

    fn root_of(&self, path: &str) -> Option<String> {
        self.roots.iter().find(|r| path == r.as_str() || path.starts_with(&format!("{r}/"))).cloned()
    }
}

fn read_note(path: &str) -> Option<Vec<u8>> {
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)
        .ok()?;
    let md = f.metadata().ok()?;
    if !md.file_type().is_file() || md.len() > MAX_NOTE {
        return None;
    }
    let mut b = Vec::with_capacity(md.len() as usize);
    (&mut f).take(MAX_NOTE).read_to_end(&mut b).ok()?;
    Some(b)
}

fn mask() -> Mask {
    Mask::CLOSE_WRITE | Mask::MOVED_TO | Mask::CREATE | Mask::DONT_FOLLOW
}

/// The vaults on the daemon's loop: a first scan, then the kernel's word only.
pub struct VaultSource {
    w: Watcher,
    ino: Option<Inotify>,
    paths: HashMap<i32, String>,
    started: bool,
    /// When the first scan is due (the loop's start): a fixed instant, never "now", or the loop would never reach it.
    start: Instant,
}

impl VaultSource {
    pub fn new(w: Watcher) -> VaultSource {
        VaultSource { w, ino: None, paths: HashMap::new(), started: false, start: Instant::now() }
    }

    fn add(&mut self, dir: &str) {
        if let Some(ino) = &self.ino {
            if let Ok(wd) = ino.add(dir, mask()) {
                self.paths.insert(wd, dir.to_owned());
            }
        }
    }

    fn issues(&mut self, out: &mut Vec<Msg>) {
        out.extend(self.w.issues.drain(..).map(|i| Msg::Log(format!("vault watch: {i}"))));
    }
}

impl Source for VaultSource {
    fn name(&self) -> &'static str {
        "vault"
    }
    fn fd(&self) -> Option<BorrowedFd<'_>> {
        self.ino.as_ref().map(Inotify::fd)
    }
    fn due(&self) -> Option<Instant> {
        if self.started {
            None
        } else {
            Some(self.start)
        }
    }
    fn run(&mut self, _now: Instant, out: &mut Vec<Msg>) {
        self.started = true;
        let (events, dirs) = self.w.scan();
        self.issues(out);
        out.extend(events.into_iter().map(Msg::Event));
        if dirs.is_empty() {
            return;
        }
        match Inotify::new() {
            Ok(i) => self.ino = Some(i),
            Err(e) => {
                out.push(Msg::Log(format!("vault watch: {}", super::go_errno(&e))));
                return;
            }
        }
        for d in dirs {
            self.add(&d);
        }
    }
    fn ready(&mut self, _now: Instant, out: &mut Vec<Msg>) {
        let Some(ino) = &self.ino else { return };
        let Ok(evs) = ino.read() else {
            self.ino = None;
            return;
        };
        for ev in evs {
            let Some(dir) = self.paths.get(&ev.wd).cloned() else { continue };
            if ev.name.is_empty() {
                continue;
            }
            let p = format!("{dir}/{}", ev.name);
            let Some(root) = self.w.root_of(&p) else { continue };
            if ev.mask & inotify::IN_ISDIR != 0 {
                if ev.mask & (inotify::IN_CREATE | inotify::IN_MOVED_TO) != 0 && !skip_dir(&ev.name) {
                    // a new folder: watch it, and check notes moved in with it
                    self.add(&p);
                    let mut events = Vec::new();
                    let mut dirs = Vec::new();
                    let mut n = 0;
                    self.w.walk(&p, &p, true, &mut n, &mut events, &mut dirs);
                    for d in dirs.iter().filter(|d| **d != p) {
                        self.add(d);
                    }
                    for mut e in events {
                        let path = e.f("path").to_owned();
                        e.fields.insert("vault".into(), root.clone());
                        e.fields.insert("note".into(), path.strip_prefix(&format!("{root}/")).unwrap_or(&path).to_owned());
                        out.push(Msg::Event(e));
                    }
                    self.w.save();
                }
                continue;
            }
            if !is_note(&ev.name) || ev.mask & (inotify::IN_CLOSE_WRITE | inotify::IN_MOVED_TO) == 0 {
                continue;
            }
            if let Some(e) = self.w.check(&root, &p) {
                self.w.save();
                out.push(Msg::Event(e));
            }
        }
    }
}
