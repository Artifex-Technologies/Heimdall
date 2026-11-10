//! File integrity (Go: internal/sources/hostsource/fim.go): the watched files (and folders) by modification time and size
//! first, the SHA-256 only when those changed; baselines in fim.json (the Go daemon's file, read and written alike).

use super::{mtime, Msg, Source};
use crate::event::{Event, Fields};
use crate::gojson::{self, FromGo, ObjectWriter};
use crate::gotime::Time;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

const DIR_MARKER: &str = "dir:";

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Baseline {
    pub mod_time: Time,
    pub size: i64,
    pub hash: String,
}
crate::go_struct!(Baseline { mod_time: "mod_time", size: "size", hash: "hash" });

struct Pending {
    seen: Time,
    event: Event,
}

pub struct Watcher {
    paths: Vec<String>,
    dirs: Vec<String>,
    state_path: String,
    baselines: BTreeMap<String, Baseline>,
    loaded: Option<BTreeMap<String, Baseline>>,
    trust_dirs: BTreeSet<String>,
    graced: BTreeSet<String>,
    grace: i64,
    pending: BTreeMap<String, Pending>,
    dirty: bool,
}

fn split_dirs(paths: &[String]) -> (Vec<String>, Vec<String>) {
    let (mut files, mut dirs) = (Vec::new(), Vec::new());
    for p in paths {
        match std::fs::symlink_metadata(p) {
            Ok(md) if md.is_dir() => dirs.push(super::clean_path(p)),
            _ => files.push(p.clone()),
        }
    }
    (files, dirs)
}

fn hash_file(path: &str) -> std::io::Result<String> {
    crate::state::sha256_file(path)
}

impl Watcher {
    pub fn new(paths: &[String], state_path: &str) -> Watcher {
        let (paths, dirs) = split_dirs(paths);
        let mut w = Watcher {
            paths,
            dirs,
            state_path: state_path.into(),
            baselines: BTreeMap::new(),
            loaded: None,
            trust_dirs: BTreeSet::new(),
            graced: BTreeSet::new(),
            grace: 0,
            pending: BTreeMap::new(),
            dirty: false,
        };
        if !state_path.is_empty() {
            if let Ok(b) = std::fs::read(state_path) {
                let mut m: BTreeMap<String, Baseline> = BTreeMap::new();
                if gojson::parse(&b).ok().is_some_and(|v| m.read_into(&v, "").is_ok()) {
                    w.loaded = Some(m);
                    w.keep_loaded();
                }
            }
        }
        w
    }

    /// The AI agents' behaviour files and folders (trust, step 4), judged after a grace period.
    pub fn with_trust(mut self, files: &[String], dirs: &[String], grace: i64) -> Watcher {
        for f in files {
            self.paths.push(f.clone());
            self.graced.insert(f.clone());
        }
        self.dirs.extend(dirs.iter().cloned());
        self.trust_dirs.extend(dirs.iter().cloned());
        self.grace = grace;
        self.keep_loaded();
        self
    }

    pub fn baselines(&self) -> &BTreeMap<String, Baseline> {
        &self.baselines
    }

    fn under(dirs: &[String], path: &str) -> bool {
        dirs.iter().any(|d| path.starts_with(&format!("{d}/")))
    }

    fn keep_loaded(&mut self) {
        let Some(loaded) = &self.loaded else { return };
        for (path, b) in loaded {
            let watched = self.paths.contains(path)
                || path.strip_prefix(DIR_MARKER).is_some_and(|d| self.dirs.iter().any(|x| x == d))
                || Self::under(&self.dirs, path);
            if watched {
                self.baselines.insert(path.clone(), b.clone());
            }
        }
    }

    fn dir_files(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for d in &self.dirs {
            let mut n = 0;
            walk_files(d, &mut |p| {
                if n < 5000 {
                    out.insert(p.to_owned());
                    n += 1;
                }
            });
        }
        out
    }

    fn emit(&mut self, events: &mut Vec<Event>, path: &str, e: Event) {
        if self.graced.contains(path) || self.trust_dirs.iter().any(|d| path.starts_with(&format!("{d}/"))) {
            self.pending.entry(path.to_owned()).or_insert(Pending { seen: Time::now(), event: e });
            return;
        }
        events.push(e);
    }

    pub fn poll(&mut self) -> (Vec<Event>, Option<std::io::Error>) {
        self.keep_loaded();
        self.loaded = None;
        let mut events = Vec::new();
        let in_dirs = self.dir_files();
        for d in self.dirs.clone() {
            let marker = format!("{DIR_MARKER}{d}");
            if !self.baselines.contains_key(&marker) {
                for f in in_dirs.iter().filter(|f| f.starts_with(&format!("{d}/"))) {
                    if let (Ok(md), Ok(h)) = (std::fs::metadata(f), hash_file(f)) {
                        self.baselines.insert(f.clone(), Baseline { mod_time: mtime(&md), size: md.len() as i64, hash: h });
                    }
                }
                self.baselines.insert(marker, Baseline { hash: "dir".into(), ..Default::default() });
                self.dirty = true;
            }
        }
        for path in &in_dirs {
            if self.baselines.contains_key(path) {
                continue;
            }
            let Ok(md) = std::fs::metadata(path) else { continue };
            let Ok(hash) = hash_file(path) else { continue };
            self.baselines.insert(path.clone(), Baseline { mod_time: mtime(&md), size: md.len() as i64, hash: hash.clone() });
            self.dirty = true;
            let e = fim_event(mtime(&md), "file_created", path, &[("new_hash", &hash)]);
            self.emit(&mut events, path, e);
        }
        let gone: Vec<(String, String)> = self
            .baselines
            .iter()
            .filter(|(p, _)| Self::under(&self.dirs, p) && !in_dirs.contains(*p))
            .filter(|(p, _)| matches!(std::fs::symlink_metadata(p), Err(e) if e.kind() == std::io::ErrorKind::NotFound))
            .map(|(p, b)| (p.clone(), b.hash.clone()))
            .collect();
        for (path, prior) in gone {
            let e = fim_event(Time::now(), "file_deleted", &path, &[("prior_hash", &prior)]);
            self.emit(&mut events, &path, e);
            self.baselines.remove(&path);
            self.dirty = true;
        }
        let mut paths = self.paths.clone();
        paths.extend(in_dirs.iter().cloned());
        for path in paths {
            let md = match std::fs::metadata(&path) {
                Ok(md) => md,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        if let Some(prior) = self.baselines.remove(&path) {
                            self.dirty = true;
                            let e = fim_event(Time::now(), "file_deleted", &path, &[("prior_hash", &prior.hash)]);
                            self.emit(&mut events, &path, e);
                        }
                    }
                    continue; // unreadable for another reason: retry next poll
                }
            };
            let (mt, size) = (mtime(&md), md.len() as i64);
            let prior = self.baselines.get(&path).cloned();
            if let Some(p) = &prior {
                if mt == p.mod_time && size == p.size {
                    continue; // the cheap precheck says unchanged
                }
            }
            let Ok(hash) = hash_file(&path) else { continue };
            let next = Baseline { mod_time: mt, size, hash: hash.clone() };
            if let Some(p) = prior {
                if hash != p.hash {
                    let e = fim_event(mt, "file_modified", &path, &[("prior_hash", &p.hash), ("new_hash", &hash)]);
                    self.emit(&mut events, &path, e);
                }
            }
            self.baselines.insert(path, next);
            self.dirty = true;
        }
        let now = Time::now();
        let due: Vec<String> = self.pending.iter().filter(|(_, p)| now.sub(&p.seen) >= self.grace).map(|(k, _)| k.clone()).collect();
        for path in due {
            let mut e = self.pending.remove(&path).expect("listed").event;
            if e.kind != "file_deleted" {
                match hash_file(&path) {
                    Ok(h) => {
                        e.fields.insert("new_hash".into(), h);
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        e.kind = "file_deleted".into();
                        e.fields.remove("new_hash");
                    }
                    Err(_) => {}
                }
            }
            events.push(e);
        }
        (events, self.save().err())
    }

    /// fim.json as Go writes it (indented, keys sorted); only when a baseline changed.
    fn save(&mut self) -> std::io::Result<()> {
        if self.state_path.is_empty() || !self.dirty {
            return Ok(());
        }
        let mut out = String::from("{");
        for (i, (k, b)) in self.baselines.iter().enumerate() {
            out.push_str(if i > 0 { ",\n  " } else { "\n  " });
            gojson::write_str(&mut out, k);
            out.push_str(": ");
            let mut inner = String::new();
            let mut w = ObjectWriter::new(&mut inner);
            w.str("mod_time", &b.mod_time.rfc3339_nano());
            w.raw("size", &b.size.to_string());
            w.str("hash", &b.hash);
            w.end();
            // Go's MarshalIndent puts each member on its own line
            out.push_str(&inner.replacen('{', "{\n    ", 1).replace(",\"", ",\n    \"").replace("\":", "\": ").replacen('}', "\n  }", 1));
        }
        out.push_str(if self.baselines.is_empty() { "}" } else { "\n}" });
        crate::state::write_atomic(&self.state_path, out.as_bytes(), 0o600)?;
        self.dirty = false;
        Ok(())
    }
}

fn walk_files(dir: &str, f: &mut dyn FnMut(&str)) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut entries: Vec<(Vec<u8>, std::fs::FileType)> = rd
        .filter_map(|e| e.ok())
        .filter_map(|e| Some((std::os::unix::ffi::OsStrExt::as_bytes(e.file_name().as_os_str()).to_vec(), e.file_type().ok()?)))
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, ft) in entries {
        let p = format!("{dir}/{}", crate::gotext::lossy(&name));
        if ft.is_dir() {
            walk_files(&p, f);
        } else if ft.is_file() {
            f(&p);
        }
    }
}

fn fim_event(time: Time, kind: &str, path: &str, extra: &[(&str, &str)]) -> Event {
    let mut fields = Fields::from([("path".to_string(), path.to_string())]);
    for (k, v) in extra {
        fields.insert((*k).into(), (*v).into());
    }
    Event { source: "host-fim".into(), session_id: String::new(), time, kind: kind.into(), text: path.into(), fields }
}

/// The FIM watcher on the daemon's loop: the first look one interval after the start, as in Go.
pub struct FimSource {
    pub w: Watcher,
    interval: Duration,
    next: Instant,
}

impl FimSource {
    pub fn new(w: Watcher, interval: Duration) -> FimSource {
        FimSource { w, interval, next: Instant::now() + interval }
    }
}

impl Source for FimSource {
    fn name(&self) -> &'static str {
        "fim"
    }
    fn due(&self) -> Option<Instant> {
        Some(self.next)
    }
    fn run(&mut self, now: Instant, out: &mut Vec<Msg>) {
        self.next = now + self.interval;
        let (events, err) = self.w.poll();
        if let Some(e) = err {
            out.push(Msg::Log(format!("fim state save error: {}", super::go_errno(&e))));
        }
        out.extend(events.into_iter().map(Msg::Event));
    }
}
