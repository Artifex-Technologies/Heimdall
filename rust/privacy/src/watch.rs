//! The downloads guard as a user service (`heimdall-fileguard watch`): watches the download folders with inotify and checks
//! each file once it is finished, quiet for a second after its last write or its arrival by rename, and not a browser's or
//! torrent client's partial file. It sleeps in poll() between events (no timer while nothing is pending), checks one file at a
//! time at idle priority, and never changes a file.
//!
//! The folders: the desktop's download folder (XDG_DOWNLOAD_DIR in ~/.config/user-dirs.dirs, else ~/Downloads), the folders of
//! Deluge (download_location, move_completed_path), qBittorrent (Session\DefaultSavePath, Downloads\SavePath) and
//! Transmission (download-dir), each also as a Flatpak, and "folders" in ~/.config/heimdall/fileguard.json. Their
//! sub-folders are watched too (four levels at most, 4096 watches in all). The settings files are watched, so a folder the
//! person changes is followed; Settings > Security > Privacy's switch (privacy.json "downloads_guard") is followed the same
//! way: off, nothing is watched or checked.

use crate::guard::{self, Limits, Report};
use crate::lookalike;
use crate::prefs::{self, Prefs};
use std::collections::{HashMap, VecDeque};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The download folders of this person, deduplicated, existing ones only.
pub fn folders() -> Vec<PathBuf> {
    let home = prefs::home();
    let cfg = prefs::config_home();
    let mut v: Vec<PathBuf> = vec![];
    v.push(xdg_download(&home, &std::fs::read_to_string(cfg.join("user-dirs.dirs")).unwrap_or_default()));
    let flat = |app: &str, rest: &str| home.join(".var/app").join(app).join("config").join(rest);
    for p in [cfg.join("deluge/core.conf"), flat("org.deluge_torrent.deluge", "deluge/core.conf")] {
        v.extend(deluge(&std::fs::read(p).unwrap_or_default()));
    }
    for p in [cfg.join("qBittorrent/qBittorrent.conf"), flat("org.qbittorrent.qBittorrent", "qBittorrent/qBittorrent.conf")] {
        v.extend(qbittorrent(&std::fs::read_to_string(p).unwrap_or_default()));
    }
    for p in [
        cfg.join("transmission/settings.json"),
        cfg.join("transmission-daemon/settings.json"),
        flat("com.transmissionbt.Transmission", "transmission/settings.json"),
    ] {
        v.extend(transmission(&std::fs::read(p).unwrap_or_default()));
    }
    v.extend(own(&std::fs::read(cfg.join("heimdall/fileguard.json")).unwrap_or_default(), &home));
    let mut out: Vec<PathBuf> = vec![];
    for p in v {
        let Ok(c) = std::fs::canonicalize(&p) else { continue };
        if c.is_dir() && allowed(&c, &home) && !out.contains(&c) {
            out.push(c);
        }
    }
    out
}

/// Folders never watched: the whole system or the home itself (too many files; a download folder is a part of it).
fn allowed(p: &Path, home: &Path) -> bool {
    let bad = ["/", "/proc", "/sys", "/dev", "/run", "/usr", "/etc", "/boot", "/var", "/tmp"];
    !bad.iter().any(|b| p == Path::new(b)) && p != home && p.components().count() > 1
}

/// XDG_DOWNLOAD_DIR="$HOME/Downloads".
pub fn xdg_download(home: &Path, text: &str) -> PathBuf {
    for line in text.lines() {
        if let Some(v) = line.trim().strip_prefix("XDG_DOWNLOAD_DIR=") {
            let v = v.trim().trim_matches('"');
            return match v.strip_prefix("$HOME") {
                Some(rest) => home.join(rest.trim_start_matches('/')),
                None => PathBuf::from(v),
            };
        }
    }
    home.join("Downloads")
}

/// Deluge's core.conf is two JSON objects one after the other (a version header, then the settings).
pub fn deluge(text: &[u8]) -> Vec<PathBuf> {
    let mut out = vec![];
    let stream = serde_json::Deserializer::from_slice(text).into_iter::<serde_json::Value>();
    for v in stream.take(4).map_while(Result::ok) {
        for k in ["download_location", "move_completed_path"] {
            if k == "move_completed_path" && v.get("move_completed").and_then(|x| x.as_bool()) == Some(false) {
                continue;
            }
            if let Some(p) = v.get(k).and_then(|x| x.as_str()).filter(|p| p.starts_with('/')) {
                out.push(PathBuf::from(p));
            }
        }
    }
    out
}

/// qBittorrent.conf: [BitTorrent] Session\DefaultSavePath, [Preferences] Downloads\SavePath (older).
pub fn qbittorrent(text: &str) -> Vec<PathBuf> {
    let mut out = vec![];
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            let k = k.trim().replace('/', "\\");
            if k == "Session\\DefaultSavePath" || k == "Downloads\\SavePath" {
                let v = v.trim();
                if v.starts_with('/') {
                    out.push(PathBuf::from(v));
                }
            }
        }
    }
    out
}

/// Transmission's settings.json: download-dir.
pub fn transmission(text: &[u8]) -> Vec<PathBuf> {
    let v: serde_json::Value = serde_json::from_slice(text).unwrap_or_default();
    v.get("download-dir").and_then(|x| x.as_str()).filter(|p| p.starts_with('/')).map(PathBuf::from).into_iter().collect()
}

/// ~/.config/heimdall/fileguard.json: {"folders": ["~/Torrents", "/mnt/data/in"]}.
pub fn own(text: &[u8], home: &Path) -> Vec<PathBuf> {
    let v: serde_json::Value = serde_json::from_slice(text).unwrap_or_default();
    v.get("folders")
        .and_then(|f| f.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .take(64)
                .filter_map(|p| match p.strip_prefix("~/") {
                    Some(rest) => Some(home.join(rest)),
                    None if p.starts_with('/') => Some(PathBuf::from(p)),
                    None => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// A file still being written by a browser or a torrent client, or a hidden temporary file.
pub fn partial(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    const ENDS: &[&str] = &[
        ".part",
        ".crdownload",
        ".download",
        ".tmp",
        ".!qb",
        ".!ut",
        ".!bt",
        ".partial",
        ".opdownload",
        ".aria2",
        ".filepart",
        ".unconfirmed",
        ".incomplete",
    ];
    ENDS.iter().any(|e| l.ends_with(e))
        || l.starts_with(".com.google.chrome.")
        || l.starts_with(".goutputstream")
        || l.starts_with(".~lock.")
        || l.starts_with("~$")
        || l.starts_with(".nfs")
        || l.starts_with(".trashed-")
}

// ---- inotify ----

struct Inotify {
    fd: i32,
    wd: HashMap<i32, (PathBuf, u8)>,
}

const DIR_MASK: u32 = libc::IN_CLOSE_WRITE
    | libc::IN_MOVED_TO
    | libc::IN_CREATE
    | libc::IN_DELETE_SELF
    | libc::IN_MOVE_SELF
    | libc::IN_EXCL_UNLINK
    | libc::IN_ONLYDIR;
const CFG_MASK: u32 = libc::IN_CLOSE_WRITE | libc::IN_MOVED_TO | libc::IN_CREATE | libc::IN_ONLYDIR;
/// Most watches, and how deep sub-folders are followed.
const MAX_WATCHES: usize = 4096;
const MAX_DEPTH: u8 = 4;

impl Inotify {
    fn new() -> std::io::Result<Self> {
        // SAFETY: plain system call
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Inotify { fd, wd: HashMap::new() })
    }

    fn add(&mut self, p: &Path, mask: u32, depth: u8) -> Option<i32> {
        if self.wd.len() >= MAX_WATCHES {
            return None;
        }
        let c = CString::new(p.as_os_str().as_bytes()).ok()?;
        // SAFETY: a valid C string
        let wd = unsafe { libc::inotify_add_watch(self.fd, c.as_ptr(), mask) };
        (wd >= 0).then(|| {
            self.wd.insert(wd, (p.to_path_buf(), depth));
            wd
        })
    }

    /// A folder and its sub-folders (not following links), depth-limited.
    fn add_tree(&mut self, root: &Path, depth: u8) {
        let mut todo = vec![(root.to_path_buf(), depth)];
        while let Some((d, k)) = todo.pop() {
            if self.add(&d, DIR_MASK, k).is_none() {
                continue;
            }
            if k >= MAX_DEPTH {
                continue;
            }
            if let Ok(rd) = std::fs::read_dir(&d) {
                for e in rd.flatten().take(10_000) {
                    if e.file_type().is_ok_and(|t| t.is_dir()) && !e.file_name().as_bytes().starts_with(b".") {
                        todo.push((e.path(), k + 1));
                    }
                }
            }
        }
    }

    fn clear(&mut self) {
        for wd in self.wd.keys() {
            // SAFETY: our own descriptors
            unsafe { libc::inotify_rm_watch(self.fd, *wd) };
        }
        self.wd.clear();
    }

    /// The events waiting: (watch, mask, name).
    fn read(&mut self) -> Vec<(i32, u32, Vec<u8>)> {
        let mut out = vec![];
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            // SAFETY: reading into our buffer
            let n = unsafe { libc::read(self.fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break;
            }
            let n = n as usize;
            let mut i = 0;
            let hdr = std::mem::size_of::<libc::inotify_event>();
            while i + hdr <= n {
                // SAFETY: the kernel wrote a whole event header here
                let ev: libc::inotify_event = unsafe { std::ptr::read_unaligned(buf[i..].as_ptr().cast()) };
                let len = ev.len as usize;
                let name = buf[i + hdr..(i + hdr + len).min(n)].split(|&b| b == 0).next().unwrap_or(&[]).to_vec();
                out.push((ev.wd, ev.mask, name));
                i += hdr + len;
            }
        }
        out
    }
}

impl Drop for Inotify {
    fn drop(&mut self) {
        // SAFETY: our own descriptor
        unsafe { libc::close(self.fd) };
    }
}

/// The places whose settings say where downloads go (watched so a change is followed).
fn settings_dirs() -> Vec<PathBuf> {
    let home = prefs::home();
    let cfg = prefs::config_home();
    let flat = |app: &str, rest: &str| home.join(".var/app").join(app).join("config").join(rest);
    vec![
        cfg.clone(),
        cfg.join("heimdall"),
        cfg.join("deluge"),
        cfg.join("qBittorrent"),
        cfg.join("transmission"),
        cfg.join("transmission-daemon"),
        flat("org.deluge_torrent.deluge", "deluge"),
        flat("org.qbittorrent.qBittorrent", "qBittorrent"),
        flat("com.transmissionbt.Transmission", "transmission"),
    ]
}

// ---- the service ----

/// One instance per person: a lock in the runtime folder, held while the guard runs.
fn lock_path() -> PathBuf {
    let rt = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    rt.join(format!("heimdall-fileguard-{}.lock", unsafe { libc::getuid() }))
}

/// Takes the lock (None: another guard holds it).
pub fn take_lock() -> Option<std::fs::File> {
    let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(lock_path()).ok()?;
    // SAFETY: flock on our own descriptor
    let r = unsafe { libc::flock(std::os::unix::io::AsRawFd::as_raw_fd(&f), libc::LOCK_EX | libc::LOCK_NB) };
    (r == 0).then_some(f)
}

/// The guard runs now (someone holds the lock).
pub fn running() -> bool {
    match std::fs::OpenOptions::new().write(true).open(lock_path()) {
        Ok(f) => {
            // SAFETY: flock on our own descriptor; released when f closes
            let r = unsafe { libc::flock(std::os::unix::io::AsRawFd::as_raw_fd(&f), libc::LOCK_EX | libc::LOCK_NB) };
            r != 0
        }
        Err(_) => false,
    }
}

/// How long a file must be quiet before it is checked.
const QUIET: Duration = Duration::from_secs(1);
/// Folders are read again this often even without a settings change (a folder made later, a drive mounted).
const RESCAN: Duration = Duration::from_secs(300);

/// Runs the guard until it is stopped.
pub fn run() -> i32 {
    let Some(_lock) = take_lock() else {
        eprintln!("heimdall-fileguard: another guard is running for this account");
        return 1;
    };
    // SAFETY: lower our own priority (we are a background check)
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, 0, 10);
    }
    let mut ino = match Inotify::new() {
        Ok(i) => i,
        Err(e) => {
            eprintln!("heimdall-fileguard: inotify: {e}");
            return 1;
        }
    };
    let mut settings = match Inotify::new() {
        Ok(i) => i,
        Err(e) => {
            eprintln!("heimdall-fileguard: inotify: {e}");
            return 1;
        }
    };
    let mut prefs = Prefs::default();
    let mut watched: Vec<PathBuf> = vec![];
    let mut pending: HashMap<PathBuf, Instant> = HashMap::new();
    let mut done: VecDeque<(PathBuf, u64, i64)> = VecDeque::new();
    let mut last_scan = Instant::now() - RESCAN;
    let notifier = Notifier::default();
    loop {
        if last_scan.elapsed() >= RESCAN {
            settings.clear();
            for d in settings_dirs() {
                settings.add(&d, CFG_MASK, 0);
            }
            // read after the watches are back: a file written while they were being made is not missed
            prefs = Prefs::load();
            let want = if prefs.downloads_guard { folders() } else { vec![] };
            if want != watched {
                ino.clear();
                pending.clear();
                for f in &want {
                    ino.add_tree(f, 0);
                }
                if !want.is_empty() {
                    eprintln!(
                        "heimdall-fileguard: watching {}",
                        want.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")
                    );
                } else if prefs.downloads_guard {
                    eprintln!("heimdall-fileguard: no download folder found yet");
                } else {
                    eprintln!("heimdall-fileguard: switched off in Settings; watching nothing");
                }
                watched = want;
            }
            last_scan = Instant::now();
        }
        // sleep until an event, the next pending check or the next rescan
        let next_check = pending.values().min().map(|t| (*t + QUIET).saturating_duration_since(Instant::now()));
        let wait = next_check.unwrap_or(RESCAN).min(RESCAN.saturating_sub(last_scan.elapsed()));
        let mut fds = [
            libc::pollfd { fd: ino.fd, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: settings.fd, events: libc::POLLIN, revents: 0 },
        ];
        // SAFETY: two valid pollfds
        unsafe { libc::poll(fds.as_mut_ptr(), 2, wait.as_millis().min(i32::MAX as u128) as i32 + 1) };
        if fds[1].revents != 0 {
            // ~/.config is busy: only the files (and folders) that say where downloads go count
            let names = [
                "user-dirs.dirs",
                "privacy.json",
                "fileguard.json",
                "core.conf",
                "qBittorrent.conf",
                "settings.json",
                "heimdall",
                "deluge",
                "qBittorrent",
                "transmission",
                "transmission-daemon",
            ];
            let evs = settings.read();
            if evs.iter().any(|(_, _, n)| names.iter().any(|x| x.as_bytes() == n.as_slice())) {
                prefs = Prefs::load();
                last_scan = Instant::now() - RESCAN; // read the folders again now
            }
        }
        if fds[0].revents != 0 {
            for (wd, mask, name) in ino.read() {
                let Some((dir, depth)) = ino.wd.get(&wd).cloned() else { continue };
                if mask & (libc::IN_DELETE_SELF | libc::IN_MOVE_SELF) != 0 {
                    ino.wd.remove(&wd);
                    continue;
                }
                if name.is_empty() {
                    continue;
                }
                let p = dir.join(std::ffi::OsStr::from_bytes(&name));
                if mask & libc::IN_ISDIR != 0 {
                    if mask & (libc::IN_CREATE | libc::IN_MOVED_TO) != 0 && depth < MAX_DEPTH && !name.starts_with(b".") {
                        ino.add_tree(&p, depth + 1);
                        if mask & libc::IN_MOVED_TO != 0 {
                            // a finished torrent's folder moved in: its files are new here
                            for f in walk(&p, 2000) {
                                pending.insert(f, Instant::now());
                            }
                        }
                    }
                    continue;
                }
                if mask & (libc::IN_CLOSE_WRITE | libc::IN_MOVED_TO) != 0 && !partial(&String::from_utf8_lossy(&name)) {
                    pending.insert(p, Instant::now());
                }
            }
        }
        // the files quiet for long enough, one at a time
        let now = Instant::now();
        let ready: Vec<PathBuf> = pending.iter().filter(|(_, t)| now.duration_since(**t) >= QUIET).map(|(p, _)| p.clone()).collect();
        for p in ready {
            pending.remove(&p);
            let Ok(m) = std::fs::symlink_metadata(&p) else { continue };
            if !m.is_file() {
                continue;
            }
            let stamp = (p.clone(), m.len(), std::os::unix::fs::MetadataExt::mtime(&m));
            if done.contains(&stamp) {
                continue;
            }
            done.push_back(stamp);
            if done.len() > 4096 {
                done.pop_front();
            }
            if let Ok(r) = guard::inspect_path(&p, &Limits::default()) {
                if r.found() {
                    notifier.tell(&p, &r, prefs.lookalike_warnings);
                }
            }
        }
    }
}

/// Files under a folder (not following links), at most `max`.
fn walk(root: &Path, max: usize) -> Vec<PathBuf> {
    let mut out = vec![];
    let mut todo = vec![(root.to_path_buf(), 0u8)];
    while let Some((d, k)) = todo.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            if out.len() >= max {
                return out;
            }
            match e.file_type() {
                Ok(t) if t.is_dir() && k < MAX_DEPTH => todo.push((e.path(), k + 1)),
                Ok(t) if t.is_file() && !partial(&e.file_name().to_string_lossy()) => out.push(e.path()),
                _ => {}
            }
        }
    }
    out
}

// ---- the notice ----

/// The notice's text: title, body. The file's name is shown made safe (lookalike::visible), with a warning when it imitates
/// another (and the switch for that is on).
pub fn notice(p: &Path, r: &Report, lookalikes: bool) -> (String, String) {
    let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let shown = lookalike::visible(&name);
    let first = &r.findings[0];
    let mut body = format!("{shown}: {}", first.what);
    if let Some(i) = &first.inside {
        body.push_str(&format!(" (in {})", lookalike::visible(i)));
    }
    body.push('.');
    if r.findings.len() > 1 {
        body.push_str(&format!(" And {} more.", r.findings.len() - 1));
    }
    if lookalikes {
        let lr = lookalike::check(&name);
        if lr.suspicious() {
            body.push_str(&format!(" Its name may not be what it seems: {}", lr.words()));
        }
    }
    body.push_str(" It was not changed.");
    // the notification daemon reads simple markup: nothing in a name may become a tag
    let esc = |s: String| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    (r.title().to_string(), esc(body))
}

/// The details page (Markdown), for Show details.
pub fn details(p: &Path, r: &Report) -> String {
    let mut s = String::new();
    s.push_str("# This file can contact a server\n\n");
    let shown = lookalike::visible(&p.display().to_string());
    s.push_str(&format!("**File:** `{}`\n\n", shown.replace('`', "'")));
    s.push_str(&format!("**Kind:** {}\n\n", r.kind.words()));
    let lr = lookalike::check(&p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default());
    if lr.suspicious() {
        s.push_str(&format!("**Its name:** {}\n\n", lr.words()));
    }
    s.push_str("## What it does\n\n");
    for f in &r.findings {
        let target = f.target.as_deref().map(|t| format!(": `{}`", lookalike::visible(t).replace('`', "'"))).unwrap_or_default();
        let inside = f.inside.as_deref().map(|i| format!(" (inside `{}`)", lookalike::visible(i).replace('`', "'"))).unwrap_or_default();
        let sure = if f.sure { "" } else { " *(it can, it may not)*" };
        s.push_str(&format!("- {}{target}{inside}{sure}\n", f.what));
    }
    if !r.complete {
        s.push_str(&format!("\n**Not checked in full:** {}.\n", r.notes.join("; ")));
    }
    s.push_str(
        "\n## What to do\n\nIf you did not expect this, do not open it. If you must, open it with the network off. A server that \
         receives the request learns that the file was opened, when, and from which address.\n\nHeimdall did not change the file \
         (a torrent keeps seeding; a signature stays valid). Turn these notices off in Settings > Security > Privacy > Check \
         downloads.\n",
    );
    s
}

/// Shows notices, three at most at a time (each waits for its buttons on a thread of its own).
#[derive(Default)]
struct Notifier {
    open: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

fn on_path(prog: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| std::env::split_paths(&paths).map(|d| d.join(prog)).find(|p| p.is_file()))
}

impl Notifier {
    fn tell(&self, p: &Path, r: &Report, lookalikes: bool) {
        use std::sync::atomic::Ordering;
        let (title, body) = notice(p, r, lookalikes);
        eprintln!("heimdall-fileguard: {}: {}", lookalike::visible(&p.display().to_string()), r.findings[0].what);
        if self.open.load(Ordering::Relaxed) >= 3 {
            return;
        }
        let Some(notify) = on_path("notify-send") else { return };
        self.open.fetch_add(1, Ordering::Relaxed);
        let open = self.open.clone();
        let page = details(p, r);
        let path = p.to_path_buf();
        std::thread::spawn(move || {
            // notify-send -A waits for the answer; an unanswered notice is let go after 10 minutes
            let out = std::process::Command::new("timeout")
                .args(["600"])
                .arg(notify)
                .args([
                    "-a",
                    "Heimdall",
                    "-u",
                    "normal",
                    "-i",
                    "dialog-warning",
                    "-A",
                    "details=Show details",
                    "-A",
                    "show=Show in Minos",
                    "-A",
                    "dismiss=Dismiss",
                    "--",
                ])
                .arg(&title)
                .arg(&body)
                .stdin(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .output();
            let answer = out.map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default();
            match answer.as_str() {
                "details" => show_details(&path, &page),
                "show" => show_folder(&path),
                _ => {}
            }
            open.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        });
    }
}

fn spawn_detached(prog: &Path, arg: &Path) {
    let mut c = std::process::Command::new(prog);
    c.arg(arg).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    // SAFETY: setsid in the child, so the program outlives the guard's thread
    unsafe {
        std::os::unix::process::CommandExt::pre_exec(&mut c, || {
            libc::setsid();
            Ok(())
        });
    }
    if let Ok(mut ch) = c.spawn() {
        std::thread::spawn(move || ch.wait());
    }
}

/// Writes the details page (private, in the runtime folder) and opens it in Saga MD, else the default program for Markdown.
fn show_details(p: &Path, page: &str) {
    let rt = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    let dir = rt.join("heimdall-fileguard");
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700));
    let mut h = std::collections::hash_map::DefaultHasher::new();
    std::hash::Hash::hash(&p, &mut h);
    let f = dir.join(format!("{:016x}.md", std::hash::Hasher::finish(&h)));
    if std::fs::write(&f, page).is_err() {
        return;
    }
    let _ = std::fs::set_permissions(&f, std::os::unix::fs::PermissionsExt::from_mode(0o600));
    match on_path("saga-md").or_else(|| on_path("xdg-open")) {
        Some(prog) => spawn_detached(&prog, &f),
        None => eprintln!("heimdall-fileguard: no program to show {}", f.display()),
    }
}

/// Opens the file's folder in Minos (Minos opens a folder given to it; it cannot select one file yet), else the default
/// file manager.
fn show_folder(p: &Path) {
    let Some(dir) = p.parent() else { return };
    if let Some(prog) = on_path("minos").or_else(|| on_path("xdg-open")) {
        spawn_detached(&prog, dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn torrent_clients_settings_are_read() {
        let deluge_conf = br#"{"file": 1, "format": 1}{"download_location": "/home/u/Downloads/torrents", "move_completed": true, "move_completed_path": "/mnt/media/done"}"#;
        assert_eq!(deluge(deluge_conf), [PathBuf::from("/home/u/Downloads/torrents"), PathBuf::from("/mnt/media/done")]);
        let off = br#"{"file": 1}{"download_location": "/a", "move_completed": false, "move_completed_path": "/b"}"#;
        assert_eq!(deluge(off), [PathBuf::from("/a")]);
        let qb = "[BitTorrent]\nSession\\DefaultSavePath=/home/u/Torrents/\nSession\\TempPath=/home/u/Torrents/temp/\n[Preferences]\nDownloads\\SavePath=/old/\n";
        assert_eq!(qbittorrent(qb), [PathBuf::from("/home/u/Torrents/"), PathBuf::from("/old/")]);
        assert_eq!(transmission(br#"{"download-dir": "/home/u/Downloads", "incomplete-dir": "/x"}"#), [PathBuf::from("/home/u/Downloads")]);
        assert!(deluge(b"garbage").is_empty() && transmission(b"").is_empty() && qbittorrent("").is_empty());
        let home = Path::new("/home/u");
        assert_eq!(own(br#"{"folders": ["~/In", "/mnt/x", "relative"]}"#, home), [PathBuf::from("/home/u/In"), PathBuf::from("/mnt/x")]);
        assert_eq!(
            xdg_download(home, "XDG_DESKTOP_DIR=\"$HOME/Desktop\"\nXDG_DOWNLOAD_DIR=\"$HOME/Hämtningar\"\n"),
            PathBuf::from("/home/u/Hämtningar")
        );
        assert_eq!(xdg_download(home, ""), PathBuf::from("/home/u/Downloads"));
    }

    #[test]
    fn partial_files_wait() {
        for n in [
            "film.mkv.part",
            "a.crdownload",
            "x.iso.!qB",
            "y.zip.!ut",
            ".com.google.Chrome.abc",
            "z.aria2",
            "Unconfirmed 1.crdownload",
            "~$doc.docx",
        ] {
            assert!(partial(n), "{n}");
        }
        for n in ["film.mkv", "report.pdf", "party.jpg"] {
            assert!(!partial(n), "{n}");
        }
        assert!(!allowed(Path::new("/"), Path::new("/home/u")));
        assert!(!allowed(Path::new("/home/u"), Path::new("/home/u")), "not the whole home");
        assert!(allowed(Path::new("/home/u/Downloads"), Path::new("/home/u")));
    }

    #[test]
    fn the_notice_says_it_plainly_and_shows_names_safely() {
        let r = guard::inspect_bytes("a.pdf", &crate::samples::pdf(true), &Limits::default());
        let (t, b) = notice(Path::new("/home/u/Downloads/invoice\u{202E}fdp.exe"), &r, true);
        assert_eq!(t, "This file tries to contact a server when opened.");
        assert!(b.starts_with("invoice&lt;U+202E&gt;fdp.exe: It opens a web address"), "{b}");
        assert!(b.contains("may not be what it seems") && b.ends_with("It was not changed."), "{b}");
        let (_, b) = notice(Path::new("/d/invoice\u{202E}fdp.exe"), &r, false);
        assert!(!b.contains("may not be what it seems"), "the switch for look-alike warnings is off");
        let page = details(Path::new("/d/x.pdf"), &r);
        assert!(page.contains("https://tracker.example.net/opened?id=1") && page.contains("did not change the file"));
    }

    /// The watcher end to end in a made-up home: a finished download is checked, a partial one is not, the switch is followed.
    #[test]
    fn a_finished_download_is_noticed() {
        let base = std::env::temp_dir().join(format!("heimdall-fileguard-watch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let dl = base.join("Downloads");
        std::fs::create_dir_all(&dl).unwrap();
        let mut ino = Inotify::new().unwrap();
        ino.add_tree(&dl, 0);
        std::fs::write(dl.join("a.pdf.part"), b"x").unwrap();
        std::fs::write(dl.join("a.pdf"), crate::samples::pdf(true)).unwrap();
        std::fs::create_dir(dl.join("sub")).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        let evs = ino.read();
        let names: Vec<String> =
            evs.iter().filter(|e| e.1 & libc::IN_CLOSE_WRITE != 0).map(|e| String::from_utf8_lossy(&e.2).into_owned()).collect();
        assert!(names.contains(&"a.pdf".to_string()) && names.contains(&"a.pdf.part".to_string()));
        assert!(evs.iter().any(|e| e.1 & libc::IN_ISDIR != 0 && e.2 == b"sub"));
        assert!(partial("a.pdf.part") && !partial("a.pdf"));
        let r = guard::inspect_path(&dl.join("a.pdf"), &Limits::default()).unwrap();
        assert!(r.found());
        let _ = std::fs::remove_dir_all(&base);
    }
}
