//! The downloads guard's check of one file: does it contact a server when it is opened? Office documents (remote templates,
//! pictures, linked objects, field codes that fetch), OpenDocument files (linked pictures, objects, templates), PDFs (actions
//! that run on opening, JavaScript, Launch), SVG and HTML (outside pictures, fonts, scripts, styles), playlists (entries on a
//! server), shortcuts (.desktop, .url, .webloc), and archives (their list of files; files inside a ZIP are checked in memory,
//! one level deep, never extracted). The file is only read, never changed: a torrent keeps seeding, a signature stays valid.
//!
//! Every reader has a size cap and none recurses; what a cap stops is said in the report ("not checked in full").

use crate::markup::{self, classify, Addr};
use crate::pdf::{self, Tok};
use crate::zip;
use std::io::Read;
use std::path::Path;

/// What kind of file it is, from its content (and for text formats its name).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Office,
    OpenDocument,
    Pdf,
    Svg,
    Html,
    Playlist(Playlist),
    Desktop,
    UrlShortcut,
    Webloc,
    Zip,
    /// Another archive, listed with bsdtar (tar, compressed tar, 7z, rar...).
    Archive,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Playlist {
    M3u,
    Pls,
    Xspf,
    Asx,
}

impl Kind {
    /// The kind in plain words ("an Office document").
    pub fn words(self) -> &'static str {
        match self {
            Kind::Office => "an Office document",
            Kind::OpenDocument => "an OpenDocument file",
            Kind::Pdf => "a PDF",
            Kind::Svg => "an SVG picture",
            Kind::Html => "a web page",
            Kind::Playlist(_) => "a playlist",
            Kind::Desktop => "a launcher (.desktop)",
            Kind::UrlShortcut => "an internet shortcut (.url)",
            Kind::Webloc => "a web location (.webloc)",
            Kind::Zip => "a ZIP archive",
            Kind::Archive => "an archive",
            Kind::Other => "a file",
        }
    }

    /// The short name `--json` prints.
    pub fn id(self) -> &'static str {
        match self {
            Kind::Office => "office",
            Kind::OpenDocument => "opendocument",
            Kind::Pdf => "pdf",
            Kind::Svg => "svg",
            Kind::Html => "html",
            Kind::Playlist(_) => "playlist",
            Kind::Desktop => "desktop",
            Kind::UrlShortcut => "url",
            Kind::Webloc => "webloc",
            Kind::Zip => "zip",
            Kind::Archive => "archive",
            Kind::Other => "other",
        }
    }
}

/// One thing found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    /// It contacts a server by itself when opened (false: it can, e.g. a script, or after a question).
    pub sure: bool,
    /// What it does, in plain words ("It loads its template from a server when opened").
    pub what: String,
    /// The address, when there is one.
    pub target: Option<String>,
    /// The file inside an archive it is in.
    pub inside: Option<String>,
}

/// The check of one file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub kind: Kind,
    pub findings: Vec<Finding>,
    /// Everything was read (no cap reached, nothing unreadable).
    pub complete: bool,
    pub notes: Vec<String>,
}

/// Most findings kept per file.
const MAX_FINDINGS: usize = 64;

impl Report {
    fn new(kind: Kind) -> Self {
        Report { kind, findings: vec![], complete: true, notes: vec![] }
    }

    pub fn found(&self) -> bool {
        !self.findings.is_empty()
    }

    /// The notice's title.
    pub fn title(&self) -> &'static str {
        if self.findings.iter().any(|f| f.sure) {
            "This file tries to contact a server when opened."
        } else {
            "This file has parts that can contact a server."
        }
    }

    fn add(&mut self, sure: bool, what: impl Into<String>, target: Option<String>) {
        let what = what.into();
        // one finding per kind of thing and address
        if self.findings.len() >= MAX_FINDINGS || self.findings.iter().any(|f| f.what == what && f.target == target && f.inside.is_none()) {
            return;
        }
        self.findings.push(Finding { sure, what, target: target.map(|t| shorten(&t, 300)), inside: None });
    }

    fn incomplete(&mut self, why: impl Into<String>) {
        self.complete = false;
        let why = why.into();
        if !self.notes.contains(&why) && self.notes.len() < 16 {
            self.notes.push(why);
        }
    }
}

fn shorten(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let mut t: String = s.chars().take(n).collect();
    t.push('…');
    t
}

/// The caps.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Most bytes of a text file (SVG, HTML, playlist, shortcut) read.
    pub text: u64,
    /// Most bytes of a PDF read.
    pub pdf: u64,
    /// Most bytes one ZIP entry may unpack to.
    pub part: u64,
    /// Most bytes unpacked from one ZIP file in all.
    pub budget: u64,
    /// Most files inside a ZIP archive checked.
    pub members: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { text: 8 << 20, pdf: 128 << 20, part: 16 << 20, budget: 96 << 20, members: 256 }
    }
}

fn ext(name: &str) -> String {
    let base = name.rsplit('/').next().unwrap_or(name);
    match base.rsplit_once('.') {
        Some((stem, e)) if !stem.is_empty() => e.to_ascii_lowercase(),
        _ => String::new(),
    }
}

fn starts_ci(h: &[u8], n: &[u8]) -> bool {
    h.len() >= n.len() && h[..n.len()].eq_ignore_ascii_case(n)
}

/// The start of a text file without a byte order mark and leading space.
fn text_head(head: &[u8]) -> &[u8] {
    let h = head.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(head);
    let i = h.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(h.len());
    &h[i..]
}

/// The kind of a file from its first bytes (8 KiB are plenty) and its name; a ZIP file's kind is settled by `zip_kind`.
pub fn sniff(name: &str, head: &[u8]) -> Kind {
    let e = ext(name);
    if head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06") {
        return Kind::Zip;
    }
    if pdf::find(&head[..head.len().min(1024)], 0, b"%PDF-").is_some() {
        return Kind::Pdf;
    }
    if head.starts_with(b"7z\xBC\xAF\x27\x1C") || head.starts_with(b"Rar!\x1A\x07") || head.len() > 262 && &head[257..262] == b"ustar" {
        return Kind::Archive;
    }
    let compressed = head.starts_with(b"\x1F\x8B")
        || head.starts_with(b"\xFD7zXZ\x00")
        || head.starts_with(b"BZh")
        || head.starts_with(b"\x28\xB5\x2F\xFD");
    if compressed {
        if e == "svgz" && head.starts_with(b"\x1F\x8B") {
            return Kind::Svg;
        }
        let tarry = name.to_ascii_lowercase();
        return if [".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2", ".tbz2", ".tbz", ".tar.zst", ".tzst"]
            .iter()
            .any(|s| tarry.ends_with(s))
        {
            Kind::Archive
        } else {
            Kind::Other
        };
    }
    let t = text_head(head);
    match e.as_str() {
        "desktop" => return Kind::Desktop,
        "url" | "website" | "scf" => return Kind::UrlShortcut,
        "webloc" | "inetloc" => return Kind::Webloc,
        "m3u" | "m3u8" => return Kind::Playlist(Playlist::M3u),
        "pls" => return Kind::Playlist(Playlist::Pls),
        "xspf" => return Kind::Playlist(Playlist::Xspf),
        "asx" | "wax" | "wvx" => return Kind::Playlist(Playlist::Asx),
        "svg" => return Kind::Svg,
        "html" | "htm" | "xhtml" | "shtml" | "xht" => return Kind::Html,
        _ => {}
    }
    if starts_ci(t, b"[Desktop Entry]") {
        return Kind::Desktop;
    }
    if starts_ci(t, b"[InternetShortcut]") {
        return Kind::UrlShortcut;
    }
    if starts_ci(t, b"#EXTM3U") {
        return Kind::Playlist(Playlist::M3u);
    }
    if starts_ci(t, b"[playlist]") {
        return Kind::Playlist(Playlist::Pls);
    }
    if starts_ci(t, b"<asx") {
        return Kind::Playlist(Playlist::Asx);
    }
    if markup::find_ci(t, 0, b"<!doctype html").is_some_and(|p| p < 512) || starts_ci(t, b"<html") {
        return Kind::Html;
    }
    let early = &t[..t.len().min(4096)];
    if starts_ci(t, b"<") {
        if markup::find_ci(early, 0, b"<svg").is_some() {
            return Kind::Svg;
        }
        if markup::find_ci(early, 0, b"<playlist").is_some() && markup::find_ci(early, 0, b"xspf").is_some() {
            return Kind::Playlist(Playlist::Xspf);
        }
    }
    Kind::Other
}

/// A ZIP file's kind: Office (a [Content_Types].xml), OpenDocument (its mimetype entry), or a plain archive.
fn zip_kind(src: &dyn zip::Source, a: &zip::Archive) -> Kind {
    if a.find("[Content_Types].xml").is_some() {
        return Kind::Office;
    }
    if let Some(m) = a.find("mimetype") {
        let mut b = 1024;
        if zip::content(src, m, 256, &mut b).is_ok_and(|c| c.starts_with(b"application/vnd.oasis.opendocument")) {
            return Kind::OpenDocument;
        }
    }
    Kind::Zip
}

/// Checks a file on disk.
pub fn inspect_path(p: &Path, lim: &Limits) -> std::io::Result<Report> {
    let f = std::fs::File::open(p)?;
    let meta = f.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let mut head = vec![0u8; 8192.min(meta.len() as usize)];
    zip::Source::read_at(&f, 0, &mut head)?;
    let kind = sniff(&name, &head);
    Ok(match kind {
        Kind::Zip => check_zip(&name, &f, lim, true),
        Kind::Archive => list_archive(p, &name),
        Kind::Other => Report::new(Kind::Other),
        Kind::Pdf => {
            let data = read_capped(&f, lim.pdf)?;
            let mut r = check_pdf(&data);
            if meta.len() > lim.pdf {
                r.incomplete(format!("only the first {} MiB were read", lim.pdf >> 20));
            }
            r
        }
        k => {
            let mut data = read_capped(&f, lim.text)?;
            let mut r = Report::new(k);
            if meta.len() > lim.text {
                r.incomplete(format!("only the first {} MiB were read", lim.text >> 20));
            }
            if data.starts_with(b"\x1F\x8B") {
                // .svgz
                let mut out = vec![];
                let _ = flate2::read::GzDecoder::new(&data[..]).take(lim.text).read_to_end(&mut out);
                data = out;
            }
            check_text(k, &data, &mut r);
            r
        }
    })
}

fn read_capped(f: &std::fs::File, cap: u64) -> std::io::Result<Vec<u8>> {
    let mut v = vec![];
    f.take(cap).read_to_end(&mut v)?;
    Ok(v)
}

/// Checks bytes in memory (a file inside an archive; the fuzz targets).
pub fn inspect_bytes(name: &str, data: &[u8], lim: &Limits) -> Report {
    bytes(name, data, lim, true)
}

/// `members`: a ZIP archive's files are checked too (not for a ZIP inside a ZIP: one level only).
fn bytes(name: &str, data: &[u8], lim: &Limits, members: bool) -> Report {
    let kind = sniff(name, &data[..data.len().min(8192)]);
    match kind {
        Kind::Zip => check_zip(name, &data, lim, members),
        Kind::Pdf => check_pdf(&data[..data.len().min(lim.pdf as usize)]),
        Kind::Archive | Kind::Other => Report::new(kind),
        k => {
            let mut r = Report::new(k);
            let mut d = data[..data.len().min(lim.text as usize)].to_vec();
            if d.starts_with(b"\x1F\x8B") {
                let mut out = vec![];
                let _ = flate2::read::GzDecoder::new(&d[..]).take(lim.text).read_to_end(&mut out);
                d = out;
            }
            check_text(k, &d, &mut r);
            r
        }
    }
}

fn check_text(k: Kind, d: &[u8], r: &mut Report) {
    match k {
        Kind::Svg | Kind::Html => check_markup(d, r),
        Kind::Playlist(p) => check_playlist(p, d, r),
        Kind::Desktop => check_desktop(d, r),
        Kind::UrlShortcut => check_url_shortcut(d, r),
        Kind::Webloc => check_webloc(d, r),
        _ => {}
    }
}

// ---- web pages and SVG ----

/// Attributes that load something when the page or picture is shown (links that need a click are not here).
const LOADING_ATTRS: &[&str] =
    &["href", "src", "data", "poster", "background", "codebase", "manifest", "lowsrc", "dynsrc", "longdesc", "icon", "profile"];

fn check_markup(d: &[u8], r: &mut Report) {
    let mut script = false;
    for t in markup::tags(d, 200_000) {
        let local = t.local();
        if matches!(local.as_str(), "a" | "area" | "form") {
            continue;
        }
        for (k, v) in &t.attrs {
            let key = k.rsplit(':').next().unwrap_or("").to_ascii_lowercase();
            if LOADING_ATTRS.contains(&key.as_str()) {
                note_addr(r, &local, v);
            } else if key == "srcset" || key == "imagesrcset" {
                for part in v.split(',') {
                    if let Some(u) = part.split_whitespace().next() {
                        note_addr(r, &local, u);
                    }
                }
            } else if key == "style" {
                for u in markup::css_urls(v.as_bytes()) {
                    note_addr(r, "style", &u);
                }
            } else if key.starts_with("on") && key.len() > 2 && !v.trim().is_empty() {
                script = true;
            }
        }
        match local.as_str() {
            "script" if t.attr_local("src").is_none() => script = true,
            "style" => {
                for u in markup::css_urls(markup::text_until_close(d, t.end)) {
                    note_addr(r, "style", &u);
                }
            }
            "meta" if t.attr("http-equiv").is_some_and(|h| h.eq_ignore_ascii_case("refresh")) => {
                let c = t.attr("content").unwrap_or("");
                if let Some(p) = c.to_ascii_lowercase().find("url=") {
                    let u = c[p + 4..].trim().trim_matches(|ch| ch == '\'' || ch == '"');
                    if classify(u) == Addr::Remote {
                        r.add(true, "It sends you to a web address as soon as it is opened", Some(u.to_string()));
                    }
                }
            }
            _ => {}
        }
    }
    // a stylesheet named in a processing instruction, an outside DTD or entity
    let mut i = 0;
    while let Some(p) = markup::find_ci(d, i, b"<?xml-stylesheet") {
        let end = d[p..].iter().position(|&b| b == b'>').map_or(d.len(), |e| p + e);
        let pi = String::from_utf8_lossy(&d[p..end]);
        if let Some(h) = pi.find("href=") {
            let rest = &pi[h + 5..];
            let q = rest.chars().next().unwrap_or('"');
            let v: String = rest.chars().skip(1).take_while(|&c| c != q).collect();
            note_addr(r, "style", &v);
        }
        i = end;
    }
    for decl in [&b"<!DOCTYPE"[..], b"<!ENTITY"] {
        let mut i = 0;
        while let Some(p) = markup::find_ci(d, i, decl) {
            let end = d[p..].iter().position(|&b| b == b'>' || b == b'[').map_or(d.len(), |e| p + e);
            let text = String::from_utf8_lossy(&d[p..end]);
            for part in text.split(['"', '\'']).skip(1).step_by(2) {
                if classify(part) == Addr::Remote && !part.starts_with("http://www.w3.org/") {
                    r.add(false, "It names an outside definition on a server (some programs fetch it)", Some(part.to_string()));
                }
            }
            i = end.max(p + 1);
        }
    }
    if script {
        r.add(false, "It contains a script, which can contact servers when it runs", None);
    }
}

fn note_addr(r: &mut Report, element: &str, v: &str) {
    match classify(v) {
        Addr::Remote => {
            let what = match element {
                "img" | "image" | "picture" | "feimage" | "input" | "body" | "table" | "td" => {
                    "It loads a picture from a server when shown"
                }
                "script" => "It loads a script from a server when opened",
                "link" | "style" => "It loads a style or font from a server when shown",
                "iframe" | "frame" | "embed" | "object" | "applet" => "It loads another page or object from a server when opened",
                "video" | "audio" | "source" | "track" => "It loads media from a server when opened",
                "base" => "It points all its links and pictures at a server",
                "use" => "It loads part of the picture from a server when shown",
                _ => "It loads something from a server when opened",
            };
            r.add(true, what, Some(v.trim().to_string()));
        }
        Addr::Script => r.add(false, "It contains a script, which can contact servers when it runs", None),
        Addr::Local => {}
    }
}

// ---- playlists ----

fn check_playlist(p: Playlist, d: &[u8], r: &mut Report) {
    let text = String::from_utf8_lossy(d);
    let mut remote: Vec<String> = vec![];
    let mut push = |u: &str| {
        let u = u.trim();
        if classify(u) == Addr::Remote {
            remote.push(u.to_string());
        }
    };
    match p {
        Playlist::M3u => {
            for line in text.lines().take(1_000_000) {
                let l = line.trim();
                if let Some(rest) = l.strip_prefix('#') {
                    if let Some(i) = rest.find("URI=\"") {
                        let v: String = rest[i + 5..].chars().take_while(|&c| c != '"').collect();
                        push(&v);
                    }
                } else if !l.is_empty() {
                    push(l);
                }
            }
        }
        Playlist::Pls => {
            for line in text.lines().take(1_000_000) {
                if let Some((k, v)) = line.split_once('=') {
                    if k.trim().to_ascii_lowercase().starts_with("file") {
                        push(v);
                    }
                }
            }
        }
        Playlist::Xspf => {
            for t in markup::tags(d, 200_000) {
                if matches!(t.local().as_str(), "location" | "image") && !t.empty {
                    push(&markup::decode_entities(&String::from_utf8_lossy(markup::text_until_close(d, t.end))));
                }
            }
        }
        Playlist::Asx => {
            for t in markup::tags(d, 200_000) {
                if matches!(t.local().as_str(), "ref" | "entryref" | "logo" | "banner") {
                    if let Some(h) = t.attr_local("href") {
                        push(h);
                    }
                }
            }
        }
    }
    if !remote.is_empty() {
        let n = remote.len();
        let what = if n == 1 { "It plays from a server".to_string() } else { format!("It plays from servers ({n} addresses)") };
        r.add(true, what, remote.into_iter().next());
    }
}

// ---- shortcuts ----

/// The keys of an INI-style file's sections: (section, key, value), the first 10,000.
fn ini(d: &[u8]) -> Vec<(String, String, String)> {
    let text = String::from_utf8_lossy(d);
    let mut sec = String::new();
    let mut out = vec![];
    for line in text.lines().take(10_000) {
        let l = line.trim();
        if l.starts_with('[') && l.ends_with(']') {
            sec = l[1..l.len() - 1].to_string();
        } else if let Some((k, v)) = l.split_once('=') {
            out.push((sec.clone(), k.trim().to_string(), v.trim().to_string()));
        }
    }
    out
}

fn check_desktop(d: &[u8], r: &mut Report) {
    let kv = ini(d);
    let get = |key: &str| kv.iter().find(|(s, k, _)| s == "Desktop Entry" && k == key).map(|(_, _, v)| v.clone());
    let ty = get("Type").unwrap_or_default();
    if ty == "Link" {
        if let Some(u) = get("URL") {
            if classify(&u) == Addr::Remote {
                r.add(true, "It is a shortcut that opens a web address", Some(u));
            }
        }
    } else if let Some(exec) = get("Exec") {
        r.add(false, "It is a launcher that runs a command when opened (it can reach anything)", Some(exec));
    }
    if let Some(icon) = get("Icon").filter(|i| classify(i) == Addr::Remote) {
        r.add(true, "It loads its icon from a server when shown", Some(icon));
    }
}

fn check_url_shortcut(d: &[u8], r: &mut Report) {
    for (_, k, v) in ini(d) {
        let key = k.to_ascii_lowercase();
        if key == "url" && classify(&v) == Addr::Remote {
            r.add(true, "It is a shortcut that opens a web address", Some(v));
        } else if (key == "iconfile" || key == "iconlocation") && classify(&v) == Addr::Remote {
            r.add(true, "It loads its icon from a server as soon as its folder is shown", Some(v));
        }
    }
}

fn check_webloc(d: &[u8], r: &mut Report) {
    // an XML property list (<key>URL</key><string>...</string>) or a binary one: the addresses in it either way
    let text = String::from_utf8_lossy(d);
    let mut found = None;
    if let Some(p) = text.find("<string>") {
        let v: String = text[p + 8..].chars().take_while(|&c| c != '<').collect();
        found = Some(markup::decode_entities(&v));
    } else {
        for scheme in ["https://", "http://", "ftp://", "smb://"] {
            if let Some(p) = text.find(scheme) {
                found = Some(text[p..].chars().take_while(|c| !c.is_control()).collect());
                break;
            }
        }
    }
    if let Some(u) = found.filter(|u| classify(u) == Addr::Remote) {
        r.add(true, "It is a shortcut that opens a web address", Some(u));
    }
}

// ---- ZIP: Office, OpenDocument, archives ----

fn check_zip(name: &str, src: &dyn zip::Source, lim: &Limits, members: bool) -> Report {
    let a = match zip::read(src) {
        Ok(a) => a,
        Err(e) => {
            let mut r = Report::new(Kind::Zip);
            r.incomplete(e);
            return r;
        }
    };
    let kind = zip_kind(src, &a);
    let mut r = Report::new(kind);
    let mut budget = lim.budget;
    match kind {
        Kind::Office => check_office(src, &a, lim, &mut budget, &mut r),
        Kind::OpenDocument => check_odf(src, &a, lim, &mut budget, &mut r),
        _ => {
            if !members {
                // a ZIP inside a ZIP is not opened
                return r;
            }
            let _ = name;
            let mut checked = 0;
            for e in &a.entries {
                if e.is_dir() {
                    continue;
                }
                let n = e.name_lossy();
                if let Some(w) = risky_member(&n) {
                    let inner = if checked < lim.members && !e.encrypted() && e.usize <= lim.part {
                        checked += 1;
                        zip::content(src, e, lim.part, &mut budget).ok().map(|c| bytes(&n, &c, lim, false))
                    } else {
                        None
                    };
                    match inner {
                        Some(ir) => {
                            for mut f in ir.findings {
                                f.inside = Some(n.clone());
                                if r.findings.len() < MAX_FINDINGS {
                                    r.findings.push(f);
                                }
                            }
                            if !ir.complete {
                                r.incomplete(format!("{n} was not checked in full"));
                            }
                        }
                        None if w.by_name => {
                            if r.findings.len() < MAX_FINDINGS {
                                r.findings.push(Finding { sure: false, what: w.what.to_string(), target: None, inside: Some(n.clone()) });
                            }
                        }
                        None => r.incomplete(format!("{n} was not checked (too big, encrypted, or over the limit)")),
                    }
                }
            }
        }
    }
    r
}

/// A file inside an archive that is worth a look, and what it is when only its name can be judged.
pub struct Risky {
    pub what: &'static str,
    /// Flagged by its name alone when its content cannot be read.
    pub by_name: bool,
}

/// Files inside archives that can contact a server when opened: shortcuts and playlists always (by name, when they cannot be
/// read), documents and pictures only when their content says so.
pub fn risky_member(name: &str) -> Option<Risky> {
    let e = ext(name);
    let shortcut = Risky { what: "A shortcut inside can open a web address", by_name: true };
    match e.as_str() {
        "desktop" | "url" | "website" | "webloc" | "inetloc" | "scf" | "lnk" | "library-ms" | "searchconnector-ms" => Some(shortcut),
        "m3u" | "m3u8" | "pls" | "xspf" | "asx" | "wax" | "wvx" => {
            Some(Risky { what: "A playlist inside may play from a server", by_name: true })
        }
        "docx" | "docm" | "dotx" | "dotm" | "xlsx" | "xlsm" | "xltx" | "pptx" | "pptm" | "potx" | "ppsx" | "odt" | "ods" | "odp"
        | "odg" | "ott" | "pdf" | "svg" | "svgz" | "html" | "htm" | "xhtml" => Some(Risky { what: "", by_name: false }),
        _ => None,
    }
}

fn rels_word(ty: &str) -> (&'static str, bool) {
    match ty.rsplit('/').next().unwrap_or("") {
        "attachedTemplate" => ("It loads its template from a server when opened", true),
        "image" => ("It loads a picture from a server when opened", true),
        "oleObject" | "package" => ("It opens a linked object from a server when opened", true),
        "frame" => ("It loads a frame from a server when opened", true),
        "subDocument" => ("It loads part of itself from a server when opened", true),
        "video" | "audio" | "media" => ("It plays media from a server", true),
        "externalLinkPath" | "xlExternalLinkPath" | "externalLink" => {
            ("It links to a workbook on a server (updated when you allow it)", false)
        }
        "font" => ("It loads a font from a server when opened", true),
        _ => ("It loads something from a server when opened", true),
    }
}

fn check_office(src: &dyn zip::Source, a: &zip::Archive, lim: &Limits, budget: &mut u64, r: &mut Report) {
    let mut rels = 0;
    for e in &a.entries {
        let n = e.name_lossy();
        let lower = n.to_ascii_lowercase();
        if lower.ends_with(".rels") {
            rels += 1;
            if rels > 1024 {
                r.incomplete("too many parts");
                break;
            }
            let Ok(x) = zip::content(src, e, lim.part.min(4 << 20), budget) else {
                r.incomplete(format!("{n} could not be read"));
                continue;
            };
            for t in markup::tags(&x, 100_000) {
                if t.local() != "relationship" {
                    continue;
                }
                let external = t.attr("TargetMode").is_some_and(|m| m.eq_ignore_ascii_case("External"));
                let ty = t.attr("Type").unwrap_or("");
                if !external || ty.ends_with("/hyperlink") {
                    continue;
                }
                let target = t.attr("Target").unwrap_or("");
                if classify(target) == Addr::Remote {
                    let (what, sure) = rels_word(ty);
                    r.add(sure, what, Some(target.to_string()));
                }
            }
        } else if (lower.starts_with("word/") && lower.ends_with(".xml") && !lower.contains("/media/")) || lower == "xl/connections.xml" {
            let Ok(x) = zip::content(src, e, lim.part, budget) else {
                r.incomplete(format!("{n} could not be read"));
                continue;
            };
            if lower == "xl/connections.xml" {
                check_connections(&x, r);
            } else {
                check_fields(&x, r);
            }
        }
    }
}

/// Word fields that fetch when the document is opened or updated: INCLUDEPICTURE, INCLUDETEXT, LINK.
fn check_fields(x: &[u8], r: &mut Report) {
    if markup::find_ci(x, 0, b"INCLUDE").is_none() && markup::find_ci(x, 0, b"LINK").is_none() {
        return;
    }
    // a field's code can be split over several runs: join the text of every instrText, and the instr of simple fields
    let mut code = String::new();
    for t in markup::tags(x, 2_000_000) {
        match t.local().as_str() {
            "instrtext" if !t.empty => {
                code.push_str(&markup::decode_entities(&String::from_utf8_lossy(markup::text_until_close(x, t.end))));
            }
            "fldsimple" => {
                code.push(' ');
                code.push_str(t.attr_local("instr").unwrap_or(""));
                code.push(' ');
            }
            _ => {}
        }
        if code.len() > 4 << 20 {
            break;
        }
    }
    let upper = code.to_ascii_uppercase();
    for kw in ["INCLUDEPICTURE", "INCLUDETEXT", "LINK "] {
        let mut i = 0;
        while let Some(p) = upper[i..].find(kw).map(|p| p + i) {
            let rest = &code[p + kw.len()..];
            let rest = &rest[..rest.len().min(2048)];
            let target =
                rest.split('"').nth(1).map(str::to_string).unwrap_or_else(|| rest.split_whitespace().next().unwrap_or("").to_string());
            // in a field code a backslash is written twice
            let target = target.replace("\\\\", "\\");
            if classify(&target) == Addr::Remote {
                let what = if kw == "INCLUDEPICTURE" {
                    "It loads a picture from a server when opened"
                } else {
                    "It loads content from a server when opened or updated"
                };
                r.add(true, what, Some(target));
            }
            i = p + kw.len();
        }
    }
}

fn check_connections(x: &[u8], r: &mut Report) {
    let mut on_load = false;
    for t in markup::tags(x, 100_000) {
        match t.local().as_str() {
            "connection" => on_load = t.attr("refreshOnLoad").is_some_and(|v| v == "1" || v == "true"),
            "webpr" => {
                if let Some(u) = t.attr("url").filter(|u| classify(u) == Addr::Remote) {
                    let what = if on_load {
                        "It fetches data from a server when opened"
                    } else {
                        "It has a web data connection (fetched when you refresh)"
                    };
                    r.add(on_load, what, Some(u.to_string()));
                }
            }
            _ => {}
        }
    }
}

fn check_odf(src: &dyn zip::Source, a: &zip::Archive, lim: &Limits, budget: &mut u64, r: &mut Report) {
    for part in ["content.xml", "styles.xml", "meta.xml", "settings.xml"] {
        let Some(e) = a.find(part) else { continue };
        let Ok(x) = zip::content(src, e, lim.part, budget) else {
            r.incomplete(format!("{part} could not be read"));
            continue;
        };
        for t in markup::tags(&x, 1_000_000) {
            let local = t.local();
            if matches!(local.as_str(), "a" | "form") {
                continue;
            }
            for (k, v) in &t.attrs {
                if !k.to_ascii_lowercase().ends_with(":href") || classify(v) != Addr::Remote {
                    continue;
                }
                let (what, sure) = match local.as_str() {
                    "image" | "fill-image" | "background-image" | "bullet-image" | "list-level-style-image" => {
                        ("It loads a picture from a server when opened", true)
                    }
                    "object" | "object-ole" | "plugin" | "applet" | "frame" => ("It loads a linked object from a server when opened", true),
                    "template" => ("It names its template on a server", true),
                    "section-source" => ("It loads a section from a server (updated when you allow it)", false),
                    "table-source" | "cell-range-source" => ("It loads table data from a server (updated when you allow it)", false),
                    "event-listener" | "script" => ("It runs a script from a server", false),
                    _ => ("It loads something from a server when opened", true),
                };
                r.add(sure, what, Some(v.clone()));
            }
            if local == "dde-source" || local == "dde-connection-decl" {
                r.add(false, "It has a DDE link to another program's data (updated when you allow it)", None);
            }
        }
    }
}

// ---- PDF ----

/// Actions that reach outside the document.
const OUTSIDE: &[&[u8]] =
    &[b"URI", b"GoToR", b"GoToE", b"Launch", b"SubmitForm", b"ImportData", b"JavaScript", b"Rendition", b"Sound", b"Movie"];

/// Checks a PDF: what runs by itself (the catalog's /OpenAction, every /AA, followed through /Next), JavaScript, Launch.
pub fn check_pdf(data: &[u8]) -> Report {
    let mut r = Report::new(Kind::Pdf);
    let doc = pdf::Doc::scan(data);
    if !doc.complete {
        r.incomplete("part of it could not be unpacked");
    }
    if doc.trailer_has(b"Encrypt") {
        r.incomplete("it is encrypted: only its structure was read");
    }
    let mut js = false;
    let mut launch = false;
    // where actions start by themselves: (the value's tokens, its range)
    let mut roots: Vec<Vec<pdf::T>> = vec![];
    let mut nums: Vec<&u32> = doc.objs.keys().collect();
    nums.sort();
    for n in nums {
        let o = &doc.objs[n];
        let t = doc.toks(o);
        for (i, x) in t.iter().enumerate() {
            if let Tok::Name(k) = &x.tok {
                match k.as_slice() {
                    b"JS" | b"JavaScript" => js = true,
                    b"Launch" => launch = true,
                    b"OpenAction" | b"AA" => {
                        let e = pdf::value_end(&t, i + 1);
                        let v = t[(i + 1).min(t.len())..e].to_vec();
                        // an /OpenAction that is a destination ([page /Fit]) only turns a page
                        if !v.is_empty() && !matches!(v[0].tok, Tok::ArrOpen) && roots.len() < 4096 {
                            roots.push(v);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    // follow the automatic actions: references and inline dictionaries, at most 512 objects, never the same twice
    let mut seen = std::collections::HashSet::new();
    let mut queue: std::collections::VecDeque<Vec<pdf::T>> = roots.into();
    let mut steps = 0;
    while let Some(v) = queue.pop_front() {
        steps += 1;
        if steps > 2048 {
            r.incomplete("too many actions to follow");
            break;
        }
        let dict = if let Some(num) = pdf::as_ref(&v, 0, v.len()) {
            if !seen.insert(num) || seen.len() > 512 {
                continue;
            }
            match doc.objs.get(&num) {
                Some(o) => doc.toks(o),
                None => continue,
            }
        } else {
            v
        };
        if !matches!(dict.first().map(|x| &x.tok), Some(Tok::DictOpen)) {
            continue;
        }
        let es = pdf::entries(&dict, 0);
        let s = pdf::get(&es, b"S").and_then(|(a, b)| pdf::as_name(&dict, a, b)).map(<[u8]>::to_vec);
        match s {
            Some(action) => {
                if OUTSIDE.contains(&action.as_slice()) {
                    let target = ["URI", "F", "URL"]
                        .iter()
                        .find_map(|k| pdf::get(&es, k.as_bytes()))
                        .and_then(|(a, b)| string_in(&doc, &dict[a..b]));
                    pdf_action(&mut r, &action, target);
                }
                if let Some((a, b)) = pdf::get(&es, b"Next") {
                    push_values(&dict[a..b], &mut queue);
                }
            }
            None => {
                // an /AA dictionary: each event's action
                for (_, a, b) in es {
                    push_values(&dict[a..b], &mut queue);
                }
            }
        }
    }
    if js && !r.findings.iter().any(|f| f.what.contains("JavaScript")) {
        r.add(false, "It contains JavaScript (some PDF readers run it, and it can contact servers)", None);
    }
    if launch && !r.findings.iter().any(|f| f.what.contains("program")) {
        r.add(false, "It has an action that can start a program or open another file", None);
    }
    r
}

/// A value's references and inline dictionaries (an array of them, or one), queued.
fn push_values(v: &[pdf::T], q: &mut std::collections::VecDeque<Vec<pdf::T>>) {
    if q.len() > 4096 {
        return;
    }
    let (mut i, end) = if matches!(v.first().map(|x| &x.tok), Some(Tok::ArrOpen)) { (1, v.len().saturating_sub(1)) } else { (0, v.len()) };
    while i < end {
        let e = pdf::value_end(v, i).min(end);
        if pdf::as_ref(v, i, e).is_some() || matches!(v[i].tok, Tok::DictOpen) {
            q.push_back(v[i..e].to_vec());
        }
        i = e.max(i + 1);
    }
}

/// The first string in a value, following one reference (a file specification's /F, /UF or /URL).
fn string_in(doc: &pdf::Doc, v: &[pdf::T]) -> Option<String> {
    let owned;
    let toks = match pdf::as_ref(v, 0, v.len()).and_then(|n| doc.objs.get(&n)) {
        Some(o) => {
            owned = doc.toks(o);
            &owned[..]
        }
        None => v,
    };
    toks.iter().find_map(|t| match &t.tok {
        Tok::Str(s) => Some(String::from_utf8_lossy(s).into_owned()),
        _ => None,
    })
}

fn pdf_action(r: &mut Report, action: &[u8], target: Option<String>) {
    let remote = target.as_deref().is_some_and(|t| classify(t) == Addr::Remote);
    match action {
        b"URI" => r.add(true, "It opens a web address by itself when opened", target),
        b"SubmitForm" => r.add(remote || target.is_none(), "It sends its form to an address by itself", target),
        b"ImportData" if remote => r.add(true, "It loads data from a server by itself", target),
        b"GoToR" | b"GoToE" if remote => r.add(true, "It opens another document from a server by itself", target),
        b"Launch" => r.add(remote, "It starts a program or opens a file by itself when opened", target),
        b"JavaScript" => {
            r.add(false, "It runs JavaScript by itself when opened (some PDF readers run it, and it can contact servers)", None)
        }
        b"Rendition" | b"Sound" | b"Movie" if remote => r.add(true, "It plays media from a server by itself", target),
        _ => {}
    }
}

// ---- other archives: the list only ----

/// Lists a tar, 7z, rar or compressed tar with bsdtar (in a bubblewrap sandbox without network when bwrap is there), 30 s at
/// most, and flags the shortcuts and playlists in it by name.
pub fn list_archive(p: &Path, _name: &str) -> Report {
    let mut r = Report::new(Kind::Archive);
    let names = match list_names(p) {
        Ok(n) => n,
        Err(e) => {
            r.incomplete(e);
            return r;
        }
    };
    for n in names {
        if let Some(w) = risky_member(&n).filter(|w| w.by_name) {
            if r.findings.len() < MAX_FINDINGS {
                r.findings.push(Finding { sure: false, what: w.what.to_string(), target: None, inside: Some(n) });
            }
        }
    }
    r
}

fn on_path(prog: &str) -> Option<std::path::PathBuf> {
    std::env::var_os("PATH").and_then(|paths| std::env::split_paths(&paths).map(|d| d.join(prog)).find(|p| p.is_file()))
}

fn list_names(p: &Path) -> Result<Vec<String>, String> {
    use std::process::{Command, Stdio};
    let abs = std::fs::canonicalize(p).map_err(|e| e.to_string())?;
    let tool = on_path("bsdtar").ok_or("bsdtar is not installed, so the archive was not listed")?;
    let mut cmd = match on_path("bwrap") {
        Some(bw) => {
            let mut c = Command::new(bw);
            c.args(["--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL", "--ro-bind", "/usr", "/usr"]);
            c.args([
                "--symlink",
                "usr/lib",
                "/lib",
                "--symlink",
                "usr/lib64",
                "/lib64",
                "--symlink",
                "usr/bin",
                "/bin",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
            ]);
            c.arg("--ro-bind").arg(&abs).arg("/archive").arg("--").arg(&tool).args(["-tf", "/archive"]);
            c
        }
        None => {
            let mut c = Command::new(&tool);
            c.arg("-tf").arg(&abs);
            c
        }
    };
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    // SAFETY: setrlimit in the child before exec: 30 s of processor time and 1 GiB of memory for a hostile archive
    unsafe {
        std::os::unix::process::CommandExt::pre_exec(&mut cmd, || {
            let cpu = libc::rlimit { rlim_cur: 30, rlim_max: 30 };
            let mem = libc::rlimit { rlim_cur: 1 << 30, rlim_max: 1 << 30 };
            libc::setrlimit(libc::RLIMIT_CPU, &cpu);
            libc::setrlimit(libc::RLIMIT_AS, &mem);
            Ok(())
        });
    }
    let mut child = cmd.spawn().map_err(|e| format!("bsdtar could not start: {e}"))?;
    let mut out = vec![];
    if let Some(o) = child.stdout.take() {
        let _ = o.take(8 << 20).read_to_end(&mut out);
    }
    let start = std::time::Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) if start.elapsed() < std::time::Duration::from_secs(40) => std::thread::sleep(std::time::Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let names: Vec<String> = String::from_utf8_lossy(&out).lines().take(zip::MAX_ENTRIES).map(str::to_string).collect();
    match status {
        Some(s) if s.success() => Ok(names),
        _ if !names.is_empty() => Ok(names),
        _ => Err("the archive could not be listed (damaged, encrypted, or of a kind bsdtar does not read)".into()),
    }
}

#[cfg(test)]
mod tests;
