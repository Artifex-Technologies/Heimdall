//! Safe extraction (`heimdall-fileguard extract`) and the archive check `scan` makes (the same code, writing nothing).
//!
//! Formats: ZIP (stored and deflated entries, ZIP64), tar (ustar, GNU long names, pax), tar compressed with gzip (flate2, in
//! this process), xz, zstd or bzip2 (the system's `xz`, `zstd` and `bzip2`, which every Arch install has, run inside the same
//! sandbox with a memory limit of their own), and a single file compressed with one of those ("notes.txt.gz"). 7z and RAR are
//! not opened. A pure-Rust xz reader was looked at (lzma-rs 0.3): it keeps a whole LZMA2 block in memory before it hands out a
//! byte, so its output could not be counted as it streams; the system's xz streams.
//!
//! Every limit is counted on the bytes really unpacked, never on what a header says: headers only make a refusal come
//! sooner. Names are cleaned (control characters become "_", invisible and direction-changing characters go), and a name that
//! is absolute or climbs out with ".." refuses the whole archive, as do two entries with one name. Links, devices and FIFOs
//! are never made; archives inside are written as files, never opened (scan looks at each such file once, one level deep).
//! Nothing here deletes: on a refusal the caller removes the folder it made.

use crate::lookalike;
use crate::zip::{self, Source};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::path::Path;

/// The limits. The defaults are the command's; tests use small ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Most bytes unpacked in all (for a compressed tar: the whole unpacked stream, skipped files included).
    pub total: u64,
    /// Most bytes one file may unpack to.
    pub per_file: u64,
    /// Most entries (files, folders, links).
    pub entries: usize,
    /// Most times a file (and the archive in all) may grow when unpacked...
    pub ratio: u64,
    /// ...once a file has unpacked to more than this (small files compress well and are harmless)...
    pub entry_allowance: u64,
    /// ...and once the archive has unpacked to more than this in all.
    pub total_allowance: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { total: 512 << 20, per_file: 256 << 20, entries: 10_000, ratio: 100, entry_allowance: 1 << 20, total_allowance: 4 << 20 }
    }
}

/// Why an archive was refused; `scan` decides from it whether the archive is dangerous or only too big to check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// A decompression bomb: a ratio over the limit, overlapping entries, more data than the header says.
    Bomb,
    /// A name that is absolute or climbs out of the folder (zip slip).
    Escape,
    /// The archive names a file one way in its directory and another in the file's own header.
    Trick,
    /// Bigger than the limits (size, entries) at an ordinary ratio.
    TooBig,
    /// Two entries with one name, a file and a folder with one name, a name too long or too deep.
    Names,
    /// Damaged or cut short.
    Damaged,
    /// A kind of archive this does not open.
    Unsupported,
    /// The files could not be written (a full disk...).
    Write,
}

impl Why {
    pub fn id(self) -> &'static str {
        match self {
            Why::Bomb => "bomb",
            Why::Escape => "escape",
            Why::Trick => "trick",
            Why::TooBig => "too-big",
            Why::Names => "names",
            Why::Damaged => "damaged",
            Why::Unsupported => "unsupported",
            Why::Write => "write",
        }
    }

    pub fn from_id(s: &str) -> Why {
        match s {
            "bomb" => Why::Bomb,
            "escape" => Why::Escape,
            "trick" => Why::Trick,
            "too-big" => Why::TooBig,
            "names" => Why::Names,
            "unsupported" => Why::Unsupported,
            "write" => Why::Write,
            _ => Why::Damaged,
        }
    }
}

/// A refusal: why, in plain words.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub why: Why,
    pub reason: String,
}

fn no<T>(why: Why, reason: impl Into<String>) -> Result<T, Refusal> {
    Err(Refusal { why, reason: reason.into() })
}

fn mib(n: u64) -> String {
    if n >= 1 << 20 {
        format!("{} MiB", n >> 20)
    } else {
        format!("{} KiB", n >> 10)
    }
}

/// How a tar stream (or a single file) is compressed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compression {
    None,
    Gzip,
    Xz,
    Zstd,
    Bzip2,
}

/// The kinds opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Zip,
    /// A tar, or with compression also a single compressed file.
    Tar(Compression),
}

/// The kind of archive from its first bytes (512 are enough): `Ok(None)` when it is not an archive, `Err(kind)` for an
/// archive this does not open.
pub fn detect(head: &[u8]) -> Result<Option<Format>, &'static str> {
    if head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06") || head.starts_with(b"PK\x07\x08") {
        return Ok(Some(Format::Zip));
    }
    if head.starts_with(b"\x1F\x8B") {
        return Ok(Some(Format::Tar(Compression::Gzip)));
    }
    if head.starts_with(b"\xFD7zXZ\x00") {
        return Ok(Some(Format::Tar(Compression::Xz)));
    }
    if head.starts_with(b"\x28\xB5\x2F\xFD") {
        return Ok(Some(Format::Tar(Compression::Zstd)));
    }
    if head.len() >= 10
        && head.starts_with(b"BZh")
        && (b'1'..=b'9').contains(&head[3])
        && (&head[4..10] == b"\x31\x41\x59\x26\x53\x59" || &head[4..10] == b"\x17\x72\x45\x38\x50\x90")
    {
        return Ok(Some(Format::Tar(Compression::Bzip2)));
    }
    if head.len() >= 512 && tar_header_ok(&head[..512]) {
        return Ok(Some(Format::Tar(Compression::None)));
    }
    if head.starts_with(b"7z\xBC\xAF\x27\x1C") {
        return Err("7z");
    }
    if head.starts_with(b"Rar!\x1A\x07") {
        return Err("RAR");
    }
    Ok(None)
}

/// What to keep.
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// Only files with these extensions (lower case, without the dot); empty: everything.
    pub only: Vec<String>,
    pub limits: Limits,
}

impl Options {
    fn keeps(&self, parts: &[String]) -> bool {
        if self.only.is_empty() {
            return true;
        }
        let last = parts.last().map(String::as_str).unwrap_or("");
        match last.rsplit_once('.') {
            Some((stem, e)) if !stem.is_empty() => self.only.iter().any(|o| o.eq_ignore_ascii_case(e)),
            _ => false,
        }
    }

    fn only_words(&self) -> String {
        format!("not one of the kinds asked for ({})", self.only.join(", "))
    }
}

/// One file written (or, in a dry run, that would have been).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Written {
    /// The name in the archive, made safe to show (lookalike::visible).
    pub name: String,
    /// Where it was written, relative to the folder, cleaned.
    pub path: String,
    pub size: u64,
}

/// One entry left out, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skipped {
    pub name: String,
    pub reason: String,
}

/// What an extraction did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub files: Vec<Written>,
    pub skipped: Vec<Skipped>,
    pub refused: Option<Refusal>,
    /// Bytes unpacked in all (for a compressed tar, the whole stream).
    pub unpacked: u64,
}

/// Where the files go: a folder on disk, or nowhere (the dry run of `scan`).
pub trait Sink {
    fn dir(&mut self, parts: &[String]) -> io::Result<()>;
    fn file(&mut self, parts: &[String]) -> io::Result<Box<dyn Write + '_>>;
}

/// The dry run: every limit is counted, nothing is written.
pub struct Discard;

impl Sink for Discard {
    fn dir(&mut self, _: &[String]) -> io::Result<()> {
        Ok(())
    }
    fn file(&mut self, _: &[String]) -> io::Result<Box<dyn Write + '_>> {
        Ok(Box::new(io::sink()))
    }
}

/// A folder on disk, held open: every part of a path is opened relative to the one before it without following links
/// (openat with O_NOFOLLOW), and files are created only where nothing is (O_EXCL), so nothing can be redirected out of it.
pub struct Disk {
    root: std::fs::File,
}

fn cstr(s: &str) -> io::Result<std::ffi::CString> {
    std::ffi::CString::new(s).map_err(|_| io::Error::other("a name with a zero byte"))
}

fn at(parent: &std::fs::File, name: &str, make: bool) -> io::Result<std::fs::File> {
    use std::os::unix::io::{AsRawFd, FromRawFd};
    let c = cstr(name)?;
    if make {
        // SAFETY: a valid C string and our own descriptor
        if unsafe { libc::mkdirat(parent.as_raw_fd(), c.as_ptr(), 0o700) } != 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EEXIST) {
                return Err(e);
            }
        }
    }
    // SAFETY: as above; the descriptor returned is ours
    let fd =
        unsafe { libc::openat(parent.as_raw_fd(), c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a descriptor we just opened and own
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

impl Disk {
    pub fn open(dir: &Path) -> io::Result<Disk> {
        use std::os::unix::fs::OpenOptionsExt;
        let root = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC).open(dir)?;
        Ok(Disk { root })
    }

    fn walk(&self, dirs: &[String]) -> io::Result<Option<std::fs::File>> {
        let mut cur: Option<std::fs::File> = None;
        for d in dirs {
            let next = at(cur.as_ref().unwrap_or(&self.root), d, true)?;
            cur = Some(next);
        }
        Ok(cur)
    }
}

impl Sink for Disk {
    fn dir(&mut self, parts: &[String]) -> io::Result<()> {
        self.walk(parts).map(|_| ())
    }

    fn file(&mut self, parts: &[String]) -> io::Result<Box<dyn Write + '_>> {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let (last, dirs) = parts.split_last().ok_or_else(|| io::Error::other("an empty name"))?;
        let parent = self.walk(dirs)?;
        let c = cstr(last)?;
        let p = parent.as_ref().unwrap_or(&self.root);
        // SAFETY: a valid C string; the descriptor returned is ours
        let fd = unsafe {
            libc::openat(
                p.as_raw_fd(),
                c.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600 as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a descriptor we just opened and own
        Ok(Box::new(io::BufWriter::with_capacity(64 << 10, unsafe { std::fs::File::from_raw_fd(fd) })))
    }
}

// ---- names ----

/// A name from an archive made safe for the disk: its parts, without empty and "." parts. Backslashes count as separators
/// (archives made on Windows). Control characters become "_", invisible and direction-changing characters are removed. An
/// absolute name, a drive letter or a ".." part (also one that only becomes ".." once cleaned) refuses the archive.
pub fn clean_name(raw: &[u8]) -> Result<Vec<String>, Refusal> {
    let s = String::from_utf8_lossy(raw).replace('\\', "/");
    let b = s.as_bytes();
    if s.starts_with('/') || (b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic()) {
        return no(Why::Escape, "a file inside has an absolute path (it would be written outside the folder)");
    }
    let mut parts = vec![];
    for comp in s.split('/') {
        let c: String = comp
            .chars()
            .filter(|&ch| !lookalike::invisible(ch) && !lookalike::direction_control(ch))
            .map(|ch| if ch.is_control() || ch == '\u{FFFD}' || matches!(ch as u32, 0x2028 | 0x2029) { '_' } else { ch })
            .collect();
        if c.is_empty() || c == "." {
            continue;
        }
        if c == ".." {
            return no(Why::Escape, "a file inside has \"..\" in its name, to be written outside the folder (a \"zip slip\")");
        }
        if c.len() > 255 {
            return no(Why::Names, "a name inside is too long");
        }
        parts.push(c);
    }
    if parts.len() > 64 {
        return no(Why::Names, "a file inside is nested too deep");
    }
    Ok(parts)
}

/// The names seen so far: a second entry with a name (or a file where a folder is) refuses the archive.
#[derive(Default)]
struct Names {
    seen: HashMap<String, bool>,
}

impl Names {
    fn add(&mut self, parts: &[String], dir: bool) -> Result<(), Refusal> {
        for i in 1..parts.len() {
            let p = parts[..i].join("/");
            match self.seen.get(&p) {
                Some(false) => {
                    return no(Why::Names, format!("a file and a folder inside have the same name ({})", lookalike::visible(&p)))
                }
                Some(true) => {}
                None => {
                    self.seen.insert(p, true);
                }
            }
        }
        let full = parts.join("/");
        match self.seen.get(&full) {
            Some(true) if dir => Ok(()),
            Some(_) => no(Why::Names, format!("two entries inside have the same name ({})", lookalike::visible(&full))),
            None => {
                self.seen.insert(full, dir);
                Ok(())
            }
        }
    }
}

// ---- counting ----

/// The running count of what was unpacked, and the archive's own size for the overall ratio.
#[derive(Clone, Copy, Debug)]
struct Meter {
    lim: Limits,
    archive: u64,
    total: u64,
}

impl Meter {
    fn add(&mut self, n: u64) -> Result<(), Refusal> {
        self.total = self.total.saturating_add(n);
        let lim = self.lim;
        if self.total > lim.total_allowance && self.total > lim.ratio.saturating_mul(self.archive.max(1)) {
            return no(Why::Bomb, format!("it unpacks to more than {} times its size: a decompression bomb (\"ZIP bomb\")", lim.ratio));
        }
        if self.total > lim.total {
            return no(Why::TooBig, format!("it unpacks to more than {} in all", mib(lim.total)));
        }
        Ok(())
    }
}

/// What one file may do while it is unpacked.
struct Caps {
    /// Its packed size, for its own ratio (ZIP).
    packed: Option<u64>,
    /// The size its header gives (ZIP): more than that is a lie.
    declared: Option<u64>,
    /// Count it in the meter (a compressed tar is counted on the stream instead).
    count: bool,
}

const LIMIT_HIT: &str = "heimdall-extract-limit";

/// Copies one file's bytes, counting them against every limit as they come; returns how many were copied.
fn pump(r: &mut dyn Read, w: &mut dyn Write, m: &mut Meter, caps: &Caps, mut crc: Option<&mut flate2::Crc>) -> Result<u64, Refusal> {
    let lim = m.lim;
    let mut buf = vec![0u8; 64 << 10];
    let mut out: u64 = 0;
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.to_string() == LIMIT_HIT => return no(Why::Damaged, LIMIT_HIT),
            Err(_) => return no(Why::Damaged, "it is damaged or cut short"),
        };
        out += n as u64;
        if caps.declared.is_some_and(|d| out > d) {
            return no(Why::Bomb, "a file inside unpacks to more than its header says (a decompression bomb)");
        }
        if let Some(p) = caps.packed {
            if out > lim.entry_allowance && out > lim.ratio.saturating_mul(p.max(1)) {
                return no(
                    Why::Bomb,
                    format!("a file inside unpacks to more than {} times its packed size: a decompression bomb", lim.ratio),
                );
            }
        }
        if out > lim.per_file {
            return no(Why::TooBig, format!("a file inside is bigger than {}", mib(lim.per_file)));
        }
        if caps.count {
            m.add(n as u64)?;
        }
        if let Some(c) = crc.as_deref_mut() {
            c.update(&buf[..n]);
        }
        if let Err(e) = w.write_all(&buf[..n]) {
            return match e.raw_os_error() {
                Some(libc::EFBIG) => no(Why::TooBig, format!("a file inside is bigger than {}", mib(lim.per_file))),
                _ => no(Why::Write, format!("the files could not be written: {e}")),
            };
        }
    }
    Ok(out)
}

fn finish(w: Box<dyn Write + '_>) -> Result<(), Refusal> {
    let mut w = w;
    w.flush().map_err(|e| Refusal { why: Why::Write, reason: format!("the files could not be written: {e}") })
}

// ---- ZIP ----

/// The bytes of a range of a source, as a reader.
struct Range<'a> {
    src: &'a dyn Source,
    pos: u64,
    end: u64,
}

impl Read for Range<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = (self.end - self.pos).min(buf.len() as u64) as usize;
        if n == 0 {
            return Ok(0);
        }
        self.src.read_at(self.pos, &mut buf[..n])?;
        self.pos += n as u64;
        Ok(n)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ZipKind {
    File,
    Dir,
    Link,
    Device,
    Fifo,
}

fn zip_kind(e: &zip::Entry) -> ZipKind {
    let unix = e.made_by >> 8 == 3;
    let ft = (e.external >> 16) & 0o170000;
    if unix && ft == 0o120000 {
        ZipKind::Link
    } else if unix && (ft == 0o020000 || ft == 0o060000 || ft == 0o140000) {
        ZipKind::Device
    } else if unix && ft == 0o010000 {
        ZipKind::Fifo
    } else if e.is_dir() || (unix && ft == 0o040000) {
        ZipKind::Dir
    } else {
        ZipKind::File
    }
}

fn not_made(k: ZipKind) -> &'static str {
    match k {
        ZipKind::Link => "a link (links are never made: one could point anywhere)",
        ZipKind::Device => "a device or socket (never made)",
        _ => "a FIFO (never made)",
    }
}

/// Extracts a ZIP archive into `sink` (or, with Discard, checks it).
pub fn zip(src: &dyn Source, o: &Options, sink: &mut dyn Sink) -> Outcome {
    let mut out = Outcome::default();
    let mut m = Meter { lim: o.limits, archive: src.size(), total: 0 };
    if let Err(r) = zip_inner(src, o, sink, &mut m, &mut out) {
        out.refused = Some(r);
    }
    out.unpacked = m.total;
    out
}

fn zip_inner(src: &dyn Source, o: &Options, sink: &mut dyn Sink, m: &mut Meter, out: &mut Outcome) -> Result<(), Refusal> {
    let lim = o.limits;
    let a = zip::read(src).map_err(|e| Refusal { why: Why::Damaged, reason: e })?;
    if a.declared > lim.entries as u64 || a.entries.len() > lim.entries {
        return no(Why::TooBig, format!("it holds more than {} files", lim.entries));
    }
    if a.declared != a.entries.len() as u64 {
        return no(Why::Damaged, "its list of files is damaged");
    }
    // first the whole directory, before anything is written: where each file is (files that share bytes are a bomb), then
    // the names
    let mut ranges: Vec<(u64, u64)> = Vec::with_capacity(a.entries.len());
    for e in &a.entries {
        let (start, len) = zip::data_range(src, e).map_err(|_| Refusal {
            why: Why::Damaged,
            reason: "a file inside is out of place or runs past the end (the archive is damaged or cut short)".into(),
        })?;
        ranges.push((e.local, start + len));
    }
    ranges.sort_unstable();
    if ranges.windows(2).any(|w| w[1].0 < w[0].1) {
        return no(Why::Bomb, "its files share the same bytes (overlapping entries): a decompression bomb (\"ZIP bomb\")");
    }
    let mut names = Names::default();
    let mut plan: Vec<(usize, Vec<String>, ZipKind)> = Vec::with_capacity(a.entries.len());
    for (i, e) in a.entries.iter().enumerate() {
        let parts = clean_name(&e.name)?;
        let local = zip::local_name(src, e)
            .map_err(|_| Refusal { why: Why::Damaged, reason: "a file inside is out of place (the archive is damaged)".into() })?;
        if local != e.name {
            return no(Why::Trick, "it gives a file inside two different names (a trick to hide what it holds)");
        }
        if parts.is_empty() {
            continue;
        }
        let kind = zip_kind(e);
        names.add(&parts, kind == ZipKind::Dir)?;
        plan.push((i, parts, kind));
    }
    let mut promised: u64 = 0;
    for (i, parts, kind) in plan {
        let e = &a.entries[i];
        let shown = lookalike::visible(&e.name_lossy());
        match kind {
            ZipKind::Dir => {
                if o.only.is_empty() {
                    sink.dir(&parts).map_err(|e| Refusal { why: Why::Write, reason: format!("the files could not be written: {e}") })?;
                }
                continue;
            }
            ZipKind::File => {}
            k => {
                out.skipped.push(Skipped { name: shown, reason: not_made(k).into() });
                continue;
            }
        }
        if !o.keeps(&parts) {
            out.skipped.push(Skipped { name: shown, reason: o.only_words() });
            continue;
        }
        if e.encrypted() {
            out.skipped.push(Skipped { name: shown, reason: "encrypted: Heimdall cannot look inside, so it was not extracted".into() });
            continue;
        }
        if e.method != 0 && e.method != 8 {
            out.skipped.push(Skipped { name: shown, reason: format!("packed with a method Heimdall does not read ({})", e.method) });
            continue;
        }
        // a header that admits to too much ends it early (a header that hides it is caught while unpacking)
        if e.usize > lim.per_file {
            return no(Why::TooBig, format!("a file inside is bigger than {}", mib(lim.per_file)));
        }
        promised = promised.saturating_add(e.usize);
        if promised > lim.total {
            return no(Why::TooBig, format!("it unpacks to more than {} in all", mib(lim.total)));
        }
        let (start, len) = zip::data_range(src, e).map_err(|err| Refusal { why: Why::Damaged, reason: err })?;
        if e.method == 0 && len != e.usize {
            return no(Why::Damaged, "a file inside is damaged (its sizes disagree)");
        }
        let range = Range { src, pos: start, end: start + len };
        let mut reader: Box<dyn Read> = if e.method == 8 { Box::new(flate2::read::DeflateDecoder::new(range)) } else { Box::new(range) };
        let mut crc = flate2::Crc::new();
        let caps = Caps { packed: Some(len), declared: Some(e.usize), count: true };
        let w = sink.file(&parts).map_err(|err| Refusal { why: Why::Write, reason: format!("the files could not be written: {err}") });
        let mut w = w?;
        let n = pump(&mut reader, &mut w, m, &caps, Some(&mut crc))?;
        finish(w)?;
        if n != e.usize {
            return no(Why::Damaged, "a file inside is shorter than its header says (damaged or cut short)");
        }
        if crc.sum() != e.crc {
            return no(Why::Damaged, "a file inside is damaged (its checksum does not match)");
        }
        out.files.push(Written { name: shown, path: parts.join("/"), size: n });
    }
    Ok(())
}

// ---- tar ----

fn octal(f: &[u8]) -> Option<u64> {
    if f.first().is_some_and(|b| b & 0x80 != 0) {
        // base-256 (GNU): big-endian, the first byte's top bit is the flag
        let mut v: u64 = (f[0] & 0x7F) as u64;
        for &b in &f[1..] {
            v = v.checked_mul(256)?.checked_add(b as u64)?;
        }
        return Some(v);
    }
    let mut v: u64 = 0;
    let mut any = false;
    for &b in f {
        match b {
            b'0'..=b'7' => {
                v = v.checked_mul(8)?.checked_add((b - b'0') as u64)?;
                any = true;
            }
            b' ' | 0 if !any => continue,
            b' ' | 0 => break,
            _ => return None,
        }
    }
    Some(v)
}

/// A tar header block whose checksum is right (unsigned, or the signed sum old tars wrote).
pub fn tar_header_ok(h: &[u8]) -> bool {
    if h.len() < 512 || h.iter().all(|&b| b == 0) {
        return false;
    }
    let Some(stored) = octal(&h[148..156]) else { return false };
    let mut unsigned: u64 = 0;
    let mut signed: i64 = 0;
    for (i, &b) in h[..512].iter().enumerate() {
        let b = if (148..156).contains(&i) { b' ' } else { b };
        unsigned += b as u64;
        signed += b as i8 as i64;
    }
    stored == unsigned || stored as i64 == signed
}

fn field(f: &[u8]) -> &[u8] {
    &f[..f.iter().position(|&b| b == 0).unwrap_or(f.len())]
}

/// Reads until `buf` is full or the stream ends; how many bytes came.
fn read_full(r: &mut dyn Read, buf: &mut [u8]) -> Result<usize, io::Error> {
    let mut got = 0;
    while got < buf.len() {
        match r.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(got)
}

/// A reader that counts every byte unpacked from the stream against the meter, and stops with LIMIT_HIT once a limit is
/// reached (the refusal is kept in `stop`).
struct Counting<R: Read> {
    inner: R,
    m: Meter,
    stop: Option<Refusal>,
}

impl<R: Read> Read for Counting<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.stop.is_some() {
            return Err(io::Error::other(LIMIT_HIT));
        }
        let n = self.inner.read(buf)?;
        if let Err(r) = self.m.add(n as u64) {
            self.stop = Some(r);
            return Err(io::Error::other(LIMIT_HIT));
        }
        Ok(n)
    }
}

/// The refusal behind a failed read: the limit when one was hit, else damage.
fn why_failed<R: Read>(c: &mut Counting<R>, r: Refusal) -> Refusal {
    match c.stop.take() {
        Some(s) => s,
        None if r.reason == LIMIT_HIT => Refusal { why: Why::Damaged, reason: "it is damaged or cut short".into() },
        None => r,
    }
}

fn skip<R: Read>(c: &mut Counting<R>, n: u64) -> Result<(), Refusal> {
    let got = io::copy(&mut c.by_ref().take(n), &mut io::sink());
    match got {
        Ok(k) if k == n => Ok(()),
        Ok(_) => no(Why::Damaged, "it is cut short"),
        Err(_) => Err(why_failed(c, Refusal { why: Why::Damaged, reason: "it is damaged or cut short".into() })),
    }
}

/// The name a single compressed file gets: the archive's without the compression's extension.
pub fn single_name(archive: &str) -> String {
    let lower = archive.to_ascii_lowercase();
    for e in [".gz", ".xz", ".zst", ".bz2", ".tgz", ".txz", ".tbz2", ".tzst"] {
        if lower.ends_with(e) && archive.len() > e.len() {
            let stem = &archive[..archive.len() - e.len()];
            return if e.starts_with(".t") { format!("{stem}.tar") } else { stem.to_string() };
        }
    }
    format!("{archive}.out")
}

/// Extracts a tar stream (already decompressed by `r`), or when `compressed` and the stream is not a tar, the single file
/// in it as `name` (the archive's name without the compression's extension). `archive` is the archive's size on disk.
pub fn stream(r: &mut dyn Read, archive: u64, name: &str, compressed: bool, o: &Options, sink: &mut dyn Sink) -> Outcome {
    let mut out = Outcome::default();
    let mut c = Counting { inner: r, m: Meter { lim: o.limits, archive, total: 0 }, stop: None };
    if let Err(e) = stream_inner(&mut c, name, compressed, o, sink, &mut out) {
        out.refused = Some(why_failed(&mut c, e));
    }
    out.unpacked = c.m.total;
    out
}

fn stream_inner<R: Read>(
    c: &mut Counting<R>,
    name: &str,
    compressed: bool,
    o: &Options,
    sink: &mut dyn Sink,
    out: &mut Outcome,
) -> Result<(), Refusal> {
    let lim = o.limits;
    let mut block = [0u8; 512];
    let got = read_full(c, &mut block).map_err(|_| Refusal { why: Why::Damaged, reason: "it is damaged or cut short".into() })?;
    if got < 512 || !tar_header_ok(&block) {
        if got == 512 && block.iter().all(|&b| b == 0) {
            return Ok(()); // an empty tar
        }
        if !compressed {
            return no(Why::Unsupported, "it is not an archive Heimdall can open");
        }
        // a single compressed file
        let parts = clean_name(name.as_bytes())?;
        if parts.is_empty() {
            return no(Why::Names, "the file inside has no name");
        }
        let shown = lookalike::visible(name);
        if !o.keeps(&parts) {
            out.skipped.push(Skipped { name: shown, reason: o.only_words() });
            return Ok(());
        }
        let caps = Caps { packed: None, declared: None, count: false };
        let mut w = sink.file(&parts).map_err(|e| Refusal { why: Why::Write, reason: format!("the files could not be written: {e}") })?;
        let mut head = io::Cursor::new(block[..got].to_vec());
        let mut rest = (&mut head).chain(c.by_ref());
        let n = pump(&mut rest, &mut w, &mut Meter { lim, archive: u64::MAX, total: 0 }, &caps, None)?;
        finish(w)?;
        out.files.push(Written { name: shown, path: parts.join("/"), size: n });
        return Ok(());
    }
    let mut names = Names::default();
    let mut entries = 0usize;
    let mut long_name: Option<Vec<u8>> = None;
    let mut pax_path: Option<Vec<u8>> = None;
    let mut pax_size: Option<u64> = None;
    let mut first = true;
    loop {
        if !first {
            let got = read_full(c, &mut block).map_err(|_| Refusal { why: Why::Damaged, reason: "it is damaged or cut short".into() })?;
            if got == 0 {
                return Ok(()); // no end blocks: tolerated, as GNU tar does
            }
            if got < 512 {
                return no(Why::Damaged, "it is cut short");
            }
            if block.iter().all(|&b| b == 0) {
                return Ok(()); // the end
            }
            if !tar_header_ok(&block) {
                return no(Why::Damaged, "it is damaged (a header's checksum does not match)");
            }
        }
        first = false;
        let ty = block[156];
        let Some(hsize) = octal(&block[124..136]) else { return no(Why::Damaged, "it is damaged (a size cannot be read)") };
        let size = if matches!(ty, b'x' | b'g' | b'L' | b'K') { hsize } else { pax_size.take().unwrap_or(hsize) };
        let padded =
            size.checked_add(511).map(|s| s / 512 * 512).ok_or_else(|| Refusal { why: Why::Damaged, reason: "it is damaged".into() })?;
        match ty {
            b'x' | b'g' | b'L' | b'K' => {
                if size > 1 << 20 {
                    return no(Why::Damaged, "it is damaged (an extended header is too long)");
                }
                let mut data = vec![0u8; size as usize];
                if read_full(c, &mut data).map_err(|_| Refusal { why: Why::Damaged, reason: "it is cut short".into() })? != data.len() {
                    return no(Why::Damaged, "it is cut short");
                }
                skip(c, padded - size)?;
                match ty {
                    b'L' => long_name = Some(field(&data).to_vec()),
                    b'x' => {
                        for (k, v) in pax_records(&data) {
                            match k.as_slice() {
                                b"path" => pax_path = Some(v),
                                b"size" => {
                                    pax_size = std::str::from_utf8(&v).ok().and_then(|s| s.trim().parse().ok());
                                    if pax_size.is_none() {
                                        return no(Why::Damaged, "it is damaged (a size cannot be read)");
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
                continue;
            }
            _ => {}
        }
        entries += 1;
        if entries > lim.entries {
            return no(Why::TooBig, format!("it holds more than {} files", lim.entries));
        }
        let raw = match (pax_path.take(), long_name.take()) {
            (Some(p), _) => p,
            (None, Some(l)) => l,
            _ => {
                let n = field(&block[0..100]);
                let prefix = field(&block[345..500]);
                if &block[257..262] == b"ustar" && !prefix.is_empty() {
                    [prefix, b"/", n].concat()
                } else {
                    n.to_vec()
                }
            }
        };
        let parts = clean_name(&raw)?;
        let shown = lookalike::visible(&String::from_utf8_lossy(&raw));
        if parts.is_empty() {
            skip(c, padded)?;
            continue;
        }
        let dir = ty == b'5';
        names.add(&parts, dir)?;
        let reason = match ty {
            b'0' | 0 | b'7' => None,
            b'5' => {
                if o.only.is_empty() {
                    sink.dir(&parts).map_err(|e| Refusal { why: Why::Write, reason: format!("the files could not be written: {e}") })?;
                }
                skip(c, padded)?;
                continue;
            }
            b'1' => Some("a hard link (links are never made: one could point anywhere)".to_string()),
            b'2' => Some("a link (links are never made: one could point anywhere)".to_string()),
            b'3' | b'4' => Some("a device (never made)".to_string()),
            b'6' => Some("a FIFO (never made)".to_string()),
            b'S' => Some("a sparse file (not extracted)".to_string()),
            t => Some(format!("an entry of a kind Heimdall does not make ({})", (t as char).escape_default())),
        };
        let reason = reason.or_else(|| (!o.keeps(&parts)).then(|| o.only_words()));
        if let Some(reason) = reason {
            out.skipped.push(Skipped { name: shown, reason });
            skip(c, padded)?;
            continue;
        }
        if size > lim.per_file {
            return no(Why::TooBig, format!("a file inside is bigger than {}", mib(lim.per_file)));
        }
        let caps = Caps { packed: None, declared: None, count: false };
        let mut w = sink.file(&parts).map_err(|e| Refusal { why: Why::Write, reason: format!("the files could not be written: {e}") })?;
        let n = {
            let mut body = c.by_ref().take(size);
            pump(&mut body, &mut w, &mut Meter { lim, archive: u64::MAX, total: 0 }, &caps, None)?
        };
        finish(w)?;
        if n != size {
            return no(Why::Damaged, "it is cut short");
        }
        skip(c, padded - size)?;
        out.files.push(Written { name: shown, path: parts.join("/"), size: n });
    }
}

/// pax records: "LEN key=value\n".
fn pax_records(d: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = vec![];
    let mut i = 0;
    while i < d.len() && out.len() < 256 {
        let Some(sp) = d[i..].iter().position(|&b| b == b' ') else { break };
        let Some(len) = std::str::from_utf8(&d[i..i + sp]).ok().and_then(|s| s.parse::<usize>().ok()) else { break };
        if len == 0 || i + len > d.len() || sp + 1 >= len {
            break;
        }
        let rec = &d[i + sp + 1..i + len];
        let rec = rec.strip_suffix(b"\n").unwrap_or(rec);
        if let Some(eq) = rec.iter().position(|&b| b == b'=') {
            out.push((rec[..eq].to_vec(), rec[eq + 1..].to_vec()));
        }
        i += len;
    }
    out
}

#[cfg(test)]
pub mod tests;
