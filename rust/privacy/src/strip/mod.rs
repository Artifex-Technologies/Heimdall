//! Remove hidden info (`heimdall-strip`, Minos' right-click entry): a copy of a file without what it says about who made it,
//! where and with what, beside the original as "name (clean).ext". The original is never changed, and the copy never
//! replaces a file: it is written under a temporary name and linked into place only where nothing is.
//!
//! Our own code: JPEG, PNG, WebP, HEIF/AVIF, TIFF, PDF, Office, OpenDocument, ZIP, MP3, FLAC, WAV. ffmpeg (copying the
//! streams, `media.rs`): MP4/MOV/M4A/3GP, Matroska/WebM, Ogg/Opus, AVI, ASF.

pub mod audio;
pub mod doc;
pub mod exif;
pub mod image;
pub mod media;

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// What was taken out, in plain words, each once.
pub type Removed = Vec<String>;

pub(crate) fn note(r: &mut Removed, s: &str) {
    if !r.iter().any(|x| x == s) && r.len() < 64 {
        r.push(s.to_string());
    }
}

/// A kind of file this tool cleans.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Jpeg,
    Png,
    Webp,
    Heif,
    Tiff,
    Pdf,
    Office,
    OpenDocument,
    Zip,
    Mp3,
    Flac,
    Wav,
    /// ffmpeg, with this format.
    Media(&'static str),
}

impl Kind {
    pub fn id(self) -> &'static str {
        match self {
            Kind::Jpeg => "jpeg",
            Kind::Png => "png",
            Kind::Webp => "webp",
            Kind::Heif => "heif",
            Kind::Tiff => "tiff",
            Kind::Pdf => "pdf",
            Kind::Office => "office",
            Kind::OpenDocument => "opendocument",
            Kind::Zip => "zip",
            Kind::Mp3 => "mp3",
            Kind::Flac => "flac",
            Kind::Wav => "wav",
            Kind::Media(f) => f,
        }
    }
}

/// The largest file cleaned in memory (all kinds but ffmpeg's).
pub const MAX_IN_MEMORY: u64 = 1 << 30;

/// The kind of a file from its first bytes (4 KiB are enough), or None. `media`: ffmpeg is there for the video kinds.
pub fn kind(head: &[u8], zip_kind: impl FnOnce() -> Option<Kind>, media: bool) -> Option<Kind> {
    let at = |i: usize, m: &[u8]| head.len() >= i + m.len() && &head[i..i + m.len()] == m;
    if at(0, b"\xFF\xD8\xFF") {
        return Some(Kind::Jpeg);
    }
    if at(0, b"\x89PNG\r\n\x1a\n") {
        return Some(Kind::Png);
    }
    if at(0, b"RIFF") && at(8, b"WEBP") {
        return Some(Kind::Webp);
    }
    if at(0, b"RIFF") && at(8, b"WAVE") {
        return Some(Kind::Wav);
    }
    if at(0, b"II\x2A\0") || at(0, b"MM\0\x2A") {
        return Some(Kind::Tiff);
    }
    if at(4, b"ftyp")
        && matches!(head.get(8..12), Some(b"heic" | b"heix" | b"mif1" | b"msf1" | b"avif" | b"avis" | b"heim" | b"heis" | b"hevc"))
    {
        return Some(Kind::Heif);
    }
    if pdf_head(head) {
        return Some(Kind::Pdf);
    }
    if at(0, b"PK\x03\x04") {
        return zip_kind();
    }
    if at(0, b"fLaC") || at(0, b"ID3") && contains(head, b"fLaC") {
        return Some(Kind::Flac);
    }
    if at(0, b"ID3") || head.len() >= 2 && head[0] == 0xFF && head[1] & 0xE6 == 0xE2 {
        return Some(Kind::Mp3);
    }
    if media {
        return media::muxer(head).map(Kind::Media);
    }
    None
}

fn contains(h: &[u8], n: &[u8]) -> bool {
    h.windows(n.len()).any(|w| w == n)
}

fn pdf_head(h: &[u8]) -> bool {
    crate::pdf::find(&h[..h.len().min(1024)], 0, b"%PDF-").is_some()
}

/// A ZIP file's kind for cleaning.
pub fn zip_kind_of(src: &dyn crate::zip::Source) -> Option<Kind> {
    let a = crate::zip::read(src).ok()?;
    if a.find("[Content_Types].xml").is_some() {
        return Some(Kind::Office);
    }
    if let Some(m) = a.find("mimetype") {
        let mut b = 4096;
        if crate::zip::content(src, m, 256, &mut b).is_ok_and(|c| c.starts_with(b"application/vnd.oasis.opendocument")) {
            return Some(Kind::OpenDocument);
        }
    }
    Some(Kind::Zip)
}

/// Cleans bytes in memory (every kind but ffmpeg's).
pub fn clean(k: Kind, d: &[u8], r: &mut Removed) -> Result<Vec<u8>, String> {
    match k {
        Kind::Jpeg => image::jpeg(d, r),
        Kind::Png => image::png(d, r),
        Kind::Webp => image::webp(d, r),
        Kind::Heif => image::heif(d, r),
        Kind::Tiff => image::tiff(d, r),
        Kind::Pdf => doc::pdf(d, r),
        Kind::Office => doc::office(d, r),
        Kind::OpenDocument => doc::odf(d, r),
        Kind::Zip => doc::plain_zip(d, r),
        Kind::Mp3 => audio::mp3(d, r),
        Kind::Flac => audio::flac(d, r),
        Kind::Wav => audio::wav(d, r),
        Kind::Media(_) => Err("this kind needs ffmpeg".into()),
    }
}

/// The kind of a file on disk.
pub fn kind_of_path(p: &Path) -> std::io::Result<Option<Kind>> {
    let f = std::fs::File::open(p)?;
    if !f.metadata()?.is_file() {
        return Ok(None);
    }
    let mut head = vec![0u8; 4096];
    let n = read_full(&f, &mut head)?;
    head.truncate(n);
    Ok(kind(&head, || zip_kind_of(&f), media::available()))
}

fn read_full(mut f: &std::fs::File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match std::io::Read::read(&mut f, &mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

/// "name (clean).ext" beside the original, or "name (clean 2).ext", 3... when that is taken.
pub fn clean_path(original: &Path) -> PathBuf {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let dir = original.parent().unwrap_or(Path::new("."));
    let name = original.file_name().map(|n| n.as_bytes().to_vec()).unwrap_or_else(|| b"file".to_vec());
    let (stem, ext) = match name.iter().rposition(|&b| b == b'.') {
        Some(i) if i > 0 && i + 1 < name.len() => (name[..i].to_vec(), name[i..].to_vec()),
        _ => (name.clone(), vec![]),
    };
    (1..)
        .map(|n: u32| {
            let mut v = stem.clone();
            v.extend_from_slice(if n == 1 { b" (clean)".to_vec() } else { format!(" (clean {n})").into_bytes() }.as_slice());
            v.extend_from_slice(&ext);
            dir.join(std::ffi::OsString::from_vec(v))
        })
        .find(|p| p.symlink_metadata().is_err())
        .expect("unbounded")
}

/// The result of a run.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// The copy, or None when nothing hidden was found (then no copy is made).
    pub wrote: Option<PathBuf>,
    pub removed: Removed,
    pub kind: String,
}

/// A temporary name beside `out`, made only by us (O_EXCL), removed again on every error.
struct Temp(PathBuf);

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn temp_beside(out: &Path) -> std::io::Result<(Temp, std::fs::File)> {
    use std::os::unix::ffi::OsStrExt;
    let dir = out.parent().unwrap_or(Path::new("."));
    for k in 0..100u32 {
        let mut name = b".".to_vec();
        name.extend_from_slice(out.file_name().map(|n| n.as_bytes()).unwrap_or(b"copy"));
        name.extend_from_slice(format!(".heimdall-strip-{}-{k}", std::process::id()).as_bytes());
        let p = dir.join(std::ffi::OsStr::from_bytes(&name));
        match std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&p) {
            Ok(f) => return Ok((Temp(p), f)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other("no free temporary name"))
}

/// Puts the temporary file at `out` only if nothing is there (a hard link, which fails on an existing name; on a file
/// system without links, a rename after a last check).
fn place(tmp: &Temp, out: &Path, mode: u32) -> Result<(), String> {
    std::fs::set_permissions(&tmp.0, std::os::unix::fs::PermissionsExt::from_mode(mode)).map_err(|e| e.to_string())?;
    match std::fs::hard_link(&tmp.0, out) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(format!("{} exists; it is not replaced", out.display())),
        Err(_) => {
            if out.symlink_metadata().is_ok() {
                return Err(format!("{} exists; it is not replaced", out.display()));
            }
            std::fs::rename(&tmp.0, out).map_err(|e| e.to_string())
        }
    }
}

/// Cleans `input` into `out` (by default "name (clean).ext" beside it). `dry`: only say what would be removed.
pub fn run(input: &Path, out: Option<&Path>, dry: bool) -> Result<Outcome, String> {
    let meta = std::fs::metadata(input).map_err(|e| format!("{}: {e}", input.display()))?;
    if !meta.is_file() {
        return Err(format!("{} is not a file", input.display()));
    }
    let k = kind_of_path(input).map_err(|e| e.to_string())?.ok_or("this kind of file is not cleaned (or ffmpeg is missing for it)")?;
    let out = out.map(Path::to_path_buf).unwrap_or_else(|| clean_path(input));
    if !dry {
        if out.symlink_metadata().is_ok() {
            return Err(format!("{} exists; it is not replaced", out.display()));
        }
        if std::fs::canonicalize(out.parent().unwrap_or(Path::new("."))).ok().map(|d| d.join(out.file_name().unwrap_or_default()))
            == std::fs::canonicalize(input).ok()
        {
            return Err("the copy cannot be the original".into());
        }
    }
    let mode = std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o666;
    let mut removed = vec![];
    if let Kind::Media(fmt) = k {
        if dry {
            media::describe(input, &mut removed)?;
            return Ok(Outcome { wrote: None, removed, kind: k.id().into() });
        }
        let (tmp, f) = temp_beside(&out).map_err(|e| e.to_string())?;
        drop(f);
        std::fs::remove_file(&tmp.0).map_err(|e| e.to_string())?; // ffmpeg makes it itself (-n)
        media::strip(input, &tmp.0, fmt, &mut removed)?;
        if removed.is_empty() {
            return Ok(Outcome { wrote: None, removed, kind: k.id().into() });
        }
        place(&tmp, &out, mode)?;
        return Ok(Outcome { wrote: Some(out), removed, kind: k.id().into() });
    }
    if meta.len() > MAX_IN_MEMORY {
        return Err("the file is too big to clean (more than 1 GiB)".into());
    }
    let data = std::fs::read(input).map_err(|e| e.to_string())?;
    let cleaned = clean(k, &data, &mut removed)?;
    if dry || removed.is_empty() {
        return Ok(Outcome { wrote: None, removed, kind: k.id().into() });
    }
    if k == Kind::Pdf {
        verify_pdf(&cleaned)?;
    }
    let (tmp, mut f) = temp_beside(&out).map_err(|e| e.to_string())?;
    f.write_all(&cleaned).and_then(|_| f.sync_all()).map_err(|e| e.to_string())?;
    drop(f);
    place(&tmp, &out, mode)?;
    Ok(Outcome { wrote: Some(out), removed, kind: k.id().into() })
}

/// A cleaned PDF must read back: our own scan finds its catalogue, and poppler's pdfinfo (when installed) opens it.
fn verify_pdf(d: &[u8]) -> Result<(), String> {
    let doc = crate::pdf::Doc::scan(d);
    if doc.trailer_ref(b"Root").is_none_or(|r| !doc.objs.contains_key(&r)) {
        return Err("the cleaned PDF did not read back; no copy was made".into());
    }
    let Some(tool) = std::env::var_os("PATH").and_then(|p| std::env::split_paths(&p).map(|d| d.join("pdfinfo")).find(|p| p.is_file()))
    else {
        return Ok(());
    };
    let dir = std::env::temp_dir().join(format!("heimdall-strip-check-{}", std::process::id()));
    if std::fs::create_dir(&dir).is_err() {
        return Ok(()); // our own check passed; pdfinfo is a second opinion only
    }
    let p = dir.join("check.pdf");
    let res = std::fs::write(&p, d).map_err(|e| e.to_string()).and_then(|_| {
        std::process::Command::new(tool)
            .arg(&p)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|e| e.to_string())
    });
    let _ = std::fs::remove_dir_all(&dir);
    match res {
        Ok(s) if s.success() => Ok(()),
        Ok(_) => Err("the cleaned PDF did not open in pdfinfo; no copy was made".into()),
        Err(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests;
