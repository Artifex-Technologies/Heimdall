//! The few coreutils and findutils steps the shell programs took (`mkdir -p`, `mktemp -d`, `mv -f`, `rm -rf`, `find -mtime`,
//! `sort -u`, `wc -l`, `tail -n`), with GNU's results and its error lines in the C locale (the scripts set `LC_ALL=C`, so
//! their words do not depend on the system language).

use std::ffi::OsStr;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

/// A line on standard output; a write error is ignored, as the shell's `echo` goes on after one.
pub fn say(s: &str) {
    let mut o = std::io::stdout().lock();
    let _ = o.write_all(s.as_bytes());
    let _ = o.write_all(b"\n");
    let _ = o.flush();
}

/// A line on standard error.
pub fn warn(s: &str) {
    let _ = std::io::stderr().write_all(format!("{s}\n").as_bytes());
}

/// The C library's words for an error (`strerror`), as the tools print them.
pub fn strerror(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(n) => {
            let s = std::io::Error::from_raw_os_error(n).to_string();
            match s.rfind(" (os error ") {
                Some(i) => s[..i].to_string(),
                None => s,
            }
        }
        None => e.to_string(),
    }
}

/// A file name as coreutils' `quote` writes it in the C locale: in single quotes, a quote or backslash inside escaped, a
/// control character as its C escape.
pub fn quote(p: &OsStr) -> String {
    let mut s = String::from("'");
    for &b in p.as_bytes() {
        match b {
            b'\'' => s.push_str("\\'"),
            b'\\' => s.push_str("\\\\"),
            b'\n' => s.push_str("\\n"),
            b'\t' => s.push_str("\\t"),
            b'\r' => s.push_str("\\r"),
            0x07 => s.push_str("\\a"),
            0x08 => s.push_str("\\b"),
            0x0b => s.push_str("\\v"),
            0x0c => s.push_str("\\f"),
            b if !(0x20..0x7f).contains(&b) => s.push_str(&format!("\\{b:03o}")),
            b => s.push(b as char),
        }
    }
    s.push('\'');
    s
}

/// A file name as `mv` writes it (coreutils' `quoteaf`, shell-escape quoting): in single quotes, a quote inside as `'\''`;
/// with a control character or a byte that is not ASCII, the `$'...'` form.
pub fn quoteaf(p: &OsStr) -> String {
    let b = p.as_bytes();
    if b.iter().any(|c| !(0x20..0x7f).contains(c)) {
        let mut s = String::from("'");
        let mut quoted = true;
        for &c in b {
            if !(0x20..0x7f).contains(&c) {
                if quoted {
                    s.push_str("'$'");
                    quoted = false;
                }
                match c {
                    b'\n' => s.push_str("\\n"),
                    b'\t' => s.push_str("\\t"),
                    b'\r' => s.push_str("\\r"),
                    c => s.push_str(&format!("\\{c:03o}")),
                }
            } else {
                if !quoted {
                    s.push_str("''");
                    quoted = true;
                }
                if c == b'\'' {
                    s.push_str("'\\''");
                } else {
                    s.push(c as char);
                }
            }
        }
        s.push('\'');
        return s.replace("''$'", "$'");
    }
    format!("'{}'", String::from_utf8_lossy(b).replace('\'', "'\\''"))
}

/// `mkdir -p PATH` (the mode of new folders: 0777 less the umask): each folder on the way made unless it is one already. The
/// error is mkdir's line, naming the folder that could not be made.
pub fn mkdir_p(path: &Path) -> Result<(), String> {
    let fail = |p: &Path, e: &std::io::Error| format!("mkdir: cannot create directory {}: {}", quote(p.as_os_str()), strerror(e));
    let b = path.as_os_str().as_bytes();
    if b.is_empty() {
        return Err(fail(path, &std::io::Error::from_raw_os_error(libc::ENOENT)));
    }
    // the folders on the way: every prefix ending before a slash (repeated slashes once)
    let mut ends = Vec::new();
    for i in 1..b.len() {
        if b[i] == b'/' && b[i - 1] != b'/' {
            ends.push(i);
        }
    }
    for &e in &ends {
        let p = Path::new(OsStr::from_bytes(&b[..e]));
        match std::fs::DirBuilder::new().mode(0o777).create(p) {
            Ok(()) => {}
            Err(err) if err.raw_os_error() == Some(libc::EEXIST) => {
                if !std::fs::metadata(p).is_ok_and(|m| m.is_dir()) {
                    return Err(fail(p, &std::io::Error::from_raw_os_error(libc::ENOTDIR)));
                }
            }
            Err(err) => return Err(fail(p, &err)),
        }
    }
    match std::fs::DirBuilder::new().mode(0o777).create(path) {
        Ok(()) => Ok(()),
        Err(err) if err.raw_os_error() == Some(libc::EEXIST) => {
            if std::fs::metadata(path).is_ok_and(|m| m.is_dir()) {
                Ok(())
            } else {
                Err(fail(path, &err))
            }
        }
        Err(err) => Err(fail(path, &err)),
    }
}

/// `mktemp -d DIR/.update.XXXXXX`: a new folder only this user may enter (0700), six random letters and digits in its name.
pub fn mktemp_d(dir: &Path) -> Result<PathBuf, String> {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let template = dir.join(".update.XXXXXX");
    let mut last = std::io::Error::from_raw_os_error(libc::EEXIST);
    for _ in 0..1000 {
        let mut r = [0u8; 6];
        if ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut r).is_err() {
            break;
        }
        let name: String = r.iter().map(|&x| CHARS[x as usize % CHARS.len()] as char).collect();
        let p = dir.join(format!(".update.{name}"));
        match std::fs::DirBuilder::new().mode(0o700).create(&p) {
            Ok(()) => return Ok(p),
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => last = e,
            Err(e) => {
                last = e;
                break;
            }
        }
    }
    Err(format!("mktemp: failed to create directory via template {}: {}", quote(template.as_os_str()), strerror(&last)))
}

/// `mv -f SRC DST` within one file system: into DST when it is a folder (or a link to one), over a file of that name. The
/// error is mv's line.
pub fn mv_f(src: &Path, dst: &Path) -> Result<(), String> {
    if let Err(e) = std::fs::symlink_metadata(src) {
        return Err(format!("mv: cannot stat {}: {}", quoteaf(src.as_os_str()), strerror(&e)));
    }
    let target = if std::fs::metadata(dst).is_ok_and(|m| m.is_dir()) {
        match src.file_name() {
            Some(n) => dst.join(n),
            None => dst.to_path_buf(),
        }
    } else {
        dst.to_path_buf()
    };
    let src_dir = std::fs::symlink_metadata(src).is_ok_and(|m| m.is_dir());
    if !src_dir && std::fs::symlink_metadata(&target).is_ok_and(|m| m.is_dir()) {
        return Err(format!(
            "mv: cannot overwrite directory {} with non-directory {}",
            quoteaf(target.as_os_str()),
            quoteaf(src.as_os_str())
        ));
    }
    std::fs::rename(src, &target)
        .map_err(|e| format!("mv: cannot move {} to {}: {}", quoteaf(src.as_os_str()), quoteaf(target.as_os_str()), strerror(&e)))
}

/// `cp SRC DST` (no options): into DST when it is a folder; an existing file is overwritten in place (its mode and owner
/// kept, a link followed), a new one made with SRC's mode less the umask. The error is cp's line.
pub fn cp(src: &Path, dst: &Path) -> Result<(), String> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let meta = std::fs::metadata(src).map_err(|e| format!("cp: cannot stat {}: {}", quoteaf(src.as_os_str()), strerror(&e)))?;
    let target = if std::fs::metadata(dst).is_ok_and(|m| m.is_dir()) {
        match src.file_name() {
            Some(n) => dst.join(n),
            None => dst.to_path_buf(),
        }
    } else {
        dst.to_path_buf()
    };
    let data = std::fs::read(src).map_err(|e| format!("cp: cannot open {} for reading: {}", quoteaf(src.as_os_str()), strerror(&e)))?;
    let exists = std::fs::metadata(&target).is_ok();
    let mut o = std::fs::OpenOptions::new();
    o.write(true);
    if exists {
        o.truncate(true);
    } else {
        o.create_new(true).mode(meta.permissions().mode() & 0o777);
    }
    let mut f = o.open(&target).map_err(|e| format!("cp: cannot create regular file {}: {}", quoteaf(target.as_os_str()), strerror(&e)))?;
    f.write_all(&data).map_err(|e| format!("cp: error writing {}: {}", quoteaf(target.as_os_str()), strerror(&e)))
}

/// `rm -rf PATH`, quietly.
pub fn rm_rf(p: &Path) {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => {
            let _ = std::fs::remove_dir_all(p);
        }
        Ok(_) => {
            let _ = std::fs::remove_file(p);
        }
        Err(_) => {}
    }
}

/// `find DIR -maxdepth 1 -name PATTERN -mtime -DAYS`: whether anything matched (DIR itself included, as find tests the
/// starting point too). `name` decides on a file name; `-mtime -N` is "modified less than N whole days ago" (a time in the
/// future counts), measured from now; links are not followed.
pub fn find_fresh(dir: &Path, name: impl Fn(&[u8]) -> bool, days: i64) -> bool {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
    let fresh = |m: &std::fs::Metadata| (now - m.mtime()).div_euclid(86400) < days;
    let Ok(top) = std::fs::symlink_metadata(dir) else { return false };
    let own = dir.as_os_str().as_bytes();
    let trimmed = {
        let mut t = own;
        while t.len() > 1 && t.ends_with(b"/") {
            t = &t[..t.len() - 1];
        }
        t
    };
    let base = match trimmed.iter().rposition(|&c| c == b'/') {
        Some(i) if trimmed.len() > 1 => &trimmed[i + 1..],
        _ => trimmed,
    };
    if name(base) && fresh(&top) {
        return true;
    }
    if !top.is_dir() {
        return false;
    }
    let Ok(rd) = std::fs::read_dir(dir) else { return false };
    for e in rd.flatten() {
        if name(e.file_name().as_bytes()) {
            if let Ok(m) = e.path().symlink_metadata() {
                if fresh(&m) {
                    return true;
                }
            }
        }
    }
    false
}

/// The lines of a text as `sort` and `wc` see them: split at each newline, a last line without one still a line.
pub fn lines(b: &[u8]) -> Vec<&[u8]> {
    let mut out: Vec<&[u8]> = b.split(|&c| c == b'\n').collect();
    if b.is_empty() || b.ends_with(b"\n") {
        out.pop();
    }
    out
}

/// `sort -u` in the C locale: the lines in byte order, each once, every one ending with a newline.
pub fn sort_u(b: &[u8]) -> Vec<u8> {
    let mut l = lines(b);
    l.sort_unstable();
    l.dedup();
    let mut out = Vec::with_capacity(b.len() + 1);
    for x in l {
        out.extend_from_slice(x);
        out.push(b'\n');
    }
    out
}

/// `wc -l`: the newlines.
pub fn wc_l(b: &[u8]) -> usize {
    b.iter().filter(|&&c| c == b'\n').count()
}

/// `tail -n N`: the last N lines (a last line without a newline counts).
pub fn tail_n(b: &[u8], n: usize) -> &[u8] {
    if n == 0 {
        return &b[b.len()..];
    }
    let mut end = b.len();
    if b.ends_with(b"\n") {
        end -= 1;
    }
    let mut seen = 0;
    let mut i = end;
    while i > 0 {
        if b[i - 1] == b'\n' {
            seen += 1;
            if seen == n {
                return &b[i..];
            }
        }
        i -= 1;
    }
    b
}

/// A shell command substitution's text: the output with every newline at its end removed.
pub fn subst(b: &[u8]) -> &[u8] {
    let mut e = b.len();
    while e > 0 && b[e - 1] == b'\n' {
        e -= 1;
    }
    &b[..e]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_as_coreutils() {
        assert_eq!(quote(OsStr::new("ro/a b")), "'ro/a b'");
        assert_eq!(quote(OsStr::new("it's")), "'it\\'s'");
        assert_eq!(quoteaf(OsStr::new("f1")), "'f1'");
        assert_eq!(quoteaf(OsStr::new("it's")), "'it'\\''s'");
    }

    #[test]
    fn lines_tail_sort() {
        assert_eq!(wc_l(b"a\nb"), 1);
        assert_eq!(lines(b"a\nb"), vec![&b"a"[..], b"b"]);
        assert_eq!(sort_u(b"b\na\nb"), b"a\nb\n");
        assert_eq!(sort_u(b""), b"");
        assert_eq!(tail_n(b"1\n2\n3\n", 2), b"2\n3\n");
        assert_eq!(tail_n(b"1\n2\n3", 2), b"2\n3");
        assert_eq!(tail_n(b"1\n", 5), b"1\n");
        assert_eq!(subst(b"x\n\n"), b"x");
    }
}
