//! Go's `path/filepath` and the `os` calls the one-shot commands lean on, with Go's results and error texts: `Clean`, `Dir`,
//! `Base`, `Join`, `os.MkdirAll`, `os.WriteFile`, `os.ReadFile`.

use crate::goerr;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::OpenOptionsExt;

/// Go's `filepath.Clean`: the shortest lexically equal path.
pub fn clean(p: &str) -> String {
    if p.is_empty() {
        return ".".into();
    }
    let rooted = p.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|l| *l != "..") {
                    parts.pop();
                } else if !rooted {
                    parts.push("..");
                }
            }
            s => parts.push(s),
        }
    }
    let joined = parts.join("/");
    match (rooted, joined.is_empty()) {
        (true, _) => format!("/{joined}"),
        (false, true) => ".".into(),
        (false, false) => joined,
    }
}

/// Go's `filepath.Dir`: everything before the last slash, cleaned.
pub fn dir(p: &str) -> String {
    match p.rfind('/') {
        Some(i) => clean(&p[..=i]),
        None => clean(""),
    }
}

/// Go's `filepath.Base`.
pub fn base(p: &str) -> String {
    if p.is_empty() {
        return ".".into();
    }
    let t = p.trim_end_matches('/');
    if t.is_empty() {
        return "/".into();
    }
    match t.rfind('/') {
        Some(i) => t[i + 1..].to_string(),
        None => t.to_string(),
    }
}

/// Go's `filepath.Join`: the non-empty parts joined and cleaned.
pub fn join(parts: &[&str]) -> String {
    let kept: Vec<&str> = parts.iter().copied().filter(|s| !s.is_empty()).collect();
    if kept.is_empty() {
        return String::new();
    }
    clean(&kept.join("/"))
}

/// Go's `os.Getwd`: $PWD when it names the current folder (Go's "clumsy but widespread kludge"), else the kernel's answer.
pub fn getwd() -> Result<String, String> {
    use std::os::unix::fs::MetadataExt;
    if let Ok(pwd) = std::env::var("PWD") {
        if pwd.starts_with('/') {
            let dot = std::fs::metadata(".").map_err(|e| goerr::path("stat", ".", &e))?;
            if let Ok(d) = std::fs::metadata(&pwd) {
                if d.dev() == dot.dev() && d.ino() == dot.ino() {
                    return Ok(pwd);
                }
            }
        }
    }
    std::env::current_dir().map(|p| p.to_string_lossy().into_owned()).map_err(|e| goerr::syscall("getwd", &e))
}

/// Go's `filepath.Abs`: an absolute path cleaned, a relative one joined to the current folder.
pub fn abs(p: &str) -> Result<String, String> {
    if p.starts_with('/') {
        return Ok(clean(p));
    }
    Ok(join(&[&getwd()?, p]))
}

/// Go's `os.MkdirAll(path, perm)`, errors included ("mkdir /a: permission denied", ENOTDIR for a file in the way).
pub fn mkdir_all(path: &str, perm: u32) -> Result<(), String> {
    match std::fs::metadata(path) {
        Ok(m) if m.is_dir() => return Ok(()),
        Ok(_) => return Err(goerr::path("mkdir", path, &std::io::Error::from_raw_os_error(libc::ENOTDIR))),
        Err(_) => {}
    }
    let b = path.as_bytes();
    let mut i = b.len() as isize - 1;
    while i >= 0 && b[i as usize] == b'/' {
        i -= 1;
    }
    while i >= 0 && b[i as usize] != b'/' {
        i -= 1;
    }
    let i = i.max(0) as usize;
    let parent = &path[..i];
    if !parent.is_empty() {
        mkdir_all(parent, perm)?;
    }
    if let Err(e) = std::fs::DirBuilder::new().mode(perm).create(path) {
        if std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()) {
            return Ok(());
        }
        return Err(goerr::path("mkdir", path, &e));
    }
    Ok(())
}

/// Go's `os.ReadFile`.
pub fn read_file(path: &str) -> Result<Vec<u8>, std::io::Error> {
    std::fs::read(path)
}

/// Go's `os.ReadFile` error text for `e` ("open PATH: no such file or directory"; a read error is "read PATH: ...").
pub fn read_err(path: &str, e: &std::io::Error) -> String {
    if e.raw_os_error() == Some(libc::EISDIR) {
        return goerr::path("read", path, e);
    }
    goerr::path("open", path, e)
}

/// Go's `os.WriteFile(path, data, perm)`: created with perm (before the umask) or truncated, never chmod-ed when it exists.
pub fn write_file(path: &str, data: &[u8], perm: u32) -> Result<(), String> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(perm)
        .open(path)
        .map_err(|e| goerr::path("open", path, &e))?;
    f.write_all(data).map_err(|e| goerr::path("write", path, &e))
}

/// Go's `os.Rename` error text.
pub fn rename(from: &str, to: &str) -> Result<(), String> {
    std::fs::rename(from, to).map_err(|e| goerr::link("rename", from, to, &e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_go() {
        for (p, c) in [("", "."), ("/", "/"), ("a/../..", ".."), ("/../a", "/a"), ("a//b/./c/", "a/b/c"), ("./", "."), ("/a/b/..", "/a")] {
            assert_eq!(clean(p), c, "{p}");
        }
        for (p, d) in [("", "."), ("/a", "/"), ("a", "."), ("/a/b/", "/a/b"), ("a/b", "a"), ("//x", "/")] {
            assert_eq!(dir(p), d, "{p}");
        }
        for (p, b) in [("", "."), ("/", "/"), ("/a/b/", "b"), ("a", "a")] {
            assert_eq!(base(p), b, "{p}");
        }
        assert_eq!(join(&["/var/lib", "", "x/../y"]), "/var/lib/y");
        assert_eq!(join(&["", ""]), "");
    }
}
