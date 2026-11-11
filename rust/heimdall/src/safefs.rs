//! How Heimdall, running as root, touches files in places other users can write (Go: internal/safefs): never through a link,
//! and a user's files only as that user (heimdalld started again as them, the hidden `__write-as-owner` command). Trust's
//! restore and immunity's hold and release go through it. The error texts are Go's.
//!
//! One difference from Go, on purpose: the child started as the file's owner has no supplementary groups (Rust's
//! `Command::uid` drops root's), where Go's `NoSetGroups` let it keep root's. The file written is the same (its owner and
//! group come from the user and group given); the child only has fewer rights while it writes.

use crate::goerr;
use rustix::fs::{Mode, OFlags, ResolveFlags, CWD};
use std::fs::File as StdFile;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

/// The hidden command that does a write already running as the file's owner (`write_as`).
pub const CHILD_COMMAND: &str = "__write-as-owner";

fn dir_of(p: &str) -> String {
    crate::gopath::dir(p)
}

/// Opens `path` refusing a link anywhere on it (openat2 with RESOLVE_NO_SYMLINKS and RESOLVE_NO_MAGICLINKS). On a kernel
/// without openat2 it falls back to O_NOFOLLOW on the last part and a check of every folder on the way.
pub fn open_no_links(path: &str, flags: OFlags, mode: u32) -> Result<StdFile, String> {
    let how = ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS;
    match rustix::fs::openat2(CWD, path, flags | OFlags::CLOEXEC, Mode::from_raw_mode(mode & 0o777), how) {
        Ok(fd) => Ok(StdFile::from(fd)),
        Err(e) if e == rustix::io::Errno::NOSYS => {
            no_links_above(&dir_of(path))?;
            rustix::fs::openat(CWD, path, flags | OFlags::CLOEXEC | OFlags::NOFOLLOW, Mode::from_raw_mode(mode & 0o777))
                .map(StdFile::from)
                .map_err(|e| goerr::path("open", path, &e.into()))
        }
        Err(e) => Err(goerr::path("open", path, &e.into())),
    }
}

/// Refuses a folder path that includes a link.
pub fn no_links_above(dir: &str) -> Result<(), String> {
    let mut d = crate::gopath::clean(dir);
    loop {
        match std::fs::symlink_metadata(&d) {
            Ok(m) if m.file_type().is_symlink() => return Err(format!("{d} is a link: not going through it")),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(goerr::path("lstat", &d, &e)),
        }
        if d == "/" || d == "." {
            return Ok(());
        }
        d = dir_of(&d);
    }
}

/// The owner of the closest folder above `path` that exists, looked at without following links; a link anywhere on the
/// way is refused.
pub fn owner_of(path: &str) -> Result<(u32, u32), String> {
    let mut dir = dir_of(&crate::gopath::clean(path));
    loop {
        match std::fs::symlink_metadata(&dir) {
            Ok(m) => {
                if m.file_type().is_symlink() {
                    return Err(format!("{dir} is a link: not going through it"));
                }
                if !m.is_dir() {
                    return Err(format!("{dir} is not a folder"));
                }
                no_links_above(&dir)?;
                return Ok((m.uid(), m.gid()));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(goerr::path("lstat", &dir, &e)),
        }
        let parent = dir_of(&dir);
        if parent == dir {
            return Err(format!("no existing folder above {path}"));
        }
        dir = parent;
    }
}

/// Why root may not write into `dir`: every existing folder from / down to it must be root's, not a link, and writable by
/// nobody else, or a user could swap something in on the way.
pub fn root_only(dir: &str) -> Result<(), String> {
    let mut d = crate::gopath::clean(dir);
    loop {
        match std::fs::symlink_metadata(&d) {
            Ok(m) => {
                if !m.is_dir() || m.file_type().is_symlink() || m.uid() != 0 || m.permissions().mode() & 0o022 != 0 {
                    return Err(format!("{d} is not a root-only folder: not writing there as root"));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(goerr::path("lstat", &d, &e)),
        }
        if d == "/" {
            return Ok(());
        }
        d = dir_of(&d);
    }
}

/// What to write: the bytes, the mode, an optional modification time, and whether an existing file may be replaced.
#[derive(Clone, Debug, Default)]
pub struct File {
    pub data: Vec<u8>,
    pub mode: u32,
    /// Nanoseconds since the Unix epoch; None: now.
    pub mtime: Option<i64>,
    /// Never replace a file (or link) already there.
    pub exclusive: bool,
}

/// Writes `path` as uid/gid: this program started again with that user and group (the kernel drops root before it runs).
pub fn write_as(path: &str, f: &File, uid: u32, gid: u32) -> Result<(), String> {
    use std::os::unix::process::CommandExt;
    let exe = std::env::current_exe().map_err(|e| goerr::text(&e))?;
    let mt = f.mtime.unwrap_or(0);
    let mut cmd = std::process::Command::new(&exe);
    cmd.args([CHILD_COMMAND, path, &format!("{:o}", f.mode & 0o777), &mt.to_string(), &f.exclusive.to_string()])
        .uid(uid)
        .gid(gid)
        .env_clear()
        .env("PATH", "/usr/bin")
        .current_dir("/")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    // Go: "writing PATH as uid N: fork/exec EXE: ERR " (the output, empty here, after the space)
    let mut child = cmd.spawn().map_err(|e| format!("writing {path} as uid {uid}: fork/exec {}: {} ", exe.display(), goerr::text(&e)))?;
    if let Some(mut stdin) = child.stdin.take() {
        let data = f.data.clone();
        std::thread::spawn(move || {
            let _ = stdin.write_all(&data);
        });
    }
    let out = child.wait_with_output().map_err(|e| goerr::text(&e))?;
    if !out.status.success() {
        // Go's CombinedOutput: both streams, in the order written; the child writes only to standard error
        let mut both = out.stdout.clone();
        both.extend_from_slice(&out.stderr);
        let status = match out.status.code() {
            Some(c) => format!("exit status {c}"),
            None => {
                use std::os::unix::process::ExitStatusExt;
                format!("signal: {}", signal_name(out.status.signal().unwrap_or(0)))
            }
        };
        return Err(format!("writing {path} as uid {uid}: {status} {}", crate::gotext::trim_space(&crate::gotext::lossy(&both))));
    }
    Ok(())
}

/// Go's names for the signals a child may die of (`syscall.Signal.String`).
fn signal_name(s: i32) -> String {
    match s {
        1 => "hangup".into(),
        2 => "interrupt".into(),
        6 => "aborted".into(),
        9 => "killed".into(),
        11 => "segmentation fault".into(),
        13 => "broken pipe".into(),
        15 => "terminated".into(),
        n => format!("signal {n}"),
    }
}

/// The child's side of `write_as` (args: path, octal mode, mtime in ns or 0, exclusive): it runs as the owner already.
pub fn child(args: &[String]) -> Result<(), String> {
    if args.len() != 4 {
        return Err(format!("usage: {CHILD_COMMAND} PATH MODE MTIME EXCLUSIVE"));
    }
    let mode = u32::from_str_radix(&args[1], 8).ok().filter(|_| !args[1].is_empty() && !args[1].starts_with(['+', '-']));
    let mt = crate::gotext::atoi(&args[2]);
    let excl = crate::cli::goflag::parse_bool(&args[3]);
    let (Some(mode), Some(mt), Some(excl)) = (mode, mt, excl) else {
        return Err("bad arguments".into());
    };
    let mut data = Vec::new();
    std::io::stdin().lock().take(256 << 20).read_to_end(&mut data).map_err(|e| goerr::path("read", "/dev/stdin", &e))?;
    write(&args[0], &File { data, mode, mtime: (mt != 0).then_some(mt), exclusive: excl })
}

/// Puts `f` at `path` from the current user's rights: folders made as needed, never through a link, through a temporary
/// file and a rename (or, exclusive, straight into a new file).
pub fn write(path: &str, f: &File) -> Result<(), String> {
    let dir = dir_of(path);
    crate::gopath::mkdir_all(&dir, 0o755)?;
    no_links_above(&dir)?;
    let target = if f.exclusive { path.to_string() } else { format!("{path}.heimdall-tmp") };
    if !f.exclusive {
        let _ = std::fs::remove_file(&target);
    }
    let mut out = open_no_links(&target, OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL, f.mode)?;
    let mut werr = out.write_all(&f.data).err().map(|e| goerr::path("write", &target, &e));
    if werr.is_none() {
        werr = out.set_permissions(std::fs::Permissions::from_mode(f.mode & 0o777)).err().map(|e| goerr::path("chmod", &target, &e));
    }
    if werr.is_none() {
        if let Some(mt) = f.mtime {
            let t = std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_nanos(mt.max(0) as u64)).unwrap_or(std::time::UNIX_EPOCH);
            let times = std::fs::FileTimes::new().set_accessed(t).set_modified(t);
            werr = out.set_times(times).err().map(|e| goerr::path("chtimes", &target, &e));
        }
    }
    drop(out);
    if let Some(e) = werr {
        let _ = std::fs::remove_file(&target);
        return Err(e);
    }
    if !f.exclusive {
        return std::fs::rename(&target, path).map_err(|e| goerr::link("rename", &target, path, &e));
    }
    Ok(())
}

/// Writes `path` as the owner of its folder, or as root only inside root-only folders.
pub fn put(path: &str, f: &File) -> Result<(), String> {
    let (uid, gid) = owner_of(path)?;
    put_as(path, f, uid, gid)
}

/// Writes `path` as uid/gid; as root (uid 0) only inside root-only folders.
pub fn put_as(path: &str, f: &File, uid: u32, gid: u32) -> Result<(), String> {
    if uid != 0 {
        return write_as(path, f, uid, gid);
    }
    root_only(&dir_of(path))?;
    write(path, f)
}

/// The modification time of a file in nanoseconds, as Go's `fi.ModTime().UnixNano()`.
pub fn mtime_nanos(m: &std::fs::Metadata) -> i64 {
    m.mtime() * 1_000_000_000 + m.mtime_nsec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> String {
        let d = std::env::temp_dir().join(format!("heimdall-safefs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().into_owned()
    }

    #[test]
    fn writes_never_through_a_link() {
        let d = tmp("links");
        std::fs::create_dir(format!("{d}/real")).unwrap();
        std::os::unix::fs::symlink(format!("{d}/real"), format!("{d}/link")).unwrap();
        let f = File { data: b"hi".to_vec(), mode: 0o640, mtime: Some(1_700_000_000_123_456_789), exclusive: false };
        assert_eq!(write(&format!("{d}/link/x"), &f), Err(format!("{d}/link is a link: not going through it")));
        write(&format!("{d}/real/sub/x"), &f).unwrap();
        let m = std::fs::metadata(format!("{d}/real/sub/x")).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0o640);
        assert_eq!(mtime_nanos(&m), 1_700_000_000_123_456_789);
        // exclusive: never replaces
        let ex = File { exclusive: true, ..f.clone() };
        assert!(write(&format!("{d}/real/sub/x"), &ex).unwrap_err().starts_with(&format!("open {d}/real/sub/x: file exists")));
        std::os::unix::fs::symlink("/etc/passwd", format!("{d}/real/l")).unwrap();
        assert!(write(&format!("{d}/real/l"), &ex).is_err());
        assert_eq!(std::fs::read(format!("{d}/real/sub/x")).unwrap(), b"hi");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn owners_and_root_only_folders() {
        let d = tmp("owner");
        let me = std::fs::metadata(&d).unwrap();
        assert_eq!(owner_of(&format!("{d}/a/b/c")), Ok((me.uid(), me.gid())));
        if me.uid() != 0 {
            assert!(root_only(&d).unwrap_err().ends_with("is not a root-only folder: not writing there as root"));
        }
        assert_eq!(root_only("/usr"), Ok(()));
        assert_eq!(child(&["a".into()]), Err("usage: __write-as-owner PATH MODE MTIME EXCLUSIVE".into()));
        assert_eq!(child(&["/x".into(), "9".into(), "0".into(), "false".into()]), Err("bad arguments".into()));
        std::fs::remove_dir_all(&d).unwrap();
    }
}
