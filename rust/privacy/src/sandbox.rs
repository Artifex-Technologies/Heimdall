//! The sandbox the extraction runs in: a process of its own (`heimdall-fileguard extract-worker`, started by `extract` and by
//! `scan` for an archive) that has opened the archive before it shuts itself in. Chosen over bubblewrap because it needs
//! nothing installed and costs no extra process: Landlock is in the kernel (Linux 5.13 and later; Arch and the Raspberry Pi
//! kernels have it) and is a few system calls.
//!
//! - **Landlock**: it may write only inside the output folder (create files and folders there, nothing else: no links, no
//!   devices), read and run only what is under /usr (the system's xz, zstd and bzip2), and nothing else at all: not the home
//!   folder, not /etc. Where the kernel's Landlock knows networks (version 4, Linux 6.7) TCP is shut too; version 6 also stops
//!   it from signalling other processes or reaching abstract sockets.
//! - **No network**: a new user and network namespace when the kernel allows it (an empty one, not even loopback).
//! - **Limits** (set by the parent before the program starts): 1 GiB of address space, 120 s of processor time, files no
//!   bigger than the per-file limit (the kernel itself refuses the write), 64 open files, no core dump; the parent kills it
//!   after 300 s of wall time.
//!
//! Without Landlock (an old kernel, or one built without it) the extraction still runs under the limits and the namespace,
//! and says so on standard error.

use std::os::unix::ffi::OsStrExt;
use std::path::Path;

const CREATE_RULESET_VERSION: u32 = 1;
const RULE_PATH_BENEATH: libc::c_int = 1;

const FS_EXECUTE: u64 = 1 << 0;
const FS_WRITE_FILE: u64 = 1 << 1;
const FS_READ_FILE: u64 = 1 << 2;
const FS_READ_DIR: u64 = 1 << 3;
const FS_REMOVE_DIR: u64 = 1 << 4;
const FS_REMOVE_FILE: u64 = 1 << 5;
const FS_MAKE_DIR: u64 = 1 << 7;
const FS_MAKE_REG: u64 = 1 << 8;
const FS_TRUNCATE: u64 = 1 << 14;
/// Everything version 1 knows (execute ... make symlink).
const FS_V1: u64 = (1 << 13) - 1;
const FS_REFER: u64 = 1 << 13;
const FS_IOCTL_DEV: u64 = 1 << 15;
const NET_BIND_TCP: u64 = 1 << 0;
const NET_CONNECT_TCP: u64 = 1 << 1;
const SCOPE_ABSTRACT_UNIX: u64 = 1 << 0;
const SCOPE_SIGNAL: u64 = 1 << 1;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C, packed)]
struct PathBeneath {
    allowed_access: u64,
    parent_fd: i32,
}

/// What the sandbox could do here.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// The Landlock version in force (0: none).
    pub landlock: i32,
    /// A network namespace of its own.
    pub no_network: bool,
}

fn open_path(p: &Path) -> Option<i32> {
    let c = std::ffi::CString::new(p.as_os_str().as_bytes()).ok()?;
    // SAFETY: a valid C string
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    (fd >= 0).then_some(fd)
}

/// Shuts this process in: writes only in `write_dir` (when given), reads and runs only /usr. Call it after every file the
/// process needs is open.
pub fn confine(write_dir: Option<&Path>) -> Report {
    let mut rep = Report::default();
    // SAFETY: plain system calls on our own process
    unsafe {
        if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) == 0 {
            rep.no_network = true;
        }
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        let abi = libc::syscall(libc::SYS_landlock_create_ruleset, std::ptr::null::<RulesetAttr>(), 0usize, CREATE_RULESET_VERSION) as i32;
        if abi < 1 {
            return rep;
        }
        let mut fs = FS_V1;
        if abi >= 2 {
            fs |= FS_REFER;
        }
        if abi >= 3 {
            fs |= FS_TRUNCATE;
        }
        if abi >= 5 {
            fs |= FS_IOCTL_DEV;
        }
        let attr = RulesetAttr {
            handled_access_fs: fs,
            handled_access_net: if abi >= 4 { NET_BIND_TCP | NET_CONNECT_TCP } else { 0 },
            scoped: if abi >= 6 { SCOPE_ABSTRACT_UNIX | SCOPE_SIGNAL } else { 0 },
        };
        let size = if abi >= 6 {
            24
        } else if abi >= 4 {
            16
        } else {
            8
        };
        let rs = libc::syscall(libc::SYS_landlock_create_ruleset, &attr as *const RulesetAttr, size as usize, 0u32) as i32;
        if rs < 0 {
            return rep;
        }
        let mut rules: Vec<(&Path, u64)> = vec![(Path::new("/usr"), FS_EXECUTE | FS_READ_FILE | FS_READ_DIR)];
        if let Some(w) = write_dir {
            let mut a = FS_WRITE_FILE | FS_READ_FILE | FS_READ_DIR | FS_REMOVE_DIR | FS_REMOVE_FILE | FS_MAKE_DIR | FS_MAKE_REG;
            if abi >= 3 {
                a |= FS_TRUNCATE;
            }
            rules.push((w, a));
        }
        for (p, access) in rules {
            let Some(fd) = open_path(p) else { continue };
            let rule = PathBeneath { allowed_access: access & fs, parent_fd: fd };
            libc::syscall(libc::SYS_landlock_add_rule, rs, RULE_PATH_BENEATH, &rule as *const PathBeneath, 0u32);
            libc::close(fd);
        }
        if libc::syscall(libc::SYS_landlock_restrict_self, rs, 0u32) == 0 {
            rep.landlock = abi;
        }
        libc::close(rs);
    }
    rep
}

/// The limits the parent sets in the child before it starts (async-signal-safe: system calls only).
pub fn limits(per_file: u64) -> impl FnMut() -> std::io::Result<()> + Send + Sync + 'static {
    move || {
        let set = |res: libc::__rlimit_resource_t, v: u64| {
            let r = libc::rlimit { rlim_cur: v as libc::rlim_t, rlim_max: v as libc::rlim_t };
            // SAFETY: setrlimit on the child itself
            unsafe { libc::setrlimit(res, &r) };
        };
        set(libc::RLIMIT_AS, 1 << 30);
        set(libc::RLIMIT_CPU, 120);
        set(libc::RLIMIT_FSIZE, per_file + 1);
        set(libc::RLIMIT_NOFILE, 64);
        set(libc::RLIMIT_CORE, 0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In a child process (the sandbox cannot be undone): after confine, the home folder cannot be read, a file outside the
    /// output folder cannot be written, and one inside can.
    #[test]
    fn the_sandbox_holds() {
        let base = std::env::temp_dir().join(format!("heimdall-sandbox-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(base.join("secret"), b"x").unwrap();
        // SAFETY: fork in a test; the child only makes system calls and _exits
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let rep = confine(Some(&out));
            let code = if rep.landlock == 0 {
                // no Landlock here: nothing to prove
                0
            } else {
                let read_outside = std::fs::read(base.join("secret")).is_ok();
                let write_outside = std::fs::write(base.join("new"), b"x").is_ok();
                let write_inside = std::fs::write(out.join("ok"), b"x").is_ok();
                let usr = std::path::Path::new("/usr/bin").read_dir().is_ok();
                if !read_outside && !write_outside && write_inside && usr {
                    0
                } else {
                    1
                }
            };
            // SAFETY: leave the child at once
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        // SAFETY: waiting for our child
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0, "the sandbox let something through");
        assert!(!base.join("new").exists());
        let _ = std::fs::remove_dir_all(&base);
    }
}
