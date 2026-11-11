//! A small inotify wrapper: watches by path, events read in batches without blocking (the daemon's loop polls the fd).

use rustix::fs::inotify::{self, CreateFlags, WatchFlags};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

pub use rustix::fs::inotify::WatchFlags as Mask;

/// One event: the watch it came from, what happened, and the name in the watched folder.
#[derive(Clone, Debug, PartialEq)]
pub struct Ev {
    pub wd: i32,
    pub mask: u32,
    pub name: String,
}

pub const IN_ISDIR: u32 = 0x4000_0000;
pub const IN_IGNORED: u32 = 0x0000_8000;
pub const IN_Q_OVERFLOW: u32 = 0x0000_4000;
pub const IN_CLOSE_WRITE: u32 = 0x0000_0008;
pub const IN_MOVED_TO: u32 = 0x0000_0080;
pub const IN_CREATE: u32 = 0x0000_0100;
pub const IN_DELETE_SELF: u32 = 0x0000_0400;
pub const IN_MOVE_SELF: u32 = 0x0000_0800;

pub struct Inotify {
    fd: OwnedFd,
}

impl Inotify {
    pub fn new() -> std::io::Result<Inotify> {
        Ok(Inotify { fd: inotify::init(CreateFlags::CLOEXEC | CreateFlags::NONBLOCK)? })
    }

    pub fn add(&self, path: &str, mask: WatchFlags) -> std::io::Result<i32> {
        Ok(inotify::add_watch(&self.fd, path, mask)?)
    }

    pub fn remove(&self, wd: i32) {
        let _ = inotify::remove_watch(&self.fd, wd);
    }

    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Every event waiting now (none when nothing is waiting). Err: the descriptor is broken.
    pub fn read(&self) -> std::io::Result<Vec<Ev>> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 64 << 10];
        loop {
            let n = match rustix::io::read(&self.fd, &mut buf[..]) {
                Ok(n) => n,
                Err(rustix::io::Errno::AGAIN) => return Ok(out),
                Err(rustix::io::Errno::INTR) => continue,
                Err(e) => return Err(e.into()),
            };
            if n == 0 {
                return Ok(out);
            }
            let mut off = 0;
            // struct inotify_event: wd, mask, cookie, len, then len bytes of NUL-padded name
            while off + 16 <= n {
                let u = |at: usize| u32::from_ne_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]);
                let (wd, mask, len) = (u(off) as i32, u(off + 4), u(off + 12) as usize);
                let end = off + 16 + len;
                if end > n {
                    break;
                }
                let raw = &buf[off + 16..end];
                let name = crate::gotext::lossy(&raw[..raw.iter().position(|&c| c == 0).unwrap_or(raw.len())]);
                out.push(Ev { wd, mask, name });
                off = end;
            }
        }
    }
}
