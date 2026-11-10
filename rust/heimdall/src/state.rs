//! Small file helpers for the state files: written whole (a temporary file renamed into place, so a crash never leaves half a
//! file) with the modes the Go daemon uses.

use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;

/// Writes `b` to `path` with mode 0600 (created or truncated).
pub fn write_private(path: &str, b: &[u8]) -> std::io::Result<()> {
    write_mode(path, b, 0o600)
}

pub fn write_mode(path: &str, b: &[u8], mode: u32) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(mode).open(path)?;
    f.write_all(b)
}

/// Writes `b` to `path` atomically: `path.tmp`, then a rename over it (the Go daemon's pattern).
pub fn write_atomic(path: &str, b: &[u8], mode: u32) -> std::io::Result<()> {
    let tmp = format!("{path}.tmp");
    write_mode(&tmp, b, mode)?;
    std::fs::rename(&tmp, path)
}

/// The SHA-256 of a file, lowercase hex.
pub fn sha256_file(path: &str) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 << 10];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex(&h.finalize()))
}

pub fn hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}
