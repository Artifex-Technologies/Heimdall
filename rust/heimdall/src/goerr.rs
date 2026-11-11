//! Go's error texts, for the one-shot commands that print them (`open /etc/heimdall/x: permission denied`): the kernel's
//! error numbers as Go names them (`syscall.Errno.Error`, its own table: `goerr_table.rs`, written by rust/gotools/errtable)
//! and the shapes of Go's `os.PathError` ("op path: err"), `os.LinkError` ("op old new: err") and `os.SyscallError`.

#[path = "goerr_table.rs"]
mod table;

/// Go's `syscall.Errno(n).Error()`.
pub fn errno(n: i32) -> String {
    match usize::try_from(n).ok().and_then(|i| table::ERRNO.get(i)) {
        Some(s) => s.to_string(),
        None => format!("errno {n}"),
    }
}

/// The text Go prints for an error Rust got from the kernel; an error without a number keeps Rust's own text.
pub fn text(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(n) => errno(n),
        None => e.to_string(),
    }
}

/// Go's `*os.PathError`: "open /x: no such file or directory".
pub fn path(op: &str, path: &str, e: &std::io::Error) -> String {
    format!("{op} {path}: {}", text(e))
}

/// Go's `*os.LinkError`: "rename /a /b: invalid cross-device link".
pub fn link(op: &str, old: &str, new: &str, e: &std::io::Error) -> String {
    format!("{op} {old} {new}: {}", text(e))
}

/// Go's `*os.SyscallError`: "openat2: function not implemented".
pub fn syscall(name: &str, e: &std::io::Error) -> String {
    format!("{name}: {}", text(e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_texts() {
        assert_eq!(errno(2), "no such file or directory");
        assert_eq!(errno(13), "permission denied");
        assert_eq!(errno(40), "too many levels of symbolic links");
        assert_eq!(errno(0), "errno 0");
        assert_eq!(errno(9999), "errno 9999");
        assert_eq!(errno(-1), "errno -1");
        let e = std::io::Error::from_raw_os_error(2);
        assert_eq!(path("open", "/x", &e), "open /x: no such file or directory");
        assert_eq!(link("rename", "/a", "/b", &std::io::Error::from_raw_os_error(18)), "rename /a /b: invalid cross-device link");
    }
}
