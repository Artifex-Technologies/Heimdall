//! Go's string functions on the device list's text, where Rust's differ: `strings.EqualFold` (Go's simple case folding, from
//! `fold_table.rs`, written by rust/gotools/foldtable), `strings.ToLower` and `strings.ToUpper` on any bytes (a byte that is not
//! UTF-8 becomes U+FFFD), and the list's own `clean`.

#[path = "fold_table.rs"]
mod table;

fn canon(c: char) -> u32 {
    let r = c as u32;
    match table::FOLD.binary_search_by_key(&r, |&(k, _)| k) {
        Ok(i) => table::FOLD[i].1,
        Err(_) => r,
    }
}

/// Go's `strings.EqualFold`.
pub fn equal_fold(a: &str, b: &str) -> bool {
    let (mut x, mut y) = (a.chars(), b.chars());
    loop {
        match (x.next(), y.next()) {
            (None, None) => return true,
            (Some(p), Some(q)) if p == q || canon(p) == canon(q) => {}
            _ => return false,
        }
    }
}

/// Whether `list` holds `s`, ignoring case as Go's `strings.EqualFold` does.
pub fn contains_fold(list: &[String], s: &str) -> bool {
    list.iter().any(|x| equal_fold(x, s))
}

/// Go's `strings.ToLower` of a Go string (any bytes).
pub fn to_lower(b: &[u8]) -> String {
    crate::gotext::to_lower(&crate::gotext::lossy(b))
}

/// Go's `unicode.ToUpper` of one rune (the simple mapping: a rune whose uppercase is longer stays as it is).
fn upper_rune(c: char) -> char {
    let mut u = c.to_uppercase();
    match (u.next(), u.next()) {
        (Some(one), None) => one,
        _ => c,
    }
}

/// Go's `strings.ToUpper` of a Go string (any bytes).
pub fn to_upper(b: &[u8]) -> String {
    crate::gotext::lossy(b).chars().map(upper_rune).collect()
}

/// Keeps a name printable and short (Go: `clean`): spaces trimmed, control characters and the invisible direction and
/// zero-width marks dropped, at most 64 characters. Whoever runs a device chooses its name.
pub fn clean(b: &[u8]) -> String {
    let s = crate::gotext::lossy(b);
    let kept: String = crate::gotext::trim_space(&s)
        .chars()
        .filter(|&c| {
            let r = c as u32;
            !(r < 0x20 || r == 0x7f || (0x200b..=0x200f).contains(&r) || (0x202a..=0x202e).contains(&r) || (0x2066..=0x2069).contains(&r))
        })
        .collect();
    kept.chars().take(64).collect()
}

/// Go's `strings.Index` on bytes.
pub fn index(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fold_as_go() {
        assert!(equal_fold("Router", "rOUTER"));
        assert!(equal_fold("\u{212A}elvin", "kelvin"));
        assert!(equal_fold("ſ", "S"));
        assert!(equal_fold("Σ", "ς"));
        assert!(!equal_fold("ı", "I"), "dotless i is in no orbit with I in Go");
        assert!(!equal_fold("İ", "i"));
        assert!(!equal_fold("ab", "a"));
        assert_eq!(clean(b"  Living\x00 Room\xe2\x80\x8b TV \t"), "Living Room TV");
        assert_eq!(clean(b"\xffA"), "\u{FFFD}A");
        assert_eq!(clean("é".repeat(70).as_bytes()).chars().count(), 64);
        assert_eq!(to_upper("ß".as_bytes()), "ß");
    }
}
