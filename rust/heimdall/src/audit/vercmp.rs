//! pacman's version comparison (Go: internal/pkgaudit/vercmp.go, alpm_pkg_vercmp): `[epoch:]version[-release]`, segment by
//! segment as rpm compares them. On bytes, as Go's strings are: a version from pacman's database is not checked for UTF-8.

use std::cmp::Ordering;

/// -1, 0 or 1, as pacman's `vercmp` prints.
pub fn vercmp(a: &[u8], b: &[u8]) -> i32 {
    if a == b {
        return 0;
    }
    let (e1, v1, r1) = evr(a);
    let (e2, v2, r2) = evr(b);
    let c = rpmvercmp(e1, e2);
    if c != 0 {
        return c;
    }
    let c = rpmvercmp(v1, v2);
    if c != 0 {
        return c;
    }
    if !r1.is_empty() && !r2.is_empty() {
        return rpmvercmp(r1, r2);
    }
    0
}

/// Splits `[epoch:]version[-release]`; the epoch is "0" when absent (or when what precedes the colon is not all digits, in
/// which case the colon belongs to the version).
pub fn evr(s: &[u8]) -> (&[u8], &[u8], &[u8]) {
    let mut epoch: &[u8] = b"0";
    let mut s = s;
    if let Some(i) = s.iter().position(|&c| c == b':') {
        if s[..i].iter().all(u8::is_ascii_digit) {
            if i > 0 {
                epoch = &s[..i];
            }
            s = &s[i + 1..];
        }
    }
    match s.iter().rposition(|&c| c == b'-') {
        Some(i) => (epoch, &s[..i], &s[i + 1..]),
        None => (epoch, s, b""),
    }
}

/// Two versions are the same release, ignoring the package release after the dash.
pub fn same_upstream(a: &[u8], b: &[u8]) -> bool {
    let (ea, va, _) = evr(a);
    let (eb, vb, _) = evr(b);
    rpmvercmp(ea, eb) == 0 && rpmvercmp(va, vb) == 0
}

fn alpha(c: u8) -> bool {
    c.is_ascii_alphabetic()
}

fn alnum(c: u8) -> bool {
    c.is_ascii_alphanumeric()
}

fn trim_zeros(s: &[u8]) -> &[u8] {
    let n = s.iter().take_while(|&&c| c == b'0').count();
    &s[n..]
}

/// The segment comparison pacman inherited from rpm.
pub fn rpmvercmp(a: &[u8], b: &[u8]) -> i32 {
    if a == b {
        return 0;
    }
    let (mut one, mut two) = (0usize, 0usize);
    let (mut p1, mut p2) = (0usize, 0usize);
    while one < a.len() && two < b.len() {
        while one < a.len() && !alnum(a[one]) {
            one += 1;
        }
        while two < b.len() && !alnum(b[two]) {
            two += 1;
        }
        if one >= a.len() || two >= b.len() {
            break;
        }
        if one - p1 != two - p2 {
            return if one - p1 < two - p2 { -1 } else { 1 };
        }
        p1 = one;
        p2 = two;
        let num = a[p1].is_ascii_digit();
        while p1 < a.len() && (num && a[p1].is_ascii_digit() || !num && alpha(a[p1])) {
            p1 += 1;
        }
        while p2 < b.len() && (num && b[p2].is_ascii_digit() || !num && alpha(b[p2])) {
            p2 += 1;
        }
        let (mut s1, mut s2) = (&a[one..p1], &b[two..p2]);
        if s2.is_empty() {
            return if num { 1 } else { -1 };
        }
        if num {
            s1 = trim_zeros(s1);
            s2 = trim_zeros(s2);
            if s1.len() != s2.len() {
                return if s1.len() > s2.len() { 1 } else { -1 };
            }
        }
        match s1.cmp(s2) {
            Ordering::Less => return -1,
            Ordering::Greater => return 1,
            Ordering::Equal => {}
        }
        one = p1;
        two = p2;
    }
    if one >= a.len() && two >= b.len() {
        return 0;
    }
    if (one >= a.len() && !(two < b.len() && alpha(b[two]))) || (one < a.len() && alpha(a[one])) {
        return -1;
    }
    1
}

/// Kani: the comparison never panics (no index past the end) and is antisymmetric, for every pair of short versions.
/// Run with `cargo kani -p heimdall`; tests/audit_properties.rs checks the same exhaustively over a small alphabet.
#[cfg(kani)]
mod proofs {
    use super::*;

    fn any_version() -> ([u8; 4], usize) {
        let b: [u8; 4] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 4);
        (b, n)
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn vercmp_is_antisymmetric() {
        let (a, n) = any_version();
        let (b, m) = any_version();
        assert_eq!(vercmp(&a[..n], &b[..m]), -vercmp(&b[..m], &a[..n]));
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn vercmp_answers_minus_one_zero_or_one() {
        let (a, n) = any_version();
        let (b, m) = any_version();
        assert!((-1..=1).contains(&vercmp(&a[..n], &b[..m])));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn some_known_answers() {
        for (a, b, want) in [
            ("1.0", "1.0", 0),
            ("1.0", "1.1", -1),
            ("1.0.0", "1.0", 1),
            ("1.0a", "1.0", -1),
            ("1:1.0-1", "2.0-1", 1),
            ("1.0-1", "1.0", 0),
            ("8.4.27-1", "8.4.27-1.1", -1),
            ("6.1.2-1", "6.10-1", -1),
            ("1.001", "1.1", 0),
        ] {
            assert_eq!(vercmp(a.as_bytes(), b.as_bytes()), want, "{a} {b}");
            assert_eq!(vercmp(b.as_bytes(), a.as_bytes()), -want, "{b} {a}");
        }
    }
}
