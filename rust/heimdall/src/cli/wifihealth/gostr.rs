//! Go strings are bytes: a tool's output that is not valid UTF-8 stays as it was through Go's regular expressions (each bad
//! byte one character to them) and comes out of the JSON encoder as `�` per byte, or raw in text. Here such a byte
//! travels inside a Rust string as one character of a private-use block (U+10FF00 + the byte), so the patterns see one
//! character as Go's do, and `encode` gives the original bytes back for writing. Go's number parsing as these parsers
//! use it (errors ignored, overflow kept) is here too.

const BASE: u32 = 0x10FF00;

/// Bytes as Go sees them: valid UTF-8 kept, each other byte one stand-in character.
pub fn decode(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len());
    let mut rest = b;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                out.push_str(s);
                break;
            }
            Err(e) => {
                let ok = e.valid_up_to();
                out.push_str(std::str::from_utf8(&rest[..ok]).unwrap_or_default());
                out.push(char::from_u32(BASE + rest[ok] as u32).unwrap_or('\u{FFFD}'));
                rest = &rest[ok + 1..];
            }
        }
    }
    out
}

/// The original bytes.
pub fn encode(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for c in s.chars() {
        let u = c as u32;
        if (BASE..BASE + 256).contains(&u) {
            out.push((u - BASE) as u8);
        } else {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
    }
    out
}

/// Go's `for _, r := range s` writing each rune back: every bad byte becomes a real U+FFFD.
pub fn runes(s: &str) -> String {
    s.chars().map(|c| if (BASE..BASE + 256).contains(&(c as u32)) { '\u{FFFD}' } else { c }).collect()
}

/// A Go string in JSON, as `encoding/json` writes it (Go 1.27: each bad byte as the character U+FFFD itself, not as the
/// escape \\ufffd older Go wrote; HTML characters and U+2028/U+2029 escaped as before).
pub fn json(out: &mut String, s: &str) {
    crate::gojson::write_str(out, &runes(s));
}

/// `strconv.ParseFloat(s, 64)` with the error ignored: 0 for a malformed number, ±Inf for one too large (Go keeps it).
pub fn parse_float(s: &str) -> f64 {
    let ok = !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit() || b == b'.') && s.bytes().filter(|&b| b == b'.').count() <= 1;
    if !ok || s == "." {
        return 0.0;
    }
    s.parse::<f64>().unwrap_or(0.0)
}

/// Go's `int(f)` on amd64: out of range (or NaN) is the smallest int.
pub fn float_to_int(f: f64) -> i64 {
    if f.is_nan() || f >= 9_223_372_036_854_775_808.0 || f < -9_223_372_036_854_775_808.0 {
        i64::MIN
    } else {
        f as i64
    }
}

/// `strconv.Atoi(s)` with the error ignored: 0 for a malformed number, the nearest int for one out of range.
pub fn atoi(s: &str) -> i64 {
    let (neg, body) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    if body.is_empty() {
        return 0;
    }
    let mut v: u64 = 0;
    for b in body.bytes() {
        if !b.is_ascii_digit() {
            return 0;
        }
        match v.checked_mul(10).and_then(|x| x.checked_add((b - b'0') as u64)) {
            Some(x) => v = x,
            None => return if neg { i64::MIN } else { i64::MAX },
        }
    }
    if neg {
        if v > 1 << 63 {
            i64::MIN
        } else {
            (v as i64).wrapping_neg()
        }
    } else if v > i64::MAX as u64 {
        i64::MAX
    } else {
        v as i64
    }
}

/// `strconv.ParseUint(s, 10, 64)` with the error ignored: 0 for a malformed number, the largest for one out of range.
pub fn parse_uint(s: &str) -> u64 {
    if s.is_empty() {
        return 0;
    }
    let mut v: u64 = 0;
    for b in s.bytes() {
        if !b.is_ascii_digit() {
            return 0;
        }
        match v.checked_mul(10).and_then(|x| x.checked_add((b - b'0') as u64)) {
            Some(x) => v = x,
            None => return u64::MAX,
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_round_trip() {
        let b = b"Caf\xe9 \xe2\x84 ok \xc3\xa9";
        assert_eq!(encode(&decode(b)), b.to_vec());
        assert_eq!(runes(&decode(b"a\xffb")), "a\u{FFFD}b");
        let mut s = String::new();
        json(&mut s, &decode(b"a\xffb<"));
        assert_eq!(s, "\"a\u{FFFD}b\\u003c\"");
    }

    #[test]
    fn numbers_as_go() {
        assert_eq!(atoi("-75"), -75);
        assert_eq!(atoi("+5"), 5);
        assert_eq!(atoi(" 5"), 0);
        assert_eq!(atoi("99999999999999999999"), i64::MAX);
        assert_eq!(atoi("-99999999999999999999"), i64::MIN);
        assert_eq!(parse_uint("18446744073709551616"), u64::MAX);
        assert_eq!(parse_float("1.5"), 1.5);
        assert_eq!(parse_float("1.2.3"), 0.0);
        assert_eq!(parse_float("."), 0.0);
        assert_eq!(parse_float(&"9".repeat(400)), f64::INFINITY);
        assert_eq!(float_to_int(f64::INFINITY), i64::MIN);
        assert_eq!(float_to_int(2412.9), 2412);
    }
}
