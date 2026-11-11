//! Go's `filepath.Match`, line for line (path/filepath/match.go, Linux): `*` and `?` never match a slash, classes with ranges
//! and `^`, backslash escapes; a malformed pattern is Go's `ErrBadPattern` (None).

/// Go's `utf8.DecodeRune`: the character and its length; a bad byte is (U+FFFD, 1).
fn decode(b: &[u8]) -> (char, usize) {
    let n = match b[0] {
        0x00..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return ('\u{FFFD}', 1),
    };
    match b.get(..n).and_then(|x| std::str::from_utf8(x).ok()) {
        Some(s) => (s.chars().next().unwrap(), n),
        None => ('\u{FFFD}', 1),
    }
}

/// Go's `getEsc`.
fn get_esc(chunk: &[u8]) -> Result<(char, &[u8]), ()> {
    if chunk.is_empty() || chunk[0] == b'-' || chunk[0] == b']' {
        return Err(());
    }
    let chunk = if chunk[0] == b'\\' {
        if chunk.len() == 1 {
            return Err(());
        }
        &chunk[1..]
    } else {
        chunk
    };
    let (r, n) = decode(chunk);
    let bad = r == '\u{FFFD}' && n == 1;
    let rest = &chunk[n..];
    if bad || rest.is_empty() {
        return Err(());
    }
    Ok((r, rest))
}

/// Go's `scanChunk`.
fn scan_chunk(mut p: &[u8]) -> (bool, &[u8], &[u8]) {
    let mut star = false;
    while p.first() == Some(&b'*') {
        p = &p[1..];
        star = true;
    }
    let mut in_range = false;
    let mut i = 0;
    while i < p.len() {
        match p[i] {
            b'\\' => {
                if i + 1 < p.len() {
                    i += 1;
                }
            }
            b'[' => in_range = true,
            b']' => in_range = false,
            b'*' if !in_range => break,
            _ => {}
        }
        i += 1;
    }
    (star, &p[..i], &p[i..])
}

/// Go's `matchChunk`: Ok(Some(rest)) matched, Ok(None) did not, Err for a malformed chunk.
fn match_chunk<'a>(mut chunk: &[u8], mut s: &'a [u8]) -> Result<Option<&'a [u8]>, ()> {
    let mut failed = false;
    while !chunk.is_empty() {
        if !failed && s.is_empty() {
            failed = true;
        }
        match chunk[0] {
            b'[' => {
                let mut r = '\0';
                if !failed {
                    let (c, n) = decode(s);
                    r = c;
                    s = &s[n..];
                }
                chunk = &chunk[1..];
                let mut negated = false;
                if chunk.first() == Some(&b'^') {
                    negated = true;
                    chunk = &chunk[1..];
                }
                let mut matched = false;
                let mut nrange = 0;
                loop {
                    if chunk.first() == Some(&b']') && nrange > 0 {
                        chunk = &chunk[1..];
                        break;
                    }
                    let (lo, rest) = get_esc(chunk)?;
                    chunk = rest;
                    let mut hi = lo;
                    if chunk[0] == b'-' {
                        let (h, rest) = get_esc(&chunk[1..])?;
                        hi = h;
                        chunk = rest;
                    }
                    if lo <= r && r <= hi {
                        matched = true;
                    }
                    nrange += 1;
                }
                if matched == negated {
                    failed = true;
                }
            }
            b'?' => {
                if !failed {
                    if s[0] == b'/' {
                        failed = true;
                    }
                    let (_, n) = decode(s);
                    s = &s[n..];
                }
                chunk = &chunk[1..];
            }
            c => {
                let c = if c == b'\\' {
                    chunk = &chunk[1..];
                    if chunk.is_empty() {
                        return Err(());
                    }
                    chunk[0]
                } else {
                    c
                };
                if !failed {
                    if c != s[0] {
                        failed = true;
                    }
                    s = &s[1..];
                }
                chunk = &chunk[1..];
            }
        }
    }
    Ok(if failed { None } else { Some(s) })
}

/// Go's `filepath.Match(pattern, name)`: Some(matched), None for a malformed pattern.
pub fn go_match(pattern: &[u8], name: &[u8]) -> Option<bool> {
    let mut pattern = pattern;
    let mut name = name;
    'pattern: while !pattern.is_empty() {
        let (star, chunk, rest) = scan_chunk(pattern);
        pattern = rest;
        if star && chunk.is_empty() {
            return Some(!name.contains(&b'/'));
        }
        let r = match_chunk(chunk, name);
        if let Ok(Some(t)) = r {
            if t.is_empty() || !pattern.is_empty() {
                name = t;
                continue;
            }
        }
        if r.is_err() {
            return None;
        }
        if star {
            let mut i = 0;
            while i < name.len() && name[i] != b'/' {
                match match_chunk(chunk, &name[i + 1..]) {
                    Ok(Some(t)) => {
                        if !(pattern.is_empty() && !t.is_empty()) {
                            name = t;
                            continue 'pattern;
                        }
                    }
                    Err(()) => return None,
                    Ok(None) => {}
                }
                i += 1;
            }
        }
        while !pattern.is_empty() {
            let (_, chunk, rest) = scan_chunk(pattern);
            pattern = rest;
            if match_chunk(chunk, b"").is_err() {
                return None;
            }
        }
        return Some(false);
    }
    Some(name.is_empty())
}

#[cfg(test)]
mod tests {
    use super::go_match;

    #[test]
    fn match_as_go() {
        // Go's own table (path/filepath/match_test.go, Linux)
        for (p, s, want) in [
            ("abc", "abc", Some(true)),
            ("*", "abc", Some(true)),
            ("*c", "abc", Some(true)),
            ("a*", "a", Some(true)),
            ("a*", "abc", Some(true)),
            ("a*", "ab/c", Some(false)),
            ("a*/b", "abc/b", Some(true)),
            ("a*/b", "a/c/b", Some(false)),
            ("a*b*c*d*e*/f", "axbxcxdxe/f", Some(true)),
            ("a*b*c*d*e*/f", "axbxcxdxexxx/f", Some(true)),
            ("a*b*c*d*e*/f", "axbxcxdxe/xxx/f", Some(false)),
            ("a*b*c*d*e*/f", "axbxcxdxexxx/fff", Some(false)),
            ("a*b?c*x", "abxbbxdbxebxczzx", Some(true)),
            ("a*b?c*x", "abxbbxdbxebxczzy", Some(false)),
            ("ab[c]", "abc", Some(true)),
            ("ab[b-d]", "abc", Some(true)),
            ("ab[e-g]", "abc", Some(false)),
            ("ab[^c]", "abc", Some(false)),
            ("ab[^b-d]", "abc", Some(false)),
            ("ab[^e-g]", "abc", Some(true)),
            ("a\\*b", "a*b", Some(true)),
            ("a\\*b", "ab", Some(false)),
            ("a?b", "a☺b", Some(true)),
            ("a[^a]b", "a☺b", Some(true)),
            ("a???b", "a☺b", Some(false)),
            ("a[^a][^a][^a]b", "a☺b", Some(false)),
            ("[a-ζ]*", "α", Some(true)),
            ("*[a-ζ]", "A", Some(false)),
            ("a?b", "a/b", Some(false)),
            ("a*b", "a/b", Some(false)),
            ("[\\]a]", "]", Some(true)),
            ("[\\-]", "-", Some(true)),
            ("[x\\-]", "x", Some(true)),
            ("[x\\-]", "-", Some(true)),
            ("[x\\-]", "z", Some(false)),
            ("[\\-x]", "x", Some(true)),
            ("[\\-x]", "-", Some(true)),
            ("[\\-x]", "a", Some(false)),
            ("[]a]", "]", None),
            ("[-]", "-", None),
            ("[x-]", "x", None),
            ("[x-]", "-", None),
            ("[x-]", "z", None),
            ("[-x]", "x", None),
            ("[-x]", "-", None),
            ("[-x]", "a", None),
            ("\\", "a", None),
            ("[a-b-c]", "a", None),
            ("[", "a", None),
            ("[^", "a", None),
            ("[^bc", "a", None),
            ("a[", "a", None),
            ("a[", "ab", None),
            ("a[", "x", None),
            ("a/b[", "x", None),
            ("*x", "xxx", Some(true)),
        ] {
            assert_eq!(go_match(p.as_bytes(), s.as_bytes()), want, "{p} {s}");
        }
    }
}
