//! PDF files from hostile sources: a tokenizer, the objects found by scanning the whole file (the cross-reference table is
//! not trusted; it can lie or be missing), object streams unpacked in memory with a cap, and dictionaries read as flat token
//! lists. Nothing recurses: nesting is counted, with a limit. Used to find what a PDF does by itself when opened
//! (`guard`), and to write a copy without its document information and XMP (`strip`).

use std::collections::HashMap;
use std::io::Read;

/// A token.
#[derive(Clone, Debug, PartialEq)]
pub enum Tok {
    /// A name, with its #xx escapes decoded ("/J#61vaScript" is "JavaScript").
    Name(Vec<u8>),
    Int(i64),
    Real,
    /// A string's bytes (literal or hex), decoded.
    Str(Vec<u8>),
    DictOpen,
    DictClose,
    ArrOpen,
    ArrClose,
    /// Anything else: obj, endobj, stream, R, true, null...
    Kw(Vec<u8>),
}

/// A token and where it is in its buffer.
#[derive(Clone, Debug, PartialEq)]
pub struct T {
    pub tok: Tok,
    pub start: usize,
    pub end: usize,
}

fn ws(b: u8) -> bool {
    matches!(b, 0 | 9 | 10 | 12 | 13 | 32)
}
fn delim(b: u8) -> bool {
    matches!(b, b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%')
}

/// The longest string kept (the rest of a longer one is skipped, not kept).
const MAX_STR: usize = 1 << 20;

/// Tokens of a buffer from `pos` to `end`.
pub struct Lexer<'a> {
    pub d: &'a [u8],
    pub pos: usize,
    pub end: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(d: &'a [u8], pos: usize, end: usize) -> Self {
        Lexer { d, pos, end: end.min(d.len()) }
    }

    fn skip_space(&mut self) {
        while self.pos < self.end {
            let b = self.d[self.pos];
            if ws(b) {
                self.pos += 1;
            } else if b == b'%' {
                while self.pos < self.end && !matches!(self.d[self.pos], b'\n' | b'\r') {
                    self.pos += 1;
                }
            } else {
                break;
            }
        }
    }

    pub fn next_tok(&mut self) -> Option<T> {
        self.skip_space();
        if self.pos >= self.end {
            return None;
        }
        let (d, start) = (self.d, self.pos);
        let b = d[start];
        let tok = match b {
            b'/' => {
                let mut i = start + 1;
                let mut name = vec![];
                while i < self.end && !ws(d[i]) && !delim(d[i]) {
                    if d[i] == b'#' && i + 2 < self.end && d[i + 1].is_ascii_hexdigit() && d[i + 2].is_ascii_hexdigit() {
                        let h = std::str::from_utf8(&d[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()).unwrap_or(0);
                        name.push(h);
                        i += 3;
                    } else {
                        name.push(d[i]);
                        i += 1;
                    }
                }
                self.pos = i;
                Tok::Name(name)
            }
            b'(' => {
                let mut i = start + 1;
                let mut depth = 1usize;
                let mut s = vec![];
                while i < self.end {
                    let c = d[i];
                    i += 1;
                    match c {
                        b'\\' if i < self.end => {
                            let e = d[i];
                            i += 1;
                            let v = match e {
                                b'n' => Some(b'\n'),
                                b'r' => Some(b'\r'),
                                b't' => Some(b'\t'),
                                b'b' => Some(8),
                                b'f' => Some(12),
                                b'\r' => {
                                    if i < self.end && d[i] == b'\n' {
                                        i += 1;
                                    }
                                    None
                                }
                                b'\n' => None,
                                b'0'..=b'7' => {
                                    let mut n = (e - b'0') as u32;
                                    for _ in 0..2 {
                                        if i < self.end && (b'0'..=b'7').contains(&d[i]) {
                                            n = n * 8 + (d[i] - b'0') as u32;
                                            i += 1;
                                        }
                                    }
                                    Some(n as u8)
                                }
                                other => Some(other),
                            };
                            if let (Some(v), true) = (v, s.len() < MAX_STR) {
                                s.push(v);
                            }
                        }
                        b'(' => {
                            depth += 1;
                            if s.len() < MAX_STR {
                                s.push(c);
                            }
                        }
                        b')' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                            if s.len() < MAX_STR {
                                s.push(c);
                            }
                        }
                        _ => {
                            if s.len() < MAX_STR {
                                s.push(c);
                            }
                        }
                    }
                }
                self.pos = i;
                Tok::Str(s)
            }
            b'<' if start + 1 < self.end && d[start + 1] == b'<' => {
                self.pos = start + 2;
                Tok::DictOpen
            }
            b'<' => {
                let mut i = start + 1;
                let mut hex = vec![];
                while i < self.end && d[i] != b'>' {
                    if d[i].is_ascii_hexdigit() && hex.len() < 2 * MAX_STR {
                        hex.push(d[i]);
                    }
                    i += 1;
                }
                if hex.len() % 2 == 1 {
                    hex.push(b'0');
                }
                let s = hex.chunks(2).map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap_or("0"), 16).unwrap_or(0)).collect();
                self.pos = (i + 1).min(self.end);
                Tok::Str(s)
            }
            b'>' if start + 1 < self.end && d[start + 1] == b'>' => {
                self.pos = start + 2;
                Tok::DictClose
            }
            b'[' => {
                self.pos = start + 1;
                Tok::ArrOpen
            }
            b']' => {
                self.pos = start + 1;
                Tok::ArrClose
            }
            b'>' | b')' | b'{' | b'}' => {
                self.pos = start + 1;
                Tok::Kw(vec![b])
            }
            _ => {
                let mut i = start;
                while i < self.end && !ws(d[i]) && !delim(d[i]) {
                    i += 1;
                }
                if i == start {
                    i += 1;
                }
                self.pos = i;
                let w = &d[start..i];
                let numeric =
                    w.iter().all(|c| c.is_ascii_digit() || matches!(c, b'+' | b'-' | b'.')) && w.iter().any(|c| c.is_ascii_digit());
                if numeric && !w.contains(&b'.') {
                    std::str::from_utf8(w).ok().and_then(|s| s.parse::<i64>().ok()).map_or(Tok::Real, Tok::Int)
                } else if numeric {
                    Tok::Real
                } else {
                    Tok::Kw(w.to_vec())
                }
            }
        };
        Some(T { tok, start, end: self.pos })
    }
}

/// All tokens of a range, at most `max`.
pub fn tokens(d: &[u8], start: usize, end: usize, max: usize) -> Vec<T> {
    let mut lx = Lexer::new(d, start, end);
    let mut v = vec![];
    while v.len() < max {
        match lx.next_tok() {
            Some(t) => v.push(t),
            None => break,
        }
    }
    v
}

pub fn is_kw(t: &T, w: &[u8]) -> bool {
    matches!(&t.tok, Tok::Kw(k) if k == w)
}
pub fn is_name(t: &T, w: &[u8]) -> bool {
    matches!(&t.tok, Tok::Name(k) if k == w)
}

/// Deepest nesting of dictionaries and arrays followed.
const MAX_DEPTH: usize = 256;

/// The index just after the value that starts at `i` (a reference "n g R" is one value).
pub fn value_end(t: &[T], i: usize) -> usize {
    if i >= t.len() {
        return t.len();
    }
    if let (Tok::Int(_), Some(T { tok: Tok::Int(_), .. }), Some(r)) = (&t[i].tok, t.get(i + 1), t.get(i + 2)) {
        if is_kw(r, b"R") {
            return i + 3;
        }
    }
    match t[i].tok {
        Tok::DictOpen | Tok::ArrOpen => {
            let mut depth = 0usize;
            let mut j = i;
            while j < t.len() {
                match t[j].tok {
                    Tok::DictOpen | Tok::ArrOpen => depth += 1,
                    Tok::DictClose | Tok::ArrClose => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            return j + 1;
                        }
                    }
                    _ => {}
                }
                if depth > MAX_DEPTH {
                    return t.len();
                }
                j += 1;
            }
            t.len()
        }
        _ => i + 1,
    }
}

/// The entries of the dictionary whose "<<" is at `open`: (key, value start, value end) in token indices.
pub fn entries(t: &[T], open: usize) -> Vec<(Vec<u8>, usize, usize)> {
    let mut out = vec![];
    if !matches!(t.get(open).map(|x| &x.tok), Some(Tok::DictOpen)) {
        return out;
    }
    let mut i = open + 1;
    while i < t.len() && !matches!(t[i].tok, Tok::DictClose) {
        if let Tok::Name(k) = &t[i].tok {
            let e = value_end(t, i + 1);
            // a key without a value (the dictionary cut short) is not an entry
            if e > i + 1 {
                out.push((k.clone(), i + 1, e));
            }
            i = e.max(i + 1);
        } else {
            i = value_end(t, i).max(i + 1);
        }
    }
    out
}

/// A dictionary entry's value range.
pub fn get(es: &[(Vec<u8>, usize, usize)], key: &[u8]) -> Option<(usize, usize)> {
    es.iter().find(|(k, _, _)| k == key).map(|&(_, s, e)| (s, e))
}

/// The object number of a reference value.
pub fn as_ref(t: &[T], s: usize, e: usize) -> Option<u32> {
    match (e - s, t.get(s).map(|x| &x.tok)) {
        (3, Some(Tok::Int(n))) if is_kw(&t[s + 2], b"R") => u32::try_from(*n).ok(),
        _ => None,
    }
}

/// A value that is a single integer.
pub fn as_int(t: &[T], s: usize, e: usize) -> Option<i64> {
    match (e - s, t.get(s).map(|x| &x.tok)) {
        (1, Some(Tok::Int(n))) => Some(*n),
        _ => None,
    }
}

/// A value that is a single name.
pub fn as_name(t: &[T], s: usize, e: usize) -> Option<&[u8]> {
    match (e - s, t.get(s).map(|x| &x.tok)) {
        (1, Some(Tok::Name(n))) => Some(n),
        _ => None,
    }
}

/// An object found in the file.
#[derive(Clone, Debug)]
pub struct Obj {
    pub num: u32,
    pub gen: u16,
    /// 0: the file; k: the k-th unpacked object stream.
    pub buf: usize,
    /// The object's value (before "stream" for a stream).
    pub body: (usize, usize),
    /// A stream's data, in the file.
    pub stream: Option<(usize, usize)>,
    /// Where it was found (later wins, as with incremental updates).
    pub order: usize,
}

/// The object being read: number, generation, where its value starts, its tokens so far, its stream, where "stream" was.
type Reading = (u32, u16, usize, Vec<T>, Option<(usize, usize)>, usize);

/// A scanned PDF.
pub struct Doc<'a> {
    pub file: &'a [u8],
    pub unpacked: Vec<Vec<u8>>,
    pub objs: HashMap<u32, Obj>,
    /// The trailer dictionaries' tokens (classic trailers and cross-reference streams), in file order.
    pub trailers: Vec<Vec<T>>,
    /// Something could not be read (an object stream with another filter, a cap reached).
    pub complete: bool,
    pub version: String,
}

/// Most objects kept; most tokens read per object; most bytes unpacked from object streams in all.
pub const MAX_OBJS: usize = 1_000_000;
pub const MAX_TOKS: usize = 200_000;
const MAX_UNPACKED: u64 = 128 << 20;

impl<'a> Doc<'a> {
    pub fn buf(&self, o: &Obj) -> &[u8] {
        if o.buf == 0 {
            self.file
        } else {
            &self.unpacked[o.buf - 1]
        }
    }

    /// An object's value tokens.
    pub fn toks(&self, o: &Obj) -> Vec<T> {
        tokens(self.buf(o), o.body.0, o.body.1, MAX_TOKS)
    }

    /// Scans a whole file.
    pub fn scan(file: &'a [u8]) -> Doc<'a> {
        let version = find(file, 0, b"%PDF-")
            .filter(|&p| p < 1024)
            .map(|p| {
                file[p + 5..(p + 8).min(file.len())].iter().take_while(|c| c.is_ascii_digit() || **c == b'.').map(|&c| c as char).collect()
            })
            .unwrap_or_default();
        let mut doc = Doc { file, unpacked: vec![], objs: HashMap::new(), trailers: vec![], complete: true, version };
        let mut lx = Lexer::new(file, 0, file.len());
        let mut prev: [Option<T>; 2] = [None, None];
        let mut cur: Option<Reading> = None;
        let mut order = 0usize;
        let add = |doc: &mut Doc, num: u32, gen: u16, body: (usize, usize), stream: Option<(usize, usize)>, order: &mut usize| {
            *order += 1;
            if doc.objs.len() < MAX_OBJS || doc.objs.contains_key(&num) {
                doc.objs.insert(num, Obj { num, gen, buf: 0, body, stream, order: *order });
            } else {
                doc.complete = false;
            }
        };
        while let Some(t) = lx.next_tok() {
            if is_kw(&t, b"obj") {
                if let (Some(T { tok: Tok::Int(n), start: ns, .. }), Some(T { tok: Tok::Int(g), .. })) = (&prev[0], &prev[1]) {
                    if (0..=10_000_000).contains(n) && (0..=65_535).contains(g) {
                        if let Some((num, gen, bs, _, st, se)) = cur.take() {
                            add(&mut doc, num, gen, (bs, if st.is_some() { se } else { *ns }), st, &mut order);
                        }
                        cur = Some((*n as u32, *g as u16, t.end, vec![], None, 0));
                        prev = [None, None];
                        continue;
                    }
                }
            } else if is_kw(&t, b"endobj") {
                if let Some((num, gen, bs, _, st, se)) = cur.take() {
                    add(&mut doc, num, gen, (bs, if st.is_some() { se } else { t.start }), st, &mut order);
                }
            } else if is_kw(&t, b"stream") {
                if let Some((_, _, _, toks, st, se)) = cur.as_mut() {
                    *se = t.start;
                    let mut s = t.end;
                    if file.get(s) == Some(&b'\r') {
                        s += 1;
                    }
                    if file.get(s) == Some(&b'\n') {
                        s += 1;
                    }
                    let declared = toks.first().filter(|x| matches!(x.tok, Tok::DictOpen)).and_then(|_| {
                        let es = entries(toks, 0);
                        get(&es, b"Length").and_then(|(a, b)| as_int(toks, a, b))
                    });
                    let by_length = declared.and_then(|n| usize::try_from(n).ok()).and_then(|n| s.checked_add(n)).filter(|&e| {
                        e <= file.len() && {
                            let mut k = e;
                            while k < file.len() && ws(file[k]) {
                                k += 1;
                            }
                            file[k..].starts_with(b"endstream")
                        }
                    });
                    let e = match by_length {
                        Some(e) => e,
                        None => {
                            let mut e = find(file, s, b"endstream").unwrap_or(file.len());
                            // the end of line before "endstream" is not data
                            if e > s && file[e - 1] == b'\n' {
                                e -= 1;
                            }
                            if e > s && file[e - 1] == b'\r' {
                                e -= 1;
                            }
                            e
                        }
                    };
                    *st = Some((s, e));
                    let after = find(file, e, b"endstream").map_or(file.len(), |p| p + 9);
                    lx.pos = after;
                    prev = [None, None];
                    continue;
                }
            } else if is_kw(&t, b"trailer") {
                let mut tl = vec![];
                let mut depth = 0usize;
                while let Some(x) = lx.next_tok() {
                    match x.tok {
                        Tok::DictOpen | Tok::ArrOpen => depth += 1,
                        Tok::DictClose | Tok::ArrClose => depth = depth.saturating_sub(1),
                        _ => {}
                    }
                    tl.push(x);
                    if depth == 0 || tl.len() > 10_000 {
                        break;
                    }
                }
                doc.trailers.push(tl);
                prev = [None, None];
                continue;
            }
            if let Some((_, _, _, toks, st, _)) = cur.as_mut() {
                if st.is_none() && toks.len() < MAX_TOKS {
                    toks.push(t.clone());
                }
            }
            prev = [prev[1].take(), Some(t)];
        }
        if let Some((num, gen, bs, _, st, se)) = cur.take() {
            add(&mut doc, num, gen, (bs, if st.is_some() { se } else { file.len() }), st, &mut order);
        }
        doc.unpack_object_streams();
        doc.trailers_from_xref_streams();
        doc
    }

    /// Cross-reference streams are trailers too (their dictionary has /Root, /Info, /Encrypt).
    fn trailers_from_xref_streams(&mut self) {
        let mut found: Vec<(usize, Vec<T>)> = vec![];
        for o in self.objs.values() {
            if o.stream.is_some() && o.buf == 0 {
                let t = self.toks(o);
                let es = entries(&t, 0);
                if get(&es, b"Type").and_then(|(a, b)| as_name(&t, a, b)) == Some(b"XRef") {
                    found.push((o.order, t));
                }
            }
        }
        found.sort_by_key(|(o, _)| *o);
        self.trailers.extend(found.into_iter().map(|(_, t)| t));
    }

    /// The last trailer's value for a key (a reference's object number).
    pub fn trailer_ref(&self, key: &[u8]) -> Option<u32> {
        self.trailers.iter().rev().find_map(|t| {
            let es = entries(t, 0);
            get(&es, key).and_then(|(a, b)| as_ref(t, a, b))
        })
    }

    /// Any trailer has the key.
    pub fn trailer_has(&self, key: &[u8]) -> bool {
        self.trailers.iter().any(|t| get(&entries(t, 0), key).is_some())
    }

    /// A stream's data, unpacked when it is FlateDecode (alone, without predictors) and within the cap.
    pub fn stream_data(&self, o: &Obj, cap: u64) -> Option<Vec<u8>> {
        let (s, e) = o.stream?;
        let t = self.toks(o);
        let es = entries(&t, 0);
        let filter = get(&es, b"Filter");
        let raw = &self.file[s..e.min(self.file.len())];
        match filter {
            None => Some(raw[..raw.len().min(cap as usize)].to_vec()),
            Some((a, b)) => {
                let flate = as_name(&t, a, b) == Some(b"FlateDecode")
                    || (b - a == 3 && matches!(t[a].tok, Tok::ArrOpen) && is_name(&t[a + 1], b"FlateDecode"));
                if !flate || get(&es, b"DecodeParms").is_some() {
                    return None;
                }
                let mut out = vec![];
                let mut z = flate2::read::ZlibDecoder::new(raw).take(cap + 1);
                let _ = z.read_to_end(&mut out); // a damaged stream gives what could be read
                (out.len() as u64 <= cap).then_some(out)
            }
        }
    }

    fn unpack_object_streams(&mut self) {
        let mut containers: Vec<Obj> = self
            .objs
            .values()
            .filter(|o| {
                o.stream.is_some() && {
                    let t = self.toks(o);
                    let es = entries(&t, 0);
                    get(&es, b"Type").and_then(|(a, b)| as_name(&t, a, b)) == Some(b"ObjStm")
                }
            })
            .cloned()
            .collect();
        containers.sort_by_key(|o| o.order);
        let mut total = 0u64;
        for c in containers {
            if total >= MAX_UNPACKED {
                self.complete = false;
                break;
            }
            let t = self.toks(&c);
            let es = entries(&t, 0);
            let n = get(&es, b"N").and_then(|(a, b)| as_int(&t, a, b)).unwrap_or(0).clamp(0, 100_000) as usize;
            let first = get(&es, b"First").and_then(|(a, b)| as_int(&t, a, b)).unwrap_or(-1);
            let Some(data) = self.stream_data(&c, MAX_UNPACKED - total) else {
                self.complete = false;
                continue;
            };
            total += data.len() as u64;
            let Ok(first) = usize::try_from(first) else { continue };
            if first > data.len() {
                continue;
            }
            let head = tokens(&data, 0, first, 2 * n);
            let pairs: Vec<(u32, usize)> = head
                .chunks(2)
                .filter_map(|p| match (&p[0].tok, p.get(1).map(|x| &x.tok)) {
                    (Tok::Int(num), Some(Tok::Int(off))) => Some((u32::try_from(*num).ok()?, usize::try_from(*off).ok()?)),
                    _ => None,
                })
                .collect();
            self.unpacked.push(data);
            let buf = self.unpacked.len();
            let len = self.unpacked[buf - 1].len();
            for (i, &(num, off)) in pairs.iter().enumerate() {
                let s = first.saturating_add(off).min(len);
                let e = pairs.get(i + 1).map_or(len, |&(_, o2)| first.saturating_add(o2).min(len)).max(s);
                let newer = self.objs.get(&num).is_none_or(|old| old.order < c.order);
                if newer && (self.objs.len() < MAX_OBJS || self.objs.contains_key(&num)) {
                    self.objs.insert(num, Obj { num, gen: 0, buf, body: (s, e), stream: None, order: c.order });
                }
            }
        }
    }
}

pub fn find(hay: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || from >= hay.len() || needle.len() > hay.len() - from {
        return None;
    }
    let first = needle[0];
    let mut i = from;
    while i + needle.len() <= hay.len() {
        let at = i + hay[i..hay.len() - needle.len() + 1].iter().position(|&b| b == first)?;
        if &hay[at..at + needle.len()] == needle {
            return Some(at);
        }
        i = at + 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_hide_nothing() {
        let t = tokens(b"/J#61vaScript /OpenAction 12 0 R (a\\(b\\)c) <48 49> [1 2.5] <</A 1>>", 0, 100, 100);
        assert_eq!(t[0].tok, Tok::Name(b"JavaScript".to_vec()));
        assert_eq!(value_end(&t, 2), 5, "a reference is one value");
        assert_eq!(t[5].tok, Tok::Str(b"a(b)c".to_vec()));
        assert_eq!(t[6].tok, Tok::Str(b"HI".to_vec()));
        assert_eq!(value_end(&t, 7), 11);
        let es = entries(&t, 11);
        assert_eq!(es.len(), 1);
    }

    #[test]
    fn objects_and_object_streams_are_found() {
        let inner = b"5 0 6 9 <</S/URI>> <</A 1>>";
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut z, inner).unwrap();
        let packed = z.finish().unwrap();
        let mut f = b"%PDF-1.7\n1 0 obj <</Type/Catalog/OpenAction 5 0 R>> endobj\n".to_vec();
        f.extend_from_slice(format!("2 0 obj <</Type/ObjStm/N 2/First 8/Filter/FlateDecode/Length {}>> stream\n", packed.len()).as_bytes());
        f.extend_from_slice(&packed);
        f.extend_from_slice(b"\nendstream endobj\ntrailer <</Root 1 0 R/Size 7>>\n%%EOF");
        let d = Doc::scan(&f);
        assert_eq!(d.version, "1.7");
        assert!(d.objs.contains_key(&1) && d.objs.contains_key(&2) && d.objs.contains_key(&5) && d.objs.contains_key(&6));
        assert_eq!(d.toks(&d.objs[&5])[1].tok, Tok::Name(b"S".to_vec()));
        assert_eq!(d.trailer_ref(b"Root"), Some(1));
        assert!(d.complete);
    }

    #[test]
    fn hostile_bytes_end_without_panic() {
        for s in [
            &b"%PDF-1.4 1 0 obj << /Length 999999999999 >> stream"[..],
            b"1 0 obj",
            b"((((((",
            b"<<<<<<<<",
            b"/#",
            b"/#4",
            b"<4",
            b"trailer",
            b"9 9 obj stream",
            b"\\",
        ] {
            let d = Doc::scan(s);
            for o in d.objs.values() {
                let t = d.toks(o);
                let _ = entries(&t, 0);
            }
        }
        let deep = b"[".repeat(100_000);
        let t = tokens(&deep, 0, deep.len(), 1_000_000);
        assert_eq!(value_end(&t, 0), t.len());
    }
}
