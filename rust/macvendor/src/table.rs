//! The table: the IEEE's files read into sorted arrays, one per block size, with every name stored once (Go:
//! internal/macvendor/table.go).
//!
//! Two layouts are read, told apart by the first line:
//!
//! - the text lists (hwdata's `oui.txt` and `iab.txt`, the IEEE's `.txt` files): a line `XX-XX-XX   (hex)   Name`, then
//!   `XXXXXX   (base 16)   Name` for a 24-bit block or `000000-0FFFFF   (base 16)   Name` for a smaller one inside it, then
//!   the address lines;
//! - the IEEE's CSV files (`Registry,Assignment,Organization Name,Organization Address`), quoted fields as RFC 4180 has them
//!   (commas, doubled quotes and line breaks inside quotes).
//!
//! Hostile input is expected (a damaged download, a planted file): lines are capped at 4 KiB, a CSV record at 16 KiB, the table
//! at a million blocks, a file at 64 MiB; only regular files are opened. Broken lines are skipped; the first block for a
//! prefix wins.

use crate::name;
use crate::{Answer, DataPaths, Mac, Registry, Vendor};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

/// The longest line kept, in bytes (the rest of a longer line is skipped).
pub const MAX_LINE: usize = 4096;
/// The longest CSV record (lines joined by a quoted line break), in bytes; a longer one is dropped.
pub const MAX_RECORD: usize = 16384;
/// The most blocks a table holds.
pub const MAX_ENTRIES: usize = 1 << 20;
/// The largest file read, in bytes (the IEEE's biggest is about 6 MB).
pub const MAX_FILE: u64 = 64 << 20;

#[derive(Clone, Copy, Debug)]
struct Entry {
    /// The block's leading bits as a number.
    key: u64,
    /// Index into the names.
    name: u32,
    registry: Registry,
}

#[derive(Clone, Copy, Debug)]
struct Name {
    full: u32,
    full_len: u16,
    short: u32,
    short_len: u16,
}

/// The blocks of every registry loaded, ready for lookups.
#[derive(Debug, Default)]
pub struct Table {
    /// One sorted array per block size, the longest first (36, 28, 24 bits with all four registries).
    by_bits: Vec<(u8, Vec<Entry>)>,
    names: Vec<Name>,
    text: String,
}

impl Table {
    /// The IEEE's files from `paths`: for each registry the first of its files that gives at least one block. MA-S:
    /// `oui36.csv`, `oui36.txt`; IAB: `iab.csv`, `iab.txt`, then hwdata's `iab.txt`; MA-M: `mam.csv`, `mam.txt`; MA-L:
    /// `oui.csv`, `oui.txt`, then hwdata's `oui.txt`. No file at all gives an empty table (every maker unknown).
    pub fn load(paths: &DataPaths) -> Table {
        let mut b = Builder::new();
        let slots: [(Registry, [&str; 2], Option<&str>); 4] = [
            (Registry::MaS, ["oui36.csv", "oui36.txt"], None),
            (Registry::Iab, ["iab.csv", "iab.txt"], Some("iab.txt")),
            (Registry::MaM, ["mam.csv", "mam.txt"], None),
            (Registry::MaL, ["oui.csv", "oui.txt"], Some("oui.txt")),
        ];
        for (registry, ieee, hwdata) in slots {
            let files = ieee.iter().map(|f| paths.ieee_dir.join(f)).chain(hwdata.map(|f| paths.hwdata_dir.join(f)));
            for f in files {
                if b.read_file(&f, registry) > 0 {
                    break;
                }
            }
        }
        b.finish()
    }

    /// What the address is: a special address, multicast, private (locally administered), a registered maker's (the longest
    /// block wins) or unknown. Allocates nothing.
    pub fn lookup(&self, mac: &Mac) -> Answer<'_> {
        if let Some(s) = crate::special::find(mac) {
            return Answer::Special(s);
        }
        if crate::is_multicast(mac) {
            return Answer::Multicast;
        }
        if crate::is_local(mac) {
            return Answer::Private;
        }
        let v = crate::mac_value(mac);
        for (bits, entries) in &self.by_bits {
            if let Some(e) = find(entries, v >> (48 - *bits as u32)) {
                return Answer::Vendor(self.vendor(e, *bits));
            }
        }
        Answer::Unknown
    }

    /// [`Table::lookup`] on an address as text ([`crate::parse_mac`]); [`Answer::Invalid`] when it is not one.
    pub fn lookup_str(&self, mac: &str) -> Answer<'_> {
        match crate::parse_mac(mac) {
            Some(m) => self.lookup(&m),
            None => Answer::Invalid,
        }
    }

    /// The company a 24-bit identifier is registered to (MA-L): what a Wi-Fi vendor-specific element names, for example.
    pub fn lookup_oui(&self, oui: [u8; 3]) -> Option<Vendor<'_>> {
        let key = (oui[0] as u64) << 16 | (oui[1] as u64) << 8 | oui[2] as u64;
        let (_, entries) = self.by_bits.iter().find(|(b, _)| *b == 24)?;
        find(entries, key).map(|e| self.vendor(e, 24))
    }

    /// How many blocks the table holds.
    pub fn len(&self) -> usize {
        self.by_bits.iter().map(|(_, e)| e.len()).sum()
    }

    /// No blocks at all (no file was found or readable).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// How many blocks of each size and registry (the benchmark prints them).
    pub fn counts(&self) -> Vec<(Registry, u8, usize)> {
        let mut out: Vec<(Registry, u8, usize)> = Vec::new();
        for (bits, entries) in &self.by_bits {
            for e in entries {
                match out.iter_mut().find(|(r, b, _)| *r == e.registry && *b == *bits) {
                    Some(c) => c.2 += 1,
                    None => out.push((e.registry, *bits, 1)),
                }
            }
        }
        out.sort();
        out
    }

    fn vendor(&self, e: &Entry, bits: u8) -> Vendor<'_> {
        let n = &self.names[e.name as usize];
        Vendor {
            name: &self.text[n.full as usize..n.full as usize + n.full_len as usize],
            short: &self.text[n.short as usize..n.short as usize + n.short_len as usize],
            registry: e.registry,
            bits,
        }
    }
}

fn find(entries: &[Entry], key: u64) -> Option<&Entry> {
    entries.binary_search_by_key(&key, |e| e.key).ok().map(|i| &entries[i])
}

/// Collects blocks from files, then sorts them into a [`Table`].
#[derive(Debug, Default)]
pub struct Builder {
    /// (bits, key, registry, name), in the order read
    raw: Vec<(u8, u64, Registry, u32)>,
    names: Vec<Name>,
    text: String,
    intern: HashMap<String, u32>,
}

impl Builder {
    /// An empty builder.
    pub fn new() -> Builder {
        Builder::default()
    }

    /// Reads one file ([`Builder::read`]); a missing file, one that is not a regular file or one over [`MAX_FILE`] adds
    /// nothing. Returns how many blocks it added.
    pub fn read_file(&mut self, path: &Path, hint: Registry) -> usize {
        use std::os::unix::fs::OpenOptionsExt;
        // non-blocking, so a FIFO put in the folder cannot stall the open; it is refused just below
        let Ok(f) = std::fs::OpenOptions::new().read(true).custom_flags(0o4000).open(path) else { return 0 };
        match f.metadata() {
            Ok(m) if m.is_file() && m.len() <= MAX_FILE => {}
            _ => return 0,
        }
        self.read(BufReader::new(f.take(MAX_FILE)), hint)
    }

    /// Reads a text list or a CSV file (the first line tells which); `hint` is the registry of a text list's blocks (the CSV
    /// files name their own). Returns how many blocks it added.
    pub fn read(&mut self, mut r: impl BufRead, hint: Registry) -> usize {
        let before = self.raw.len();
        let mut line = Vec::new();
        if !next_line(&mut r, &mut line) {
            return 0;
        }
        if line.starts_with(b"\xef\xbb\xbf") {
            line.drain(..3);
        }
        if line.len() >= 9 && line[..9].eq_ignore_ascii_case(b"registry,") {
            self.read_csv(line, r);
        } else {
            self.read_txt(line, r, hint);
        }
        self.raw.len() - before
    }

    fn read_txt(&mut self, first: Vec<u8>, mut r: impl BufRead, hint: Registry) {
        // the block on the last "(hex)" line, until its "(base 16)" line says whether it is smaller than 24 bits
        let mut last: Option<usize> = None;
        let mut line = first;
        loop {
            if let Some(at) = index(&line, b"(hex)") {
                last = prefix24(trim(&line[..at])).and_then(|p| self.add(24, p, hint, &line[at + 5..]));
            } else if let Some(at) = index(&line, b"(base 16)") {
                if let Some(i) = last.take() {
                    let (_, p24, _, _) = self.raw[i];
                    if let Some((bits, key)) = range(p24, trim(&line[..at])) {
                        self.raw[i].0 = bits;
                        self.raw[i].1 = key;
                    }
                }
            }
            if !next_line(&mut r, &mut line) {
                break;
            }
        }
    }

    fn read_csv(&mut self, first: Vec<u8>, mut r: impl BufRead) {
        let mut rec = Csv::default();
        let mut line = first;
        loop {
            if rec.line(&line) {
                if rec.fields >= 3 {
                    self.csv_row(&rec.cols);
                }
                rec = Csv::default();
            } else if rec.bytes > MAX_RECORD {
                rec = Csv::default();
            }
            if !next_line(&mut r, &mut line) {
                break;
            }
        }
    }

    fn csv_row(&mut self, cols: &[Vec<u8>; 3]) {
        let Some(registry) = std::str::from_utf8(&cols[0]).ok().and_then(Registry::from_name) else { return };
        let a = trim(&cols[1]);
        if !(6..=11).contains(&a.len()) {
            return;
        }
        let mut key = 0u64;
        for &c in a {
            let Some(v) = crate::hex_value(c) else { return };
            key = key << 4 | v as u64;
        }
        self.add(4 * a.len() as u8, key, registry, &cols[2]);
    }

    /// Adds one block of `bits` leading bits; `raw_name` is cleaned ([`name::clean`]); an empty name or a full table adds
    /// nothing. Returns the block's place in the order read.
    pub fn add(&mut self, bits: u8, key: u64, registry: Registry, raw_name: &[u8]) -> Option<usize> {
        if self.raw.len() >= MAX_ENTRIES || !(1..=48).contains(&bits) || key >> bits != 0 {
            return None;
        }
        let full = name::clean(raw_name);
        if full.is_empty() {
            return None;
        }
        let id = match self.intern.get(&full) {
            Some(&id) => id,
            None => {
                let short = name::short(&full);
                let at = self.text.len() as u32;
                self.text.push_str(&full);
                // the short name is usually the start of the full one: stored once
                let short_at = if full.starts_with(&short) {
                    at
                } else {
                    let s = self.text.len() as u32;
                    self.text.push_str(&short);
                    s
                };
                let id = self.names.len() as u32;
                self.names.push(Name { full: at, full_len: full.len() as u16, short: short_at, short_len: short.len() as u16 });
                self.intern.insert(full, id);
                id
            }
        };
        self.raw.push((bits, key, registry, id));
        Some(self.raw.len() - 1)
    }

    /// The table: blocks sorted by size (longest first) and prefix; of two blocks with the same prefix the first read stays.
    pub fn finish(self) -> Table {
        let mut by_bits: Vec<(u8, Vec<Entry>)> = Vec::new();
        for (bits, key, registry, name) in self.raw {
            let e = Entry { key, name, registry };
            match by_bits.iter_mut().find(|(b, _)| *b == bits) {
                Some((_, v)) => v.push(e),
                None => by_bits.push((bits, vec![e])),
            }
        }
        by_bits.sort_by_key(|a| std::cmp::Reverse(a.0));
        for (_, v) in &mut by_bits {
            // stable: the first read of equal prefixes comes first and is kept
            v.sort_by_key(|e| e.key);
            v.dedup_by_key(|e| e.key);
            v.shrink_to_fit();
        }
        let mut text = self.text;
        text.shrink_to_fit();
        let mut names = self.names;
        names.shrink_to_fit();
        Table { by_bits, names, text }
    }
}

/// One CSV record being read: the first three fields (registry, assignment, name) kept, the rest counted.
#[derive(Default)]
struct Csv {
    cols: [Vec<u8>; 3],
    fields: usize,
    quoted: bool,
    started: bool,
    bytes: usize,
}

impl Csv {
    /// Reads one line into the record; true when the record ends with it (no quote left open).
    fn line(&mut self, line: &[u8]) -> bool {
        self.bytes += line.len() + 1;
        let mut i = 0;
        while i < line.len() {
            let c = line[i];
            if self.quoted {
                if c == b'"' {
                    if line.get(i + 1) == Some(&b'"') {
                        self.push(b'"');
                        i += 1;
                    } else {
                        self.quoted = false;
                    }
                } else {
                    self.push(c);
                }
            } else if c == b'"' && !self.started {
                self.quoted = true;
                self.started = true;
            } else if c == b',' {
                self.fields += 1;
                self.started = false;
            } else {
                self.push(c);
                self.started = true;
            }
            i += 1;
        }
        if self.quoted {
            self.push(b'\n');
            return false;
        }
        self.fields += 1;
        true
    }

    fn push(&mut self, c: u8) {
        if let Some(col) = self.cols.get_mut(self.fields) {
            col.push(c);
        }
    }
}

/// Reads the next line into `buf` without its line break (a `\r` before it goes too), at most [`MAX_LINE`] bytes of it.
/// False at the end of the input (or on a read error) with nothing read.
fn next_line(r: &mut impl BufRead, buf: &mut Vec<u8>) -> bool {
    buf.clear();
    let mut total = 0usize;
    let mut last = 0u8;
    let mut ended = false;
    while !ended {
        let chunk = match r.fill_buf() {
            Ok(c) if !c.is_empty() => c,
            _ => break,
        };
        let (take, used) = match chunk.iter().position(|&b| b == b'\n') {
            Some(p) => {
                ended = true;
                (p, p + 1)
            }
            None => (chunk.len(), chunk.len()),
        };
        if take > 0 {
            last = chunk[take - 1];
            let room = (MAX_LINE + 1).saturating_sub(buf.len());
            buf.extend_from_slice(&chunk[..take.min(room)]);
        }
        total += used;
        r.consume(used);
    }
    if total == 0 {
        return false;
    }
    if last == b'\r' && buf.len() <= MAX_LINE {
        buf.pop();
    }
    buf.truncate(MAX_LINE);
    true
}

fn trim(b: &[u8]) -> &[u8] {
    let s = b.iter().position(|&c| c != b' ' && c != b'\t').unwrap_or(b.len());
    let e = b.iter().rposition(|&c| c != b' ' && c != b'\t').map_or(s, |p| p + 1);
    &b[s..e.max(s)]
}

fn index(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// "28-6F-B9" as a number.
fn prefix24(b: &[u8]) -> Option<u64> {
    if b.len() != 8 || b[2] != b'-' || b[5] != b'-' {
        return None;
    }
    let mut v = 0u64;
    for (i, &c) in b.iter().enumerate() {
        if i == 2 || i == 5 {
            continue;
        }
        v = v << 4 | crate::hex_value(c)? as u64;
    }
    Some(v)
}

/// A "(base 16)" line's range ("0D7000-0D7FFF") inside the 24-bit block `p24`: the smaller block's size in bits and its
/// prefix. None for a single "286FB9" (the block is the whole 24 bits) or a range that is not an aligned power of two.
fn range(p24: u64, b: &[u8]) -> Option<(u8, u64)> {
    if b.len() != 13 || b[6] != b'-' {
        return None;
    }
    let num = |s: &[u8]| s.iter().try_fold(0u64, |v, &c| Some(v << 4 | crate::hex_value(c)? as u64));
    let (lo, hi) = (num(&b[..6])?, num(&b[7..])?);
    if hi < lo {
        return None;
    }
    let size = hi - lo + 1;
    if !size.is_power_of_two() || size >= 1 << 24 || lo % size != 0 {
        return None;
    }
    let k = size.trailing_zeros();
    Some(((48 - k) as u8, (p24 << 24 | lo) >> k))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &[u8]) -> Vec<Vec<u8>> {
        let mut r = text;
        let mut out = Vec::new();
        let mut buf = Vec::new();
        while next_line(&mut r, &mut buf) {
            out.push(buf.clone());
        }
        out
    }

    #[test]
    fn lines_lose_their_breaks_and_long_ones_are_capped() {
        assert_eq!(lines(b"a\r\nb\n\nc"), vec![b"a".to_vec(), b"b".to_vec(), vec![], b"c".to_vec()]);
        assert_eq!(lines(b"a\r\r\n"), vec![b"a\r".to_vec()]);
        assert_eq!(lines(b""), Vec::<Vec<u8>>::new());
        let long = [vec![b'x'; MAX_LINE + 10], b"\r\nnext\n".to_vec()].concat();
        let got = lines(&long);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].len(), MAX_LINE);
        assert_eq!(got[1], b"next");
        // exactly at the cap, with and without the carriage return
        assert_eq!(lines(&[vec![b'x'; MAX_LINE], b"\r\n".to_vec()].concat())[0].len(), MAX_LINE);
        assert_eq!(lines(&[vec![b'x'; MAX_LINE - 1], b"\r\n".to_vec()].concat())[0].len(), MAX_LINE - 1);
    }

    #[test]
    fn ranges_inside_a_block() {
        assert_eq!(range(0x40d855, b"0D7000-0D7FFF"), Some((36, 0x40d8550d7)));
        assert_eq!(range(0xb0c5ca, b"000000-0FFFFF"), Some((28, 0xb0c5ca0)));
        assert_eq!(range(0xb0c5ca, b"F00000-FFFFFF"), Some((28, 0xb0c5caf)));
        assert_eq!(range(0x286fb9, b"286FB9"), None);
        assert_eq!(range(0, b"000000-FFFFFF"), None);
        assert_eq!(range(0, b"000001-001000"), None);
        assert_eq!(range(0, b"001000-000FFF"), None);
        assert_eq!(range(0, b"0D7000-0D7FFG"), None);
    }

    #[test]
    fn trimming() {
        assert_eq!(trim(b" \tab c\t "), b"ab c");
        assert_eq!(trim(b" \t"), b"");
        assert_eq!(trim(b""), b"");
    }
}
