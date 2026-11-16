//! ZIP files (Office and OpenDocument files are ZIP files too), read from hostile input: the central directory from the end,
//! an entry's bytes from its local header, deflated entries inflated in memory with a cap. Nothing is ever written to disk
//! while reading. The writer makes the cleaned copies of `heimdall-strip`: entries copied as they are compressed, or new
//! content deflated, with fixed times and without extra fields or comments.

use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::FileExt;

/// Where the bytes come from: a file (read where needed) or memory.
pub trait Source {
    fn size(&self) -> u64;
    fn read_at(&self, off: u64, buf: &mut [u8]) -> std::io::Result<()>;
}

impl Source for &[u8] {
    fn size(&self) -> u64 {
        self.len() as u64
    }
    fn read_at(&self, off: u64, buf: &mut [u8]) -> std::io::Result<()> {
        let end = off.checked_add(buf.len() as u64).filter(|&e| e <= self.len() as u64);
        match end {
            Some(e) => {
                buf.copy_from_slice(&self[off as usize..e as usize]);
                Ok(())
            }
            None => Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "past the end")),
        }
    }
}

impl Source for Vec<u8> {
    fn size(&self) -> u64 {
        self.len() as u64
    }
    fn read_at(&self, off: u64, buf: &mut [u8]) -> std::io::Result<()> {
        (&self[..]).read_at(off, buf)
    }
}

impl Source for File {
    fn size(&self) -> u64 {
        self.metadata().map(|m| m.len()).unwrap_or(0)
    }
    fn read_at(&self, off: u64, buf: &mut [u8]) -> std::io::Result<()> {
        self.read_exact_at(buf, off)
    }
}

/// Most entries listed (a central directory with more is refused).
pub const MAX_ENTRIES: usize = 65_536;
/// The largest central directory read.
const MAX_CD: u64 = 64 << 20;

/// One entry of the central directory.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Entry {
    pub name: Vec<u8>,
    pub method: u16,
    pub flags: u16,
    pub crc: u32,
    pub csize: u64,
    pub usize: u64,
    pub local: u64,
    pub time: u16,
    pub date: u16,
    pub made_by: u16,
    pub external: u32,
    /// Extra fields in the central directory (times, owner ids...).
    pub extra_len: u16,
    pub comment_len: u16,
}

impl Entry {
    pub fn name_lossy(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }
    pub fn is_dir(&self) -> bool {
        self.name.ends_with(b"/")
    }
    pub fn encrypted(&self) -> bool {
        self.flags & 1 != 0
    }
}

/// A ZIP file's directory.
#[derive(Clone, Debug, Default)]
pub struct Archive {
    pub entries: Vec<Entry>,
    pub comment: Vec<u8>,
}

impl Archive {
    pub fn find(&self, name: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.name == name.as_bytes())
    }
}

fn u16_at(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[i], b[i + 1]])
}
fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}
fn u64_at(b: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(b[i..i + 8].try_into().unwrap())
}

fn bad(s: &str) -> String {
    format!("not a readable ZIP file: {s}")
}

/// Reads the directory at the end of a ZIP file.
pub fn read(src: &dyn Source) -> Result<Archive, String> {
    let size = src.size();
    if size < 22 {
        return Err(bad("too short"));
    }
    // the end record is in the last 64 KiB + 22 bytes (its comment is at most 65535)
    let tail_len = size.min(65_535 + 22);
    let mut tail = vec![0u8; tail_len as usize];
    src.read_at(size - tail_len, &mut tail).map_err(|e| bad(&e.to_string()))?;
    let eocd = (0..=tail.len() - 22).rev().find(|&i| &tail[i..i + 4] == b"PK\x05\x06").ok_or_else(|| bad("no end record"))?;
    let eocd_off = size - tail_len + eocd as u64;
    let mut count = u16_at(&tail, eocd + 10) as u64;
    let mut cd_size = u32_at(&tail, eocd + 12) as u64;
    let mut cd_off = u32_at(&tail, eocd + 16) as u64;
    let clen = u16_at(&tail, eocd + 20) as usize;
    let comment = tail[eocd + 22..(eocd + 22 + clen).min(tail.len())].to_vec();
    // ZIP64: the locator just before the end record points at the ZIP64 end record
    if (count == 0xFFFF || cd_size == 0xFFFF_FFFF || cd_off == 0xFFFF_FFFF) && eocd_off >= 20 {
        let mut loc = [0u8; 20];
        src.read_at(eocd_off - 20, &mut loc).map_err(|e| bad(&e.to_string()))?;
        if &loc[0..4] == b"PK\x06\x07" {
            let z = u64_at(&loc, 8);
            let mut rec = [0u8; 56];
            src.read_at(z, &mut rec).map_err(|e| bad(&e.to_string()))?;
            if &rec[0..4] != b"PK\x06\x06" {
                return Err(bad("broken ZIP64 end record"));
            }
            count = u64_at(&rec, 32);
            cd_size = u64_at(&rec, 40);
            cd_off = u64_at(&rec, 48);
        }
    }
    if count as usize > MAX_ENTRIES {
        return Err(bad("too many entries"));
    }
    if cd_size > MAX_CD || cd_off.checked_add(cd_size).is_none_or(|e| e > size) {
        return Err(bad("the directory is out of place"));
    }
    let mut cd = vec![0u8; cd_size as usize];
    src.read_at(cd_off, &mut cd).map_err(|e| bad(&e.to_string()))?;
    let mut entries = Vec::with_capacity(count as usize);
    let mut i = 0usize;
    while i + 46 <= cd.len() && entries.len() < MAX_ENTRIES {
        if &cd[i..i + 4] != b"PK\x01\x02" {
            break;
        }
        let nlen = u16_at(&cd, i + 28) as usize;
        let xlen = u16_at(&cd, i + 30) as usize;
        let klen = u16_at(&cd, i + 32) as usize;
        let end = i + 46 + nlen + xlen + klen;
        if end > cd.len() {
            break;
        }
        let mut e = Entry {
            made_by: u16_at(&cd, i + 4),
            flags: u16_at(&cd, i + 8),
            method: u16_at(&cd, i + 10),
            time: u16_at(&cd, i + 12),
            date: u16_at(&cd, i + 14),
            crc: u32_at(&cd, i + 16),
            csize: u32_at(&cd, i + 20) as u64,
            usize: u32_at(&cd, i + 24) as u64,
            external: u32_at(&cd, i + 38),
            local: u32_at(&cd, i + 42) as u64,
            name: cd[i + 46..i + 46 + nlen].to_vec(),
            extra_len: xlen as u16,
            comment_len: klen as u16,
        };
        // ZIP64 extra field: the 64-bit sizes and offset, in that order, for those set to all ones
        let mut x = i + 46 + nlen;
        let xend = x + xlen;
        while x + 4 <= xend {
            let id = u16_at(&cd, x);
            let n = u16_at(&cd, x + 2) as usize;
            if x + 4 + n > xend {
                break;
            }
            if id == 1 {
                let mut p = x + 4;
                for field in [&mut e.usize, &mut e.csize, &mut e.local] {
                    if *field == 0xFFFF_FFFF && p + 8 <= x + 4 + n {
                        *field = u64_at(&cd, p);
                        p += 8;
                    }
                }
            }
            x += 4 + n;
        }
        entries.push(e);
        i = end;
    }
    Ok(Archive { entries, comment })
}

/// Where an entry's compressed bytes are: (start, length).
pub fn data_range(src: &dyn Source, e: &Entry) -> Result<(u64, u64), String> {
    let mut h = [0u8; 30];
    src.read_at(e.local, &mut h).map_err(|_| bad("an entry is out of place"))?;
    if &h[0..4] != b"PK\x03\x04" {
        return Err(bad("an entry has no header"));
    }
    let start = e.local + 30 + u16_at(&h, 26) as u64 + u16_at(&h, 28) as u64;
    match start.checked_add(e.csize) {
        Some(end) if end <= src.size() => Ok((start, e.csize)),
        _ => Err(bad("an entry runs past the end")),
    }
}

/// The compressed bytes of an entry as they are (for copying).
pub fn raw(src: &dyn Source, e: &Entry, cap: u64) -> Result<Vec<u8>, String> {
    let (start, len) = data_range(src, e)?;
    if len > cap {
        return Err("an entry is too big".into());
    }
    let mut b = vec![0u8; len as usize];
    src.read_at(start, &mut b).map_err(|e| bad(&e.to_string()))?;
    Ok(b)
}

/// An entry's content, inflated in memory: at most `cap` bytes, and no more than `budget` in total over a file (each read takes
/// from it). Only stored and deflated entries are read; encrypted ones never.
pub fn content(src: &dyn Source, e: &Entry, cap: u64, budget: &mut u64) -> Result<Vec<u8>, String> {
    if e.encrypted() {
        return Err("the entry is encrypted".into());
    }
    let limit = cap.min(*budget);
    // compressed data is never much bigger than what it unpacks to
    let packed = raw(src, e, limit.saturating_add(limit / 64).saturating_add(4096))?;
    let out = match e.method {
        0 => {
            if packed.len() as u64 > limit {
                return Err("an entry is too big".into());
            }
            packed
        }
        8 => {
            let mut out = Vec::new();
            let mut d = flate2::read::DeflateDecoder::new(&packed[..]).take(limit + 1);
            d.read_to_end(&mut out).map_err(|_| "a damaged compressed entry".to_string())?;
            if out.len() as u64 > limit {
                return Err("an entry is too big when unpacked".into());
            }
            out
        }
        m => return Err(format!("compression method {m} is not read")),
    };
    *budget = budget.saturating_sub(out.len() as u64);
    Ok(out)
}

/// The DOS date and time every cleaned entry gets: 1980-01-01 00:00 (the earliest a ZIP file can say).
pub const DOS_DATE: u16 = (1 << 5) | 1;
pub const DOS_TIME: u16 = 0;

/// Writes a ZIP file entry by entry, then its directory. No extra fields, no comments, fixed times, Unix permissions 644
/// (folders 755), "made by" Unix: nothing about who made it or when.
pub struct Writer<W: Write> {
    out: W,
    at: u64,
    cd: Vec<u8>,
    count: u64,
}

impl<W: Write> Writer<W> {
    pub fn new(out: W) -> Self {
        Writer { out, at: 0, cd: vec![], count: 0 }
    }

    fn put(&mut self, b: &[u8]) -> std::io::Result<()> {
        self.out.write_all(b)?;
        self.at += b.len() as u64;
        Ok(())
    }

    /// An entry from compressed bytes as they are (`method` 0 or 8; crc and sizes of the content).
    pub fn raw(&mut self, name: &[u8], method: u16, crc: u32, usize: u64, data: &[u8]) -> std::io::Result<()> {
        if usize > 0xFFFF_FFFE || data.len() as u64 > 0xFFFF_FFFE || self.at > 0xFFFF_FFFE || name.len() > 0xFFFF {
            return Err(std::io::Error::other("the copy would need ZIP64, which is not written"));
        }
        let flags: u16 = if std::str::from_utf8(name).is_ok() && !name.is_ascii() { 1 << 11 } else { 0 };
        let local = self.at as u32;
        let mut h = Vec::with_capacity(30 + name.len());
        h.extend_from_slice(b"PK\x03\x04");
        h.extend_from_slice(&20u16.to_le_bytes());
        h.extend_from_slice(&flags.to_le_bytes());
        h.extend_from_slice(&method.to_le_bytes());
        h.extend_from_slice(&DOS_TIME.to_le_bytes());
        h.extend_from_slice(&DOS_DATE.to_le_bytes());
        h.extend_from_slice(&crc.to_le_bytes());
        h.extend_from_slice(&(data.len() as u32).to_le_bytes());
        h.extend_from_slice(&(usize as u32).to_le_bytes());
        h.extend_from_slice(&(name.len() as u16).to_le_bytes());
        h.extend_from_slice(&0u16.to_le_bytes());
        h.extend_from_slice(name);
        self.put(&h)?;
        self.put(data)?;
        let mode: u32 = if name.ends_with(b"/") { 0o040755 } else { 0o100644 };
        let c = &mut self.cd;
        c.extend_from_slice(b"PK\x01\x02");
        c.extend_from_slice(&(0x0300u16 | 20).to_le_bytes()); // made by Unix, version 2.0
        c.extend_from_slice(&20u16.to_le_bytes());
        c.extend_from_slice(&flags.to_le_bytes());
        c.extend_from_slice(&method.to_le_bytes());
        c.extend_from_slice(&DOS_TIME.to_le_bytes());
        c.extend_from_slice(&DOS_DATE.to_le_bytes());
        c.extend_from_slice(&crc.to_le_bytes());
        c.extend_from_slice(&(data.len() as u32).to_le_bytes());
        c.extend_from_slice(&(usize as u32).to_le_bytes());
        c.extend_from_slice(&(name.len() as u16).to_le_bytes());
        c.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // extra, comment, disk, internal attributes
        c.extend_from_slice(&(mode << 16).to_le_bytes());
        c.extend_from_slice(&local.to_le_bytes());
        c.extend_from_slice(name);
        self.count += 1;
        Ok(())
    }

    /// An entry with new content: stored when `store` (an OpenDocument file's "mimetype"), else deflated.
    pub fn file(&mut self, name: &[u8], content: &[u8], store: bool) -> std::io::Result<()> {
        let mut crc = flate2::Crc::new();
        crc.update(content);
        if store {
            return self.raw(name, 0, crc.sum(), content.len() as u64, content);
        }
        let mut z = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(content)?;
        let packed = z.finish()?;
        self.raw(name, 8, crc.sum(), content.len() as u64, &packed)
    }

    /// The directory and the end record; gives back the writer.
    pub fn finish(mut self) -> std::io::Result<W> {
        if self.count > 0xFFFE {
            return Err(std::io::Error::other("too many entries"));
        }
        let cd = std::mem::take(&mut self.cd);
        let off = self.at as u32;
        self.put(&cd)?;
        let mut e = Vec::with_capacity(22);
        e.extend_from_slice(b"PK\x05\x06");
        e.extend_from_slice(&[0, 0, 0, 0]);
        e.extend_from_slice(&(self.count as u16).to_le_bytes());
        e.extend_from_slice(&(self.count as u16).to_le_bytes());
        e.extend_from_slice(&(cd.len() as u32).to_le_bytes());
        e.extend_from_slice(&off.to_le_bytes());
        e.extend_from_slice(&0u16.to_le_bytes());
        self.put(&e)?;
        Ok(self.out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn sample() -> Vec<u8> {
        let mut w = Writer::new(Vec::new());
        w.file(b"mimetype", b"application/vnd.oasis.opendocument.text", true).unwrap();
        w.file(b"content.xml", b"<doc>hello hello hello hello</doc>", false).unwrap();
        w.file(b"dir/", b"", true).unwrap();
        w.finish().unwrap()
    }

    #[test]
    fn what_is_written_reads_back() {
        let z = sample();
        let a = read(&z).unwrap();
        assert_eq!(a.entries.len(), 3);
        let mut budget = 1 << 20;
        assert_eq!(content(&z, a.find("content.xml").unwrap(), 1024, &mut budget).unwrap(), b"<doc>hello hello hello hello</doc>");
        assert_eq!(a.find("mimetype").unwrap().method, 0);
        assert!(a.find("dir/").unwrap().is_dir());
        assert!(a.entries.iter().all(|e| e.date == DOS_DATE && e.extra_len == 0 && e.comment_len == 0));
    }

    #[test]
    fn the_caps_hold() {
        // 1 MiB of zeros deflates to about a kilobyte: reading it with a 1000-byte cap fails, as does an exhausted budget
        let mut w = Writer::new(Vec::new());
        w.file(b"bomb", &vec![0u8; 1 << 20], false).unwrap();
        let z = w.finish().unwrap();
        let a = read(&z).unwrap();
        let mut budget = 1 << 30;
        assert!(content(&z, &a.entries[0], 1000, &mut budget).is_err());
        let mut small = 10;
        assert!(content(&z, &a.entries[0], 1 << 30, &mut small).is_err());
        let mut budget = 2 << 20;
        assert_eq!(content(&z, &a.entries[0], 1 << 21, &mut budget).unwrap().len(), 1 << 20);
        assert_eq!(budget, 1 << 20, "the budget pays for what was read");
    }

    #[test]
    fn damage_is_an_error_not_a_panic() {
        let z = sample();
        for cut in 0..z.len() {
            let _ = read(&&z[..cut]).map(|a| {
                let mut b = 1 << 20;
                a.entries.iter().for_each(|e| {
                    let _ = content(&&z[..cut], e, 1 << 16, &mut b);
                })
            });
        }
        let mut flipped = z.clone();
        for i in 0..flipped.len() {
            flipped[i] ^= 0xFF;
            if let Ok(a) = read(&flipped) {
                let mut b = 1 << 20;
                for e in &a.entries {
                    let _ = content(&flipped, e, 1 << 16, &mut b);
                }
            }
            flipped[i] ^= 0xFF;
        }
    }
}
