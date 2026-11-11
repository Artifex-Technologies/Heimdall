//! A zip archive read as Go's `archive/zip` reads it, for osv.dev's Linux archive (`intel-check kernel`): the end record found
//! the same way (the last 1 KiB, then the last 65 KiB; a truncated comment is no end), zip64 where the end record says so, the
//! central directory read until a header that is not one (only the count modulo 65536 must agree), Go's base-offset guess,
//! and each entry opened through its local header (stored or deflated; anything else is Go's `ErrAlgorithm`). The errors are
//! Go's texts.

use flate2::read::DeflateDecoder;
use std::io::Read;

pub const ERR_FORMAT: &str = "zip: not a valid zip file";

/// One entry of the central directory.
pub struct Entry {
    pub name: Vec<u8>,
    pub method: u16,
    pub compressed: u64,
    pub uncompressed: u64,
    header_offset: i64,
}

/// An open archive over the file's bytes.
pub struct Archive {
    data: memmap2::Mmap,
    pub entries: Vec<Entry>,
}

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn u64le(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// Go's `zip.OpenReader(path)`.
pub fn open(path: &str) -> Result<Archive, String> {
    let f = std::fs::File::open(path).map_err(|e| crate::goerr::path("open", path, &e))?;
    let md = f.metadata().map_err(|e| crate::goerr::path("stat", path, &e))?;
    if md.is_dir() {
        // Go reads the end record with ReadAt, which a folder refuses
        return Err(crate::goerr::path("read", path, &std::io::Error::from_raw_os_error(libc::EISDIR)));
    }
    if md.len() == 0 {
        return Err(ERR_FORMAT.into());
    }
    // SAFETY: a read-only private mapping of a file this command was given; a file shrunk under it would fault, as Go's
    // ReadAt would fail
    let data = unsafe { memmap2::Mmap::map(&f) }.map_err(|e| crate::goerr::path("read", path, &e))?;
    let entries = read_directory(&data)?;
    Ok(Archive { data, entries })
}

struct End {
    records: u64,
    size: u64,
    offset: u64,
}

fn find_signature(b: &[u8]) -> Option<usize> {
    if b.len() < 22 {
        return None;
    }
    let mut i = b.len() - 22;
    loop {
        if b[i] == b'P' && b[i + 1] == b'K' && b[i + 2] == 5 && b[i + 3] == 6 {
            let n = u16le(b, i + 20) as usize;
            if n + 22 + i > b.len() {
                return None; // a truncated comment
            }
            return Some(i);
        }
        if i == 0 {
            return None;
        }
        i -= 1;
    }
}

fn read_end(b: &[u8]) -> Result<(End, i64), String> {
    let size = b.len() as i64;
    let mut found = None;
    for (i, blen) in [1024i64, 65 * 1024].into_iter().enumerate() {
        let blen = blen.min(size);
        let block = &b[(size - blen) as usize..];
        if let Some(p) = find_signature(block) {
            found = Some((size - blen) as usize + p);
            break;
        }
        if i == 1 || blen == size {
            return Err(ERR_FORMAT.into());
        }
    }
    let p = found.ok_or(ERR_FORMAT)?;
    let mut end_off = p as i64;
    let mut d = End { records: u16le(b, p + 10) as u64, size: u32le(b, p + 12) as u64, offset: u32le(b, p + 16) as u64 };
    if d.records == 0xffff || d.size == 0xffff || d.offset == 0xffff_ffff {
        // the zip64 locator just before the end record
        let loc = end_off - 20;
        if loc >= 0 {
            let l = loc as usize;
            if u32le(b, l) == 0x0706_4b50 && u32le(b, l + 4) == 0 && u32le(b, l + 16) == 1 {
                let p64 = u64le(b, l + 8) as i64;
                if p64 >= 0 {
                    let q = p64 as usize;
                    if q.checked_add(56).is_none_or(|e| e > b.len()) {
                        return Err("EOF".into());
                    }
                    if u32le(b, q) != 0x0606_4b50 {
                        return Err(ERR_FORMAT.into());
                    }
                    end_off = p64;
                    d.records = u64le(b, q + 32);
                    d.size = u64le(b, q + 40);
                    d.offset = u64le(b, q + 48);
                }
            }
        }
    }
    let max = (1u64 << 63) - 1;
    if d.size > max || d.offset > max {
        return Err(ERR_FORMAT.into());
    }
    let mut base = end_off.wrapping_sub(d.size as i64).wrapping_sub(d.offset as i64);
    let o = base.wrapping_add(d.offset as i64);
    if o < 0 || o >= size {
        return Err(ERR_FORMAT.into());
    }
    if base > 0 && (d.offset as usize) < b.len() && read_header(&b[d.offset as usize..]).is_ok() {
        base = 0;
    }
    Ok((d, base))
}

enum HeaderErr {
    Format,
    UnexpectedEof,
    Eof,
}

/// One central directory header at the start of `b`: the entry and its length.
fn read_header(b: &[u8]) -> Result<(Entry, usize), HeaderErr> {
    if b.is_empty() {
        return Err(HeaderErr::Eof);
    }
    if b.len() < 46 {
        return Err(HeaderErr::UnexpectedEof);
    }
    if u32le(b, 0) != 0x0201_4b50 {
        return Err(HeaderErr::Format);
    }
    let method = u16le(b, 10);
    let csize = u32le(b, 20);
    let usize_ = u32le(b, 24);
    let (nl, xl, cl) = (u16le(b, 28) as usize, u16le(b, 30) as usize, u16le(b, 32) as usize);
    let hoff = u32le(b, 42);
    let total = 46 + nl + xl + cl;
    if b.len() < total {
        return Err(if b.len() == 46 { HeaderErr::Eof } else { HeaderErr::UnexpectedEof });
    }
    let name = b[46..46 + nl].to_vec();
    let mut extra = &b[46 + nl..46 + nl + xl];
    let mut e = Entry { name, method, compressed: csize as u64, uncompressed: usize_ as u64, header_offset: hoff as i64 };
    let (mut need_u, mut need_c, mut need_h) = (usize_ == u32::MAX, csize == u32::MAX, hoff == u32::MAX);
    while extra.len() >= 4 {
        let tag = u16le(extra, 0);
        let fsize = u16le(extra, 2) as usize;
        extra = &extra[4..];
        if extra.len() < fsize {
            break;
        }
        let mut field = &extra[..fsize];
        extra = &extra[fsize..];
        if tag == 0x0001 {
            for (need, slot) in [(&mut need_u, 0), (&mut need_c, 1), (&mut need_h, 2)] {
                if *need {
                    *need = false;
                    if field.len() < 8 {
                        return Err(HeaderErr::Format);
                    }
                    let v = u64le(field, 0);
                    field = &field[8..];
                    match slot {
                        0 => e.uncompressed = v,
                        1 => e.compressed = v,
                        _ => e.header_offset = v as i64,
                    }
                }
            }
        }
    }
    if need_c || need_h {
        return Err(HeaderErr::Format);
    }
    Ok((e, total))
}

fn read_directory(b: &[u8]) -> Result<Vec<Entry>, String> {
    let (d, base) = read_end(b)?;
    let mut off = (base + d.offset as i64) as usize;
    let mut out = Vec::new();
    let last = loop {
        match read_header(&b[off.min(b.len())..]) {
            Ok((mut e, n)) => {
                e.header_offset += base;
                out.push(e);
                off += n;
            }
            // Go stops at a header that is not one or is cut short; the data simply ending is an error of its own
            Err(HeaderErr::Eof) => return Err("EOF".into()),
            Err(e) => break e,
        }
    };
    if out.len() as u16 != d.records as u16 {
        return Err(match last {
            HeaderErr::Format => ERR_FORMAT.into(),
            HeaderErr::UnexpectedEof => "unexpected EOF".into(),
            HeaderErr::Eof => "EOF".into(),
        });
    }
    Ok(out)
}

impl Archive {
    /// The entry's bytes, at most `limit` of them, as Go's `f.Open()` read through `io.LimitReader` gives them before any error
    /// (a reader of the first JSON value only needs those); Err when it cannot be opened at all.
    pub fn read(&self, e: &Entry, limit: usize) -> Result<Vec<u8>, String> {
        let b: &[u8] = &self.data;
        let h = e.header_offset;
        if h < 0 || (h as u64).checked_add(30).is_none_or(|x| x > b.len() as u64) {
            return Err("EOF".into());
        }
        let h = h as usize;
        if u32le(b, h) != 0x0403_4b50 {
            return Err(ERR_FORMAT.into());
        }
        let body = h as u64 + 30 + u16le(b, h + 26) as u64 + u16le(b, h + 28) as u64;
        let start = body.min(b.len() as u64) as usize;
        let end = body.saturating_add(e.compressed).min(b.len() as u64) as usize;
        let raw = &b[start..end.max(start)];
        let mut out = Vec::new();
        match e.method {
            0 => out.extend_from_slice(&raw[..raw.len().min(limit)]),
            8 => {
                let mut d = DeflateDecoder::new(raw).take(limit as u64);
                let mut buf = [0u8; 32 * 1024];
                loop {
                    match d.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => out.extend_from_slice(&buf[..n]),
                    }
                }
            }
            _ => return Err("zip: unsupported compression algorithm".into()),
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    /// Any bytes, and every single-byte change and cut of a small archive: an answer or an error, never a panic or a read
    /// outside the file.
    #[test]
    fn hostile_archives_never_panic() {
        // one stored entry "a.json" = "{}", the central directory and the end record, laid out as Go's writer does
        let mut z: Vec<u8> = b"PK\x03\x04\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec();
        z.extend_from_slice(&[0, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0]);
        z.extend_from_slice(b"\x06\x00\x00\x00a.json{}");
        let cd = z.len() as u32;
        z.extend_from_slice(b"PK\x01\x02\x14\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        z.extend_from_slice(&[0, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0]);
        z.extend_from_slice(b"\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00a.json");
        let cdlen = z.len() as u32 - cd;
        z.extend_from_slice(b"PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00");
        z.extend_from_slice(&cdlen.to_le_bytes());
        z.extend_from_slice(&cd.to_le_bytes());
        z.extend_from_slice(b"\x00\x00");
        let dir = std::env::temp_dir().join(format!("heimdall-zip-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("z.zip");
        let check = |b: &[u8]| {
            std::fs::write(&p, b).unwrap();
            if let Ok(a) = super::open(p.to_str().unwrap()) {
                for e in &a.entries {
                    let _ = a.read(e, 1 << 20);
                }
            }
        };
        std::fs::write(&p, &z).unwrap();
        let a = super::open(p.to_str().unwrap()).unwrap();
        assert_eq!(a.entries.len(), 1);
        assert_eq!(a.read(&a.entries[0], 100).unwrap(), b"{}");
        for i in 0..z.len() {
            for v in [0u8, 0xff, z[i] ^ 1, z[i].wrapping_add(0x80)] {
                let mut m = z.clone();
                m[i] = v;
                check(&m);
            }
            check(&z[..i]);
            check(&z[i..]);
        }
        let mut seed = 0x9e37_79b9u32;
        for n in 0..300 {
            let b: Vec<u8> = (0..n * 3)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    if seed % 7 == 0 {
                        b'P'
                    } else {
                        seed as u8
                    }
                })
                .collect();
            check(&b);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
