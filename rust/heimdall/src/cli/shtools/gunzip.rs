//! `gzip -dc FILE >OUT` as heimdall-intel-update ran it on DB-IP's downloads: every gzip member in turn (concatenated
//! members are one file), the header's optional fields skipped, the data inflated and checked against the member's CRC and
//! length; zero bytes after the last member ignored, other bytes after it a warning (exit 2, the output complete); GNU
//! gzip's lines and exit codes. Only gzip's own format is read (gzip also unpacks `compress`, `pack` and one-file zip
//! archives; DB-IP serves gzip, and a download in another format is refused here: docs/RUST_CLI.md).

use std::io::Write;
use std::path::Path;

/// What stopped the unpacking: gzip's words for it.
enum Stop {
    /// "\ngzip: FILE: WORDS" (exit 1)
    Bad(&'static str),
    /// "gzip: FILE: WORDS" without the blank line before it (exit 1)
    Plain(String),
    /// the output could not be written (exit 1)
    Write(std::io::Error),
}

struct Input<'a> {
    b: &'a [u8],
    pos: usize,
}

impl Input<'_> {
    /// gzip's `get_byte`: the end of the file here is "unexpected end of file".
    fn byte(&mut self) -> Result<u8, Stop> {
        let c = *self.b.get(self.pos).ok_or(Stop::Bad("unexpected end of file"))?;
        self.pos += 1;
        Ok(c)
    }
    /// gzip's `try_byte`: None at the end.
    fn try_byte(&mut self) -> Option<u8> {
        let c = *self.b.get(self.pos)?;
        self.pos += 1;
        Some(c)
    }
}

/// The member's header after the magic bytes; the error when gzip refuses it.
fn header(inp: &mut Input, name: &str) -> Result<(), Stop> {
    let method = inp.byte()?;
    if method != 8 {
        return Err(Stop::Plain(format!("{name}: unknown method {method} -- not supported")));
    }
    let flags = inp.byte()?;
    if flags & 0x20 != 0 {
        return Err(Stop::Plain(format!("{name} is encrypted -- not supported")));
    }
    if flags & 0xc0 != 0 {
        return Err(Stop::Plain(format!("{name} has flags 0x{flags:x} -- not supported")));
    }
    for _ in 0..6 {
        inp.byte()?; // time, extra flags, system
    }
    if flags & 0x04 != 0 {
        let lo = inp.byte()? as usize;
        let hi = inp.byte()? as usize;
        for _ in 0..(hi << 8 | lo) {
            inp.byte()?;
        }
    }
    for bit in [0x08, 0x10] {
        if flags & bit != 0 {
            while inp.byte()? != 0 {}
        }
    }
    if flags & 0x02 != 0 {
        inp.byte()?;
        inp.byte()?;
    }
    Ok(())
}

/// One member's data: inflated into `out`, then its CRC and length checked.
fn member(inp: &mut Input, out: &mut impl Write) -> Result<(), Stop> {
    let mut d = flate2::Decompress::new(false);
    let mut crc = flate2::Crc::new();
    let mut buf = vec![0u8; 32768];
    loop {
        let before_in = d.total_in();
        let before_out = d.total_out();
        let status = d
            .decompress(&inp.b[inp.pos..], &mut buf, flate2::FlushDecompress::None)
            .map_err(|_| Stop::Bad("invalid compressed data--format violated"))?;
        let used = (d.total_in() - before_in) as usize;
        let made = (d.total_out() - before_out) as usize;
        inp.pos += used;
        crc.update(&buf[..made]);
        out.write_all(&buf[..made]).map_err(Stop::Write)?;
        match status {
            flate2::Status::StreamEnd => break,
            _ if used == 0 && made == 0 => return Err(Stop::Bad("unexpected end of file")),
            _ => {}
        }
    }
    let mut trailer = [0u8; 8];
    for t in &mut trailer {
        *t = inp.byte()?;
    }
    if u32::from_le_bytes(trailer[..4].try_into().unwrap()) != crc.sum() {
        return Err(Stop::Bad("invalid compressed data--crc error"));
    }
    if u32::from_le_bytes(trailer[4..].try_into().unwrap()) != crc.amount() {
        return Err(Stop::Bad("invalid compressed data--length error"));
    }
    Ok(())
}

/// What is after a member: None at the end of the file (or only zero bytes to it); Some(true) for another member;
/// Some(false) for trailing garbage.
fn next(inp: &mut Input) -> Result<Option<bool>, Stop> {
    let Some(m0) = inp.try_byte() else { return Ok(None) };
    if m0 == 0 {
        loop {
            match inp.try_byte() {
                None => return Ok(None),
                Some(0) => {}
                Some(_) => return Ok(Some(false)),
            }
        }
    }
    let m1 = inp.byte()?;
    Ok(Some(m0 == 0x1f && (m1 == 0x8b || m1 == 0x9e)))
}

/// `gzip -dc SRC` into `out` (already opened by the shell's redirection): gzip's exit code (0, 1 on an error, 2 after a
/// warning), its line on standard error.
pub fn gzip_dc(src: &Path, out: &mut impl Write) -> i32 {
    let name = src.to_string_lossy().into_owned();
    let data = match std::fs::read(src) {
        Ok(d) => d,
        Err(e) => {
            super::coreutils::warn(&format!("gzip: {name}: {}", super::coreutils::strerror(&e)));
            return 1;
        }
    };
    let mut inp = Input { b: &data, pos: 0 };
    let run = |inp: &mut Input, out: &mut dyn Write| -> Result<i32, Stop> {
        // the first member: two magic bytes (a file of one byte is cut short)
        let m0 = inp.byte()?;
        let m1 = if m0 != 0 { inp.byte()? } else { inp.try_byte().unwrap_or(0) };
        if !(m0 == 0x1f && (m1 == 0x8b || m1 == 0x9e)) {
            return Err(Stop::Bad("not in gzip format"));
        }
        let mut out = out;
        loop {
            header(inp, &name)?;
            member(inp, &mut out)?;
            match next(inp)? {
                None => return Ok(0),
                Some(true) => {}
                Some(false) => {
                    super::coreutils::warn(&format!("\ngzip: {name}: decompression OK, trailing garbage ignored"));
                    return Ok(2);
                }
            }
        }
    };
    let r = run(&mut inp, out);
    let _ = out.flush();
    match r {
        Ok(code) => code,
        Err(Stop::Bad(w)) => {
            super::coreutils::warn(&format!("\ngzip: {name}: {w}"));
            1
        }
        Err(Stop::Plain(w)) => {
            super::coreutils::warn(&format!("gzip: {w}"));
            1
        }
        Err(Stop::Write(e)) => {
            super::coreutils::warn(&format!("\ngzip: stdout: {}", super::coreutils::strerror(&e)));
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gz(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn run(bytes: &[u8]) -> (i32, Vec<u8>) {
        let d = std::env::temp_dir().join(format!("heimdall-gunzip-{}-{}", std::process::id(), bytes.len()));
        std::fs::write(&d, bytes).unwrap();
        let mut out = Vec::new();
        let code = gzip_dc(&d, &mut out);
        let _ = std::fs::remove_file(&d);
        (code, out)
    }

    #[test]
    fn members_and_trailers_as_gzip() {
        let a = gz(b"hello ");
        let b = gz(b"world");
        assert_eq!(run(&[a.clone(), b.clone()].concat()), (0, b"hello world".to_vec()));
        assert_eq!(run(&[a.clone(), vec![0; 20]].concat()).0, 0);
        assert_eq!(run(&[a.clone(), b"garbage".to_vec()].concat()), (2, b"hello ".to_vec()));
        assert_eq!(run(&[a.clone(), vec![0x1f]].concat()).0, 1);
        assert_eq!(run(b"").0, 1);
        assert_eq!(run(b"x").0, 1);
        assert_eq!(run(b"not gz").0, 1);
        assert_eq!(run(&a[..a.len() - 3]).0, 1);
        let mut c = a.clone();
        let n = c.len();
        c[n - 8] ^= 1;
        assert_eq!(run(&c).0, 1);
        assert_eq!(run(&[0x1f, 0x8b, 9, 0]).0, 1);
    }
}
