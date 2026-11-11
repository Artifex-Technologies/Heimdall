//! The part of Go's `debug/elf` a held program's report uses (Go: internal/immunity/report.go): `NewFile`'s checks (a file Go
//! refuses gets no ELF part in the report), the class, machine and type as Go names them (`elf_table.rs`, written by
//! rust/gotools/elftable), the interpreter, the libraries needed (`ImportedLibraries`) and whether `Symbols()` fails
//! (stripped). Only read, never run.

#[path = "elf_table.rs"]
mod table;

/// What the report keeps of an ELF file.
#[derive(Debug, PartialEq)]
pub struct Info {
    pub class: String,
    pub machine: String,
    pub typ: String,
    pub interp: Vec<u8>,
    pub needed: Vec<Vec<u8>>,
    pub stripped: bool,
}

fn name(t: &[(u16, u16, &str, Option<u32>)], v: u16) -> String {
    for &(from, to, n, off) in t {
        if (from..=to).contains(&v) {
            return match off {
                None => n.to_string(),
                Some(o) => format!("{n}+{}", o + (v - from) as u32),
            };
        }
    }
    v.to_string()
}

struct Section {
    typ: u32,
    flags: u64,
    off: u64,
    size: u64,
    link: u32,
}

struct File<'a> {
    b: &'a [u8],
    big: bool,
    sections: Vec<Section>,
}

impl File<'_> {
    fn u16(&self, o: usize) -> u16 {
        let x = [self.b[o], self.b[o + 1]];
        if self.big {
            u16::from_be_bytes(x)
        } else {
            u16::from_le_bytes(x)
        }
    }
    fn u32(&self, o: usize) -> u32 {
        let x = [self.b[o], self.b[o + 1], self.b[o + 2], self.b[o + 3]];
        if self.big {
            u32::from_be_bytes(x)
        } else {
            u32::from_le_bytes(x)
        }
    }
    fn u64(&self, o: usize) -> u64 {
        let x: [u8; 8] = self.b[o..o + 8].try_into().unwrap();
        if self.big {
            u64::from_be_bytes(x)
        } else {
            u64::from_le_bytes(x)
        }
    }
    /// A whole range of the file (Go's ReadAt: anything short is an error).
    fn range(&self, off: u64, n: u64) -> Option<&[u8]> {
        let end = off.checked_add(n)?;
        if end > self.b.len() as u64 {
            return None;
        }
        Some(&self.b[off as usize..end as usize])
    }
    /// Go's `Section.Data()`: zeros for SHT_NOBITS, the bytes otherwise (a compressed section: refused here).
    fn data(&self, s: &Section) -> Option<Vec<u8>> {
        if s.typ == 8 {
            return Some(vec![0; s.size.min(1 << 30) as usize]);
        }
        if s.flags & 0x800 != 0 {
            return None;
        }
        self.range(s.off, s.size).map(<[u8]>::to_vec)
    }
    fn string_table(&self, i: u32) -> Option<Vec<u8>> {
        if i == 0 || i as usize >= self.sections.len() {
            return None;
        }
        let s = &self.sections[i as usize];
        if s.typ != 3 {
            return None;
        }
        self.data(s)
    }
    fn by_type(&self, t: u32) -> Option<&Section> {
        self.sections.iter().find(|s| s.typ == t)
    }
}

fn get_string(sec: &[u8], start: u64) -> Option<Vec<u8>> {
    let start = usize::try_from(start).ok()?;
    if start >= sec.len() {
        return None;
    }
    sec[start..].iter().position(|&c| c == 0).map(|n| sec[start..start + n].to_vec())
}

/// Go's `elf.NewFile` and what the report reads from it; None where Go refuses the file.
pub fn read(b: &[u8]) -> Option<Info> {
    if b.len() < 16 || &b[..4] != b"\x7fELF" {
        return None;
    }
    let is64 = match b[4] {
        1 => false,
        2 => true,
        _ => return None,
    };
    let big = match b[5] {
        1 => false,
        2 => true,
        _ => return None,
    };
    if b[6] != 1 {
        return None;
    }
    let hlen = if is64 { 64 } else { 52 };
    if b.len() < hlen {
        return None;
    }
    let mut f = File { b, big, sections: Vec::new() };
    let typ = f.u16(16);
    let machine = f.u16(18);
    if f.u32(20) != 1 {
        return None;
    }
    let (phoff, shoff, phentsize, mut phnum, shentsize, mut shnum, mut shstrndx) = if is64 {
        (f.u64(32), f.u64(40), f.u16(54) as u64, f.u16(56) as u64, f.u16(58) as u64, f.u16(60) as u64, f.u16(62) as u64)
    } else {
        (f.u32(28) as u64, f.u32(32) as u64, f.u16(42) as u64, f.u16(44) as u64, f.u16(46) as u64, f.u16(48) as u64, f.u16(50) as u64)
    };
    if shoff > i64::MAX as u64 || phoff > i64::MAX as u64 {
        return None;
    }
    if shoff == 0 && shnum != 0 {
        return None;
    }
    if shnum > 0 && shstrndx >= shnum {
        return None;
    }
    let (want_ph, want_sh) = if is64 { (56, 64) } else { (32, 40) };
    if phnum > 0 && phentsize < want_ph {
        return None;
    }
    // the first section header holds the real counts when they do not fit the header
    if shoff > 0 && (shnum == 0 || phnum == 0xffff) {
        let sh = f.range(shoff, want_sh)?;
        let (styp, size, link, info) = if is64 {
            (f.u32(shoff as usize + 4), u64_at(&f, sh, 32), f.u32(shoff as usize + 40), f.u32(shoff as usize + 44))
        } else {
            (f.u32(shoff as usize + 4), f.u32(shoff as usize + 20) as u64, f.u32(shoff as usize + 24), f.u32(shoff as usize + 28))
        };
        if styp != 0 {
            return None;
        }
        if shnum == 0 {
            if size < 0xff00 {
                return None;
            }
            shnum = size;
        }
        if phnum == 0xffff {
            if info < 0xffff {
                return None;
            }
            phnum = info as u64;
        }
        if shstrndx == 0xffff {
            shstrndx = link as u64;
            if shstrndx < 0xff00 || shstrndx >= shnum {
                return None;
            }
        }
    }
    // program headers
    let mut interp: Vec<u8> = Vec::new();
    if phnum > 0 {
        let total = phnum.checked_mul(phentsize)?;
        f.range(phoff, total)?;
        for i in 0..phnum {
            let o = (phoff + i * phentsize) as usize;
            let (ptype, poff, pfilesz) =
                if is64 { (f.u32(o), f.u64(o + 8), f.u64(o + 32)) } else { (f.u32(o), f.u32(o + 4) as u64, f.u32(o + 16) as u64) };
            if poff > i64::MAX as u64 || pfilesz > i64::MAX as u64 {
                return None;
            }
            if ptype == 3 {
                // Go: ReadAt of min(filesz, 256) bytes at the segment's start; nothing on any error
                let n = pfilesz.min(256);
                if n > 0 {
                    if let Some(r) = f.range(poff, n) {
                        let mut v = r.to_vec();
                        while v.last() == Some(&0) {
                            v.pop();
                        }
                        interp = v;
                    }
                }
            }
        }
    }
    // section headers
    if shnum > 0 && shentsize < want_sh {
        return None;
    }
    if shnum > 0 {
        let total = shnum.checked_mul(shentsize)?;
        f.range(shoff, total)?;
        for i in 0..shnum {
            let o = (shoff + i * shentsize) as usize;
            let s = if is64 {
                Section { typ: f.u32(o + 4), flags: f.u64(o + 8), off: f.u64(o + 24), size: f.u64(o + 32), link: f.u32(o + 40) }
            } else {
                Section {
                    typ: f.u32(o + 4),
                    flags: f.u32(o + 8) as u64,
                    off: f.u32(o + 16) as u64,
                    size: f.u32(o + 20) as u64,
                    link: f.u32(o + 24),
                }
            };
            if s.off > i64::MAX as u64 || s.size > i64::MAX as u64 {
                return None;
            }
            if s.flags & 0x800 != 0 {
                // a compressed section: Go reads its header now, and refuses the file if it cannot
                let ch = if is64 { 24 } else { 12 };
                f.range(s.off, ch)?;
            }
            f.sections.push(s);
        }
    }
    let mut info = Info {
        class: if is64 { "ELFCLASS64" } else { "ELFCLASS32" }.into(),
        machine: name(table::MACHINES, machine),
        typ: name(table::TYPES, typ),
        interp: Vec::new(),
        needed: Vec::new(),
        stripped: true,
    }
    .with_interp(interp);
    if !f.sections.is_empty() && shstrndx != 0 {
        let shstr = &f.sections[shstrndx as usize];
        if shstr.typ != 3 {
            return None;
        }
        let names = f.data(shstr)?;
        for i in 0..f.sections.len() {
            let o = (shoff + i as u64 * shentsize) as usize;
            get_string(&names, f.u32(o) as u64)?;
        }
    }
    // ImportedLibraries: DT_NEEDED from the first SHT_DYNAMIC section (errors: none listed)
    if let Some(ds) = f.by_type(6) {
        if let Some(d) = f.data(ds) {
            let size = if is64 { 16 } else { 8 };
            if d.len() % size == 0 {
                if let Some(strs) = f.string_table(ds.link) {
                    let g = File { b: &d, big, sections: Vec::new() };
                    let mut i = 0;
                    while i < d.len() {
                        let (t, v) = if is64 { (g.u64(i), g.u64(i + 8)) } else { (g.u32(i) as u64, g.u32(i + 4) as u64) };
                        if t == 1 {
                            if let Some(s) = get_string(&strs, v) {
                                info.needed.push(s);
                            }
                        }
                        i += size;
                    }
                }
            }
        }
    }
    // Symbols(): fails without a usable SHT_SYMTAB
    if let Some(st) = f.by_type(2) {
        let size = if is64 { 24 } else { 16 };
        if let Some(d) = f.data(st) {
            if !d.is_empty() && d.len() % size == 0 && f.string_table(st.link).is_some() {
                info.stripped = false;
            }
        }
    }
    Some(info)
}

fn u64_at(f: &File, sh: &[u8], o: usize) -> u64 {
    let x: [u8; 8] = sh[o..o + 8].try_into().unwrap();
    if f.big {
        u64::from_be_bytes(x)
    } else {
        u64::from_le_bytes(x)
    }
}

impl Info {
    fn with_interp(mut self, interp: Vec<u8>) -> Info {
        self.interp = interp;
        self
    }
    /// Go's `Static`: no interpreter.
    pub fn is_static(&self) -> bool {
        self.interp.is_empty()
    }
}

#[cfg(test)]
mod tests {
    /// A real program read, then every cut and three one-byte changes at each of its first 4 KiB: an answer or None,
    /// never a panic.
    #[test]
    fn hostile_programs_never_panic() {
        let b = std::fs::read("/usr/bin/true").unwrap_or_else(|_| b"\x7fELF\x02\x01\x01".to_vec());
        if let Some(i) = super::read(&b) {
            assert_eq!(i.class, "ELFCLASS64");
        }
        for n in 0..b.len().min(4096) {
            let _ = super::read(&b[..n]);
            for v in [0u8, 0xff, b[n] ^ 0x80] {
                let mut m = b.clone();
                m[n] = v;
                let _ = super::read(&m);
            }
        }
        assert_eq!(super::name(super::table::MACHINES, 62), "EM_X86_64");
        assert_eq!(super::name(super::table::TYPES, 9), "ET_CORE+5");
    }
}
