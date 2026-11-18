//! Hostile archives, built here byte by byte: every bomb is stopped after a few megabytes at most (a test that inflated
//! gigabytes would itself be the failure), nothing is ever written outside the folder, and damage is a refusal, not a panic.

use super::*;

pub fn deflate(b: &[u8]) -> Vec<u8> {
    let mut z = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
    z.write_all(b).unwrap();
    z.finish().unwrap()
}

pub fn crc(b: &[u8]) -> u32 {
    let mut c = flate2::Crc::new();
    c.update(b);
    c.sum()
}

/// One entry as it will be written, every field free to lie.
#[derive(Clone)]
pub struct Raw {
    pub name: Vec<u8>,
    pub local_name: Option<Vec<u8>>,
    pub data: Vec<u8>,
    pub method: u16,
    pub flags: u16,
    pub crc: u32,
    pub usize: u32,
    pub made_by: u16,
    pub external: u32,
}

impl Raw {
    pub fn file(name: &str, content: &[u8]) -> Raw {
        Raw {
            name: name.as_bytes().to_vec(),
            local_name: None,
            data: deflate(content),
            method: 8,
            flags: 0,
            crc: crc(content),
            usize: content.len() as u32,
            made_by: 0x0314,
            external: 0o100644 << 16,
        }
    }
    pub fn stored(name: &str, content: &[u8]) -> Raw {
        Raw { data: content.to_vec(), method: 0, ..Raw::file(name, content) }
    }
    pub fn dir(name: &str) -> Raw {
        Raw { external: 0o040755 << 16, ..Raw::stored(name, b"") }
    }
}

/// Writes the entries one after the other, then the directory; `offsets` replaces where the directory says each entry is.
pub fn build_at(entries: &[Raw], offsets: Option<&[u32]>) -> Vec<u8> {
    let mut out = vec![];
    let mut at = vec![];
    for e in entries {
        at.push(out.len() as u32);
        let ln = e.local_name.as_ref().unwrap_or(&e.name);
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&e.flags.to_le_bytes());
        out.extend_from_slice(&e.method.to_le_bytes());
        out.extend_from_slice(&[0, 0, 0x21, 0]);
        out.extend_from_slice(&e.crc.to_le_bytes());
        out.extend_from_slice(&(e.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&e.usize.to_le_bytes());
        out.extend_from_slice(&(ln.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(ln);
        out.extend_from_slice(&e.data);
    }
    let cd_at = out.len() as u32;
    for (i, e) in entries.iter().enumerate() {
        out.extend_from_slice(b"PK\x01\x02");
        out.extend_from_slice(&e.made_by.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&e.flags.to_le_bytes());
        out.extend_from_slice(&e.method.to_le_bytes());
        out.extend_from_slice(&[0, 0, 0x21, 0]);
        out.extend_from_slice(&e.crc.to_le_bytes());
        out.extend_from_slice(&(e.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&e.usize.to_le_bytes());
        out.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(&e.external.to_le_bytes());
        out.extend_from_slice(&offsets.map(|o| o[i]).unwrap_or(at[i]).to_le_bytes());
        out.extend_from_slice(&e.name);
    }
    let cd_len = out.len() as u32 - cd_at;
    out.extend_from_slice(b"PK\x05\x06\0\0\0\0");
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_len.to_le_bytes());
    out.extend_from_slice(&cd_at.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

pub fn build(entries: &[Raw]) -> Vec<u8> {
    build_at(entries, None)
}

/// A tar header with a correct checksum.
pub fn tar_header(name: &[u8], size: u64, ty: u8, link: &[u8]) -> [u8; 512] {
    let mut h = [0u8; 512];
    h[..name.len().min(100)].copy_from_slice(&name[..name.len().min(100)]);
    h[100..107].copy_from_slice(b"0000644");
    h[108..115].copy_from_slice(b"0001750");
    h[116..123].copy_from_slice(b"0001750");
    h[124..135].copy_from_slice(format!("{size:011o}").as_bytes());
    h[136..147].copy_from_slice(b"00000000000");
    h[156] = ty;
    h[157..157 + link.len().min(100)].copy_from_slice(&link[..link.len().min(100)]);
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|&b| b as u32).sum();
    h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
    h
}

/// A tar of (name, type, content) entries, with its end blocks.
pub fn tar(entries: &[(&[u8], u8, &[u8])]) -> Vec<u8> {
    let mut out = vec![];
    for (name, ty, data) in entries {
        out.extend_from_slice(&tar_header(name, data.len() as u64, *ty, b"target"));
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(512) * 512, 0);
    }
    out.extend_from_slice(&[0u8; 1024]);
    out
}

pub fn gzip(b: &[u8]) -> Vec<u8> {
    let mut z = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    z.write_all(b).unwrap();
    z.finish().unwrap()
}

fn small() -> Limits {
    Limits { total: 8 << 20, per_file: 4 << 20, entries: 100, ratio: 100, entry_allowance: 1 << 20, total_allowance: 2 << 20 }
}

fn opts() -> Options {
    Options { only: vec![], limits: small() }
}

fn dry_zip(z: &[u8], o: &Options) -> Outcome {
    zip(&z, o, &mut Discard)
}

fn dry_tar(t: &[u8], compressed: bool, o: &Options) -> Outcome {
    let mut r: Box<dyn Read> = if compressed { Box::new(flate2::read::MultiGzDecoder::new(t)) } else { Box::new(t) };
    stream(&mut r, t.len() as u64, "x.tar", compressed, o, &mut Discard)
}

fn why(o: &Outcome) -> Option<Why> {
    o.refused.as_ref().map(|r| r.why)
}

/// A folder of its own under the temporary folder, with a "sentinel" place beside it where nothing may ever appear.
fn place(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let base = std::env::temp_dir().join(format!("heimdall-extract-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let out = base.join("out");
    std::fs::create_dir_all(&out).unwrap();
    (base, out)
}

#[test]
fn an_ordinary_zip_is_extracted() {
    let z = build(&[
        Raw::dir("fonts/"),
        Raw::file("fonts/a.ttf", b"\x00\x01\x00\x00font data"),
        Raw::stored("readme.txt", b"hello"),
        Raw::file("deep/er/b.otf", b"OTTOmore"),
    ]);
    let (base, out) = place("ordinary");
    let o = zip(&z.as_slice(), &opts(), &mut Disk::open(&out).unwrap());
    assert_eq!(o.refused, None);
    assert_eq!(o.files.len(), 3);
    assert_eq!(std::fs::read(out.join("fonts/a.ttf")).unwrap(), b"\x00\x01\x00\x00font data");
    assert_eq!(std::fs::read(out.join("deep/er/b.otf")).unwrap(), b"OTTOmore");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(out.join("readme.txt")).unwrap().permissions().mode() & 0o777, 0o600, "never runnable");
    // --only fonts: the text file is skipped, its reason said
    let (base2, out2) = place("only");
    let o = zip(&z.as_slice(), &Options { only: vec!["ttf".into(), "otf".into()], limits: small() }, &mut Disk::open(&out2).unwrap());
    assert_eq!(o.files.iter().map(|f| f.path.as_str()).collect::<Vec<_>>(), ["fonts/a.ttf", "deep/er/b.otf"]);
    assert!(o.skipped.iter().any(|s| s.name == "readme.txt" && s.reason.contains("ttf, otf")));
    assert!(!out2.join("readme.txt").exists());
    let _ = std::fs::remove_dir_all(&base);
    let _ = std::fs::remove_dir_all(&base2);
}

#[test]
fn a_classic_zip_bomb_stops_early() {
    // 16 MiB of zeros deflate to about 16 KiB: refused once it passes 100 times its packed size, a few megabytes in
    let z = build(&[Raw::file("zeros.bin", &vec![0u8; 16 << 20])]);
    let o = dry_zip(&z, &Options { only: vec![], limits: Limits::default() });
    assert_eq!(why(&o), Some(Why::Bomb), "{o:?}");
    assert!(o.unpacked < 4 << 20, "it stopped early ({} bytes)", o.unpacked);
    // on disk too, and the partial file is the caller's to remove (extract_command removes the folder)
    let (base, out) = place("bomb");
    let o = zip(&z.as_slice(), &Options { only: vec![], limits: Limits::default() }, &mut Disk::open(&out).unwrap());
    assert_eq!(why(&o), Some(Why::Bomb));
    assert!(std::fs::metadata(out.join("zeros.bin")).map(|m| m.len()).unwrap_or(0) < 4 << 20);
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn many_small_bombs_are_caught_by_the_overall_ratio() {
    // 200 entries of 512 KiB of zeros: each under the per-file allowance, together a bomb
    let one = Raw::file("x", &vec![0u8; 512 << 10]);
    let entries: Vec<Raw> = (0..200).map(|i| Raw { name: format!("z{i}.bin").into_bytes(), ..one.clone() }).collect();
    let z = build(&entries);
    let lim = Limits { entries: 1000, ..Limits::default() };
    let o = dry_zip(&z, &Options { only: vec![], limits: lim });
    assert_eq!(why(&o), Some(Why::Bomb), "{o:?}");
    assert!(o.unpacked <= 100 * z.len() as u64 + (512 << 10), "bounded: {}", o.unpacked);
}

#[test]
fn overlapping_entries_and_quines_are_bombs() {
    // two directory entries pointing at one local header (a quine points back at itself the same way)
    let a = Raw::file("a.txt", &vec![b'a'; 4096]);
    let z = build_at(&[a.clone(), a.clone()], Some(&[0, 0]));
    assert_eq!(why(&dry_zip(&z, &opts())), Some(Why::Bomb));
    // Fifield's overlap: the first file's data holds the second file's whole header, so both unpack the same bytes
    let b = Raw::stored("b.txt", b"x");
    let b_bytes = build(std::slice::from_ref(&b))[..36].to_vec();
    let a = Raw::stored("a.txt", &b_bytes);
    let z = build_at(&[a, b], Some(&[0, 35]));
    assert_eq!(why(&dry_zip(&z, &opts())), Some(Why::Bomb));
    // the second entry's header inside the first's data
    let big = Raw::stored("big.bin", &[7u8; 2000]);
    let z = build_at(&[big, Raw::stored("in.bin", b"x")], Some(&[0, 100]));
    let o = dry_zip(&z, &opts());
    assert!(matches!(why(&o), Some(Why::Bomb) | Some(Why::Damaged)), "{o:?}");
    assert!(o.files.is_empty(), "nothing was unpacked before the check");
}

#[test]
fn too_many_entries_and_too_big_files() {
    let entries: Vec<Raw> = (0..101).map(|i| Raw::stored(&format!("f{i}"), b"")).collect();
    let o = dry_zip(&build(&entries), &opts());
    assert_eq!(why(&o), Some(Why::TooBig));
    assert!(o.refused.unwrap().reason.contains("more than 100 files"));
    // an honest header over the per-file limit: refused before a byte is unpacked
    let o = dry_zip(&build(&[Raw::stored("big", &vec![1u8; 5 << 20])]), &opts());
    assert_eq!(why(&o), Some(Why::TooBig));
    assert_eq!(o.unpacked, 0);
    // a real ratio but over the total: too big, not a bomb (the scan's warning, not a refusal)
    let noise: Vec<u8> = (0..(3u32 << 20)).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    let z = build(&[Raw::stored("a", &noise), Raw::stored("b", &noise), Raw::stored("c", &noise)]);
    assert_eq!(why(&dry_zip(&z, &opts())), Some(Why::TooBig));
}

#[test]
fn headers_that_lie_about_sizes() {
    // says 10 bytes, unpacks to 64 KiB: stopped at the 11th
    let mut r = Raw::file("liar.txt", &vec![b'x'; 64 << 10]);
    r.usize = 10;
    let o = dry_zip(&build(&[r]), &opts());
    assert_eq!(why(&o), Some(Why::Bomb));
    // says more than it has: damaged
    let mut r = Raw::file("short.txt", b"tiny");
    r.usize = 1000;
    assert_eq!(why(&dry_zip(&build(&[r]), &opts())), Some(Why::Damaged));
    // a wrong checksum
    let mut r = Raw::file("crc.txt", b"content");
    r.crc ^= 1;
    assert_eq!(why(&dry_zip(&build(&[r]), &opts())), Some(Why::Damaged));
    // two names for one file
    let mut r = Raw::file("shown.txt", b"x");
    r.local_name = Some(b"hidden.exe".to_vec());
    assert_eq!(why(&dry_zip(&build(&[r]), &opts())), Some(Why::Trick));
}

#[test]
fn names_that_escape_are_refused_and_nothing_leaves_the_folder() {
    for bad in [
        "../evil.txt",
        "a/../../evil.txt",
        "/tmp/evil.txt",
        "C:\\evil.txt",
        "..\\evil.txt",
        ".\u{202E}./evil.txt",
        "a/..\u{200B}/../evil.txt",
    ] {
        let z = build(&[Raw::stored("ok.txt", b"fine"), Raw::stored(bad, b"evil")]);
        let (base, out) = place("slip");
        let o = zip(&z.as_slice(), &opts(), &mut Disk::open(&out).unwrap());
        assert_eq!(why(&o), Some(Why::Escape), "{bad}: {o:?}");
        assert!(o.files.is_empty(), "{bad}: refused before anything was written");
        assert!(!base.join("evil.txt").exists() && !Path::new("/tmp/evil.txt").exists());
        let _ = std::fs::remove_dir_all(&base);
    }
    let t = tar(&[(b"../evil.txt", b'0', b"x")]);
    assert_eq!(why(&dry_tar(&t, false, &opts())), Some(Why::Escape));
    let t = tar(&[(b"/etc/evil", b'0', b"x")]);
    assert_eq!(why(&dry_tar(&t, false, &opts())), Some(Why::Escape));
}

#[test]
fn names_are_cleaned() {
    assert_eq!(clean_name(b"a/./b//c.txt").unwrap(), ["a", "b", "c.txt"]);
    assert_eq!(clean_name("in\u{202E}fdp.exe".as_bytes()).unwrap(), ["infdp.exe"]);
    assert_eq!(clean_name(b"bell\x07\nname").unwrap(), ["bell__name"]);
    assert_eq!(clean_name(b"bad\xFFbyte").unwrap(), ["bad_byte"]);
    assert_eq!(clean_name("zero\u{200B}width".as_bytes()).unwrap(), ["zerowidth"]);
    assert_eq!(why(&Outcome { refused: clean_name(&vec![b'a'; 300]).err(), ..Outcome::default() }), Some(Why::Names));
    let deep = (0..70).map(|_| "d").collect::<Vec<_>>().join("/");
    assert_eq!(clean_name(deep.as_bytes()).unwrap_err().why, Why::Names);
}

#[test]
fn duplicates_and_conflicts_are_refused() {
    let z = build(&[Raw::stored("a.txt", b"1"), Raw::stored("a.txt", b"2")]);
    assert_eq!(why(&dry_zip(&z, &opts())), Some(Why::Names));
    let z = build(&[Raw::stored("a", b"1"), Raw::stored("a/b", b"2")]);
    assert_eq!(why(&dry_zip(&z, &opts())), Some(Why::Names));
    // cleaning that makes two names one is a duplicate too
    let z = build(&[Raw::stored("x.txt", b"1"), Raw::stored("x\u{200B}.txt", b"2")]);
    assert_eq!(why(&dry_zip(&z, &opts())), Some(Why::Names));
    // a folder named twice is fine
    let z = build(&[Raw::dir("d/"), Raw::stored("d/f", b"1"), Raw::dir("d/")]);
    assert_eq!(why(&dry_zip(&z, &opts())), None);
    let t = tar(&[(b"a.txt", b'0', b"1"), (b"a.txt", b'0', b"2")]);
    assert_eq!(why(&dry_tar(&t, false, &opts())), Some(Why::Names));
}

#[test]
fn links_devices_and_encrypted_entries_are_left_out() {
    let link = Raw { external: 0o120777 << 16, ..Raw::stored("link", b"/etc/passwd") };
    let fifo = Raw { external: 0o010644 << 16, ..Raw::stored("fifo", b"") };
    let dev = Raw { external: 0o020644 << 16, ..Raw::stored("dev", b"") };
    let enc = Raw { flags: 1, ..Raw::stored("secret.txt", b"xxxx") };
    let z = build(&[link, fifo, dev, enc, Raw::stored("ok.txt", b"ok")]);
    let (base, out) = place("links");
    let o = zip(&z.as_slice(), &opts(), &mut Disk::open(&out).unwrap());
    assert_eq!(o.refused, None);
    assert_eq!(o.files.len(), 1);
    assert_eq!(o.skipped.len(), 4);
    assert!(o.skipped.iter().any(|s| s.name == "secret.txt" && s.reason.starts_with("encrypted")));
    assert!(std::fs::symlink_metadata(out.join("link")).is_err());
    let _ = std::fs::remove_dir_all(&base);
    let t = tar(&[(b"sym", b'2', b""), (b"hard", b'1', b""), (b"fifo", b'6', b""), (b"chr", b'3', b""), (b"f.txt", b'0', b"data")]);
    let (base, out) = place("tarlinks");
    let mut r: &[u8] = &t;
    let o = stream(&mut r, t.len() as u64, "x.tar", false, &opts(), &mut Disk::open(&out).unwrap());
    assert_eq!(o.refused, None, "{o:?}");
    assert_eq!(o.files.len(), 1);
    assert_eq!(o.skipped.len(), 4);
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 1);
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn archives_inside_are_kept_as_files() {
    // a ZIP inside a ZIP inside a ZIP: one level is unpacked, the next is a file, never opened here
    let inner = build(&[Raw::file("zeros.bin", &vec![0u8; 4 << 20])]);
    let middle = build(&[Raw::stored("inner.zip", &inner)]);
    let outer = build(&[Raw::stored("middle.zip", &middle)]);
    let o = dry_zip(&outer, &opts());
    assert_eq!(o.refused, None);
    assert_eq!(o.files.len(), 1);
    assert_eq!(o.unpacked, middle.len() as u64);
}

#[test]
fn damaged_and_cut_short_archives_are_refused_not_panics() {
    let z = build(&[Raw::file("a.txt", &vec![b'a'; 3000]), Raw::stored("b.txt", b"bbb")]);
    for cut in 0..z.len() {
        let o = dry_zip(&z[..cut], &opts());
        assert!(o.refused.is_some(), "cut at {cut}");
    }
    let t = tar(&[(b"a.txt", b'0', &[b'a'; 3000]), (b"b.txt", b'0', b"bbb")]);
    for cut in (0..t.len()).step_by(7) {
        let o = dry_tar(&t[..cut], false, &opts());
        // cut on a block boundary right after a whole entry is a tar without its end blocks, and one cut inside its end
        // blocks has all its files: both tolerated
        if o.refused.is_none() {
            assert!(cut % 512 == 0 || o.files.len() == 2, "cut at {cut}: {o:?}");
        }
    }
    let g = gzip(&t);
    for cut in (0..g.len()).step_by(5) {
        // the tar can end (its end blocks) before the gzip trailer: then what was unpacked is whole
        let o = dry_tar(&g[..cut], true, &opts());
        assert!(o.refused.is_some() || o.files.iter().map(|f| f.size).sum::<u64>() == 3003, "cut at {cut}: {o:?}");
    }
}

#[test]
fn tar_and_tar_gz() {
    let long = format!("{}/name.txt", "d".repeat(120));
    let mut t = vec![];
    // a GNU long name, then a pax path, then ordinary entries
    t.extend_from_slice(&tar_header(b"././@LongLink", long.len() as u64 + 1, b'L', b""));
    t.extend_from_slice(long.as_bytes());
    t.push(0);
    t.resize(t.len().div_ceil(512) * 512, 0);
    t.extend_from_slice(&tar_header(b"short", 2, b'0', b""));
    t.extend_from_slice(b"L1");
    t.resize(t.len().div_ceil(512) * 512, 0);
    let pax = b"26 path=pax/long/name.txt\n";
    t.extend_from_slice(&tar_header(b"PaxHeader", pax.len() as u64, b'x', b""));
    t.extend_from_slice(pax);
    t.resize(t.len().div_ceil(512) * 512, 0);
    t.extend_from_slice(&tar_header(b"ignored", 2, b'0', b""));
    t.extend_from_slice(b"P2");
    t.resize(t.len().div_ceil(512) * 512, 0);
    t.extend_from_slice(&tar(&[(b"dir/", b'5', b""), (b"dir/f.txt", b'0', b"hello")]));
    for compressed in [false, true] {
        let data = if compressed { gzip(&t) } else { t.clone() };
        let (base, out) = place(if compressed { "targz" } else { "tar" });
        let mut r: Box<dyn Read> = if compressed { Box::new(flate2::read::MultiGzDecoder::new(&data[..])) } else { Box::new(&data[..]) };
        let o = stream(&mut r, data.len() as u64, "x.tar.gz", compressed, &opts(), &mut Disk::open(&out).unwrap());
        assert_eq!(o.refused, None, "{o:?}");
        assert_eq!(std::fs::read(out.join(&long)).unwrap(), b"L1");
        assert_eq!(std::fs::read(out.join("pax/long/name.txt")).unwrap(), b"P2");
        assert_eq!(std::fs::read(out.join("dir/f.txt")).unwrap(), b"hello");
        let _ = std::fs::remove_dir_all(&base);
    }
}

#[test]
fn a_tar_gz_bomb_and_a_single_compressed_file() {
    let t = tar(&[(b"zeros.bin", b'0', &vec![0u8; 16 << 20])]);
    let g = gzip(&t);
    let o = dry_tar(&g, true, &Options { only: vec![], limits: Limits::default() });
    assert_eq!(why(&o), Some(Why::Bomb), "{o:?}");
    assert!(o.unpacked < 8 << 20, "stopped early: {}", o.unpacked);
    // notes.txt.gz holds one file, named without .gz
    let g = gzip(b"just some notes\n");
    let mut r = flate2::read::MultiGzDecoder::new(&g[..]);
    let o = stream(&mut r, g.len() as u64, &single_name("notes.txt.gz"), true, &opts(), &mut Discard);
    assert_eq!(o.refused, None);
    assert_eq!(o.files[0].path, "notes.txt");
    assert_eq!(o.files[0].size, 16);
    assert_eq!(single_name("a.tgz"), "a.tar");
    // a plain file that is not a tar: not an archive
    assert_eq!(why(&dry_tar(&[b'x'; 2000], false, &opts())), Some(Why::Unsupported));
    // a huge size in base-256: too big, refused at the header
    let mut h = tar_header(b"huge", 0, b'0', b"");
    h[124..136].fill(0);
    h[124] = 0x80;
    h[131] = 0x10;
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|&b| b as u32).sum();
    h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
    assert_eq!(why(&dry_tar(&h, false, &opts())), Some(Why::TooBig));
}

#[test]
fn kinds_are_told_apart() {
    assert_eq!(detect(&build(&[Raw::stored("a", b"x")])), Ok(Some(Format::Zip)));
    assert_eq!(detect(&gzip(b"x")), Ok(Some(Format::Tar(Compression::Gzip))));
    assert_eq!(detect(&tar(&[(b"a", b'0', b"x")])), Ok(Some(Format::Tar(Compression::None))));
    assert_eq!(detect(b"\xFD7zXZ\x00\x00\x04"), Ok(Some(Format::Tar(Compression::Xz))));
    assert_eq!(detect(b"\x28\xB5\x2F\xFD\x00"), Ok(Some(Format::Tar(Compression::Zstd))));
    assert_eq!(detect(b"BZh91AY&SY"), Ok(Some(Format::Tar(Compression::Bzip2))));
    assert_eq!(detect(b"7z\xBC\xAF\x27\x1C\x00\x04"), Err("7z"));
    assert_eq!(detect(b"Rar!\x1A\x07\x01\x00"), Err("RAR"));
    assert_eq!(detect(b"hello"), Ok(None));
    assert_eq!(detect(&[0u8; 1024]), Ok(None));
}

#[test]
fn the_systems_decompressors_stream_under_the_limits() {
    // xz, zstd and bzip2 run as programs: where one is not installed the test says so and passes
    let t = tar(&[(b"f.txt", b'0', b"hello"), (b"zeros.bin", b'0', &vec![0u8; 16 << 20])]);
    for (prog, args, c) in [
        ("/usr/bin/xz", &["-zc"][..], Compression::Xz),
        ("/usr/bin/zstd", &["-qc", "-19"][..], Compression::Zstd),
        ("/usr/bin/bzip2", &["-zc"][..], Compression::Bzip2),
    ] {
        if !Path::new(prog).exists() {
            eprintln!("{prog} is not installed: not tested here");
            continue;
        }
        let mut ch = std::process::Command::new(prog)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = ch.stdin.take().unwrap();
        let data = t.clone();
        let w = std::thread::spawn(move || stdin.write_all(&data));
        let packed = ch.wait_with_output().unwrap().stdout;
        w.join().unwrap().unwrap();
        let (base, _) = place(&format!("prog-{c:?}"));
        let f = base.join("a.tar.x");
        std::fs::write(&f, &packed).unwrap();
        let file = crate::intake::open_archive(&f).unwrap();
        assert_eq!(crate::intake::kind_of(&file), Ok(Some(Format::Tar(c))));
        let o = crate::intake::engine(file, "a.tar.x", Format::Tar(c), &Options { only: vec![], limits: Limits::default() }, &mut Discard);
        assert_eq!(why(&o), Some(Why::Bomb), "{prog}: {o:?}");
        assert!(o.unpacked < 8 << 20, "{prog} stopped early: {}", o.unpacked);
        let o = crate::intake::engine(
            crate::intake::open_archive(&f).unwrap(),
            "a.tar.x",
            Format::Tar(c),
            &Options { only: vec!["txt".into()], limits: Limits { ratio: u64::MAX, ..Limits::default() } },
            &mut Discard,
        );
        assert_eq!(o.refused, None, "{prog}: {o:?}");
        assert_eq!(o.files.len(), 1);
        let _ = std::fs::remove_dir_all(&base);
    }
}
