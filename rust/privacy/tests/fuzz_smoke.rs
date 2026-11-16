//! The privacy pack's fuzz targets (src/fuzzing.rs) in the ordinary tests: on the made-up samples, every cut-short version of
//! them, mutated versions (bit flips, bytes changed to edge values, bytes inserted and removed, parts of one sample spliced
//! into another) and random bytes. The real fuzzing is `cargo +nightly fuzz run privacy_guard` (and the others) in rust/fuzz;
//! `long_mutation_run` (ignored) runs this mutator for as long as HEIMDALL_FUZZ_SECS says, where nightly is not at hand.

use heimdall_privacy::{fuzzing, samples};
use proptest::prelude::*;
use std::time::{Duration, Instant};

type Target = fn(&[u8]);

const TARGETS: &[(&str, Target)] = &[
    ("privacy_guard", fuzzing::guard),
    ("privacy_strip", fuzzing::strip),
    ("privacy_zip", fuzzing::zip),
    ("privacy_pdf", fuzzing::pdf),
    ("privacy_markup", fuzzing::markup),
    ("privacy_lookalike", fuzzing::lookalike),
];

pub fn seeds() -> Vec<Vec<u8>> {
    let mut zipped = heimdall_privacy::zip::Writer::new(Vec::new());
    zipped.file(b"a.docx", &samples::docx(true), false).unwrap();
    zipped.file(b"b.url", b"[InternetShortcut]\nURL=https://example.net/\n", false).unwrap();
    vec![
        samples::docx(true),
        samples::docx_field(),
        samples::odt(true),
        samples::pdf(true),
        samples::jpeg(),
        samples::png(),
        samples::webp(),
        samples::tiff(),
        samples::heic(),
        samples::mp3(),
        samples::flac(),
        samples::wav(),
        samples::plain_zip(),
        zipped.finish().unwrap(),
        br#"<svg xmlns:xlink="x"><image xlink:href="https://a.example.com/x.png"/><style>@import "http://b.example.com/c.css";</style><script>x()</script></svg>"#.to_vec(),
        br#"<!DOCTYPE html><meta http-equiv=refresh content="0;url=http://a.example.com"><img srcset="a 1x, //b.example.com/c 2x">"#.to_vec(),
        b"#EXTM3U\n#EXT-X-KEY:URI=\"https://k.example.com\"\nhttp://a.example.com/x\n".to_vec(),
        b"[playlist]\nFile1=http://a.example.com\n".to_vec(),
        b"[Desktop Entry]\nType=Link\nURL=https://a.example.com\nIcon=http://b.example.com/i.png\n".to_vec(),
        "Viv\u{0430}ldi \u{202E}fdp.exe \u{FF36}\u{1D405}".as_bytes().to_vec(),
    ]
}

/// A small, fast, deterministic random source (xorshift64*).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

/// One mutation of a seed, as a coverage-blind fuzzer would make.
fn mutate(rng: &mut Rng, seed: &[u8], other: &[u8]) -> Vec<u8> {
    let mut b = seed.to_vec();
    for _ in 0..1 + rng.below(8) {
        if b.is_empty() {
            b.push(rng.next() as u8);
            continue;
        }
        let i = rng.below(b.len());
        match rng.below(7) {
            0 => b[i] ^= 1 << rng.below(8),
            1 => b[i] = [0x00, 0xFF, 0x7F, 0x80, b'<', b'/', b'(', b'%'][rng.below(8)],
            2 => {
                // a length or offset field turned into an edge value
                let v: [u8; 4] = [[0xFF; 4], [0; 4], [0x7F, 0xFF, 0xFF, 0xFF], [0, 0, 0, 1]][rng.below(4)];
                for (k, x) in v.iter().enumerate() {
                    if i + k < b.len() {
                        b[i + k] = *x;
                    }
                }
            }
            3 => {
                b.insert(i, rng.next() as u8);
            }
            4 => {
                let n = 1 + rng.below(16.min(b.len() - i));
                b.drain(i..i + n);
            }
            5 => {
                // a run of the same byte (repeated structures)
                let n = rng.below(64);
                let x = b[i];
                b.splice(i..i, std::iter::repeat_n(x, n));
            }
            _ => {
                if !other.is_empty() {
                    let s = rng.below(other.len());
                    let n = rng.below((other.len() - s).min(256));
                    b.splice(i..i, other[s..s + n].iter().copied());
                }
            }
        }
    }
    b
}

/// Runs every target on `n` mutations of every seed; the slowest single call.
fn run_mutations(n: usize, seed: u64, deadline: Option<Instant>) -> (usize, Duration) {
    let s = seeds();
    let mut rng = Rng(seed);
    let mut count = 0;
    let mut slowest = Duration::ZERO;
    'outer: for _ in 0..n {
        for (i, base) in s.iter().enumerate() {
            let other = &s[(i + 1 + rng.below(s.len() - 1)) % s.len()];
            let b = mutate(&mut rng, base, other);
            // HEIMDALL_FUZZ_LAST=FILE keeps the input being tried, to find the one that crashed the process
            if let Some(p) = std::env::var_os("HEIMDALL_FUZZ_LAST") {
                let _ = std::fs::write(p, &b);
            }
            for (name, f) in TARGETS {
                let t = Instant::now();
                f(&b);
                if t.elapsed() > slowest {
                    slowest = t.elapsed();
                    // HEIMDALL_FUZZ_SLOW=FILE keeps the slowest input so far (FILE.target names its target)
                    if let Some(p) = std::env::var_os("HEIMDALL_FUZZ_SLOW") {
                        let _ = std::fs::write(&p, &b);
                        let mut n = p.clone();
                        n.push(".target");
                        let _ = std::fs::write(n, name);
                    }
                }
            }
            count += 1;
            if deadline.is_some_and(|d| Instant::now() > d) {
                break 'outer;
            }
        }
    }
    (count, slowest)
}

/// Inputs that once broke a target (found by the long run), kept in rust/fuzz/seeds/privacy_*/ as crash-*: run every time.
fn regressions() -> Vec<Vec<u8>> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fuzz/seeds");
    let mut v = vec![];
    for (name, _) in TARGETS {
        if let Ok(rd) = std::fs::read_dir(root.join(name)) {
            for e in rd.flatten() {
                if e.file_name().to_string_lossy().starts_with("crash-") {
                    v.push(std::fs::read(e.path()).unwrap());
                }
            }
        }
    }
    v
}

#[test]
fn every_target_survives_its_seeds_cut_short() {
    for b in seeds().into_iter().chain(regressions()) {
        for (_, f) in TARGETS {
            f(&b);
            for cut in (0..b.len()).step_by((b.len() / 24).max(1)) {
                f(&b[..cut]);
            }
        }
    }
}

#[test]
fn every_target_survives_mutated_seeds() {
    let (n, _) = run_mutations(40, 0x5EED_0001, None);
    assert!(n >= 40 * seeds().len());
}

/// HEIMDALL_FUZZ_SECS=600 cargo test --release -p heimdall-privacy --test fuzz_smoke -- --ignored --nocapture
#[test]
#[ignore]
fn long_mutation_run() {
    let secs: u64 = std::env::var("HEIMDALL_FUZZ_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(60);
    let seed: u64 = std::env::var("HEIMDALL_FUZZ_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(0x5EED_0002);
    let (n, slowest) = run_mutations(usize::MAX, seed, Some(Instant::now() + Duration::from_secs(secs)));
    eprintln!("long_mutation_run: {n} inputs through {} targets, slowest call {slowest:?}", TARGETS.len());
    assert!(slowest < Duration::from_secs(5), "a target took {slowest:?} on one input");
}

/// Writes the seeds for cargo-fuzz (rust/fuzz/seeds/privacy_*): `cargo test -p heimdall-privacy --test fuzz_smoke -- --ignored write_fuzz_seeds`.
#[test]
#[ignore]
fn write_fuzz_seeds() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fuzz/seeds");
    for (name, _) in TARGETS {
        let d = root.join(name);
        std::fs::create_dir_all(&d).unwrap();
        for (i, b) in seeds().iter().enumerate() {
            std::fs::write(d.join(format!("sample{i:02}")), b).unwrap();
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 300, ..ProptestConfig::default() })]

    #[test]
    fn every_target_survives_random_bytes(b in proptest::collection::vec(any::<u8>(), 0..512)) {
        for (_, f) in TARGETS {
            f(&b);
        }
    }
}

/// HEIMDALL_FUZZ_REPLAY=FILE: every target on one saved input, each named first (for a crash found by the long run).
#[test]
#[ignore]
fn replay() {
    let Some(p) = std::env::var_os("HEIMDALL_FUZZ_REPLAY") else { return };
    let b = std::fs::read(p).unwrap();
    for (name, f) in TARGETS {
        eprintln!("replay: {name}");
        f(&b);
    }
}
