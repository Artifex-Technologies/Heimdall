//! The bodies of the privacy pack's fuzz targets (rust/fuzz/fuzz_targets/privacy_*.rs): each runs a parser of hostile files
//! and must never panic, hang or run over its caps. tests/fuzz_smoke.rs runs the same bodies on the made-up samples, on every
//! cut-short and bit-flipped version of them and on random bytes, so they run in the ordinary tests too.

use crate::guard::{self, Limits};
use crate::strip::{self, Kind};

/// Small caps, so a fuzzer explores instead of waiting on big allocations.
fn small() -> Limits {
    Limits { text: 1 << 20, pdf: 4 << 20, part: 1 << 20, budget: 4 << 20, members: 16 }
}

/// The downloads guard on bytes, under every name that changes how they are read.
pub fn guard(data: &[u8]) {
    for name in ["x", "a.svg", "a.html", "a.m3u", "a.pls", "a.xspf", "a.asx", "a.desktop", "a.url", "a.webloc", "a.docx", "a.pdf"] {
        let r = guard::inspect_bytes(name, data, &small());
        assert!(r.findings.len() <= 64);
        let _ = r.title();
    }
    let _ = guard::check_pdf(data);
}

/// Remove hidden info on bytes, as every kind: an error or a copy, never a panic; a copy cleaned again stays readable.
pub fn strip(data: &[u8]) {
    let kinds = [
        Kind::Jpeg,
        Kind::Png,
        Kind::Webp,
        Kind::Heif,
        Kind::Tiff,
        Kind::Pdf,
        Kind::Office,
        Kind::OpenDocument,
        Kind::Zip,
        Kind::Mp3,
        Kind::Flac,
        Kind::Wav,
    ];
    for k in kinds {
        let mut r = vec![];
        if let Ok(out) = strip::clean(k, data, &mut r) {
            // a PDF's packed object streams are written unpacked, so only it may grow beyond its size
            assert!(k == Kind::Pdf || out.len() <= data.len().saturating_mul(2) + 4096, "{k:?} grew the file far beyond its size");
            let _ = strip::clean(k, &out, &mut vec![]);
        }
    }
    let _ = strip::kind(data, || strip::zip_kind_of(&data), true);
}

/// The ZIP reader on its own.
pub fn zip(data: &[u8]) {
    if let Ok(a) = crate::zip::read(&data) {
        let mut budget = 4 << 20;
        for e in a.entries.iter().take(64) {
            let _ = crate::zip::content(&data, e, 1 << 20, &mut budget);
        }
    }
}

/// The extraction (its dry run) on bytes as a ZIP, a tar, a gzipped tar or file, and the name cleaning: never a panic, and
/// never more unpacked than the limit (and one buffer).
pub fn extract(data: &[u8]) {
    use crate::extract::{self, Discard, Limits, Options};
    let o = Options {
        only: vec![],
        limits: Limits {
            total: 4 << 20,
            per_file: 1 << 20,
            entries: 64,
            ratio: 100,
            entry_allowance: 256 << 10,
            total_allowance: 512 << 10,
        },
    };
    let bound = o.limits.total + (128 << 10);
    let z = extract::zip(&data, &o, &mut Discard);
    assert!(z.unpacked <= bound, "the ZIP reader ran over its limit");
    let mut r: &[u8] = data;
    let t = extract::stream(&mut r, data.len() as u64, "x.tar", false, &o, &mut Discard);
    assert!(t.unpacked <= bound, "the tar reader ran over its limit");
    let mut g = flate2::read::MultiGzDecoder::new(data);
    let t = extract::stream(&mut g, data.len() as u64, "x.gz", true, &o, &mut Discard);
    assert!(t.unpacked <= bound, "the gzip stream ran over its limit");
    let _ = extract::detect(data);
    let _ = extract::clean_name(&data[..data.len().min(4096)]);
}

/// The PDF scanner on its own.
pub fn pdf(data: &[u8]) {
    let d = crate::pdf::Doc::scan(data);
    for o in d.objs.values().take(1000) {
        let t = d.toks(o);
        let _ = crate::pdf::entries(&t, 0);
        let _ = d.stream_data(o, 1 << 20);
    }
}

/// Markup and addresses.
pub fn markup(data: &[u8]) {
    for t in crate::markup::tags(data, 10_000) {
        for (_, v) in &t.attrs {
            let _ = crate::markup::classify(v);
        }
    }
    let _ = crate::markup::css_urls(data);
    let _ = crate::markup::decode_entities(&String::from_utf8_lossy(data));
}

/// Names: the look-alike check on any text.
pub fn lookalike(data: &[u8]) {
    let s = String::from_utf8_lossy(data);
    let r = crate::lookalike::check(&s);
    let _ = (r.words(), crate::lookalike::visible(&s), crate::lookalike::skeleton(&s));
    // what visible() shows has no hidden or turning characters left
    assert!(!crate::lookalike::visible(&s).chars().any(|c| crate::lookalike::invisible(c) || crate::lookalike::direction_control(c)));
}
