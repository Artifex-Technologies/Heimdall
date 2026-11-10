//! The regex differential: texts built to tell Go's and Rust's regular expressions apart (case variants with the long s and
//! the Kelvin sign, words glued to the patterns for \b, Unicode spaces for \s, JSON escapes, invisible characters, cut UTF-8),
//! with what the Go detectors made of each (internal/detect/corpus_export_test.go). The Rust detectors must make the same of
//! every one. The committed corpus is testdata/parity/regex-corpus.jsonl; HEIMDALL_REGEX_CORPUS=FILE runs a bigger one too
//! (rust/scripts/regex-differential.sh).

use heimdall::detect::{self, CredentialDetector, InjectionDetector, UnicodeDetector};
use heimdall::event::{Detector, Event};
use heimdall::gojson::{self, Value};
use heimdall::gotext;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn get<'a>(v: &'a Value, k: &str) -> &'a Value {
    match v {
        Value::Object(m) => &m.iter().find(|(key, _)| key == k).unwrap().1,
        _ => panic!("not an object"),
    }
}

fn st(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        _ => panic!("not a string: {v:?}"),
    }
}

fn run(path: &std::path::Path) -> (usize, usize, Vec<String>) {
    let b = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let (mut inj, mut cred, mut uni) = (InjectionDetector::new(), CredentialDetector::new(), UnicodeDetector::new());
    let (mut n, mut hits, mut diffs) = (0, 0, Vec::new());
    for line in b.split(|&c| c == b'\n').filter(|l| !l.is_empty()) {
        let v = gojson::parse(line).unwrap();
        let raw = unhex(&st(get(&v, "hex")));
        // what the daemon does with bytes from outside: Go's reading of them
        let text = gotext::lossy(&raw);
        let e = Event { text: text.clone(), ..Default::default() };
        let got_inj = inj.inspect(&e).first().map(|f| f.summary.clone()).unwrap_or_default();
        let got_cred = !cred.inspect(&e).is_empty();
        let got_uni = uni.inspect(&e).first().map(|f| f.summary.clone()).unwrap_or_default();
        let got_red = detect::redact_credentials(&text);
        let got_m = detect::credential_matches(&text);
        let want_m: Vec<String> = match get(&v, "matches") {
            Value::Array(a) => a.iter().map(st).collect(),
            _ => Vec::new(),
        };
        let want_cred = get(&v, "credential") == &Value::Bool(true);
        let mut d = Vec::new();
        if got_inj != st(get(&v, "injection")) {
            d.push(format!("injection go {:?} rust {got_inj:?}", st(get(&v, "injection"))));
        }
        if got_cred != want_cred {
            d.push(format!("credential go {want_cred} rust {got_cred}"));
        }
        if got_uni != st(get(&v, "unicode")) {
            d.push(format!("unicode go {:?} rust {got_uni:?}", st(get(&v, "unicode"))));
        }
        if got_red != st(get(&v, "redact")) {
            d.push(format!("redact go {:?} rust {got_red:?}", st(get(&v, "redact"))));
        }
        if got_m != want_m {
            d.push(format!("matches go {want_m:?} rust {got_m:?}"));
        }
        if !d.is_empty() && diffs.len() < 20 {
            diffs.push(format!("{text:?}: {}", d.join("; ")));
        }
        if want_cred || !st(get(&v, "injection")).is_empty() || !st(get(&v, "unicode")).is_empty() {
            hits += 1;
        }
        n += 1;
    }
    (n, hits, diffs)
}

/// The decision, shown: the Go patterns compiled with Rust's own (Unicode-aware) meaning of \b \s \d \w would decide
/// differently from Go on this corpus. Which way each difference goes is printed; the translation (rules.rs) removes all of
/// them, so the port finds what the Go daemon finds.
#[test]
fn rusts_own_unicode_classes_would_differ_from_go() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/parity/regex-corpus.jsonl");
    let rules = heimdall::rules::builtin();
    let naive: Vec<(String, regex::Regex)> =
        rules.rules.iter().map(|r| (r.detector.clone(), regex::Regex::new(&r.pattern).expect("Rust reads the Go syntax"))).collect();
    let (mut more, mut fewer, mut examples) = (0, 0, Vec::new());
    for line in std::fs::read(&path).unwrap().split(|&c| c == b'\n').filter(|l| !l.is_empty()) {
        let v = gojson::parse(line).unwrap();
        let text = gotext::lossy(&unhex(&st(get(&v, "hex"))));
        for det in ["injection-phrase", "credential-shape"] {
            let go =
                if det == "injection-phrase" { !st(get(&v, "injection")).is_empty() } else { get(&v, "credential") == &Value::Bool(true) };
            let rust_default = naive.iter().any(|(d, re)| d == det && re.find(&text).is_some_and(|m| !m.as_str().is_empty()));
            if go != rust_default {
                if rust_default {
                    more += 1;
                } else {
                    fewer += 1;
                }
                if examples.len() < 6 {
                    examples.push(format!("{det}: go {go}, rust-default {rust_default}: {text:?}"));
                }
            }
        }
    }
    eprintln!("Rust's default classes: {more} findings Go does not make, {fewer} Go makes and they miss; e.g.\n{}", examples.join("\n"));
    assert!(more + fewer > 0, "the corpus no longer tells the two meanings apart; add texts that do");
}

#[test]
fn the_rust_detectors_find_what_go_finds() {
    let mut files = vec![std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/parity/regex-corpus.jsonl")];
    if let Ok(extra) = std::env::var("HEIMDALL_REGEX_CORPUS") {
        files.push(extra.into());
    }
    for f in files {
        let (n, hits, diffs) = run(&f);
        eprintln!("{}: {n} texts, {hits} with a finding in Go, {} differences", f.display(), diffs.len());
        assert!(n > 1000, "the corpus looks empty");
        assert!(diffs.is_empty(), "differences:\n{}", diffs.join("\n"));
    }
}
