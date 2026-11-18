//! The lint of a rule draft and YARA-X's compile check (Go: internal/immunity/rulelint.go, yaracheck.go; docs/IMMUNITY.md,
//! "Rules"). Before a draft is kept, what ClamAV does not load is refused (the hard errors) and what makes a rule slow,
//! noisy or hard to trace is noted (warnings, kept with the draft). When heimdall-yara-check is installed, YARA-X compiles
//! the rule too: its errors refuse the draft, its warnings are kept. Same answers as Go: testdata/parity/rulelint.json
//! (tests/rulelint.rs) and the API fixtures with a stand-in checker.
//!
//! The text is read as bytes, as Go reads its strings: a draft's bytes need not be UTF-8 once comments and literals are
//! blanked, so the patterns are byte patterns with ASCII classes (Go's `\b` is ASCII too).

use regex::bytes::Regex;
use std::sync::OnceLock;

/// Where heimdall-yara-check-git installs the checker (Go: DefaultYARACheck).
pub const DEFAULT_YARA_CHECK: &str = "/usr/bin/heimdall-yara-check";
/// The warning kept when the checker is installed but gave no verdict (Go: NoYARAVerdict).
pub const NO_YARA_VERDICT: &str = "YARA-X: the check gave no verdict (heimdall-yara-check failed); judged without it";
const YARA_ITEMS: usize = 20;
const YARA_TEXT: usize = 300;

struct Rx {
    section: Regex,
    meta_key: Regex,
    string: Regex,
    word: Regex,
    op: Regex,
    attack: Regex,
    them: Regex,
    filesize: Regex,
    set: Regex,
    length: Regex,
    rule_name: Regex,
}

fn rx() -> &'static Rx {
    static RX: OnceLock<Rx> = OnceLock::new();
    RX.get_or_init(|| {
        let r = |p: &str| Regex::new(&format!("(?-u){p}")).expect("lint pattern");
        let s = r"[\t\n\x0B\x0C\r ]";
        Rx {
            section: r(&format!(r"\b(meta|strings|condition){s}*:")),
            meta_key: r(&format!(r"([A-Za-z_][A-Za-z0-9_]*){s}*=")),
            string: r(&format!(r"\$([A-Za-z0-9_]*){s}*={s}*")),
            word: r(r"[A-Za-z0-9_]+"),
            op: r(r"\b(contains|icontains|startswith|istartswith|endswith|iendswith|iequals|matches)\b"),
            attack: r(r"^T[0-9]{4}(\.[0-9]{3})?$"),
            them: r(r"\bthem\b"),
            filesize: r(r"\bfilesize\b"),
            set: r(r"\$([A-Za-z0-9_]*)\*"),
            length: r(r"![A-Za-z0-9_]"),
            // Go's ruleNameRx (with its ASCII \s): (?m)^\s*(?:private\s+|global\s+)*rule\s+(name)
            rule_name: {
                let g = r"[\t\n\x0C\r ]"; // Go's \s: no vertical tab
                r(&format!(r"(?m)^{g}*(?:private{g}+|global{g}+)*rule{g}+([A-Za-z_][A-Za-z0-9_]*)"))
            },
        }
    })
}

/// Strings found in most programs, documents and web pages (compared without case): Go's lintCommon.
const COMMON: &[&[u8]] = &[
    b"mz",
    b"pe",
    b"elf",
    b"\x7felf",
    b"pk",
    b"pk\x03\x04",
    b"%pdf",
    b"this program cannot be run in dos mode",
    b"this program must be run under win32",
    b"kernel32.dll",
    b"ntdll.dll",
    b"user32.dll",
    b"advapi32.dll",
    b"msvcrt.dll",
    b"getprocaddress",
    b"loadlibrarya",
    b"loadlibraryw",
    b"virtualalloc",
    b"http://",
    b"https://",
    b"www.",
    b".com",
    b"/bin/sh",
    b"/bin/bash",
    b"/tmp/",
    b"#!/bin/sh",
    b"#!/bin/bash",
    b"#!/usr/bin/env",
    b"<script",
    b"<html",
    b"<?php",
    b"libc.so.6",
    b"glibc_2.2.5",
    b".text",
    b".data",
    b".rdata",
    b".rodata",
    b".bss",
    b"microsoft",
    b"windows",
    b"cmd.exe",
    b"powershell",
];

/// One string of the strings: section (Go: lintString).
#[derive(Default)]
struct LintString {
    name: String,
    kind: u8,
    fixed: Vec<u8>,
    longest: usize,
    part_short: bool,
    not: bool,
    comment: bool,
    wild: i64,
    unbounded: bool,
    mods: Vec<Vec<u8>>,
    flags: Vec<u8>,
}

fn space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0B | 0x0C | b'\r')
}

fn hex_digit(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    if n.is_empty() {
        return Some(0);
    }
    h.windows(n.len()).position(|w| w == n)
}

fn index_byte(h: &[u8], c: u8) -> Option<usize> {
    h.iter().position(|&x| x == c)
}

fn trim_ascii(s: &[u8]) -> &[u8] {
    let mut a = 0;
    let mut b = s.len();
    while a < b && space(s[a]) {
        a += 1;
    }
    while b > a && space(s[b - 1]) {
        b -= 1;
    }
    &s[a..b]
}

/// Go's lintMask: comments blanked, the insides of text strings and regular expressions written as x, every byte where it
/// was; and where each literal starts and ends.
fn mask(text: &[u8]) -> (Vec<u8>, std::collections::HashMap<usize, usize>) {
    let mut m = text.to_vec();
    let mut lits = std::collections::HashMap::new();
    let n = text.len();
    let mut prev = 0u8;
    let mut i = 0;
    while i < n {
        let c = text[i];
        if c == b'/' && i + 1 < n && text[i + 1] == b'/' {
            while i < n && text[i] != b'\n' {
                m[i] = b' ';
                i += 1;
            }
        } else if c == b'/' && i + 1 < n && text[i + 1] == b'*' {
            let end = find(&text[i + 2..], b"*/").map(|j| i + 2 + j + 2).unwrap_or(n);
            while i < end {
                if m[i] != b'\n' {
                    m[i] = b' ';
                }
                i += 1;
            }
        } else if c == b'"' || (c == b'/' && prev == b'=') {
            let mut j = i + 1;
            while j < n && text[j] != c {
                if text[j] == b'\\' {
                    j += 1;
                }
                j += 1;
            }
            let end = (j + 1).min(n);
            for x in m.iter_mut().take(end.saturating_sub(1)).skip(i + 1) {
                *x = b'x';
            }
            lits.insert(i, end);
            prev = c;
            i = end;
        } else {
            if !space(c) {
                prev = c;
            }
            i += 1;
        }
    }
    (m, lits)
}

/// Go's lintUnescape.
fn unescape(s: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'\\' && i + 1 < s.len() {
            if s[i + 1] == b'x' && i + 3 < s.len() && hex_digit(s[i + 2]) && hex_digit(s[i + 3]) {
                b.push(u8::from_str_radix(std::str::from_utf8(&s[i + 2..i + 4]).unwrap_or("0"), 16).unwrap_or(0));
                i += 4;
                continue;
            }
            i += 1;
        }
        b.push(s[i]);
        i += 1;
    }
    b
}

/// Go's lintNum.
fn num(s: &[u8]) -> i64 {
    if s.is_empty() || !s.iter().all(u8::is_ascii_digit) {
        return 0;
    }
    if s.len() > 7 {
        return 1 << 20;
    }
    let n: i64 = std::str::from_utf8(s).ok().and_then(|x| x.parse().ok()).unwrap_or(0);
    n.min(1 << 20)
}

/// Go's lintHex.
fn hex(s: &[u8], ls: &mut LintString) {
    let (mut run, mut part, mut part_max, mut plain) = (0usize, 0usize, 0usize, true);
    let mut fixed = Vec::new();
    let end_run = |run: &mut usize, part_max: &mut usize, ls: &mut LintString| {
        ls.longest = ls.longest.max(*run);
        *part_max = (*part_max).max(*run);
        *run = 0;
    };
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if space(c) {
            i += 1;
        } else if c == b'[' {
            let j = index_byte(&s[i..], b']').unwrap_or(s.len() - i);
            let inner = trim_ascii(&s[i + 1..i + j]);
            let (lo, hi, dash) = match index_byte(inner, b'-') {
                Some(k) => (trim_ascii(&inner[..k]), trim_ascii(&inner[k + 1..]), true),
                None => (inner, &b""[..], false),
            };
            if dash && hi.is_empty() {
                ls.unbounded = true;
            } else if dash {
                ls.wild += num(hi);
            } else {
                ls.wild += num(lo);
            }
            plain = false;
            // endPart
            end_run(&mut run, &mut part_max, ls);
            if part > 0 && part_max < 2 {
                ls.part_short = true;
            }
            part = 0;
            part_max = 0;
            i += j + 1;
        } else if c == b'(' || c == b'|' || c == b')' {
            plain = false;
            end_run(&mut run, &mut part_max, ls);
            i += 1;
        } else if c == b'~' {
            ls.not = true;
            plain = false;
            end_run(&mut run, &mut part_max, ls);
            i += 1;
        } else if i + 1 < s.len() && hex_digit(c) && hex_digit(s[i + 1]) {
            fixed.push(u8::from_str_radix(std::str::from_utf8(&s[i..i + 2]).unwrap_or("0"), 16).unwrap_or(0));
            run += 1;
            part += 1;
            i += 2;
        } else if i + 1 < s.len() && (c == b'?' || hex_digit(c)) && (s[i + 1] == b'?' || hex_digit(s[i + 1])) {
            ls.wild += 1;
            plain = false;
            part += 1;
            end_run(&mut run, &mut part_max, ls);
            i += 2;
        } else {
            plain = false;
            end_run(&mut run, &mut part_max, ls);
            i += 1;
        }
    }
    end_run(&mut run, &mut part_max, ls);
    if part > 0 && part_max < 2 {
        ls.part_short = true;
    }
    if plain {
        ls.fixed = fixed;
    }
}

/// Go's lintRegexp.
fn regexp(s: &[u8], ls: &mut LintString) {
    let mut run = 0usize;
    let end_run = |run: &mut usize, ls: &mut LintString| {
        ls.longest = ls.longest.max(*run);
        *run = 0;
    };
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if c == b'\\' && i + 1 < s.len() {
            i += 1;
            if b"\\/.+*?()[]{}|^$-".contains(&s[i]) {
                run += 1;
            } else {
                end_run(&mut run, ls);
            }
        } else if c == b'[' {
            end_run(&mut run, ls);
            i += 1;
            while i < s.len() && s[i] != b']' {
                if s[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
        } else if c == b'*' || c == b'+' {
            if c == b'*' && run > 0 {
                run -= 1;
            }
            end_run(&mut run, ls);
            ls.unbounded = true;
        } else if c == b'?' {
            run = run.saturating_sub(1);
            end_run(&mut run, ls);
        } else if c == b'{' {
            let Some(j) = index_byte(&s[i..], b'}') else {
                end_run(&mut run, ls);
                i += 1;
                continue;
            };
            let inner = &s[i + 1..i + j];
            if inner.first() == Some(&b'0') && run > 0 {
                run -= 1;
            }
            end_run(&mut run, ls);
            if inner.last() == Some(&b',') {
                ls.unbounded = true;
            } else if let Some(k) = inner.iter().rposition(|&x| x == b',') {
                ls.wild += num(&inner[k + 1..]);
            }
            i += j;
        } else if c == b'.' {
            end_run(&mut run, ls);
            ls.wild += 1;
        } else if b"()|^$".contains(&c) {
            end_run(&mut run, ls);
        } else {
            run += 1;
        }
        i += 1;
    }
    end_run(&mut run, ls);
}

/// Go's lintSections: where each section's inside starts and ends in the masked text.
fn sections(masked: &[u8]) -> std::collections::HashMap<Vec<u8>, (usize, usize)> {
    let end = masked.iter().rposition(|&c| c == b'}').unwrap_or(masked.len());
    let ms: Vec<regex::bytes::Captures> = rx().section.captures_iter(masked).collect();
    let mut secs = std::collections::HashMap::new();
    for (i, m) in ms.iter().enumerate() {
        let whole = m.get(0).expect("match");
        let mut e = end;
        if let Some(next) = ms.get(i + 1) {
            let s = next.get(0).expect("match").start();
            if s < e {
                e = s;
            }
        }
        if whole.end() > e {
            e = whole.end();
        }
        secs.insert(m[1].to_vec(), (whole.end(), e));
    }
    secs
}

fn is_letter(c: u8) -> bool {
    c.is_ascii_alphabetic()
}

/// Go's lintStrings.
fn strings_of(text: &[u8], masked: &[u8], lits: &std::collections::HashMap<usize, usize>, sec: (usize, usize)) -> Vec<LintString> {
    let body = &masked[sec.0..sec.1];
    let locs: Vec<regex::bytes::Captures> = rx().string.captures_iter(body).collect();
    let mut out = Vec::new();
    for (i, m) in locs.iter().enumerate() {
        let next = locs.get(i + 1).map(|x| x.get(0).expect("match").start()).unwrap_or(body.len());
        let mut ls = LintString { name: format!("${}", String::from_utf8_lossy(&m[1])), ..Default::default() };
        let at = sec.0 + m.get(0).expect("match").end();
        let stop = sec.0 + next;
        let mut rest = at;
        if at < text.len() {
            match text[at] {
                b'"' => {
                    ls.kind = b't';
                    let end = lits.get(&at).copied().filter(|&e| e != 0).unwrap_or(at + 1);
                    if end - 1 > at {
                        ls.fixed = unescape(&text[at + 1..end - 1]);
                    }
                    ls.longest = ls.fixed.len();
                    rest = end;
                }
                b'/' => {
                    ls.kind = b'r';
                    let end = lits.get(&at).copied().filter(|&e| e != 0).unwrap_or(at + 1);
                    if end - 1 > at {
                        regexp(&text[at + 1..end - 1], &mut ls);
                    }
                    rest = end;
                    while rest < stop && is_letter(text[rest]) {
                        rest += 1;
                    }
                    ls.flags = text[end..rest.max(end)].to_vec();
                }
                b'{' => {
                    ls.kind = b'h';
                    // no closing brace: to the section's end
                    let end = index_byte(&masked[at..stop], b'}').unwrap_or(stop - at);
                    hex(&masked[at + 1..at + end], &mut ls);
                    ls.comment = masked[at..at + end] != text[at..at + end];
                    rest = at + end + 1;
                }
                _ => {}
            }
        }
        if rest < stop {
            ls.mods = rx().word.find_iter(&masked[rest..stop]).map(|w| w.as_bytes().to_vec()).collect();
        }
        out.push(ls);
    }
    out
}

/// Go's lintUsed.
fn used(cond: &[u8], name: &str) -> bool {
    if rx().them.is_match(cond) {
        return true;
    }
    let id = &name.as_bytes()[1..];
    if !id.is_empty() {
        for p in *b"$#@!" {
            let mut needle = vec![p];
            needle.extend_from_slice(id);
            let mut from = 0;
            while let Some(k) = find(&cond[from..], &needle) {
                let after = from + k + needle.len();
                if after == cond.len() || !(cond[after].is_ascii_alphanumeric() || cond[after] == b'_' || cond[after] == b'*') {
                    return true;
                }
                from += k + 1;
            }
        }
    }
    rx().set.captures_iter(cond).any(|m| id.starts_with(&m[1]))
}

fn lower(b: &[u8]) -> Vec<u8> {
    b.to_ascii_lowercase()
}

/// Go's lintRule: the first hard error ("" for none) and the warnings, for a rule that passed the form checks.
pub fn lint(text: &str) -> (String, Vec<String>) {
    let text = text.as_bytes();
    let (masked, lits) = mask(text);
    if let Some(h) = rx().rule_name.find(&masked) {
        let h = h.as_bytes();
        if find(h, b"global").is_some() {
            return ("ClamAV does not support global rules".into(), Vec::new());
        }
        if find(h, b"private").is_some() {
            return ("a private rule never reports a match in ClamAV: drop \"private\"".into(), Vec::new());
        }
    }
    let secs = sections(&masked);
    let strs = match secs.get(&b"strings"[..]) {
        Some(&sec) => strings_of(text, &masked, &lits, sec),
        None => Vec::new(),
    };
    if strs.is_empty() {
        return ("ClamAV loads only a rule with strings: add a strings: section".into(), Vec::new());
    }
    if strs.len() > 64 {
        return ("at most 64 strings in a rule (ClamAV's limit)".into(), Vec::new());
    }
    let cond: &[u8] = match secs.get(&b"condition"[..]) {
        Some(&(a, b)) => &masked[a..b],
        None => b"",
    };
    for s in &strs {
        for m in &s.mods {
            if matches!(m.as_slice(), b"xor" | b"base64" | b"base64wide" | b"private") {
                return (format!("{}: ClamAV does not support the {} modifier", s.name, String::from_utf8_lossy(m)), Vec::new());
            }
        }
        match s.kind {
            b't' if s.fixed.len() < 2 => return (format!("{}: ClamAV needs at least 2 bytes", s.name), Vec::new()),
            b'h' if s.comment => return (format!("{}: ClamAV does not accept comments inside a hex string", s.name), Vec::new()),
            b'h' if s.not => return (format!("{}: ClamAV does not accept ~ (not) in a hex string", s.name), Vec::new()),
            b'h' if s.longest < 2 || s.part_short => {
                return (
                    format!("{}: ClamAV needs 2 fixed bytes in a row in a hex string, and in each part between jumps", s.name),
                    Vec::new(),
                )
            }
            b'r' if !s.flags.is_empty() => {
                return (
                    format!("{}: ClamAV ignores regular expression flags (/i, /s): spell the cases out, e.g. [Dd]", s.name),
                    Vec::new(),
                )
            }
            _ => {}
        }
        if !used(cond, &s.name) {
            return (format!("{} is not used by the condition (ClamAV refuses the rule)", s.name), Vec::new());
        }
    }
    if let Some(m) = rx().op.captures(cond) {
        // Go's %q of an ASCII word
        return (format!("ClamAV does not support \"{}\" in a condition", String::from_utf8_lossy(&m[1])), Vec::new());
    }
    if rx().length.is_match(cond) {
        return ("ClamAV does not support match lengths (!a) in a condition".into(), Vec::new());
    }

    let mut warn = Vec::new();
    let mut wild = Vec::new();
    for s in &strs {
        let low = lower(&s.fixed);
        let common = !s.fixed.is_empty() && COMMON.iter().any(|c| low == *c);
        let repeated = s.fixed.len() >= 2 && s.fixed.iter().all(|&b| b == s.fixed[0]);
        if s.longest < 4 {
            warn.push(format!(
                "{}: shorter than 4 fixed bytes in a row: slow to search for (YARA-X calls it a slow pattern) and likely to match by chance",
                s.name
            ));
        } else if repeated {
            warn.push(format!("{} is one byte repeated: common in ordinary files", s.name));
        } else if common {
            warn.push(format!("{} is very common in ordinary programs and documents: pair it with a rarer string", s.name));
        }
        if s.unbounded || s.wild >= 16 {
            wild.push(s.name.clone());
        }
    }
    if !wild.is_empty() && !rx().filesize.is_match(cond) {
        warn.push(format!("{}: many wildcards or jumps and no filesize in the condition: bound it, e.g. filesize < 2MB", wild.join(", ")));
    }
    let mut keys: std::collections::HashMap<Vec<u8>, usize> = std::collections::HashMap::new();
    if let Some(&(a, b)) = secs.get(&b"meta"[..]) {
        for k in rx().meta_key.captures_iter(&masked[a..b]) {
            let mut v = a + k.get(0).expect("match").end();
            while v < masked.len() && space(masked[v]) {
                v += 1;
            }
            keys.insert(k[1].to_vec(), v);
        }
    }
    for (key, why) in [("sample_sha256", " (the held sample it was made from)"), ("author", ""), ("date", " (YYYY-MM-DD)")] {
        if !keys.contains_key(key.as_bytes()) {
            warn.push(format!("meta: {key} is missing{why}"));
        }
    }
    if let Some(&at) = keys.get(&b"attack"[..]) {
        let mut good = false;
        if let Some(&end) = lits.get(&at) {
            if end > at + 1 && text[at] == b'"' {
                let ids: Vec<&[u8]> = text[at + 1..end - 1].split(|&c| c == b',' || c == b' ').filter(|x| !x.is_empty()).collect();
                good = !ids.is_empty() && ids.iter().all(|id| rx().attack.is_match(id));
            }
        }
        if !good {
            warn.push("meta: attack is not a list of ATT&CK technique IDs (T1059 or T1059.004, comma-separated)".into());
        }
    }
    (String::new(), warn)
}

/// heimdall-yara-check's answer (Go: YARAVerdict).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Verdict {
    pub errors: Vec<String>,
    pub ok: bool,
    pub warnings: Vec<String>,
    pub version: String,
}

/// Go's clipItems: at most 20 lines of at most 300 bytes each, cut before a letter.
fn clip(v: Vec<String>) -> Vec<String> {
    v.into_iter()
        .take(YARA_ITEMS)
        .map(|mut s| {
            if s.len() > YARA_TEXT {
                let mut n = YARA_TEXT;
                while n > 0 && !s.is_char_boundary(n) {
                    n -= 1;
                }
                s.truncate(n);
            }
            s
        })
        .collect()
}

/// The checker a drafts file uses (Go: Rules.yaraCheckPath): its own, else HEIMDALL_YARA_CHECK (tests), else the default.
pub fn check_path(own: &str) -> String {
    if !own.is_empty() {
        return own.to_string();
    }
    match std::env::var("HEIMDALL_YARA_CHECK") {
        Ok(p) if !p.is_empty() => p,
        _ => DEFAULT_YARA_CHECK.to_string(),
    }
}

/// Go's YARACheck: Ok(None) when the checker is not installed (not a regular executable file); Err when it gave no verdict.
pub fn yara_check(path: &str, text: &str) -> Result<Option<Verdict>, String> {
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(m) if m.is_file() && m.permissions().mode() & 0o111 != 0 => {}
        _ => return Ok(None),
    }
    let no = || NO_YARA_VERDICT.to_string();
    let mut child = std::process::Command::new(path)
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|_| no())?;
    let mut stdin = child.stdin.take().ok_or_else(no)?;
    let input = text.as_bytes().to_vec();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let mut stdout = child.stdout.take().ok_or_else(no)?;
    let reader = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = (&mut stdout).take((1 << 20) + 1).read_to_end(&mut b);
        // drain the rest, so the checker never blocks on a full pipe
        let _ = std::io::copy(&mut stdout, &mut std::io::sink());
        b
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) if std::time::Instant::now() < deadline => std::thread::sleep(std::time::Duration::from_millis(5)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let _ = writer.join();
    let out = reader.join().unwrap_or_default();
    match status {
        Some(s) if s.success() && out.len() <= 1 << 20 => {}
        _ => return Err(no()),
    }
    let v = crate::gojson::parse_first(&out).map_err(|_| no())?;
    use crate::gojson::Value as J;
    // as Go's decoder fills YARAVerdict: every member whose key matches a field (without case) is applied in order, the last
    // one wins, and a member of the wrong type is an error even when a later one would be right
    let members: &[(String, J)] = match &v {
        J::Object(m) => m,
        J::Null => &[],
        _ => return Err(no()),
    };
    let (mut errors, mut ok, mut warnings, mut version) = (Vec::new(), false, Vec::new(), String::new());
    let strs = |x: &J| -> Result<Vec<String>, String> {
        match x {
            J::Null => Ok(Vec::new()),
            J::Array(a) => a
                .iter()
                .map(|e| match e {
                    J::String(s) => Ok(s.clone()),
                    J::Null => Ok(String::new()),
                    _ => Err(no()),
                })
                .collect(),
            _ => Err(no()),
        }
    };
    for (k, x) in members {
        if crate::gojson::key_matches(k, "errors") {
            errors = strs(x)?;
        } else if crate::gojson::key_matches(k, "ok") {
            match x {
                J::Null => {}
                J::Bool(b) => ok = *b,
                _ => return Err(no()),
            }
        } else if crate::gojson::key_matches(k, "warnings") {
            warnings = strs(x)?;
        } else if crate::gojson::key_matches(k, "yara_x") {
            match x {
                J::Null => {}
                J::String(s) => version = s.clone(),
                _ => return Err(no()),
            }
        }
    }
    if version.is_empty() || (!ok && errors.is_empty()) || (ok && !errors.is_empty()) {
        return Err(no());
    }
    Ok(Some(Verdict { errors: clip(errors), ok, warnings: clip(warnings), version }))
}

/// Go's Rules.judgeRule: the form checks (refuse), the lint's warnings, and YARA-X's verdict when the checker is installed
/// (its errors refuse, its warnings are kept). The warnings come back even when YARA-X refuses.
pub fn judge(check: &str, text: &str) -> (Result<String, String>, Vec<String>) {
    let name = match crate::immunity::check_rule(text) {
        Ok(n) => n,
        Err(e) => return (Err(e), Vec::new()),
    };
    let (_, mut warn) = lint(text);
    match yara_check(&check_path(check), text) {
        Err(e) => warn.push(e),
        Ok(Some(v)) => {
            warn.extend(v.warnings.iter().map(|w| format!("YARA-X: {w}")));
            if !v.ok {
                return (Err(format!("YARA-X does not compile it: {}", v.errors.join("; "))), warn);
            }
        }
        Ok(None) => {}
    }
    (Ok(name), warn)
}
