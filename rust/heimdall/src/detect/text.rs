//! The content detectors: prompt injection, credentials, invisible characters, permission denials (Go: injection.go,
//! credential.go, unicode.go, escalation.go). The first two take their patterns from the checked rule file (crate::rules).

use crate::event::{Detector, Event, Finding, Severity};
use crate::gotext;
use crate::rules::{self, RuleSet};
use regex::Regex;
use std::sync::OnceLock;

/// Flags text that reads as an attempt to override the agent's instructions.
pub struct InjectionDetector {
    rules: &'static RuleSet,
}

impl InjectionDetector {
    pub fn new() -> Self {
        InjectionDetector { rules: rules::builtin() }
    }
}

impl Default for InjectionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for InjectionDetector {
    fn id(&self) -> &'static str {
        "injection-phrase"
    }

    fn inspect(&mut self, e: &Event) -> Vec<Finding> {
        let folded = rules::fold(&e.text);
        let la = lookalikes(&e.text);
        for r in self.rules.of("injection-phrase") {
            if !r.may_match(&e.text, &folded) {
                continue;
            }
            // Go's FindString: an empty match reads as no match
            if let Some(&(a, z)) = spans(r, &e.text, &la, 1).first().filter(|(a, z)| z > a) {
                let summary = format!("text reads as an instruction override rather than task content (\"{}\")", &e.text[a..z]);
                return vec![Finding::new(self.id(), Severity::Critical, summary, e)];
            }
        }
        Vec::new()
    }
}

/// Flags text that looks like a leaked secret.
pub struct CredentialDetector {
    rules: &'static RuleSet,
}

impl CredentialDetector {
    pub fn new() -> Self {
        CredentialDetector { rules: rules::builtin() }
    }
}

impl Default for CredentialDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for CredentialDetector {
    fn id(&self) -> &'static str {
        "credential-shape"
    }

    fn inspect(&mut self, e: &Event) -> Vec<Finding> {
        let folded = rules::fold(&e.text);
        let la = lookalikes(&e.text);
        for r in self.rules.of("credential-shape") {
            if r.may_match(&e.text, &folded) && r.re.is_match(on(r, &e.text, &la)) {
                return vec![Finding::new(self.id(), Severity::Critical, "text contains what looks like a credential or secret".into(), e)];
            }
        }
        Vec::new()
    }
}

/// Every piece of text with a credential's shape, at most 20 per pattern (Go's FindAllString(text, 20)), for the verifier.
pub fn credential_matches(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let la = lookalikes(text);
    for r in rules::builtin().of("credential-shape") {
        out.extend(spans(r, text, &la, 20).into_iter().map(|(a, z)| text[a..z].to_owned()));
    }
    out
}

/// Keeps the first 4 bytes of every credential-shaped piece of text and drops the rest, so an alert never carries the secret.
/// The cut is by bytes, as in Go ([`gotext::byte_prefix`]).
pub fn redact_credentials(text: &str) -> String {
    let set = rules::builtin();
    let mut text = std::borrow::Cow::Borrowed(text);
    let mut folded = rules::fold(&text).into_owned();
    for r in set.of("credential-shape") {
        if !r.may_match(&text, &folded) {
            continue;
        }
        // matched on the look-alike copy for a case-insensitive pattern, always cut from the original text
        let la = lookalikes(&text);
        let found = spans(r, &text, &la, usize::MAX);
        if found.is_empty() {
            continue;
        }
        let mut s = String::with_capacity(text.len());
        let mut last = 0;
        for (a, z) in found {
            s.push_str(&text[last..a]);
            s.push_str(&format!("{}…[redacted]", gotext::byte_prefix(&text[a..z], 4)));
            last = z;
        }
        s.push_str(&text[last..]);
        if s != *text {
            folded = rules::fold(&s).into_owned(); // the next patterns look at the redacted text
            text = std::borrow::Cow::Owned(s);
        }
    }
    text.into_owned()
}

/// The text with the long s (U+017F) and the Kelvin sign (U+212A) written as "s" and "k", and for each of its bytes (and its
/// end) the offset in the original; None when the text has neither. Go's case-insensitive matching folds these two onto
/// s and k, but its word boundary and word class are ASCII, so a long s first ("system notice to the assistant" with one)
/// slipped past the word-boundary patterns. The case-insensitive patterns run on this copy, and every match is cut from
/// the original (approved by the owner on 2026-11-10; the Go daemon does the same, internal/detect/lookalikes.go).
pub fn lookalikes(s: &str) -> Option<(String, Vec<usize>)> {
    if !s.contains(['\u{17F}', '\u{212A}']) {
        return None;
    }
    let mut out = String::with_capacity(s.len());
    let mut at = Vec::with_capacity(s.len() + 1);
    for (i, c) in s.char_indices() {
        match c {
            '\u{17F}' => {
                out.push('s');
                at.push(i);
            }
            '\u{212A}' => {
                out.push('k');
                at.push(i);
            }
            c => {
                out.push(c);
                at.extend((0..c.len_utf8()).map(|k| i + k));
            }
        }
    }
    at.push(s.len());
    Some((out, at))
}

/// What a rule runs on: the look-alike copy for a case-insensitive rule, the text otherwise.
fn on<'a>(r: &rules::Rule, text: &'a str, la: &'a Option<(String, Vec<usize>)>) -> &'a str {
    match la {
        Some((norm, _)) if r.folded => norm,
        _ => text,
    }
}

/// A rule's matches (at most `limit`) as spans of the original text.
fn spans(r: &rules::Rule, text: &str, la: &Option<(String, Vec<usize>)>, limit: usize) -> Vec<(usize, usize)> {
    let hay = on(r, text, la);
    let back = |a: usize, z: usize| match la {
        Some((_, at)) if r.folded => (at[a], at[z]),
        _ => (a, z),
    };
    r.re.find_iter(hay).take(limit).map(|m| back(m.start(), m.end())).collect()
}

/// Flags invisible, bidi-override, isolate or tag characters, in the text as it is and with JSON `\uXXXX` escapes decoded
/// (Sarina keeps a tool result as JSON inside a string, so a zero-width space arrives as the six characters backslash, u, 2, 0, 0, b).
#[derive(Default)]
pub struct UnicodeDetector;

impl UnicodeDetector {
    pub fn new() -> Self {
        UnicodeDetector
    }
}

fn flagged(c: char) -> bool {
    let r = c as u32;
    matches!(r, 0x200B | 0x200C | 0x200D | 0x2060 | 0xFEFF | 0x00AD)
        || (0x202A..0x202F).contains(&r)
        || (0x2066..0x206A).contains(&r)
        || (0xE0000..0xE0080).contains(&r)
        || gotext::is_cf(c)
}

fn escape_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\\u[0-9a-fA-F]{4}").expect("static pattern"))
}

/// Every `\uXXXX` escape replaced by its character, surrogate pairs combined and lone surrogates as U+FFFD (Go's
/// decodeEscapes with utf16.Decode).
pub fn decode_escapes(text: &str) -> String {
    if !escape_re().is_match(text) {
        return text.to_owned();
    }
    let rs: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut units: Vec<u16> = Vec::new();
    let flush = |units: &mut Vec<u16>, out: &mut String| {
        out.extend(char::decode_utf16(units.iter().copied()).map(|r| r.unwrap_or('\u{FFFD}')));
        units.clear();
    };
    let mut i = 0;
    while i < rs.len() {
        if rs[i] == '\\' && i + 5 < rs.len() && rs[i + 1] == 'u' {
            let hex: String = rs[i + 2..i + 6].iter().collect();
            if hex.chars().all(|c| c.is_ascii_hexdigit()) {
                if let Ok(v) = u16::from_str_radix(&hex, 16) {
                    units.push(v);
                    i += 6;
                    continue;
                }
            }
        }
        flush(&mut units, &mut out);
        out.push(rs[i]);
        i += 1;
    }
    flush(&mut units, &mut out);
    out
}

impl UnicodeDetector {
    fn look(&self, e: &Event, text: &str) -> Vec<Finding> {
        for c in text.chars() {
            if (c as u32) < 0x80 {
                continue; // no ASCII character is flagged (a test checks)
            }
            if flagged(c) {
                let summary = format!("text contains an invisible/formatting Unicode character (U+{:04X})", c as u32);
                return vec![Finding::new("invisible-unicode", Severity::Warning, summary, e)];
            }
        }
        Vec::new()
    }
}

impl Detector for UnicodeDetector {
    fn id(&self) -> &'static str {
        "invisible-unicode"
    }

    fn inspect(&mut self, e: &Event) -> Vec<Finding> {
        let f = self.look(e, &e.text);
        if !f.is_empty() {
            return f;
        }
        if e.text.contains("\\u") {
            let decoded = decode_escapes(&e.text);
            if decoded != e.text {
                return self.look(e, &decoded);
            }
        }
        Vec::new()
    }
}

/// What an AI agent wrote into a file, looked through for marks a reader does not see (HEI-9; Go: AgentWatermarkDetector):
/// invisible characters, variation selectors that are not emoji styling, letters from another alphabet inside Latin words,
/// and trailing spaces and tabs that read as text. The text comes from the agent source's `agent_write` events (the tool
/// call itself); the alert names the file and the marks, never carries what was written.
#[derive(Default)]
pub struct AgentWatermarkDetector;

/// Go's isHiddenRune: a format character, a joiner or filler that shows nothing, or a tag character.
fn is_hidden_rune(c: char) -> bool {
    gotext::is_cf(c) || matches!(c as u32, 0x034F | 0x115F | 0x1160 | 0x3164 | 0xFFA0 | 0xE0000..=0xE007F)
}

/// A variation selector's byte value: VS1-16 are 0-15, VS17-256 16-255.
fn variation_byte(c: char) -> Option<u8> {
    match c as u32 {
        v @ 0xFE00..=0xFE0F => Some((v - 0xFE00) as u8),
        v @ 0xE0100..=0xE01EF => Some((v - 0xE0100 + 16) as u8),
        _ => None,
    }
}

/// VS15 or VS16 right after a symbol or an emoji: a variation selector used as meant.
fn emoji_styled(prev: char, c: char) -> bool {
    use gotext::{is_in, Table};
    matches!(c as u32, 0xFE0E | 0xFE0F)
        && (is_in(Table::So, prev) || is_in(Table::Sm, prev) || prev as u32 >= 0x1F000 || (0x2190..=0x2BFF).contains(&(prev as u32)))
}

/// Go's asciiText: the bytes as text when there are two or more and each is printable ASCII, a line break or a tab.
fn ascii_text(b: &[u8]) -> Option<String> {
    (b.len() >= 2 && b.iter().all(|c| (0x20..=0x7e).contains(c) || *c == b'\n' || *c == b'\t'))
        .then(|| String::from_utf8_lossy(b).into_owned())
}

fn clip_ascii(s: &str) -> String {
    if s.len() > 80 {
        format!("{}...", &s[..80])
    } else {
        s.to_owned()
    }
}

/// Go's watermarkMarks: each kind of mark in words, and its short name.
fn watermark_marks(s: &str) -> (Vec<String>, Vec<&'static str>) {
    use gotext::{is_in, quote, Table};
    let (mut invisible, mut selectors) = (0usize, 0usize);
    let (mut tags, mut sel) = (Vec::new(), Vec::new());
    let mut prev = '\0';
    for c in s.chars() {
        if is_hidden_rune(c) {
            invisible += 1;
            if (0xE0020..=0xE007E).contains(&(c as u32)) {
                tags.push((c as u32 - 0xE0000) as u8);
            }
        }
        if let Some(v) = variation_byte(c).filter(|_| !emoji_styled(prev, c)) {
            selectors += 1;
            sel.push(v);
        }
        prev = c;
    }
    let (mut words, mut first_word, mut first_line) = (0usize, String::new(), 0usize);
    let mut bits = String::new();
    for (i, line) in s.split('\n').enumerate() {
        let line = line.trim_end_matches('\r');
        for c in line[line.trim_end_matches([' ', '\t']).len()..].chars() {
            bits.push(if c == ' ' { '0' } else { '1' });
        }
        for w in line.split(|c: char| !gotext::is_letter(c) && !gotext::is_digit(c) && c != '_').filter(|w| !w.is_empty()) {
            let (mut latin, mut foreign) = (false, false);
            for c in w.chars() {
                if is_in(Table::Latin, c) {
                    latin = true;
                } else if is_in(Table::Cyrillic, c)
                    || is_in(Table::Greek, c)
                    || is_in(Table::Armenian, c)
                    || (0xFF01..=0xFF5E).contains(&(c as u32))
                {
                    foreign = true;
                }
            }
            if latin && foreign {
                if words == 0 {
                    first_word = w.to_owned();
                    first_line = i + 1;
                }
                words += 1;
            }
        }
    }
    let (mut marks, mut kinds) = (Vec::new(), Vec::new());
    if invisible > 0 {
        let mut m = format!("{invisible} invisible characters (zero-width, tag, direction or other format characters)");
        if let Some(t) = ascii_text(&tags) {
            m += &format!(", the tag characters reading {}", quote(&clip_ascii(&t)));
        }
        marks.push(m);
        kinds.push("invisible");
    }
    if selectors > 0 {
        let mut m = format!("{selectors} variation selectors that are not emoji styling (each can carry a byte)");
        if let Some(t) = ascii_text(&sel) {
            m += &format!(", reading {}", quote(&clip_ascii(&t)));
        }
        marks.push(m);
        kinds.push("variation-selectors");
    }
    if words > 0 {
        marks.push(format!(
            "letters from another alphabet inside {words} Latin words (the first {}, line {first_line})",
            quote(&first_word)
        ));
        kinds.push("look-alike-letters");
    }
    if bits.len() >= 16 {
        let raw: Vec<u8> = bits.as_bytes().chunks_exact(8).map(|g| g.iter().fold(0u8, |c, x| (c << 1) | (x - b'0'))).collect();
        if let Some(t) = ascii_text(&raw) {
            marks.push(format!("trailing spaces and tabs that read as {}", quote(&clip_ascii(&t))));
            kinds.push("trailing-bits");
        }
    }
    (marks, kinds)
}

impl Detector for AgentWatermarkDetector {
    fn id(&self) -> &'static str {
        "agent-watermark"
    }

    fn inspect(&mut self, e: &Event) -> Vec<Finding> {
        if e.source != "agent-session" || e.kind != "agent_write" {
            return Vec::new();
        }
        let (marks, kinds) = watermark_marks(e.f("content"));
        if marks.is_empty() {
            return Vec::new();
        }
        let mut ev = e.clone();
        ev.fields.remove("content");
        ev.fields.insert("marks".into(), kinds.join(","));
        let summary = format!(
            "an AI agent wrote {} ({}) with marks a reader does not see: {}",
            gotext::quote(e.f("path")),
            e.f("tool"),
            marks.join("; ")
        );
        vec![Finding::new("agent-watermark", Severity::Warning, summary, &ev)]
    }
}

/// Flags the "Permission denials: N" line a session reports: a warning for one or two, critical from three.
#[derive(Default)]
pub struct EscalationDetector;

impl EscalationDetector {
    pub fn new() -> Self {
        EscalationDetector
    }
}

fn denial_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| rules::compile(r"Permission denials:\s*(\d+)").expect("static pattern"))
}

impl Detector for EscalationDetector {
    fn id(&self) -> &'static str {
        "permission-escalation"
    }

    fn inspect(&mut self, e: &Event) -> Vec<Finding> {
        if !e.text.contains("Permission denials:") {
            return Vec::new();
        }
        let Some(c) = denial_re().captures(&e.text) else { return Vec::new() };
        // Go's strconv.Atoi: a count too big for an int is an error, and no finding
        let Some(count) = gotext::atoi(&c[1]) else { return Vec::new() };
        if count == 0 {
            return Vec::new();
        }
        let sev = if count >= 3 { Severity::Critical } else { Severity::Warning };
        let summary =
            format!("session reported {count} permission denial(s) -- the agent asked for a tool its current tier does not allow");
        vec![Finding::new(self.id(), sev, summary, e)]
    }
}
