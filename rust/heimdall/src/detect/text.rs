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
        for r in self.rules.of("injection-phrase") {
            if !r.may_match(&e.text, &folded) {
                continue;
            }
            if let Some(m) = r.re.find(&e.text) {
                if m.as_str().is_empty() {
                    continue; // Go's FindString: an empty match reads as no match
                }
                let summary = format!("text reads as an instruction override rather than task content (\"{}\")", m.as_str());
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
        for r in self.rules.of("credential-shape") {
            if r.may_match(&e.text, &folded) && r.re.is_match(&e.text) {
                return vec![Finding::new(self.id(), Severity::Critical, "text contains what looks like a credential or secret".into(), e)];
            }
        }
        Vec::new()
    }
}

/// Every piece of text with a credential's shape, at most 20 per pattern (Go's FindAllString(text, 20)), for the verifier.
pub fn credential_matches(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for r in rules::builtin().of("credential-shape") {
        out.extend(r.re.find_iter(text).take(20).map(|m| m.as_str().to_owned()));
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
        let replaced = r.re.replace_all(&text, |c: &regex::Captures<'_>| {
            let m = c.get(0).map_or("", |m| m.as_str());
            format!("{}…[redacted]", gotext::byte_prefix(m, 4))
        });
        if let std::borrow::Cow::Owned(s) = replaced {
            if s != *text {
                folded = rules::fold(&s).into_owned(); // the next patterns look at the redacted text
                text = std::borrow::Cow::Owned(s);
            }
        }
    }
    text.into_owned()
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
