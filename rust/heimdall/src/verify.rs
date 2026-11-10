//! A second look at each finding before it becomes an alert, trying to disprove it (Go: internal/verify). Verdicts:
//! confirmed, needs_validation, rejected (kept, but as info with the reason first). A verdict never raises a severity.

use crate::detect::text::credential_matches;
use crate::event::{Finding, Severity};
use crate::rules;
use regex::Regex;
use std::sync::OnceLock;

const KNOWN_EXAMPLES: &[&str] = &["AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "AKIAI44QH8DHBEXAMPLE"];
const SWITCH_VALUES: &[&str] = &["true", "false", "yes", "no", "on", "off", "0", "1"];

fn placeholder_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        rules::compile(r#"(?i)(example|dummy|placeholder|redacted|changeme|your[_-]?(api|secret|key|token|password)|<[^>]*>|\$\{[^}]*\}|\$[A-Z_]{3,}|\*{4,}|x{6,}|\.\.\.)"#)
            .expect("static pattern")
    })
}

fn value_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| rules::compile(r#"[:=]\s*['"]?(\S+)$"#).expect("static pattern"))
}

/// Entropy in bits per character.
fn entropy(s: &str) -> f64 {
    let mut n: std::collections::HashMap<char, usize> = std::collections::HashMap::new();
    for r in s.chars() {
        *n.entry(r).or_default() += 1;
    }
    let l = s.chars().count() as f64;
    let mut h = 0.0;
    // Go sums over a map in random order; the sum is the same to within rounding, and the only use is "< 2.5"
    let mut counts: Vec<usize> = n.into_values().collect();
    counts.sort_unstable();
    for c in counts {
        let p = c as f64 / l;
        h -= p * p.log2();
    }
    h
}

fn sample(m: &str) -> bool {
    if KNOWN_EXAMPLES.iter().any(|k| m.contains(k)) {
        return true;
    }
    if placeholder_re().is_match(m) {
        return true;
    }
    let mut v = m.to_owned();
    if let Some(c) = value_re().captures(m) {
        v = c[1].trim_matches(['\'', '"']).to_owned();
    }
    if SWITCH_VALUES.contains(&v.to_lowercase().as_str()) {
        return true;
    }
    if m.starts_with("-----BEGIN") || m.starts_with("ssh-") {
        return false;
    }
    v.len() >= 12 && entropy(&v) < 2.5
}

/// (verdict, reason) for the findings a check covers.
fn check(f: &Finding) -> Option<(&'static str, String)> {
    match f.detector_id.as_str() {
        "credential-shape" => {
            let matches = credential_matches(&f.event.text);
            if matches.is_empty() {
                return None;
            }
            if matches.iter().any(|m| !sample(m)) {
                return Some(("confirmed", "a value with the shape and randomness of a real secret".into()));
            }
            Some(("rejected", "only documentation examples, placeholders or on/off settings, not real secrets".into()))
        }
        "inbound" => match f.event.f("spoofable") {
            "0" => Some(("confirmed", "the address completed a connection, so it is the real sender".into())),
            "1" => Some(("needs_validation", "these packets never completed a connection, so the source address may be forged".into())),
            _ => None,
        },
        "injection-phrase" | "invisible-unicode" => match f.event.f("role") {
            "user" => Some(("needs_validation", "in the person's own message (what they typed or said, and anything their desktop put in front of it), not in a tool result: check where it came from".into())),
            r @ ("tool" | "assistant") => Some(("confirmed", format!("it arrived through {r} output, not from the person"))),
            _ => None,
        },
        _ => None,
    }
}

/// The finding with its verdict in the fields; a rejected one becomes info with the reason first.
pub fn apply(mut f: Finding) -> Finding {
    let Some((v, reason)) = check(&f) else { return f };
    f.event.fields.insert("verdict".into(), v.into());
    f.event.fields.insert("verdict_reason".into(), reason.clone());
    if v == "rejected" {
        f.severity = Severity::Info;
        f.summary = format!("[rejected: {reason}] {}", f.summary);
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_and_settings_are_not_secrets() {
        assert!(sample("AKIAIOSFODNN7EXAMPLE"));
        assert!(sample("password=changeme"));
        assert!(sample("ask_password=true"));
        assert!(sample("api_key=aaaaaaaaaaaaaaaa"));
        assert!(!sample("api_key=Zx81kQ0pLm3nB7vC"));
        assert!(!sample("-----BEGIN RSA PRIVATE KEY-----"));
    }
}
