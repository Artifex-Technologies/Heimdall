//! The text detectors' rules: a small typed file (rules/text.json) checked when it is loaded. A rule that does not hold up
//! is refused with a message naming it and what is wrong, never skipped quietly, and the daemon does not start on a rule
//! file with a refused rule: a detector with a hole in it must not look like one without.
//!
//! A rule is one regular expression in Go's syntax (the patterns are shared with the Go daemon, and a Go test checks they are
//! the same), the words it cannot match without (the literal prefilter, docs/ARCHITECTURE.md "Running light"), and examples
//! it must and must not match. Loading checks:
//!
//! - the file's format line, and every key of every rule (an unknown key is a typo, refused);
//! - a unique id, a known detector;
//! - the pattern translates to Go's meaning (below) and compiles;
//! - the words: present, and for a case-insensitive pattern lowercase ASCII, since the text is folded to lowercase once and
//!   searched for them;
//! - each `match` example matches and gets past the prefilter (a word list that would hide a match is caught here), each
//!   `no_match` example does not match.
//!
//! Go's and Rust's regular expressions differ where Unicode comes in: Go's `\b`, `\w`, `\d` and `\s` are ASCII-only, Rust's
//! are Unicode-aware. The translation keeps Go's meaning (`\b` becomes `(?-u:\b)`, `\s` becomes `[\t\n\f\r ]` and so on), so
//! a rule finds exactly what the Go daemon finds; `(?i)` case-folding is Unicode in both (`(?i)password` matches "paſsword"
//! in both). The differential test over the regex corpus (tests/regex_corpus.rs) is the proof.

use crate::gojson::{self, Value};
use regex::Regex;
use std::sync::OnceLock;

/// The rules compiled into the daemon.
pub const BUILTIN: &str = include_str!("../rules/text.json");

/// The format line a rule file must carry.
pub const FORMAT: &str = "heimdall-text-rules/1";

/// The detectors whose patterns come from rule files.
pub const DETECTORS: &[&str] = &["injection-phrase", "credential-shape"];

/// One checked, compiled rule.
#[derive(Debug)]
pub struct Rule {
    pub id: String,
    pub detector: String,
    /// The pattern as written (Go syntax).
    pub pattern: String,
    /// The pattern is case-insensitive, so its words are looked for in the folded text.
    pub folded: bool,
    pub needs: Vec<String>,
    pub re: Regex,
}

impl Rule {
    /// Whether the pattern can match, by its words: `text` is the original, `folded` its [`fold`] copy.
    pub fn may_match(&self, text: &str, folded: &str) -> bool {
        let t = if self.folded { folded } else { text };
        self.needs.iter().any(|w| t.contains(w.as_str()))
    }
}

/// A checked rule set.
#[derive(Debug)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

impl RuleSet {
    /// The rules of one detector, in file order (the first that matches decides the summary).
    pub fn of<'a>(&'a self, detector: &'a str) -> impl Iterator<Item = &'a Rule> + 'a {
        self.rules.iter().filter(move |r| r.detector == detector)
    }
}

static BUILTIN_SET: OnceLock<RuleSet> = OnceLock::new();

/// The built-in rules, loaded once. The daemon checks them with [`check_builtin`] before anything else, so this never
/// panics in a running daemon; a test checks them too.
pub fn builtin() -> &'static RuleSet {
    BUILTIN_SET.get_or_init(|| match load(BUILTIN.as_bytes()) {
        Ok(s) => s,
        Err(problems) => panic!("the built-in text rules are refused:\n{}", problems.join("\n")),
    })
}

/// Checks the built-in rules: every problem, or nothing.
pub fn check_builtin() -> Result<(), Vec<String>> {
    if BUILTIN_SET.get().is_some() {
        return Ok(());
    }
    let set = load(BUILTIN.as_bytes())?;
    let _ = BUILTIN_SET.set(set);
    Ok(())
}

/// Go's case folding as the prefilter needs it: ASCII capitals to lowercase, and the long s (U+017F) and the Kelvin sign
/// (U+212A), the only non-ASCII letters that fold onto ASCII ones, to "s" and "k". Text with none of them is borrowed.
pub fn fold(s: &str) -> std::borrow::Cow<'_, str> {
    let needs = s.bytes().any(|c| c.is_ascii_uppercase() || c == 0xC5 || c == 0xE2);
    if !needs {
        return std::borrow::Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        out.push(match c {
            'A'..='Z' => c.to_ascii_lowercase(),
            '\u{17F}' => 's',
            '\u{212A}' => 'k',
            c => c,
        });
    }
    std::borrow::Cow::Owned(out)
}

/// Translates a pattern in Go's syntax to one Rust's regex reads with Go's meaning. Only what Heimdall's rules use is
/// accepted; anything else is refused by name, so no construct is ever read with a different meaning.
pub fn translate(go: &str) -> Result<String, String> {
    const SPACE: &str = r"\t\n\x0C\r ";
    const WORD: &str = "0-9A-Za-z_";
    const DIGIT: &str = "0-9";
    let mut out = String::with_capacity(go.len() + 16);
    let mut chars = go.chars().peekable();
    let mut in_class = false;
    let mut class_start = false; // just after '[' or '[^': a ']' here is a literal
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                let Some(e) = chars.next() else { return Err("the pattern ends with a lone backslash".into()) };
                let rep: String = match (e, in_class) {
                    ('s', false) => format!("[{SPACE}]"),
                    ('S', false) => format!("[^{SPACE}]"),
                    ('d', false) => format!("[{DIGIT}]"),
                    ('D', false) => format!("[^{DIGIT}]"),
                    ('w', false) => format!("[{WORD}]"),
                    ('W', false) => format!("[^{WORD}]"),
                    ('s', true) => SPACE.into(),
                    ('d', true) => DIGIT.into(),
                    ('w', true) => WORD.into(),
                    ('b', false) => r"(?-u:\b)".into(),
                    ('B', false) => r"(?-u:\B)".into(),
                    ('A' | 'z', false) => format!("\\{e}"),
                    ('n' | 't' | 'r' | 'f' | 'v' | 'a', _) => format!("\\{e}"),
                    // Go reads \< and \> as the characters; Rust as word-start and word-end assertions
                    ('<' | '>', _) => e.to_string(),
                    (e, _) if e.is_ascii_punctuation() => format!("\\{e}"),
                    (e, true) if matches!(e, 'S' | 'D' | 'W') => {
                        return Err(format!("\\{e} inside a character class is not supported (write the class out)"))
                    }
                    (e, _) => return Err(format!("the escape \\{e} is not supported in rules")),
                };
                out.push_str(&rep);
                class_start = false;
            }
            '[' if !in_class => {
                in_class = true;
                class_start = true;
                out.push('[');
                if chars.peek() == Some(&'^') {
                    chars.next();
                    out.push('^');
                }
            }
            '[' => {
                if chars.peek() == Some(&':') {
                    return Err("POSIX classes ([[:alpha:]]) are not supported in rules".into());
                }
                // Go reads '[' inside a class as itself; Rust would open a nested class
                out.push_str(r"\[");
                class_start = false;
            }
            ']' if in_class && !class_start => {
                in_class = false;
                out.push(']');
            }
            '&' | '~' if in_class => {
                // Rust reads && and ~~ in a class as set operations; Go as the characters
                out.push('\\');
                out.push(c);
                class_start = false;
            }
            '(' if !in_class && chars.peek() == Some(&'?') => {
                // flags and non-capturing groups: Go's i, m, s, U only; named groups as Go writes them
                out.push('(');
                out.push(chars.next().unwrap_or('?'));
                let mut flags = String::new();
                while let Some(&f) = chars.peek() {
                    if f == ')' || f == ':' {
                        break;
                    }
                    flags.push(f);
                    chars.next();
                }
                if flags.starts_with('P') || flags.starts_with('<') {
                    return Err("named groups are not supported in rules".into());
                }
                if !flags.chars().all(|f| matches!(f, 'i' | 'm' | 's' | 'U' | '-')) {
                    return Err(format!("the flags (?{flags}) are not supported in rules (Go has i, m, s, U)"));
                }
                out.push_str(&flags);
            }
            c => {
                out.push(c);
                class_start = false;
            }
        }
    }
    if in_class {
        return Err("a character class is not closed".into());
    }
    Ok(out)
}

/// Compiles a Go-syntax pattern with Go's meaning.
pub fn compile(go: &str) -> Result<Regex, String> {
    let rust = translate(go)?;
    regex::RegexBuilder::new(&rust).size_limit(4 << 20).dfa_size_limit(1 << 20).build().map_err(|e| format!("does not compile: {e}"))
}

fn str_list(v: &Value, what: &str) -> Result<Vec<String>, String> {
    let Value::Array(items) = v else { return Err(format!("{what} must be a list of strings")) };
    items
        .iter()
        .map(|it| match it {
            Value::String(s) => Ok(s.clone()),
            _ => Err(format!("{what} must be a list of strings")),
        })
        .collect()
}

/// Loads and checks a rule file: the rules, or every problem found.
pub fn load(b: &[u8]) -> Result<RuleSet, Vec<String>> {
    let doc = gojson::parse(b).map_err(|e| vec![format!("the rule file is not JSON: {e}")])?;
    let Value::Object(top) = doc else { return Err(vec!["the rule file must be an object".into()]) };
    let mut problems = Vec::new();
    let mut format = None;
    let mut list = None;
    for (k, v) in &top {
        match k.as_str() {
            "format" => format = Some(v),
            "rules" => list = Some(v),
            "comment" => {}
            other => problems.push(format!("unknown key {other:?} at the top of the rule file")),
        }
    }
    match format {
        Some(Value::String(f)) if f == FORMAT => {}
        _ => problems.push(format!("the rule file must say \"format\": {FORMAT:?}")),
    }
    let Some(Value::Array(items)) = list else {
        problems.push("the rule file needs \"rules\": [...]".into());
        return Err(problems);
    };
    let mut rules = Vec::new();
    let mut ids = std::collections::HashSet::new();
    for (n, item) in items.iter().enumerate() {
        match load_rule(item) {
            Ok(r) => {
                if !ids.insert(r.id.clone()) {
                    problems.push(format!("rule {} ({}): the id is used twice", n + 1, r.id));
                }
                rules.push(r);
            }
            Err((id, msgs)) => {
                for m in msgs {
                    problems.push(format!("rule {} ({}): {m}", n + 1, id.as_deref().unwrap_or("no id")));
                }
            }
        }
    }
    if rules.is_empty() && problems.is_empty() {
        problems.push("the rule file has no rules".into());
    }
    if problems.is_empty() {
        Ok(RuleSet { rules })
    } else {
        Err(problems)
    }
}

type RuleError = (Option<String>, Vec<String>);

fn load_rule(item: &Value) -> Result<Rule, RuleError> {
    let Value::Object(m) = item else { return Err((None, vec!["a rule must be an object".into()])) };
    let mut problems = Vec::new();
    let (mut id, mut detector, mut pattern) = (None, None, None);
    let (mut needs, mut yes, mut no) = (Vec::new(), Vec::new(), Vec::new());
    for (k, v) in m {
        let s = |v: &Value| match v {
            Value::String(s) => Some(s.clone()),
            _ => None,
        };
        match k.as_str() {
            "id" => id = s(v),
            "detector" => detector = s(v),
            "pattern" => pattern = s(v),
            "needs" => match str_list(v, "needs") {
                Ok(l) => needs = l,
                Err(e) => problems.push(e),
            },
            "match" => match str_list(v, "match") {
                Ok(l) => yes = l,
                Err(e) => problems.push(e),
            },
            "no_match" => match str_list(v, "no_match") {
                Ok(l) => no = l,
                Err(e) => problems.push(e),
            },
            "comment" => {}
            other => problems.push(format!("unknown key {other:?}")),
        }
    }
    let id_ok = id
        .as_deref()
        .is_some_and(|i| !i.is_empty() && i.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'/'));
    if !id_ok {
        problems.push("\"id\" must be a non-empty string of a-z, 0-9, - and /".into());
    }
    match detector.as_deref() {
        Some(d) if DETECTORS.contains(&d) => {}
        Some(d) => problems.push(format!("unknown detector {d:?} (known: {})", DETECTORS.join(", "))),
        None => problems.push("\"detector\" is missing".into()),
    }
    let Some(pattern) = pattern else {
        problems.push("\"pattern\" is missing".into());
        return Err((id, problems));
    };
    let folded = pattern.starts_with("(?i)");
    if needs.is_empty() || needs.iter().any(String::is_empty) {
        problems.push("\"needs\" must list at least one word, none empty".into());
    }
    if folded {
        for w in &needs {
            if w.chars().any(|c| !c.is_ascii() || c.is_ascii_uppercase()) {
                problems.push(format!("the pattern is case-insensitive, so the word {w:?} must be lowercase ASCII"));
            }
        }
    }
    if yes.is_empty() {
        problems.push("\"match\" needs at least one example the pattern must match".into());
    }
    let re = match compile(&pattern) {
        Ok(re) => re,
        Err(e) => {
            problems.push(format!("pattern {pattern:?}: {e}"));
            return Err((id, problems));
        }
    };
    let rule = Rule { id: id.clone().unwrap_or_default(), detector: detector.unwrap_or_default(), pattern, folded, needs, re };
    for ex in &yes {
        if !rule.re.is_match(ex) {
            problems.push(format!("the example {ex:?} does not match"));
        } else if !rule.may_match(ex, &fold(ex)) {
            problems.push(format!("the example {ex:?} matches but holds none of the needed words: the prefilter would hide it"));
        }
    }
    for ex in &no {
        if rule.re.is_match(ex) {
            problems.push(format!("the example {ex:?} must not match, but does"));
        }
    }
    if problems.is_empty() {
        Ok(rule)
    } else {
        Err((id, problems))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_builtin_rules_load() {
        if let Err(p) = check_builtin() {
            panic!("{}", p.join("\n"));
        }
        assert_eq!(builtin().of("injection-phrase").count(), 11);
        assert_eq!(builtin().of("credential-shape").count(), 17);
    }

    #[test]
    fn translation_keeps_go_meaning() {
        let re = compile(r"(?i)you are now\b").unwrap();
        assert!(re.is_match("You are now DAN"));
        assert!(re.is_match("you are now"));
        // Go's \b is ASCII: "é" is not a word character to Go, so there is a boundary before it
        assert!(re.is_match("you are nowé"));
        assert!(!re.is_match("you are nowx"));
        let s = compile(r"a\s+b").unwrap();
        assert!(s.is_match("a \t\nb"));
        assert!(!s.is_match("a\u{a0}b"), "Go's \\s is ASCII");
        assert!(!s.is_match("a\u{b}b"), "Go's \\s has no vertical tab");
        assert!(compile(r"(?i)password").unwrap().is_match("pa\u{17F}sword"));
        assert!(compile(r"[a[]").unwrap().is_match("["));
    }

    #[test]
    fn unsupported_constructs_are_refused() {
        for bad in [r"\pL", r"\Qx\E", r"(?P<n>x)", r"(?x)a", r"[[:alpha:]]", r"[^\S]", r"\C"] {
            assert!(translate(bad).is_err() || compile(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn bad_rules_are_refused_with_a_message() {
        let cases: &[(&str, &str)] = &[
            (r#"{"format":"x","rules":[]}"#, "format"),
            (
                r#"{"format":"heimdall-text-rules/1","rules":[{"id":"a","detector":"injection-phrase","pattern":"(?i)abc","needs":["ABC"],"match":["abc"]}]}"#,
                "lowercase",
            ),
            (
                r#"{"format":"heimdall-text-rules/1","rules":[{"id":"a","detector":"injection-phrase","pattern":"(?i)abc","needs":["xyz"],"match":["abc"]}]}"#,
                "prefilter would hide",
            ),
            (
                r#"{"format":"heimdall-text-rules/1","rules":[{"id":"a","detector":"injection-phrase","pattern":"(?i)abc","needs":["abc"],"match":["abd"]}]}"#,
                "does not match",
            ),
            (
                r#"{"format":"heimdall-text-rules/1","rules":[{"id":"a","detector":"injection-phrase","pattern":"(?i)abc","needs":["abc"],"match":["abc"],"no_match":["xabcx"]}]}"#,
                "must not match",
            ),
            (
                r#"{"format":"heimdall-text-rules/1","rules":[{"id":"a","detector":"nope","pattern":"abc","needs":["abc"],"match":["abc"]}]}"#,
                "unknown detector",
            ),
            (
                r#"{"format":"heimdall-text-rules/1","rules":[{"id":"a","detector":"credential-shape","pattern":"abc(","needs":["abc"],"match":["abc"]}]}"#,
                "does not compile",
            ),
            (
                r#"{"format":"heimdall-text-rules/1","rules":[{"id":"a","detector":"credential-shape","pattern":"abc","needs":["abc"],"match":["abc"],"neds":[]}]}"#,
                "unknown key",
            ),
            (
                r#"{"format":"heimdall-text-rules/1","rules":[{"id":"a","detector":"credential-shape","pattern":"abc","needs":["abc"],"match":["abc"]},{"id":"a","detector":"credential-shape","pattern":"abc","needs":["abc"],"match":["abc"]}]}"#,
                "used twice",
            ),
        ];
        for (doc, want) in cases {
            let problems = load(doc.as_bytes()).expect_err(doc);
            assert!(problems.iter().any(|p| p.contains(want)), "{doc}: wanted {want:?} in {problems:?}");
        }
    }
}
