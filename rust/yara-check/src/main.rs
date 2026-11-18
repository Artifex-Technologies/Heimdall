//! heimdall-yara-check: YARA-X's exact compile check of one YARA rule draft (docs/IMMUNITY.md, "Rules").
//!
//! Reads one rule on stdin (at most 64 KiB; Heimdall's drafts are at most 16) and prints one line of JSON:
//!
//! ```text
//! {"errors":["<code>: <title> (line N)", ...],"ok":true|false,"warnings":[...],"yara_x":"1.23.0"}
//! ```
//!
//! `ok` is true when YARA-X compiles the rule without an error. Both daemons (Go and Rust) run this program, when it is
//! installed, as a rule draft is kept and as it is tested; without it they behave as before. It only compiles: the rule is
//! never built into a scanner (no machine code is generated, so it runs under heimdalld's MemoryDenyWriteExecute), no file
//! is read but stdin, includes are off, and it exits 0 whenever it could judge the rule (2 when it could not read it).

use std::io::Read;

const MAX_RULE: u64 = 64 << 10;

/// One error or warning as a stable line: its code, its title, and the line of its first label.
fn line_of(src: &str, code: &str, title: &str, start: Option<usize>) -> String {
    match start {
        Some(at) => {
            let n = src.as_bytes()[..at.min(src.len())].iter().filter(|&&b| b == b'\n').count() + 1;
            format!("{code}: {title} (line {n})")
        }
        None => format!("{code}: {title}"),
    }
}

/// The verdict on one rule's text.
fn check(src: &str) -> serde_json::Value {
    let mut c = yara_x::Compiler::new();
    c.enable_includes(false).colorize_errors(false);
    // add_source compiles (parse, types, atoms, the slow-pattern checks); its first error is in errors() too
    let _ = c.add_source(src);
    let errors: Vec<String> =
        c.errors().iter().map(|e| line_of(src, e.code(), e.title(), e.labels().next().map(|l| l.span().range().start))).collect();
    let warnings: Vec<String> =
        c.warnings().iter().map(|w| line_of(src, w.code(), w.title(), w.labels().next().map(|l| l.span().range().start))).collect();
    serde_json::json!({
        "errors": errors,
        "ok": errors.is_empty(),
        "warnings": warnings,
        "yara_x": yara_x_version(),
    })
}

fn yara_x_version() -> &'static str {
    // the exact version pinned in Cargo.toml (=1.23.0)
    "1.23.0"
}

fn main() {
    if std::env::args().len() > 1 {
        eprintln!("usage: heimdall-yara-check < RULE.yar   (prints YARA-X's verdict as JSON)");
        std::process::exit(2);
    }
    let mut b = Vec::new();
    if let Err(e) = std::io::stdin().take(MAX_RULE + 1).read_to_end(&mut b) {
        eprintln!("heimdall-yara-check: {e}");
        std::process::exit(2);
    }
    if b.len() as u64 > MAX_RULE {
        eprintln!("heimdall-yara-check: a rule is at most 64 KiB");
        std::process::exit(2);
    }
    let Ok(src) = String::from_utf8(b) else {
        eprintln!("heimdall-yara-check: a rule is UTF-8 text");
        std::process::exit(2);
    };
    println!("{}", check(&src));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(src: &str) -> (bool, Vec<String>, Vec<String>) {
        let j = check(src);
        let list = |k: &str| j[k].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect::<Vec<_>>();
        (j["ok"].as_bool().unwrap(), list("errors"), list("warnings"))
    }

    #[test]
    fn a_good_rule_compiles_clean() {
        let (ok, e, w) = v("rule Heimdall_demo {\n strings:\n  $a = \"dropper-payload-v2\"\n condition:\n  $a\n}\n");
        assert!(ok && e.is_empty() && w.is_empty(), "{e:?} {w:?}");
    }

    #[test]
    fn an_unknown_identifier_is_an_error_with_its_line() {
        let (ok, e, _) = v("rule Heimdall_demo {\n strings:\n  $a = \"dropper-payload-v2\"\n condition:\n  $a and nothing_here\n}\n");
        assert!(!ok);
        assert_eq!(e.len(), 1, "{e:?}");
        assert!(e[0].starts_with("E009: unknown identifier `nothing_here`") || e[0].contains("nothing_here"), "{e:?}");
        assert!(e[0].ends_with("(line 5)"), "{e:?}");
    }

    #[test]
    fn a_slow_pattern_is_a_warning() {
        let (ok, e, w) = v("rule Heimdall_demo {\n strings:\n  $a = { 00 00 }\n condition:\n  $a\n}\n");
        assert!(ok, "{e:?}");
        assert!(w.iter().any(|x| x.starts_with("slow_pattern:")), "{w:?}");
    }

    #[test]
    fn the_version_said_is_the_version_built() {
        let lock = include_str!("../Cargo.lock");
        let at = lock.find("name = \"yara-x\"\nversion = \"").expect("yara-x in Cargo.lock") + "name = \"yara-x\"\nversion = \"".len();
        assert_eq!(&lock[at..at + lock[at..].find('"').unwrap()], yara_x_version());
    }

    #[test]
    fn includes_and_modules_are_refused() {
        assert!(!v("include \"other.yar\"\nrule Heimdall_demo { condition: true }\n").0);
        assert!(!v("import \"pe\"\nrule Heimdall_demo { condition: pe.is_dll() }\n").0);
    }
}
