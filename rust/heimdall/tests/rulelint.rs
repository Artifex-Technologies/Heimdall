//! The lint of rule drafts against Go's answers (internal/immunity, `go test ./internal/immunity -run TestRuleLintFixtures
//! -update` writes testdata/parity/rulelint.json): for every case the same rule name, hard error and warnings.

use serde_json::Value;

fn cases() -> Vec<Value> {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/parity/rulelint.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(p).expect("rulelint.json")).expect("json");
    assert_eq!(v["format"], "heimdall-rulelint/1");
    v["cases"].as_array().unwrap().clone()
}

#[test]
fn the_lint_answers_as_go() {
    let cs = cases();
    assert!(cs.len() > 80, "{} cases", cs.len());
    for c in cs {
        let name = c["name"].as_str().unwrap();
        let text = c["text"].as_str().unwrap();
        let (rule, error) = match heimdall::immunity::check_rule(text) {
            Ok(n) => (n, String::new()),
            Err(e) => (String::new(), e),
        };
        let warnings: Vec<String> = if error.is_empty() { heimdall::rulelint::lint(text).1 } else { Vec::new() };
        let want: Vec<String> = c["warnings"].as_array().unwrap().iter().map(|w| w.as_str().unwrap().to_string()).collect();
        assert_eq!(rule, c["rule"].as_str().unwrap(), "{name}: rule");
        assert_eq!(error, c["error"].as_str().unwrap(), "{name}: error");
        assert_eq!(warnings, want, "{name}: warnings");
    }
}

/// Every beginning of every case (a draft cut anywhere, at a byte) is judged without a panic.
#[test]
fn a_cut_draft_never_panics() {
    for c in cases() {
        let text = c["text"].as_str().unwrap();
        for i in 0..=text.len() {
            if text.is_char_boundary(i) {
                let _ = heimdall::rulelint::lint(&text[..i]);
            }
        }
    }
}

/// The checker's verdict is read as Go's decoder reads it; anything else is "no verdict", never a refusal.
#[test]
fn the_checker_is_read_as_go_reads_it() {
    let d = std::env::temp_dir().join(format!("heimdall-yara-check-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let check = |name: &str, out: &str, code: i32| -> Result<Option<heimdall::rulelint::Verdict>, String> {
        let p = d.join(name);
        std::fs::write(&p, format!("#!/bin/sh\ncat >/dev/null\nprintf '%s' '{out}'\nexit {code}\n")).unwrap();
        std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        heimdall::rulelint::yara_check(p.to_str().unwrap(), "rule Heimdall_x { strings: $a = \"abcd\" condition: $a }")
    };
    let no = Err(heimdall::rulelint::NO_YARA_VERDICT.to_string());
    let v = check("ok", r#"{"errors":[],"ok":true,"warnings":["w"],"yara_x":"1.23.0"}"#, 0).unwrap().unwrap();
    assert!(v.ok && v.warnings == ["w"] && v.version == "1.23.0");
    let v = check("fold", r#"{"OK":false,"Errors":["e",null],"YARA_X":"1"} trailing"#, 0).unwrap().unwrap();
    assert!(!v.ok && v.errors == ["e", ""]);
    assert_eq!(check("exit", r#"{"errors":[],"ok":true,"warnings":[],"yara_x":"1"}"#, 1), no);
    assert_eq!(check("noversion", r#"{"errors":[],"ok":true,"warnings":[]}"#, 0), no);
    assert_eq!(check("refused-without-why", r#"{"errors":[],"ok":false,"yara_x":"1"}"#, 0), no);
    assert_eq!(check("ok-with-errors", r#"{"errors":["e"],"ok":true,"yara_x":"1"}"#, 0), no);
    assert_eq!(check("wrong-type-earlier", r#"{"ok":"yes","ok":true,"yara_x":"1"}"#, 0), no);
    assert_eq!(check("number-in-list", r#"{"ok":true,"warnings":[1],"yara_x":"1"}"#, 0), no);
    assert_eq!(check("array", "[]", 0), no);
    assert_eq!(check("null", "null", 0), no);
    assert_eq!(check("empty", "", 0), no);
    // not executable, a folder, missing: not installed
    let p = d.join("plain");
    std::fs::write(&p, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o644)).unwrap();
    assert_eq!(heimdall::rulelint::yara_check(p.to_str().unwrap(), "x"), Ok(None));
    assert_eq!(heimdall::rulelint::yara_check(d.to_str().unwrap(), "x"), Ok(None));
    assert_eq!(heimdall::rulelint::yara_check("/nonexistent/heimdall-yara-check", "x"), Ok(None));
    let _ = std::fs::remove_dir_all(&d);
}
