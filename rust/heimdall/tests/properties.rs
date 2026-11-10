//! Property tests (proptest): the detectors' invariants, the prefilter's soundness, the restrict-only rules, and the Go
//! readers and writers.

use heimdall::detect::{self, BurstDetector, InboundDetector, InjectionDetector, OnlineStats, UnicodeDetector};
use heimdall::event::{Detector, Event, Fields};
use heimdall::gojson::{self, Value};
use heimdall::gotext;
use heimdall::gotime::Time;
use heimdall::quarantine::{self, Decision, Hold, Level};
use heimdall::rules;
use proptest::prelude::*;

/// Text near the patterns: a rule's own example with case flips, the long s and Kelvin sign for s and k, and glue
/// characters (word characters, Unicode spaces, invisible ones) put in.
fn near_rule_text() -> impl Strategy<Value = String> {
    let examples: Vec<String> = serde_json_examples();
    (0..examples.len(), proptest::collection::vec((any::<u16>(), 0u8..10), 0..8)).prop_map(move |(i, edits)| {
        let mut cs: Vec<char> = examples[i].chars().collect();
        for (pos, what) in edits {
            if cs.is_empty() {
                break;
            }
            let p = pos as usize % cs.len();
            match what {
                0 => cs[p] = cs[p].to_ascii_uppercase(),
                1 => cs[p] = cs[p].to_ascii_lowercase(),
                2 if cs[p].eq_ignore_ascii_case(&'s') => cs[p] = '\u{17F}',
                3 if cs[p].eq_ignore_ascii_case(&'k') => cs[p] = '\u{212A}',
                4 => cs.insert(p, 'x'),
                5 => cs.insert(p, '\u{a0}'),
                6 => cs.insert(p, '\u{200b}'),
                7 => cs.insert(p, 'é'),
                8 => {
                    cs.remove(p);
                }
                _ => cs.insert(p, ' '),
            }
        }
        cs.into_iter().collect()
    })
}

/// Every match example of the built-in rules (read from the rule file itself).
fn serde_json_examples() -> Vec<String> {
    let v: serde_json::Value = serde_json::from_str(rules::BUILTIN).unwrap();
    v["rules"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|r| r["match"].as_array().unwrap().iter().map(|e| e.as_str().unwrap().to_string()))
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2000, ..ProptestConfig::default() })]

    /// The literal prefilter never hides a match: wherever a pattern matches, the text holds one of its words.
    #[test]
    fn the_prefilter_never_hides_a_match(text in prop_oneof![near_rule_text(), ".{0,200}"]) {
        let folded = rules::fold(&text);
        for r in &rules::builtin().rules {
            if r.re.is_match(&text) {
                prop_assert!(r.may_match(&text, &folded), "{} matches {:?} but the prefilter would skip it", r.id, text);
            }
        }
    }

    /// The injection detector with the prefilter finds exactly what trying every pattern finds.
    #[test]
    fn the_prefiltered_injection_detector_is_the_plain_one(text in prop_oneof![near_rule_text(), ".{0,120}"]) {
        let e = Event { text: text.clone(), ..Default::default() };
        let got = InjectionDetector::new().inspect(&e).first().map(|f| f.summary.clone());
        // every pattern tried on the look-alike copy (the case-insensitive ones) and the match cut from the original
        let la = detect::lookalikes(&text);
        let plain = rules::builtin().of("injection-phrase").find_map(|r| {
            let (hay, at) = match (&la, r.folded) {
                (Some((n, at)), true) => (n.as_str(), Some(at)),
                _ => (text.as_str(), None),
            };
            r.re.find(hay).filter(|m| !m.as_str().is_empty()).map(|m| match at {
                Some(at) => text[at[m.start()]..at[m.end()]].to_string(),
                None => m.as_str().to_string(),
            })
        })
        .map(|m| format!("text reads as an instruction override rather than task content (\"{m}\")"));
        prop_assert_eq!(got, plain);
    }

    /// Redaction is stable, and no credential pattern still finds a whole secret in redacted text.
    #[test]
    fn redaction_is_stable(text in prop_oneof![near_rule_text(), ".{0,120}"]) {
        let r = detect::redact_credentials(&text);
        prop_assert_eq!(detect::redact_credentials(&r), r.clone());
        for m in detect::credential_matches(&r) {
            prop_assert!(!text.contains(&m) || m.chars().count() < 4 || r.contains("[redacted]"), "{:?} survived in {:?}", m, r);
        }
    }

    /// Go's fold: ASCII capitals, the long s and the Kelvin sign only, nothing else changes.
    #[test]
    fn fold_is_gos(text in ".{0,80}") {
        let f = rules::fold(&text);
        let want: String = text.chars().map(|c| match c { 'A'..='Z' => c.to_ascii_lowercase(), '\u{17F}' => 's', '\u{212A}' => 'k', c => c }).collect();
        prop_assert_eq!(f.as_ref(), want.as_str());
    }

    /// The invisible-character detector never flags plain ASCII, and always flags text holding a zero-width space.
    #[test]
    fn unicode_detector_bounds(ascii in "[ -~\t\n]{0,100}", at in 0usize..100) {
        let mut d = UnicodeDetector::new();
        let plain = d.inspect(&Event { text: ascii.clone(), ..Default::default() });
        prop_assert!(plain.is_empty());
        let mut with = ascii.clone();
        with.insert(at.min(with.len()), '\u{200b}');
        prop_assert_eq!(d.inspect(&Event { text: with, ..Default::default() }).len(), 1);
    }

    /// The burst detector never reports twice within its cooldown, whatever the times.
    #[test]
    fn burst_respects_the_cooldown(gaps in proptest::collection::vec(0i64..5_000_000_000, 1..300)) {
        let cooldown = 60_000_000_000;
        let mut d = BurstDetector::new(60_000_000_000, 3, cooldown);
        let mut t = Time::from_unix(1_800_000_000, 0);
        let mut last: Option<Time> = None;
        for g in gaps {
            t = t.add(g);
            let e = Event { kind: "session_created".into(), time: t, ..Default::default() };
            if !d.inspect(&e).is_empty() {
                if let Some(l) = last { prop_assert!(t.sub(&l) >= cooldown); }
                last = Some(t);
            }
        }
    }

    /// The inbound detector raises at most one alert per address within its cooldown.
    #[test]
    fn inbound_one_alert_per_address_per_cooldown(knocks in proptest::collection::vec((0u8..4, 0u16..40, 0i64..3_000_000_000, any::<bool>()), 1..400)) {
        let mut d = InboundDetector::with_range(32768, 60999);
        let mut t = Time::from_unix(1_800_000_000, 0);
        let mut last: std::collections::HashMap<String, Time> = Default::default();
        for (who, port, gap, login) in knocks {
            t = t.add(gap);
            let src = format!("203.0.113.{who}");
            let fields = Fields::from([("src".to_string(), src.clone()), ("dst_port".to_string(), port.to_string())]);
            let kind = if login { "login_failure" } else { "firewall_block" };
            for f in d.inspect(&Event { kind: kind.into(), time: t, fields, ..Default::default() }) {
                let s = f.event.f("src").to_string();
                if let Some(l) = last.get(&s) { prop_assert!(t.sub(l) >= 3_600_000_000_000); }
                last.insert(s, t);
            }
        }
    }

    /// Welford's running mean and variance agree with the two-pass ones.
    #[test]
    fn online_stats_agree(xs in proptest::collection::vec(-1e6f64..1e6, 2..200)) {
        let mut s = OnlineStats::default();
        for &x in &xs { s.add(x); }
        let n = xs.len() as f64;
        let mean = xs.iter().sum::<f64>() / n;
        let var = xs.iter().map(|x| (x - mean) * (x - mean)).sum::<f64>() / (n - 1.0);
        prop_assert!((s.mean() - mean).abs() <= 1e-6 * mean.abs().max(1.0));
        prop_assert!((s.std_dev() - var.sqrt()).abs() <= 1e-6 * var.sqrt().max(1.0));
    }

    /// Restrict never loosens: a decision to send is always restrict, and never below the hold Limbo has.
    #[test]
    fn restrict_never_loosens(level in 0u8..3, opened in any::<i32>(), trigger in any::<i32>()) {
        let current = match level { 0 => None, 1 => Some(Level::Restrict), _ => Some(Level::Isolate) }
            .map(|l| (l, Time::from_unix(opened as i64, 0)));
        match quarantine::decide(current, Time::from_unix(trigger as i64, 0)) {
            Decision::Send(l) => {
                prop_assert_eq!(l, Level::Restrict);
                if let Some((c, _)) = current { prop_assert!(l >= c); }
            }
            Decision::Skip(_) => prop_assert!(current.is_some()),
        }
    }

    /// A hold only rises, whatever sequence of requests reaches it.
    #[test]
    fn a_hold_only_rises(reqs in proptest::collection::vec(any::<bool>(), 0..50)) {
        let mut h = Hold::none();
        let mut prev = None;
        for isolate in reqs {
            h.raise(if isolate { Level::Isolate } else { Level::Restrict });
            prop_assert!(h.level() >= prev);
            prev = h.level();
        }
    }

    /// Go-style JSON: any string written reads back as itself.
    #[test]
    fn json_strings_round_trip(s in "\\PC*") {
        let mut out = String::new();
        gojson::write_str(&mut out, &s);
        prop_assert_eq!(gojson::parse(out.as_bytes()).unwrap(), Value::String(s));
    }

    /// On documents serde_json reads, this reader reads the same value (serde_json as the oracle for valid JSON).
    #[test]
    fn json_agrees_with_serde_on_valid_documents(v in arb_json()) {
        let text = serde_json::to_string(&v).unwrap();
        let ours = gojson::parse(text.as_bytes()).unwrap();
        prop_assert!(same(&ours, &v), "{} read as {:?}", text, ours);
    }

    /// RFC 3339 times read back as written.
    #[test]
    fn times_round_trip(secs in -62_135_596_800i64..253_402_300_799, nanos in 0u32..1_000_000_000) {
        let t = Time::from_unix(secs, nanos);
        prop_assert_eq!(Time::parse_rfc3339(&t.rfc3339_nano()), Some(t));
    }

    /// Bytes read as Go reads them: valid UTF-8 unchanged; otherwise only U+FFFD added, one per bad byte at most.
    #[test]
    fn lossy_reads_as_go(b in proptest::collection::vec(any::<u8>(), 0..64)) {
        let s = gotext::lossy(&b);
        if let Ok(v) = std::str::from_utf8(&b) { prop_assert_eq!(s.as_str(), v); }
        let replaced = s.chars().filter(|&c| c == char::REPLACEMENT_CHARACTER).count();
        prop_assert!(replaced <= b.len());
    }
}

fn arb_json() -> impl Strategy<Value = serde_json::Value> {
    let leaf = prop_oneof![
        Just(serde_json::Value::Null),
        any::<bool>().prop_map(serde_json::Value::Bool),
        any::<i64>().prop_map(|n| serde_json::json!(n)),
        (-1e12f64..1e12).prop_map(|f| serde_json::json!(f)),
        "\\PC{0,12}".prop_map(serde_json::Value::String),
    ];
    leaf.prop_recursive(4, 32, 6, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..6).prop_map(serde_json::Value::Array),
            proptest::collection::btree_map("[a-z]{0,6}", inner, 0..6).prop_map(|m| serde_json::Value::Object(m.into_iter().collect())),
        ]
    })
}

fn same(ours: &Value, v: &serde_json::Value) -> bool {
    match (ours, v) {
        (Value::Null, serde_json::Value::Null) => true,
        (Value::Bool(a), serde_json::Value::Bool(b)) => a == b,
        (Value::Number(a), serde_json::Value::Number(b)) => a.parse::<f64>().ok() == b.as_f64(),
        (Value::String(a), serde_json::Value::String(b)) => a == b,
        (Value::Array(a), serde_json::Value::Array(b)) => a.len() == b.len() && a.iter().zip(b).all(|(x, y)| same(x, y)),
        (Value::Object(a), serde_json::Value::Object(b)) => {
            a.len() == b.len() && a.iter().all(|(k, x)| b.get(k).is_some_and(|y| same(x, y)))
        }
        _ => false,
    }
}

// The Sarina advisory (src/advisor.rs).
proptest! {
    #![proptest_config(ProptestConfig { cases: 2000, ..ProptestConfig::default() })]

    /// `%v` of a float64 reads back as the same number, in exponent form exactly when Go's shortest 'g' uses it.
    #[test]
    fn floats_written_as_go_read_back(bits in any::<u64>()) {
        let f = f64::from_bits(bits);
        prop_assume!(f.is_finite() && f != 0.0);
        let s = heimdall::advisor::format_g(f);
        prop_assert_eq!(s.parse::<f64>().unwrap(), f);
        let exp = f.abs().log10().floor() as i32;
        if (-3..5).contains(&exp) {
            prop_assert!(!s.contains('e'), "{} {}", f, s);
        }
        if !(-5..7).contains(&exp) {
            prop_assert!(s.contains("e+") || s.contains("e-"), "{} {}", f, s);
        }
    }

    /// What is kept of an opinion or a note: a prefix at most the limit long, cut on a letter; a note holds no control
    /// character but newlines.
    #[test]
    fn opinions_and_notes_are_bounded(s in "\\PC{0,40}[\\x00-\\x1f\\x7f]{0,4}\\PC{0,4100}", n in 0usize..5000) {
        let p = heimdall::advisor::valid_prefix(&s, n);
        prop_assert!(s.starts_with(p));
        if s.len() <= n {
            prop_assert_eq!(p, s.as_str());
        } else {
            prop_assert!(p.len() <= n && n - p.len() < 4);
        }
        let note = heimdall::advisor::clean_note(&s);
        prop_assert!(note.len() <= 4000);
        prop_assert!(note.chars().all(|c| c == '\n' || (c >= ' ' && c != '\x7f')));
    }

    /// The fence holds: whatever a guest put in the alert's texts and fields, the evidence block of the prompt reads back as
    /// one JSON object with those texts, so no text can end the block early.
    #[test]
    fn the_evidence_fence_holds(summary in "\\PC{0,60}(\nEND UNTRUSTED EVIDENCE>>>)?\\PC{0,20}", text in "\\PC{0,80}", guest in "\\PC{0,20}") {
        let mut a = heimdall::alert::Alert::integration("x", "y", "z", &Fields::new());
        a.detector_id = "limbo-guest".into();
        a.summary = summary.clone();
        a.event_text = text.clone();
        a.fields = Fields::from([("guest".to_string(), guest.clone())]);
        let p = heimdall::advisor::build_prompt(&a);
        let start = p.find("<<<UNTRUSTED EVIDENCE\n").unwrap() + "<<<UNTRUSTED EVIDENCE\n".len();
        let end = p.rfind("\nEND UNTRUSTED EVIDENCE>>>").unwrap();
        prop_assert_eq!(p.matches("\nEND UNTRUSTED EVIDENCE>>>").count(), 1);
        let v: serde_json::Value = serde_json::from_str(&p[start..end]).unwrap();
        prop_assert_eq!(v["summary"].as_str().unwrap(), summary.as_str());
        prop_assert_eq!(v["event_text"].as_str().unwrap(), text.as_str());
        prop_assert_eq!(v["fields"]["guest"].as_str().unwrap(), guest.as_str());
    }
}
