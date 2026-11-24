//! `heimdalld attack-layer`: what the detectors watch (internal/attack/tags.tsv) as an ATT&CK Navigator layer (layer format
//! 4.5), printed as JSON; open it in Navigator with "Open Existing Layer". And the coverage page docs/ATTACK_COVERAGE.md,
//! written from the same two tables by a test that fails when the page is stale.
//!
//! A tag says what a detector looks for, never that a technique is covered (docs/ATTACK.md); the layer and the page say so.

use crate::attack::{embedded, Table, Technique};
use crate::gojson::{write_indented, Value};
use std::collections::BTreeMap;

fn text(x: impl Into<String>) -> Value {
    Value::String(x.into())
}

fn obj(members: Vec<(&str, Value)>) -> Value {
    Value::Object(members.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// The tactics in ATT&CK's own order (Enterprise 20: stealth and defense-impairment where defense-evasion was); a tactic not
/// listed goes last.
const TACTICS: &[(&str, &str)] = &[
    ("reconnaissance", "Reconnaissance"),
    ("resource-development", "Resource Development"),
    ("initial-access", "Initial Access"),
    ("execution", "Execution"),
    ("persistence", "Persistence"),
    ("privilege-escalation", "Privilege Escalation"),
    ("stealth", "Stealth"),
    ("defense-impairment", "Defense Impairment"),
    ("credential-access", "Credential Access"),
    ("discovery", "Discovery"),
    ("lateral-movement", "Lateral Movement"),
    ("collection", "Collection"),
    ("command-and-control", "Command and Control"),
    ("exfiltration", "Exfiltration"),
    ("impact", "Impact"),
];

const WARNING: &str = "A tag says what a Heimdall detector looks for, never that the technique is covered: \
                       it does not mean Heimdall would catch every use of it (docs/ATTACK.md).";

/// Each tagged technique with the map rows that name it ("detector (kind, field=value)"), by ID.
fn watched<'a>(t: &Table<'a>) -> BTreeMap<&'a str, Vec<String>> {
    let mut out: BTreeMap<&'a str, Vec<String>> = BTreeMap::new();
    for tag in &t.tags {
        let mut when: Vec<String> = vec![];
        if tag.kind != "*" {
            when.push(tag.kind.to_string());
        }
        if tag.field != "*" {
            when.push(if tag.value == "*" { format!("{} present", tag.field) } else { format!("{}={}", tag.field, tag.value) });
        }
        let row = if when.is_empty() { tag.detector.to_string() } else { format!("{} ({})", tag.detector, when.join(", ")) };
        for id in &tag.ids {
            let rows = out.entry(id).or_default();
            if !rows.contains(&row) {
                rows.push(row.clone());
            }
        }
    }
    out
}

/// The layer, as indented JSON: every tagged technique with score 1 and the map rows as its comment; a sub-technique's parent
/// is listed too, with its sub-techniques shown, so Navigator opens it unfolded.
pub fn layer(t: &Table) -> String {
    let rows = watched(t);
    // a technique opens unfolded when a sub-technique of it is tagged
    let unfold = |id: &str| !id.contains('.') && rows.keys().any(|k| k.strip_prefix(id).is_some_and(|r| r.starts_with('.')));
    let mut techniques: Vec<Value> = vec![];
    let mut parents: Vec<&str> = vec![];
    for (id, by) in &rows {
        techniques.push(obj(vec![
            ("techniqueID", text(*id)),
            ("score", Value::Number("1".into())),
            ("comment", text(format!("Watched by {}", by.join("; ")))),
            ("enabled", Value::Bool(true)),
            ("showSubtechniques", Value::Bool(unfold(id))),
        ]));
        if let Some((parent, _)) = id.split_once('.') {
            if !parents.contains(&parent) && !rows.contains_key(parent) {
                parents.push(parent);
            }
        }
    }
    for p in parents {
        techniques.push(obj(vec![("techniqueID", text(p)), ("enabled", Value::Bool(true)), ("showSubtechniques", Value::Bool(true))]));
    }
    let major = t.version.split('.').next().unwrap_or(t.version);
    let v = obj(vec![
        ("name", text("Heimdall: what its detectors watch")),
        ("versions", obj(vec![("attack", text(major)), ("navigator", text("5.1.0")), ("layer", text("4.5"))])),
        ("domain", text("enterprise-attack")),
        (
            "description",
            text(format!(
                "The techniques Heimdall's detectors are tagged with (internal/attack/tags.tsv), ATT&CK Enterprise {}. {WARNING}",
                t.version
            )),
        ),
        ("filters", obj(vec![("platforms", Value::Array(vec![text("Linux"), text("Windows")]))])),
        ("sorting", Value::Number("0".into())),
        (
            "layout",
            obj(vec![
                ("layout", text("side")),
                ("showID", Value::Bool(true)),
                ("showName", Value::Bool(true)),
                ("hideDisabled", Value::Bool(false)),
            ]),
        ),
        ("hideDisabled", Value::Bool(false)),
        ("techniques", Value::Array(techniques)),
        (
            "gradient",
            obj(vec![
                ("colors", Value::Array(vec![text("#ffffff"), text("#66b1ff")])),
                ("minValue", Value::Number("0".into())),
                ("maxValue", Value::Number("1".into())),
            ]),
        ),
        (
            "legendItems",
            Value::Array(vec![obj(vec![("label", text("Watched by a Heimdall detector (not: covered)")), ("color", text("#66b1ff"))])]),
        ),
        ("metadata", Value::Array(vec![obj(vec![("name", text("Generated by")), ("value", text("heimdalld attack-layer"))])])),
        ("showTacticRowBackground", Value::Bool(false)),
        ("selectTechniquesAcrossTactics", Value::Bool(true)),
        ("selectSubtechniquesWithParent", Value::Bool(false)),
    ]);
    let mut out = String::new();
    write_indented(&mut out, &v, "  ");
    out
}

fn tactic_title(short: &str) -> String {
    TACTICS.iter().find(|(s, _)| *s == short).map(|(_, t)| t.to_string()).unwrap_or_else(|| short.replace('-', " "))
}

/// docs/ATTACK_COVERAGE.md: per tactic, the techniques watched and by what; then the tactics nothing is tagged with.
pub fn coverage_page(t: &Table) -> String {
    let rows = watched(t);
    let techs: Vec<Technique> = rows.keys().filter_map(|id| t.lookup(id)).collect();
    let mut tactics: Vec<&str> = t.techniques.iter().flat_map(|x| x.tactics.split(',')).collect();
    tactics.sort_by_key(|s| (TACTICS.iter().position(|(x, _)| x == s).unwrap_or(usize::MAX), *s));
    tactics.dedup();
    let mut out = String::new();
    out += "# What Heimdall's detectors watch, by ATT&CK tactic\n\n";
    out += "Generated from `internal/attack/tags.tsv` and `internal/attack/enterprise.tsv` by the test\n";
    out += "`the_coverage_page_is_current` (rust/heimdall/src/cli/attacklayer.rs); do not edit it by hand. After a change to either\n";
    out += "table: `HEIMDALL_WRITE_DOCS=1 cargo test --lib the_coverage_page_is_current` in rust/heimdall. The reasons for each tag\n";
    out += "and the gap list are in [ATTACK.md](ATTACK.md).\n\n";
    out += &format!("**{WARNING}**\n\n");
    out += &format!(
        "ATT&CK Enterprise {}: {} of its {} Linux and Windows techniques and sub-techniques are named by a detector. The same map as\n",
        t.version,
        techs.len(),
        t.techniques.len()
    );
    out += "an ATT&CK Navigator layer: `heimdalld attack-layer > heimdall-layer.json`, then Navigator's \"Open Existing Layer\".\n";
    let mut empty: Vec<String> = vec![];
    for tactic in &tactics {
        let here: Vec<&Technique> = techs.iter().filter(|x| x.tactics.split(',').any(|s| s == *tactic)).collect();
        let title = tactic_title(tactic);
        if here.is_empty() {
            empty.push(title);
            continue;
        }
        out += &format!("\n## {title}\n\n| Technique | Watched by |\n| --- | --- |\n");
        for x in here {
            out += &format!("| {} {} | {} |\n", x.id, x.name, rows[x.id].iter().map(|r| format!("`{r}`")).collect::<Vec<_>>().join(", "));
        }
    }
    if !empty.is_empty() {
        out += &format!("\n## Tactics no detector is tagged with\n\n{}.\n", empty.join(", "));
    }
    out
}

/// `heimdalld attack-layer`: the layer on standard output.
pub fn main(args: &[String]) -> Option<i32> {
    if !args.is_empty() {
        eprintln!("usage: heimdalld attack-layer > layer.json   (an ATT&CK Navigator layer of what the detectors watch)");
        return Some(2);
    }
    let t = embedded();
    if t.techniques.is_empty() {
        eprintln!("heimdalld attack-layer: the technique table did not load");
        return Some(1);
    }
    println!("{}", layer(t));
    Some(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attack::{TABLE, TAGS};

    /// The layer as Navigator's layer format 4.5 has it: the required name, versions and domain; every technique a known ID
    /// with the fields' types; a sub-technique's parent listed and unfolded; the warning in the description.
    #[test]
    fn the_layer_has_the_navigator_layer_format() {
        let t = Table::parse(TABLE, TAGS).unwrap();
        let l: serde_json::Value = serde_json::from_str(&layer(&t)).expect("the layer is JSON");
        assert!(l["name"].as_str().is_some_and(|n| !n.is_empty()));
        assert_eq!(l["versions"]["layer"], "4.5");
        assert_eq!(l["domain"], "enterprise-attack");
        let attack = l["versions"]["attack"].as_str().unwrap();
        assert!(!attack.is_empty() && attack.chars().all(|c| c.is_ascii_digit()) && t.version.starts_with(attack));
        assert!(l["description"].as_str().unwrap().contains("never that the technique is covered"));
        let techs = l["techniques"].as_array().unwrap();
        let ids: Vec<&str> = techs.iter().map(|x| x["techniqueID"].as_str().unwrap()).collect();
        for (x, id) in techs.iter().zip(&ids) {
            assert!(t.lookup(id).is_some(), "{id} is not in the table");
            let shape = id.len() == 5 || (id.len() == 9 && &id[5..6] == ".");
            assert!(id.starts_with('T') && shape && id[1..].replace('.', "").chars().all(|c| c.is_ascii_digit()), "{id}");
            assert!(x["enabled"].is_boolean() && x["showSubtechniques"].is_boolean());
            if let Some(s) = x.get("score") {
                assert!(s.is_number());
                assert!(x["comment"].as_str().unwrap().starts_with("Watched by "));
            }
            if let Some((parent, _)) = id.split_once('.') {
                let p = techs.iter().find(|y| y["techniqueID"] == parent).expect("the parent is listed");
                assert_eq!(p["showSubtechniques"], true, "{parent} opens unfolded");
            }
        }
        let mut seen = ids.clone();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), ids.len(), "each technique once");
        // every tag of the map is in the layer, with its rows
        for tag in &t.tags {
            for id in &tag.ids {
                let x = techs.iter().find(|y| y["techniqueID"] == *id).unwrap();
                assert!(x["comment"].as_str().unwrap().contains(tag.detector), "{id}: {}", x["comment"]);
            }
        }
        let arp = techs.iter().find(|y| y["techniqueID"] == "T1557.002").unwrap();
        assert!(arp["comment"].as_str().unwrap().contains("lan-watch (router_changed)"), "{}", arp["comment"]);
    }

    /// docs/ATTACK_COVERAGE.md is what the tables say; HEIMDALL_WRITE_DOCS=1 writes it again.
    #[test]
    fn the_coverage_page_is_current() {
        let t = Table::parse(TABLE, TAGS).unwrap();
        let page = coverage_page(&t);
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/ATTACK_COVERAGE.md");
        if std::env::var_os("HEIMDALL_WRITE_DOCS").is_some() {
            std::fs::write(path, &page).unwrap();
        }
        let on_disk = std::fs::read_to_string(path).unwrap_or_default();
        assert!(
            on_disk == page,
            "docs/ATTACK_COVERAGE.md is stale: HEIMDALL_WRITE_DOCS=1 cargo test --lib the_coverage_page_is_current (rust/heimdall)"
        );
        assert!(page.contains("| T1557.002 Adversary-in-the-Middle: ARP Cache Poisoning | `lan-watch (router_changed)`"));
    }

    #[test]
    fn anything_after_the_command_is_refused() {
        assert_eq!(main(&["x".to_string()]), Some(2));
    }
}
