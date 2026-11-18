//! attack-table: writes Heimdall's ATT&CK technique table, `internal/attack/enterprise.tsv`, from one release of MITRE's
//! attack-stix-data Enterprise bundle. Run by hand when I choose to move to a new ATT&CK release (docs/ATTACK.md):
//!
//! ```text
//! gh release download v20.1 -R mitre-attack/attack-stix-data -p enterprise-attack.json -D /tmp/attack
//! cd rust && cargo run --release -p heimdall-attack-table -- /tmp/attack/enterprise-attack.json 20.1 \
//!     > ../internal/attack/enterprise.tsv
//! ```
//!
//! Kept: techniques and sub-techniques (`attack-pattern`) whose platforms include Linux or Windows. Revoked and deprecated
//! ones are left out. A row is the ID, the name (a sub-technique as "Parent: Sub", the way MITRE's site names it) and the
//! tactics (MITRE's short names, in the bundle's order). The version given on the command line must be the bundle's own
//! (its `x-mitre-collection`), so a table can never carry the wrong release's label; the header records the bundle's
//! SHA-256 and MITRE's copyright statement from the bundle itself.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write;

const PLATFORMS: [&str; 2] = ["Linux", "Windows"];

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: attack-table ENTERPRISE-ATTACK.JSON VERSION > internal/attack/enterprise.tsv");
        std::process::exit(2);
    }
    let bytes = match std::fs::read(&args[1]) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("attack-table: {}: {e}", args[1]);
            std::process::exit(1);
        }
    };
    match table(&bytes, &args[2]) {
        Ok((out, rows)) => {
            std::io::stdout().write_all(out.as_bytes()).expect("stdout");
            eprintln!("attack-table: {rows} techniques and sub-techniques, {} bytes", out.len());
        }
        Err(e) => {
            eprintln!("attack-table: {e}");
            std::process::exit(1);
        }
    }
}

fn str_of<'a>(o: &'a serde_json::Value, k: &str) -> &'a str {
    o.get(k).and_then(|v| v.as_str()).unwrap_or("")
}

fn flag(o: &serde_json::Value, k: &str) -> bool {
    o.get(k).and_then(|v| v.as_bool()).unwrap_or(false)
}

fn list<'a>(o: &'a serde_json::Value, k: &str) -> &'a [serde_json::Value] {
    o.get(k).and_then(|v| v.as_array()).map(|a| a.as_slice()).unwrap_or(&[])
}

/// The technique's ATT&CK ID (the external reference whose source is "mitre-attack").
fn attack_id(o: &serde_json::Value) -> &str {
    list(o, "external_references")
        .iter()
        .find(|r| str_of(r, "source_name") == "mitre-attack")
        .map(|r| str_of(r, "external_id"))
        .unwrap_or("")
}

fn valid_id(id: &str) -> bool {
    let b = id.as_bytes();
    let digits = |s: &[u8]| s.iter().all(u8::is_ascii_digit);
    match b.len() {
        5 => b[0] == b'T' && digits(&b[1..]),
        9 => b[0] == b'T' && digits(&b[1..5]) && b[5] == b'.' && digits(&b[6..]),
        _ => false,
    }
}

/// A value that must sit inside one tab-separated field.
fn plain(s: &str, what: &str) -> Result<(), String> {
    if s.is_empty() || s.chars().any(|c| c.is_control()) || s.starts_with('#') || s != s.trim() {
        return Err(format!("{what} {s:?} cannot be one field of the table"));
    }
    Ok(())
}

/// The table's text and its number of rows.
fn table(bytes: &[u8], version: &str) -> Result<(String, usize), String> {
    let bundle: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| format!("not a STIX bundle: {e}"))?;
    if str_of(&bundle, "type") != "bundle" {
        return Err("not a STIX bundle".into());
    }
    let objects = list(&bundle, "objects");
    let collection = objects
        .iter()
        .find(|o| str_of(o, "type") == "x-mitre-collection")
        .ok_or("the bundle has no x-mitre-collection (is it an ATT&CK bundle?)")?;
    if str_of(collection, "name") != "Enterprise ATT&CK" {
        return Err(format!("the bundle is {:?}, not Enterprise ATT&CK", str_of(collection, "name")));
    }
    let have = str_of(collection, "x_mitre_version");
    if have != version {
        return Err(format!("the bundle is ATT&CK {have}, not {version}"));
    }
    let copyright = objects
        .iter()
        .filter(|o| str_of(o, "type") == "marking-definition")
        .filter_map(|o| o.get("definition").map(|d| str_of(d, "statement")))
        .find(|s| s.starts_with("Copyright"))
        .ok_or("the bundle has no copyright statement")?;
    plain(copyright, "the copyright statement")?;

    // every technique's name (revoked and deprecated too), for naming a kept sub-technique after its parent
    let patterns: Vec<&serde_json::Value> = objects.iter().filter(|o| str_of(o, "type") == "attack-pattern").collect();
    let names: BTreeMap<&str, &str> = patterns.iter().map(|o| (attack_id(o), str_of(o, "name"))).collect();
    let mut rows = BTreeMap::new();
    for o in patterns {
        if flag(o, "revoked") || flag(o, "x_mitre_deprecated") {
            continue;
        }
        if !list(o, "x_mitre_platforms").iter().any(|p| PLATFORMS.contains(&p.as_str().unwrap_or(""))) {
            continue;
        }
        let id = attack_id(o);
        if !valid_id(id) {
            return Err(format!("{:?}: unexpected ATT&CK ID {id:?}", str_of(o, "name")));
        }
        let mut name = str_of(o, "name").to_string();
        if let Some((parent, _)) = id.split_once('.') {
            let p = names.get(parent).ok_or(format!("{id}: its parent {parent} is not in the bundle"))?;
            name = format!("{p}: {name}");
        }
        plain(&name, id)?;
        let tactics: Vec<&str> = list(o, "kill_chain_phases")
            .iter()
            .filter(|k| str_of(k, "kill_chain_name") == "mitre-attack")
            .map(|k| str_of(k, "phase_name"))
            .collect();
        if tactics.is_empty() || tactics.iter().any(|t| t.is_empty() || !t.bytes().all(|c| c.is_ascii_lowercase() || c == b'-')) {
            return Err(format!("{id}: unexpected tactics {tactics:?}"));
        }
        if rows.insert(id.to_string(), (name, tactics.join(","))).is_some() {
            return Err(format!("{id} appears twice"));
        }
    }
    if rows.is_empty() {
        return Err("no technique kept".into());
    }
    let sha: String = Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect();
    let mut out = format!(
        "# MITRE ATT&CK Enterprise {version}: techniques and sub-techniques for Linux or Windows; revoked and deprecated ones left out.\n\
         # version {version}\n\
         # source mitre-attack/attack-stix-data release v{version}, enterprise-attack.json, SHA-256 {sha}\n\
         # {copyright}\n\
         # Terms of use: NOTICE-ATTACK. Written by rust/tools/attack-table (docs/ATTACK.md); do not edit by hand.\n\
         # id\tname\ttactics\n"
    );
    for (id, (name, tactics)) in &rows {
        out.push_str(&format!("{id}\t{name}\t{tactics}\n"));
    }
    Ok((out, rows.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(id: &str, name: &str, platforms: &[&str], extra: &str) -> String {
        format!(
            r#"{{"type":"attack-pattern","name":"{name}","external_references":[{{"source_name":"capec","external_id":"CAPEC-1"}},{{"source_name":"mitre-attack","external_id":"{id}"}}],"x_mitre_platforms":{platforms:?},"kill_chain_phases":[{{"kill_chain_name":"mitre-attack","phase_name":"credential-access"}},{{"kill_chain_name":"mitre-attack","phase_name":"collection"}}]{extra}}}"#
        )
    }

    fn bundle(version: &str, patterns: &[String]) -> Vec<u8> {
        format!(
            r#"{{"type":"bundle","objects":[{{"type":"x-mitre-collection","name":"Enterprise ATT&CK","x_mitre_version":"{version}"}},{{"type":"marking-definition","definition":{{"statement":"Copyright 2015-2026, The MITRE Corporation."}}}},{}]}}"#,
            patterns.join(",")
        )
        .into_bytes()
    }

    #[test]
    fn keeps_linux_and_windows_techniques_drops_the_rest() {
        let b = bundle(
            "20.1",
            &[
                pattern("T1557", "Adversary-in-the-Middle", &["Linux", "Network Devices"], ""),
                pattern("T1557.002", "ARP Cache Poisoning", &["Windows"], ""),
                pattern("T1557.004", "Evil Twin", &["Network Devices"], ""),
                pattern("T1595", "Active Scanning", &["PRE"], ""),
                pattern("T1562", "Impair Defenses", &["Linux"], r#","revoked":true"#),
                pattern("T1000", "Old", &["Windows"], r#","x_mitre_deprecated":true"#),
            ],
        );
        let (out, n) = table(&b, "20.1").unwrap();
        assert_eq!(n, 2);
        let rows: Vec<&str> = out.lines().filter(|l| !l.starts_with('#')).collect();
        assert_eq!(
            rows,
            [
                "T1557\tAdversary-in-the-Middle\tcredential-access,collection",
                "T1557.002\tAdversary-in-the-Middle: ARP Cache Poisoning\tcredential-access,collection"
            ]
        );
        assert!(out.contains("# version 20.1\n"));
        assert!(out.contains("# Copyright 2015-2026, The MITRE Corporation.\n"));
    }

    #[test]
    fn refuses_the_wrong_release_and_odd_data() {
        let ok = [pattern("T1557", "Adversary-in-the-Middle", &["Linux"], "")];
        assert!(table(&bundle("20.0", &ok), "20.1").unwrap_err().contains("not 20.1"));
        assert!(table(&bundle("20.1", &[pattern("T1557", "Bad\tname", &["Linux"], "")]), "20.1").is_err());
        assert!(table(&bundle("20.1", &[pattern("X1557", "Name", &["Linux"], "")]), "20.1").is_err());
        assert!(table(&bundle("20.1", &[pattern("T1557.001", "Orphan", &["Linux"], "")]), "20.1").is_err());
        assert!(table(&bundle("20.1", &[ok[0].clone(), ok[0].clone()]), "20.1").is_err());
        assert!(table(b"[]", "20.1").is_err());
    }
}
