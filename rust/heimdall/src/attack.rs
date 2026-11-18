//! What the detectors watch, in MITRE ATT&CK's words (Go: internal/attack). An alert's tags are technique IDs chosen by a
//! fixed map from its detector, event kind and at most one field (`internal/attack/tags.tsv`), named from a trimmed copy of
//! ATT&CK Enterprise (`internal/attack/enterprise.tsv`, Linux and Windows techniques, written by rust/tools/attack-table
//! from one pinned release; MITRE's terms in NOTICE-ATTACK). Both files are the Go daemon's own, compiled in from the same
//! paths. A tag says what a detector looks for, never that a technique is covered (docs/ATTACK.md).
//!
//! The table is parsed once, on the first alert, into slices of the compiled-in text: about 30 KB of text and a small index.

use crate::event::Fields;
use std::collections::HashMap;
use std::sync::OnceLock;

/// The technique table, the Go daemon's file.
pub const TABLE: &str = include_str!("../../../internal/attack/enterprise.tsv");
/// The detector map, the Go daemon's file.
pub const TAGS: &str = include_str!("../../../internal/attack/tags.tsv");

/// One row of the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Technique<'a> {
    pub id: &'a str,
    /// a sub-technique as "Parent: Sub", as MITRE's site names it
    pub name: &'a str,
    /// MITRE's short names, comma-separated ("credential-access,collection")
    pub tactics: &'a str,
}

/// A technique as an alert's explanation shows it: the ID and its name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ref {
    pub id: String,
    pub name: String,
}

crate::go_struct!(Ref { id: "id", name: "name" });

/// One row of the detector map ("*" for any kind, field or value).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tag<'a> {
    pub detector: &'a str,
    pub kind: &'a str,
    pub field: &'a str,
    pub value: &'a str,
    pub ids: Vec<&'a str>,
}

/// The parsed table and map.
#[derive(Debug, Default)]
pub struct Table<'a> {
    pub version: &'a str,
    /// the rows in the file's order
    pub techniques: Vec<Technique<'a>>,
    index: HashMap<&'a str, usize>,
    pub tags: Vec<Tag<'a>>,
}

impl<'a> Table<'a> {
    /// Reads a technique table and a detector map; anything unexpected is an error (they are this repository's own files).
    pub fn parse(table: &'a str, tags: &'a str) -> Result<Table<'a>, String> {
        let mut t = Table::default();
        for (n, line) in table.split('\n').enumerate() {
            if line.is_empty() {
                continue;
            }
            if line.starts_with('#') {
                if let Some(v) = line.strip_prefix("# version ") {
                    t.version = v;
                }
                continue;
            }
            let col: Vec<&str> = line.split('\t').collect();
            if col.len() != 3 || col.iter().any(|c| c.is_empty()) {
                return Err(format!("technique table, line {}: want ID, name and tactics", n + 1));
            }
            if t.index.insert(col[0], t.techniques.len()).is_some() {
                return Err(format!("technique table, line {}: {} twice", n + 1, col[0]));
            }
            t.techniques.push(Technique { id: col[0], name: col[1], tactics: col[2] });
        }
        if t.version.is_empty() || t.techniques.is_empty() {
            return Err("technique table: no version line or no techniques".into());
        }
        for (n, line) in tags.split('\n').enumerate() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let col: Vec<&str> = line.split('\t').collect();
            if col.len() != 4 || col[0].is_empty() || col[0] == "*" || col[1..].iter().any(|c| c.is_empty()) {
                return Err(format!("detector map, line {}: want detector, kind, field and techniques", n + 1));
            }
            let (field, value) = if col[2] == "*" {
                ("*", "*")
            } else {
                match col[2].split_once('=') {
                    Some((k, v)) if !k.is_empty() && k != "*" && !v.is_empty() => (k, v),
                    _ => return Err(format!("detector map, line {}: the field condition is key=value or *", n + 1)),
                }
            };
            let mut ids = Vec::new();
            for id in col[3].split(',') {
                if !t.index.contains_key(id) {
                    return Err(format!("detector map, line {}: {id:?} is not in the technique table", n + 1));
                }
                ids.push(id);
            }
            t.tags.push(Tag { detector: col[0], kind: col[1], field, value, ids });
        }
        Ok(t)
    }

    /// A technique by its ID.
    pub fn lookup(&self, id: &str) -> Option<Technique<'a>> {
        self.index.get(id).map(|&i| self.techniques[i])
    }

    /// The technique IDs an alert is tagged with: the first map row matching its detector, event kind and field; empty
    /// when none does.
    pub fn tags_for(&self, detector: &str, kind: &str, fields: &Fields) -> Vec<String> {
        for tag in &self.tags {
            if tag.detector != detector || (tag.kind != "*" && tag.kind != kind) {
                continue;
            }
            if tag.field != "*" {
                let v = fields.get(tag.field).map(String::as_str).unwrap_or("");
                if v.is_empty() || (tag.value != "*" && v != tag.value) {
                    continue;
                }
            }
            return tag.ids.iter().map(|s| s.to_string()).collect();
        }
        Vec::new()
    }

    /// Each known ID with its name, in the same order (an unknown one, from an alert another release wrote, is left out).
    pub fn names(&self, ids: &[String]) -> Vec<Ref> {
        ids.iter().filter_map(|id| self.lookup(id)).map(|t| Ref { id: t.id.into(), name: t.name.into() }).collect()
    }
}

/// The table and map compiled into the daemon, read on first use. A broken file (which the tests rule out) gives an empty
/// table: alerts then carry no tags, and nothing else changes.
pub fn embedded() -> &'static Table<'static> {
    static T: OnceLock<Table<'static>> = OnceLock::new();
    T.get_or_init(|| Table::parse(TABLE, TAGS).unwrap_or_default())
}

/// The tags of an alert, from the compiled-in map.
pub fn tags_for(detector: &str, kind: &str, fields: &Fields) -> Vec<String> {
    embedded().tags_for(detector, kind, fields)
}

/// The names of tags, from the compiled-in table.
pub fn names(ids: &[String]) -> Vec<Ref> {
    embedded().names(ids)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_compiled_in_files_parse_and_every_mapped_id_is_in_the_table() {
        let t = Table::parse(TABLE, TAGS).unwrap();
        assert_eq!((t.version, t.techniques.len()), ("20.1", 511));
        assert!(!t.tags.is_empty());
        for tag in &t.tags {
            for id in &tag.ids {
                assert!(t.lookup(id).is_some(), "{}: {id} is not in the table", tag.detector);
            }
        }
        assert_eq!(embedded().version, "20.1");
    }

    #[test]
    fn tags_and_names() {
        let f = |pairs: &[(&str, &str)]| -> Fields { pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect() };
        assert_eq!(tags_for("lan-watch", "router_changed", &f(&[])), ["T1557.002"]);
        assert!(tags_for("lan-watch", "new_listener", &f(&[])).is_empty());
        assert_eq!(tags_for("remote-access", "new_connection", &f(&[("ra_kind", "tunnel")])), ["T1572"]);
        assert!(tags_for("remote-access", "remote_access", &f(&[("ra_kind", "c2")])).is_empty());
        assert_eq!(tags_for("inbound", "firewall_block", &f(&[("ports", "12")])), ["T1046"]);
        assert!(tags_for("inbound", "firewall_block", &f(&[("ports", "")])).is_empty());
        let n = names(&["T1557.002".into(), "T9999".into(), "T1110".into()]);
        assert_eq!(
            n,
            [
                Ref { id: "T1557.002".into(), name: "Adversary-in-the-Middle: ARP Cache Poisoning".into() },
                Ref { id: "T1110".into(), name: "Brute Force".into() }
            ]
        );
    }

    #[test]
    fn refuses_what_is_not_ours() {
        let table = "# version 1\nT1000\tA\tdiscovery\n";
        let more = format!("{table}T1000\tB\tdiscovery\n");
        for (tab, tags) in [
            ("T1000\tA\tdiscovery\n", ""),
            ("# version 1\n", ""),
            ("# version 1\nT1000\tA\n", ""),
            (more.as_str(), ""),
            (table, "x\t*\t*\tT1001\n"),
            (table, "x\t*\t*\n"),
            (table, "*\t*\t*\tT1000\n"),
            (table, "x\t*\tkey\tT1000\n"),
            (table, "x\t*\t=v\tT1000\n"),
            (table, "x\t*\t*\tT1000,\n"),
        ] {
            assert!(Table::parse(tab, tags).is_err(), "{tab:?} {tags:?}");
        }
        assert!(Table::parse(&format!("{table}T1000.001\tA: B\tdiscovery,impact"), "x\t*\tk=*\tT1000.001").is_ok());
    }
}
