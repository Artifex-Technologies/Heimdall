// Package attack names what Heimdall's detectors watch in MITRE ATT&CK's words: an alert's tags are technique IDs
// ("T1557.002"), chosen by a fixed map from the alert's detector, event kind and at most one field (tags.tsv), and named
// from a trimmed copy of ATT&CK Enterprise (enterprise.tsv, Linux and Windows techniques, written by rust/tools/attack-table
// from one pinned release; MITRE's terms in NOTICE-ATTACK). The Rust port reads the same two files (rust/heimdall/src/attack.rs).
//
// A tag says what a detector looks for, never that a technique is covered; docs/ATTACK.md gives the reason for every row
// and the list of what is not watched. The table is read once, on the first alert, and keeps slices of the embedded text.
package attack

import (
	_ "embed"
	"fmt"
	"strings"
	"sync"
)

//go:embed enterprise.tsv
var tableText string

//go:embed tags.tsv
var tagsText string

// Technique is one row of the table.
type Technique struct {
	ID      string
	Name    string // a sub-technique as "Parent: Sub", as MITRE's site names it
	Tactics string // MITRE's short names, comma-separated ("credential-access,collection")
}

// Ref is a technique as an alert's explanation shows it: the ID and its name.
type Ref struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Tag is one row of the detector map.
type Tag struct {
	Detector, Kind, Field, Value string // "*" for any kind, field or value
	IDs                          []string
}

// Table is the parsed technique table and detector map.
type Table struct {
	Version    string
	Techniques map[string]Technique
	Order      []string // the IDs in the file's order
	Tags       []Tag
}

// Parse reads a technique table and a detector map. Both are this repository's own files, so anything unexpected is an
// error (the tests parse the embedded ones; the daemon never sees an error from them).
func Parse(table, tags string) (*Table, error) {
	t := &Table{Techniques: map[string]Technique{}}
	for n, line := range strings.Split(table, "\n") {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if v, ok := strings.CutPrefix(line, "# version "); ok {
				t.Version = v
			}
			continue
		}
		col := strings.Split(line, "\t")
		if len(col) != 3 || col[0] == "" || col[1] == "" || col[2] == "" {
			return nil, fmt.Errorf("technique table, line %d: want ID, name and tactics", n+1)
		}
		if _, dup := t.Techniques[col[0]]; dup {
			return nil, fmt.Errorf("technique table, line %d: %s twice", n+1, col[0])
		}
		t.Techniques[col[0]] = Technique{ID: col[0], Name: col[1], Tactics: col[2]}
		t.Order = append(t.Order, col[0])
	}
	if t.Version == "" || len(t.Order) == 0 {
		return nil, fmt.Errorf("technique table: no version line or no techniques")
	}
	for n, line := range strings.Split(tags, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		col := strings.Split(line, "\t")
		if len(col) != 4 || col[0] == "" || col[0] == "*" || col[1] == "" || col[2] == "" || col[3] == "" {
			return nil, fmt.Errorf("detector map, line %d: want detector, kind, field and techniques", n+1)
		}
		tag := Tag{Detector: col[0], Kind: col[1], Field: "*", Value: "*"}
		if col[2] != "*" {
			k, v, ok := strings.Cut(col[2], "=")
			if !ok || k == "" || k == "*" || v == "" {
				return nil, fmt.Errorf("detector map, line %d: the field condition is key=value or *", n+1)
			}
			tag.Field, tag.Value = k, v
		}
		for _, id := range strings.Split(col[3], ",") {
			if _, ok := t.Techniques[id]; !ok {
				return nil, fmt.Errorf("detector map, line %d: %q is not in the technique table", n+1, id)
			}
			tag.IDs = append(tag.IDs, id)
		}
		t.Tags = append(t.Tags, tag)
	}
	return t, nil
}

var (
	once     sync.Once
	embedded *Table
)

// Embedded is the table and map built into heimdalld, read on first use. A broken file (which the tests rule out) gives
// an empty table: alerts then carry no tags, and nothing else changes.
func Embedded() *Table {
	once.Do(func() {
		t, err := Parse(tableText, tagsText)
		if err != nil {
			t = &Table{Techniques: map[string]Technique{}}
		}
		embedded = t
	})
	return embedded
}

// For is the technique IDs an alert is tagged with: the first map row matching its detector, event kind and field;
// nil when none does.
func (t *Table) For(detector, kind string, fields map[string]string) []string {
	for _, tag := range t.Tags {
		if tag.Detector != detector || (tag.Kind != "*" && tag.Kind != kind) {
			continue
		}
		if tag.Field != "*" {
			v := fields[tag.Field]
			if v == "" || (tag.Value != "*" && v != tag.Value) {
				continue
			}
		}
		return append([]string(nil), tag.IDs...)
	}
	return nil
}

// Names gives each known ID its name, in the same order (an unknown ID, from an alert written by another release, is left
// out); nil for none.
func (t *Table) Names(ids []string) []Ref {
	var out []Ref
	for _, id := range ids {
		if tech, ok := t.Techniques[id]; ok {
			out = append(out, Ref{ID: id, Name: tech.Name})
		}
	}
	return out
}

// For tags an alert from the embedded map (see Table.For).
func For(detector, kind string, fields map[string]string) []string {
	return Embedded().For(detector, kind, fields)
}

// Names names IDs from the embedded table (see Table.Names).
func Names(ids []string) []Ref { return Embedded().Names(ids) }
