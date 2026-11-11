package parity

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/maintenance"
)

// CLIAdmin is the fixture of the pure parts of the admin commands (testdata/parity/cli-admin.json), which
// rust/heimdall/tests/cli_admin.rs runs: the maintenance window's texts, its opening and reading, Go's duration rounding.
// The commands themselves are compared as whole programs in fake roots (the same test file).
type CLIAdmin struct {
	Format   string          `json:"format"`
	Describe []MaintDescribe `json:"maintenance_describe"`
	Open     []MaintOpen     `json:"maintenance_open"`
	Read     []MaintRead     `json:"maintenance_read"`
	Round    []RoundCase     `json:"round"`
	Grants   []GrantOp       `json:"grants"`
	Guards   []GuardCase     `json:"guards"`
}

// MaintDescribe: the window (as the file holds it; empty: none found) at `now`, and Describe's text.
type MaintDescribe struct {
	Window string `json:"window"`
	Now    string `json:"now"`
	Text   string `json:"text"`
}

// MaintOpen: Open's arguments, then the file Write leaves (or the error).
type MaintOpen struct {
	Actor  string `json:"actor"`
	Reason string `json:"reason"`
	D      int64  `json:"d"`
	Now    string `json:"now"`
	File   string `json:"file"`
	Error  string `json:"error"`
}

// MaintRead: a file's bytes, whether Read found a window, and that window written back.
type MaintRead struct {
	File  string `json:"file"`
	Found bool   `json:"found"`
	Back  string `json:"back"`
}

// RoundCase: time.Duration(D).Round(M).
type RoundCase struct {
	D   int64 `json:"d"`
	M   int64 `json:"m"`
	Out int64 `json:"out"`
}

// AllCLIAdmin builds the fixture; tmp gives scratch folders.
func AllCLIAdmin(tmp func() string) (CLIAdmin, error) {
	f := CLIAdmin{Format: "heimdall-cli-admin/1"}
	zones := []*time.Location{time.UTC, time.FixedZone("", -5*3600), time.FixedZone("", 5*3600+1800), time.FixedZone("", 14*3600), time.FixedZone("", -9*3600-1800)}
	base := time.Date(2026, 11, 10, 20, 0, 0, 123456789, time.UTC)
	reasons := []string{"kernel update", "agent installs \"vim\", <git> & ü", "tab\there\nnew line \x01 ​  ", ""}
	lefts := []time.Duration{-time.Second, 0, 1, 29*time.Second + 999*time.Millisecond, 30 * time.Second, 89*time.Second + 500*time.Millisecond,
		90 * time.Second, 15 * time.Minute, 3*time.Hour + 59*time.Minute + 30*time.Second, 4 * time.Hour, 6 * time.Hour}
	for zi, z := range zones {
		for li, left := range lefts {
			now := base.Add(time.Duration(zi*7+li) * time.Minute).In(z)
			opened := now.Add(-37 * time.Minute)
			w := maintenance.Window{Reason: reasons[(zi+li)%len(reasons)], Actor: "owner", Opened: opened, Until: now.Add(left).In(zones[(zi+1)%len(zones)])}
			b, _ := json.Marshal(w)
			// as Read sees it: from the file, capped
			p := filepath.Join(tmp(), "m.json")
			if err := os.WriteFile(p, b, 0o644); err != nil {
				return f, err
			}
			rw, found := maintenance.Read(p)
			f.Describe = append(f.Describe, MaintDescribe{Window: string(b), Now: now.Format(time.RFC3339Nano), Text: maintenance.Describe(rw, found, now)})
		}
	}
	f.Describe = append(f.Describe, MaintDescribe{Window: "", Now: base.Format(time.RFC3339Nano), Text: maintenance.Describe(maintenance.Window{}, false, base)})
	durations := []time.Duration{-time.Minute, 0, 1, time.Minute, 15 * time.Minute, 4 * time.Hour, 4*time.Hour + 1, 10 * time.Hour, 1<<63 - 1}
	for zi, z := range zones {
		for di, d := range durations {
			now := base.Add(time.Duration(di) * time.Hour).In(z)
			reason := reasons[(zi+di)%len(reasons)]
			c := MaintOpen{Actor: fmt.Sprintf("user%d", di), Reason: reason, D: int64(d), Now: now.Format(time.RFC3339Nano)}
			w, err := maintenance.Open(c.Actor, reason, d, now)
			if err != nil {
				c.Error = err.Error()
			} else {
				p := filepath.Join(tmp(), "w.json")
				if err := maintenance.Write(p, w); err != nil {
					return f, err
				}
				b, _ := os.ReadFile(p)
				c.File = string(b)
			}
			f.Open = append(f.Open, c)
		}
	}
	for _, file := range []string{
		``, `{}`, `null`, `[]`, `{"until": 5}`, `{"reason": "x", "until": "2026-11-10T20:00:00Z"}`,
		`{"reason":"r","actor":"a","opened":"2026-11-10T20:00:00+01:00","until":"2026-11-11T20:00:00-05:00"}`,
		`{"REASON":"r","Actor":"a","opened":"2026-11-10T20:00:00.5Z","until":"2026-11-10T21:00:00.25Z","extra":[1,2]}`,
		`{"reason":"\ud800","opened":"0001-01-01T00:00:00Z","until":"2030-01-01T00:00:00Z"}`,
		`{"opened":"2026-11-10T20:00:00Z","until":"2026-11-10T19:00:00Z"}`,
		`{"until":"not a time"}`, `{"reason":"a","reason":"b"}`, "{\"reason\":\"x\"} trailing", `{"until":"2026-11-10T20:00:00Z",}`,
	} {
		p := filepath.Join(tmp(), "r.json")
		if err := os.WriteFile(p, []byte(file), 0o644); err != nil {
			return f, err
		}
		w, found := maintenance.Read(p)
		c := MaintRead{File: file, Found: found}
		if found {
			b, _ := json.Marshal(w)
			c.Back = string(b)
		}
		f.Read = append(f.Read, c)
	}
	ms := []time.Duration{-1, 0, 1, time.Second, time.Minute, time.Hour}
	ds := []time.Duration{0, 1, -1, 29 * time.Second, 30 * time.Second, -30 * time.Second, 31 * time.Second, 90 * time.Second, -90 * time.Second,
		1<<63 - 1, -1 << 63, time.Duration(1<<63-1) - 30*time.Second + 1, time.Duration(-1<<63) + 30*time.Second, 59*time.Minute + 59*time.Second}
	for _, d := range ds {
		for _, m := range ms {
			f.Round = append(f.Round, RoundCase{D: int64(d), M: int64(m), Out: int64(d.Round(m))})
		}
	}
	var err error
	if f.Grants, err = grantOps(tmp); err != nil {
		return f, err
	}
	if f.Guards, err = guardCases(tmp); err != nil {
		return f, err
	}
	return f, nil
}
