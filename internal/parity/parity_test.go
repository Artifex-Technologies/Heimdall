package parity

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// go test ./internal/parity -update writes testdata/parity from the scenarios and the Go daemon's answers; without it, the
// files must hold exactly what the Go code says today (so a change to a detector that changes an alert shows up here, and the
// Rust port's test, rust/heimdall/tests/parity.rs, runs the same files).
var update = flag.Bool("update", false, "rewrite testdata/parity")

func dir(t *testing.T) string {
	t.Helper()
	d, err := filepath.Abs(filepath.Join("..", "..", "testdata", "parity"))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// encode writes a fixture file with one step, one golden step and one case per line: small, and a diff shows what changed.
func encode(v any) ([]byte, error) {
	var b bytes.Buffer
	line := func(x any) error {
		j, err := json.Marshal(x)
		b.Write(j)
		return err
	}
	switch f := v.(type) {
	case File:
		fmt.Fprintf(&b, "{\"format\": %q,\n \"from\": %q,\n \"scenarios\": [\n", f.Format, f.From)
		for i, s := range f.Scenarios {
			head := s
			head.Steps, head.Golden = nil, nil
			hj, err := json.Marshal(head)
			if err != nil {
				return nil, err
			}
			b.Write(hj[:len(hj)-len(`,"steps":null,"golden":null}`)])
			b.WriteString(",\n  \"steps\": [\n")
			for k, st := range s.Steps {
				b.WriteString("   ")
				if err := line(st); err != nil {
					return nil, err
				}
				if k < len(s.Steps)-1 {
					b.WriteByte(',')
				}
				b.WriteByte('\n')
			}
			b.WriteString("  ],\n  \"golden\": [\n")
			for k, g := range s.Golden {
				b.WriteString("   ")
				if err := line(g); err != nil {
					return nil, err
				}
				if k < len(s.Golden)-1 {
					b.WriteByte(',')
				}
				b.WriteByte('\n')
			}
			b.WriteString("  ]}")
			if i < len(f.Scenarios)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		b.WriteString(" ]\n}\n")
		return b.Bytes(), nil
	}
	return json.MarshalIndent(v, "", " ")
}

func write(t *testing.T, path string, v any) {
	t.Helper()
	b, err := encode(v)
	if err != nil {
		t.Fatal(err)
	}
	var check any
	if err := json.Unmarshal(b, &check); err != nil {
		t.Fatalf("%s: the written fixture does not read back: %v", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFixturesMatchTheGoDaemon(t *testing.T) {
	steps, alerts := 0, 0
	for name, f := range Groups() {
		for i := range f.Scenarios {
			s := &f.Scenarios[i]
			got, err := Run(*s, t.TempDir())
			if err != nil {
				t.Fatalf("%s: %v", s.Name, err)
			}
			for k, st := range s.Steps {
				if err := Check(st, got[k]); err != nil {
					t.Errorf("%s: %s, step %d: the original test's assertion fails: %v", name, s.Name, k, err)
				}
				alerts += len(got[k])
			}
			steps += len(s.Steps)
			s.Golden = got
		}
		path := filepath.Join(dir(t), name)
		if *update {
			write(t, path, f)
			continue
		}
		var have File
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%v (run go test ./internal/parity -update)", err)
		}
		if err := json.Unmarshal(b, &have); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want, _ := json.Marshal(f)
		var norm File
		_ = json.Unmarshal(want, &norm)
		if !reflect.DeepEqual(have, norm) {
			t.Errorf("%s is out of date: run go test ./internal/parity -update and review the diff", name)
		}
	}
	t.Logf("%d steps, %d alerts", steps, alerts)

	fn := AllFunctions()
	path := filepath.Join(dir(t), "functions.json")
	if *update {
		write(t, path, fn)
		return
	}
	var have Functions
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &have); err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(fn)
	var norm Functions
	_ = json.Unmarshal(want, &norm)
	if !reflect.DeepEqual(have, norm) {
		t.Error("functions.json is out of date: run go test ./internal/parity -update")
	}
}
