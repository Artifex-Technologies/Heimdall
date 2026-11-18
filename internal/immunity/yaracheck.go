package immunity

// YARA-X's exact compile check of a draft (my decision 2026-11-18, reference plan R4): heimdall-yara-check, a small program
// of its own package (rust/yara-check, built on the yara-x crate), reads the rule on stdin and prints its verdict as one
// line of JSON. The daemons (Go and Rust) run it when a draft is kept and when it is tested; when it is not installed,
// drafts are judged by CheckRule and the lint alone, as before. Its errors refuse a draft; its warnings (slow patterns
// above all) are kept with it, marked "YARA-X:".

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode/utf8"
)

// DefaultYARACheck is where heimdall-yara-check-git installs the checker (HEIMDALL_YARA_CHECK in tests).
const DefaultYARACheck = "/usr/bin/heimdall-yara-check"

const (
	yaraCheckWait  = 30 * time.Second
	yaraCheckItems = 20  // errors or warnings kept, each
	yaraCheckText  = 300 // bytes of each
	// NoYARAVerdict is the warning kept when the checker is installed but gave no verdict (it failed, took too long, or
	// printed something else): the draft is judged without it, never refused for it.
	NoYARAVerdict = "YARA-X: the check gave no verdict (heimdall-yara-check failed); judged without it"
)

// YARAVerdict is heimdall-yara-check's answer.
type YARAVerdict struct {
	Errors   []string `json:"errors"`
	OK       bool     `json:"ok"`
	Warnings []string `json:"warnings"`
	Version  string   `json:"yara_x"`
}

// yaraCheckPath is the checker a Rules value uses: its own Check, else HEIMDALL_YARA_CHECK (tests), else the default.
func (r Rules) yaraCheckPath() string {
	if r.Check != "" {
		return r.Check
	}
	if p := os.Getenv("HEIMDALL_YARA_CHECK"); p != "" {
		return p
	}
	return DefaultYARACheck
}

// clipItems keeps at most yaraCheckItems lines of at most yaraCheckText bytes each (cut before a letter, not inside one).
func clipItems(in []string) []string {
	if len(in) > yaraCheckItems {
		in = in[:yaraCheckItems]
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if len(s) > yaraCheckText {
			n := yaraCheckText
			for n > 0 && !utf8.RuneStart(s[n]) {
				n--
			}
			s = s[:n]
		}
		out = append(out, s)
	}
	return out
}

// YARACheck runs the checker at p on one rule: nil and no error when it is not installed (not a regular executable file).
func YARACheck(p, text string) (*YARAVerdict, error) {
	if fi, err := os.Stat(p); err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), yaraCheckWait)
	defer cancel()
	cmd := exec.CommandContext(ctx, p)
	cmd.Stdin = strings.NewReader(text)
	cmd.Env = []string{"PATH=/usr/bin", "LC_ALL=C"}
	var out limitedBuffer
	out.max = 1 << 20
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil || out.over {
		return nil, errors.New(NoYARAVerdict)
	}
	var v YARAVerdict
	dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
	if err := dec.Decode(&v); err != nil || v.Version == "" || (!v.OK && len(v.Errors) == 0) || (v.OK && len(v.Errors) > 0) {
		return nil, errors.New(NoYARAVerdict)
	}
	v.Errors, v.Warnings = clipItems(v.Errors), clipItems(v.Warnings)
	return &v, nil
}

// limitedBuffer keeps at most max bytes and notes that there was more.
type limitedBuffer struct {
	bytes.Buffer
	max  int
	over bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.max {
		b.over = true
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

// judgeRule is everything a draft goes through before it is kept: CheckRule (refuses), the lint's warnings, and YARA-X's
// verdict when the checker is installed (its errors refuse, its warnings are kept). The warnings come back even when
// YARA-X refuses, for `rule test` to show.
func (r Rules) judgeRule(text string) (string, []string, error) {
	name, warn, err := LintRule(text)
	if err != nil {
		return "", nil, err
	}
	v, verr := YARACheck(r.yaraCheckPath(), text)
	switch {
	case verr != nil:
		warn = append(warn, verr.Error())
	case v != nil:
		for _, w := range v.Warnings {
			warn = append(warn, "YARA-X: "+w)
		}
		if !v.OK {
			return name, warn, errors.New("YARA-X does not compile it: " + strings.Join(v.Errors, "; "))
		}
	}
	return name, warn, nil
}
