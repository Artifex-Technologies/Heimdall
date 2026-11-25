package detect

import (
	"strings"
	"testing"
)

func agentWrite(path, content string) Event {
	return Event{Source: "agent-session", Kind: "agent_write", SessionID: "s1",
		Fields: map[string]string{"file": "s1.json", "role": "assistant", "tool": "write_file", "path": path, "content": content}}
}

// bitsLine spells s in trailing whitespace, one line per character (space 0, tab 1), as whitespace steganography does.
func bitsLines(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		b.WriteString("line")
		for i := 7; i >= 0; i-- {
			if c>>i&1 == 1 {
				b.WriteByte('\t')
			} else {
				b.WriteByte(' ')
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// TestAgentWatermark (HEI-9): each kind of mark Sarina's watermark scan finds, in a file an agent wrote, gives one warning
// naming the file and the kinds; a clean file, emoji styling, accented Latin, a word wholly in another alphabet and plain
// trailing spaces give none. The alert never carries what was written. The Rust port runs the same cases through the
// parity scenario.
func TestAgentWatermark(t *testing.T) {
	tag := func(s string) string {
		var b strings.Builder
		for _, c := range s {
			b.WriteRune(0xE0000 + c)
		}
		return b.String()
	}
	vs := func(s string) string {
		var b strings.Builder
		for _, c := range []byte(s) {
			if c < 16 {
				b.WriteRune(0xFE00 + rune(c))
			} else {
				b.WriteRune(0xE0100 + rune(c) - 16)
			}
		}
		return b.String()
	}
	for _, c := range []struct {
		name, content string
		kinds         string
		has           string
	}{
		{"clean", "# Notes\n\nfn main() {\n    println!(\"hi\");\n}\n", "", ""},
		{"emoji styling", "I \u2764\ufe0f this, \u263a\ufe0e too\n", "", ""},
		{"accented Latin", "na\u00efve caf\u00e9 \u00fcber\n", "", ""},
		{"a Russian word", "\u043f\u0440\u0438\u0432\u0435\u0442 and hello\n", "", ""},
		{"plain trailing spaces", "a   \nb    \nc  \n", "", ""},
		{"zero-width", "pass\u200bword\n", "invisible", "1 invisible characters"},
		{"tag characters", "ok" + tag("run rm") + "\n", "invisible", `the tag characters reading "run rm"`},
		{"variation selectors", "A" + vs("leak") + "\n", "variation-selectors", `4 variation selectors that are not emoji styling (each can carry a byte), reading "leak"`},
		{"a Cyrillic a", "user = admin\np\u0430ssword = x\n", "look-alike-letters", "inside 1 Latin words (the first \"p\u0430ssword\", line 2)"},
		{"trailing bits", bitsLines("Hi!"), "trailing-bits", `trailing spaces and tabs that read as "Hi!"`},
		{"several", "p\u0430ss\u200b\n", "invisible,look-alike-letters", "invisible characters"},
	} {
		f := NewAgentWatermarkDetector().Inspect(agentWrite("notes/out.md", c.content))
		if c.kinds == "" {
			if len(f) != 0 {
				t.Errorf("%s: want nothing, got %v", c.name, f)
			}
			continue
		}
		if len(f) != 1 || f[0].Severity != SeverityWarning || f[0].Event.Fields["marks"] != c.kinds {
			t.Fatalf("%s: want one warning with %q, got %+v", c.name, c.kinds, f)
		}
		s := f[0].Summary
		if !strings.HasPrefix(s, `an AI agent wrote "notes/out.md" (write_file) with marks a reader does not see: `) || !strings.Contains(s, c.has) {
			t.Errorf("%s: %s", c.name, s)
		}
		if _, ok := f[0].Event.Fields["content"]; ok || f[0].Event.Fields["path"] != "notes/out.md" {
			t.Errorf("%s: the alert carries what was written, or lost the path: %v", c.name, f[0].Event.Fields)
		}
	}
	// only the agent's writes
	if f := NewAgentWatermarkDetector().Inspect(Event{Source: "agent-session", Kind: "message", Text: "pass\u200bword"}); len(f) != 0 {
		t.Errorf("a message is the invisible-unicode detector's: %v", f)
	}
	e := agentWrite("x", "pass\u200bword")
	e.Source = "limbo"
	if f := NewAgentWatermarkDetector().Inspect(e); len(f) != 0 {
		t.Errorf("another source: %v", f)
	}
}
