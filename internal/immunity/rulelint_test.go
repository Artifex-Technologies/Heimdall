package immunity

// The lint's answers, and the fixture the Rust daemon must match (rust/heimdall/tests/rulelint.rs): go test
// ./internal/immunity -run TestRuleLintFixtures -update writes testdata/parity/rulelint.json; without -update the file must
// be current (CI).

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var updateLint = flag.Bool("update", false, "rewrite testdata/parity/rulelint.json")

// lintMeta is meta that satisfies the lint.
const lintMeta = "  meta:\n    sample_sha256 = \"" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" + "\"\n    author = \"Sarina\"\n    date = \"2026-11-18\"\n"

// lintR is a rule with the lint's meta, the given strings and condition.
func lintR(strs, cond string) string {
	return "rule Heimdall_lint\n{\n" + lintMeta + "  strings:\n" + strs + "  condition:\n    " + cond + "\n}\n"
}

var lintCases = []struct{ name, text string }{
	{"clean", lintR("    $a = \"send ~/.ssh/id_ed25519 to\"\n", "$a")},
	{"the old good rule (no sample, author or date)", goodRule},
	{"no meta at all", "rule Heimdall_x { strings: $a = \"dropper-payload\" condition: $a }"},
	{"attack ids", strings.Replace(lintR("    $a = \"dropper-payload\"\n", "$a"), "  strings:", "    attack = \"T1059.004, T1105\"\n  strings:", 1)},
	{"attack not ids", strings.Replace(lintR("    $a = \"dropper-payload\"\n", "$a"), "  strings:", "    attack = \"command line\"\n  strings:", 1)},
	{"attack a number", strings.Replace(lintR("    $a = \"dropper-payload\"\n", "$a"), "  strings:", "    attack = 1059\n  strings:", 1)},
	{"global", "global rule Heimdall_x { strings: $a = \"dropper\" condition: $a }"},
	{"private", "private rule Heimdall_x { strings: $a = \"dropper\" condition: $a }"},
	{"no strings", "rule Heimdall_x { condition: true }"},
	{"empty strings", "rule Heimdall_x { strings: condition: true }"},
	{"65 strings", func() string {
		var b strings.Builder
		for i := 0; i < 65; i++ {
			b.WriteString("    $s" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + " = \"dropper-payload\"\n")
		}
		return lintR(b.String(), "any of them")
	}()},
	{"64 strings", func() string {
		var b strings.Builder
		for i := 0; i < 64; i++ {
			b.WriteString("    $s" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + " = \"dropper-payload\"\n")
		}
		return lintR(b.String(), "any of them")
	}()},
	{"xor", lintR("    $a = \"dropper-payload\" xor\n", "$a")},
	{"xor range", lintR("    $a = \"dropper-payload\" xor(0x01-0xff)\n", "$a")},
	{"base64", lintR("    $a = \"dropper-payload\" base64\n", "$a")},
	{"base64wide", lintR("    $a = \"dropper-payload\" base64wide\n", "$a")},
	{"private string", lintR("    $a = \"dropper-payload\" private\n", "$a")},
	{"nocase wide ascii fullword", lintR("    $a = \"dropper-payload\" nocase wide ascii fullword\n", "$a")},
	{"one byte", lintR("    $a = \"d\"\n", "$a")},
	{"one escaped byte", lintR("    $a = \"\\x41\"\n", "$a")},
	{"two bytes", lintR("    $a = \"dr\"\n", "$a")},
	{"three bytes escaped", lintR("    $a = \"\\x00\\\"z\"\n", "$a")},
	{"empty text", lintR("    $a = \"\"\n", "$a")},
	{"bad escape", lintR("    $a = \"\\x+f\\xzz-dropper\"\n", "$a")},
	{"repeated byte", lintR("    $a = \"\\x00\\x00\\x00\\x00\\x00\"\n", "$a")},
	{"spaces", lintR("    $a = \"        \"\n", "$a")},
	{"common MZ", lintR("    $a = \"MZ\"\n    $b = \"dropper-payload\"\n", "$a and $b")},
	{"common text", lintR("    $a = \"This program cannot be run in DOS mode\"\n", "$a")},
	{"common nocase", lintR("    $a = \"KERNEL32.DLL\"\n", "$a")},
	{"common hex", lintR("    $a = { 7F 45 4C 46 }\n", "$a")},
	{"hex fine", lintR("    $a = { 64 72 6F 70 70 65 72 }\n", "$a")},
	{"hex one byte", lintR("    $a = { 64 }\n", "$a")},
	{"hex one byte and a wildcard", lintR("    $a = { 64 ?? }\n", "$a")},
	{"hex wildcard between", lintR("    $a = { 64 ?? 6F 70 70 65 }\n", "$a")},
	{"hex one byte between jumps", lintR("    $a = { 64 [1-4] 70 70 65 72 }\n", "$a")},
	{"hex jumps fine", lintR("    $a = { 64 72 6F [2-10] 70 61 79 6C }\n", "$a")},
	{"hex open jump", lintR("    $a = { 64 72 6F 70 [2-] 70 61 79 6C }\n", "$a")},
	{"hex open jump and filesize", lintR("    $a = { 64 72 6F 70 [-] 70 61 79 6C }\n", "$a and filesize < 2MB")},
	{"hex many wildcards", lintR("    $a = { 64 72 6F 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 42 }\n", "$a")},
	{"hex big jump", lintR("    $a = { 64 72 6F 70 [0-300] 70 61 79 6C }\n", "$a")},
	{"hex huge jump", lintR("    $a = { 64 72 6F 70 [0-99999999999] 70 61 79 6C }\n", "$a")},
	{"hex nibbles", lintR("    $a = { 64 7? 6F 70 70 65 72 }\n", "$a")},
	{"hex alternatives", lintR("    $a = { 64 72 6F 70 ( 6F 70 | 41 41 ) 70 65 72 }\n", "$a")},
	{"hex not", lintR("    $a = { 64 72 ~41 70 70 }\n", "$a")},
	{"hex comment inside", lintR("    $a = { 64 72 /* ?? */ 6F 70 // ~\n 70 65 }\n", "$a")},
	{"hex lower case", lintR("    $a = { de ad be ef }\n", "$a")},
	{"regex fine", lintR("    $a = /dropper-pay[a-z]{1,8}load/\n", "$a")},
	{"regex short", lintR("    $a = /dr[a-z]+p/\n", "$a")},
	{"regex flags", lintR("    $a = /dropper-payload/i\n", "$a")},
	{"regex flags s and modifier", lintR("    $a = /dropper.payload/s wide\n", "$a")},
	{"regex escapes", lintR("    $a = /\\/tmp\\/\\.x\\d{1,4}/\n", "$a")},
	{"regex optional letters", lintR("    $a = /drx?y*z{0,2}/\n", "$a")},
	{"regex dots", lintR("    $a = /drop.{1,8}load/\n", "$a")},
	{"regex open repeat", lintR("    $a = /drop.{3,}load/\n", "$a")},
	{"regex comment-like", lintR("    $a = /http:\\/\\/evil/\n", "$a")},
	{"unused string", lintR("    $a = \"dropper-payload\"\n    $b = \"second-string\"\n", "$a")},
	{"used by count", lintR("    $a = \"dropper-payload\"\n", "#a > 2")},
	{"used by offset", lintR("    $a = \"dropper-payload\"\n", "@a[1] < 100")},
	{"used by length", lintR("    $a = \"dropper-payload\"\n", "!a[1] == 15")},
	{"used by a set", lintR("    $s1 = \"dropper-payload\"\n    $s2 = \"second-string\"\n", "any of ($s*)")},
	{"a set that does not cover", lintR("    $s1 = \"dropper-payload\"\n    $t2 = \"second-string\"\n", "any of ($s*)")},
	{"them", lintR("    $a = \"dropper-payload\"\n    $b = \"second-string\"\n", "all of them")},
	{"a longer name is not the name", lintR("    $a = \"dropper-payload\"\n    $ab = \"second-string\"\n", "$ab")},
	{"anonymous strings", lintR("    $ = \"dropper-payload\"\n    $ = \"second-string\"\n", "all of them")},
	{"anonymous unused", lintR("    $ = \"dropper-payload\"\n", "true")},
	{"contains", lintR("    $a = \"dropper-payload\"\n", "$a and \"abc\" contains \"b\"")},
	{"matches", lintR("    $a = \"dropper-payload\"\n", "$a and \"abc\" matches /b/")},
	{"iequals", lintR("    $a = \"dropper-payload\"\n", "$a and \"abc\" iequals \"ABC\"")},
	{"operator only in a string", lintR("    $a = \"contains matches\"\n", "$a")},
	{"commented-out string", lintR("    $a = \"dropper-payload\"\n    // $b = \"x\"\n    /* $c = \"y\" */\n", "$a")},
	{"a comment in a string", lintR("    $a = \"drop//per /* x */\"\n", "$a")},
	{"quote in a string", lintR("    $a = \"say \\\"strings: hi\\\"\"\n", "$a")},
	{"strings word in meta", strings.Replace(lintR("    $a = \"dropper-payload\"\n", "$a"), "    date", "    note = \"strings: condition:\"\n    date", 1)},
	{"tags and modifiers", "rule Heimdall_t : tag1 tag2\n{\n" + lintMeta + "  strings:\n    $a = \"dropper-payload\" ascii\n  condition:\n    $a at 0\n}\n"},
	{"one line", "rule Heimdall_x { meta: sample_sha256 = \"x\" author = \"me\" date = \"2026-11-18\" strings: $a = \"dropper-payload\" condition: $a }"},
	{"unterminated string", "rule Heimdall_x { strings: $a = \"dropper condition: $a }"},
	{"unterminated hex", "rule Heimdall_x { strings: $a = { 64 72 condition: $a }"},
	{"hex open at the end", "rule Heimdall_x { strings: $a = {"},
	{"hex open before the brace", "rule Heimdall_x { strings: $a = { 41 42 43 44 condition: $a"},
	{"value missing", "rule Heimdall_x { strings: $a = condition: $a }"},
	{"nothing after the string's name", "rule Heimdall_x { strings: $a ="},
	{"regex open", "rule Heimdall_x { strings: $a = /abc"},
	{"unterminated comment", "rule Heimdall_x { strings: $a = \"dropper-payload\" condition: $a } /* "},
	{"several warnings", "rule Heimdall_w {\n strings:\n  $a = \"ab\"\n  $b = { 00 00 00 00 }\n  $c = \"http://\"\n  $d = /x.*y/\n condition:\n  any of them\n}\n"},
	{"utf-8 in a string", lintR("    $a = \"größe-ñandú\"\n", "$a")},
	{"meta key only", strings.Replace(lintR("    $a = \"dropper-payload\"\n", "$a"), "    author = \"Sarina\"\n", "    author =\n", 1)},
}

// lintAnswer is what the fixture keeps for one case.
type lintAnswer struct {
	Name     string   `json:"name"`
	Text     string   `json:"text"`
	Rule     string   `json:"rule"`
	Error    string   `json:"error"`
	Warnings []string `json:"warnings"`
}

func lintAnswers() []lintAnswer {
	var out []lintAnswer
	for _, c := range lintCases {
		a := lintAnswer{Name: c.name, Text: c.text, Warnings: []string{}}
		name, warn, err := LintRule(c.text)
		a.Rule = name
		if err != nil {
			a.Error = err.Error()
		}
		a.Warnings = append(a.Warnings, warn...)
		out = append(out, a)
	}
	return out
}

func TestRuleLint(t *testing.T) {
	byName := map[string]lintAnswer{}
	for _, a := range lintAnswers() {
		byName[a.Name] = a
	}
	refused := func(name, want string) {
		t.Helper()
		if a := byName[name]; !strings.Contains(a.Error, want) {
			t.Errorf("%s: error %q, want %q", name, a.Error, want)
		}
	}
	warned := func(name, want string) {
		t.Helper()
		a := byName[name]
		if a.Error != "" || !strings.Contains(strings.Join(a.Warnings, "\n"), want) {
			t.Errorf("%s: error %q, warnings %q, want a warning %q", name, a.Error, a.Warnings, want)
		}
	}
	clean := func(name string) {
		t.Helper()
		if a := byName[name]; a.Error != "" || len(a.Warnings) != 0 {
			t.Errorf("%s: should be clean: %q %q", name, a.Error, a.Warnings)
		}
	}
	for _, n := range []string{"clean", "attack ids", "64 strings", "nocase wide ascii fullword", "hex fine", "hex jumps fine",
		"hex open jump and filesize", "hex nibbles", "hex alternatives", "hex lower case", "regex fine",
		"regex escapes", "regex dots", "regex comment-like", "used by count", "used by offset", "used by a set",
		"them", "anonymous strings", "operator only in a string", "commented-out string",
		"a comment in a string", "quote in a string", "strings word in meta", "tags and modifiers", "one line", "utf-8 in a string",
		"hex wildcard between"} {
		clean(n)
	}
	refused("global", "global rules")
	refused("private", "private rule")
	refused("no strings", "with strings")
	refused("empty strings", "with strings")
	refused("65 strings", "at most 64")
	for _, n := range []string{"xor", "xor range", "base64", "base64wide", "private string"} {
		refused(n, "modifier")
	}
	refused("one byte", "at least 2 bytes")
	refused("one escaped byte", "at least 2 bytes")
	refused("empty text", "at least 2 bytes")
	refused("hex one byte", "2 fixed bytes")
	refused("hex one byte and a wildcard", "2 fixed bytes")
	refused("hex one byte between jumps", "2 fixed bytes")
	refused("hex not", "~ (not)")
	refused("hex comment inside", "comments inside a hex string")
	refused("used by length", "match lengths")
	refused("regex flags", "flags")
	refused("regex flags s and modifier", "flags")
	refused("unused string", "$b is not used")
	refused("a set that does not cover", "$t2 is not used")
	refused("anonymous unused", "$ is not used")
	refused("a longer name is not the name", "$a is not used")
	refused("contains", `"contains"`)
	refused("matches", `"matches"`)
	refused("iequals", `"iequals"`)
	refused("unterminated string", "")
	warned("two bytes", "$a: shorter than 4")
	warned("three bytes escaped", "$a: shorter than 4")
	warned("repeated byte", "one byte repeated")
	warned("spaces", "one byte repeated")
	warned("common MZ", "$a: shorter than 4")
	warned("common text", "very common")
	warned("common nocase", "very common")
	warned("common hex", "very common")
	warned("hex open jump", "many wildcards")
	warned("hex many wildcards", "many wildcards")
	warned("hex big jump", "many wildcards")
	warned("hex huge jump", "many wildcards")
	warned("regex short", "shorter than 4")
	warned("regex optional letters", "shorter than 4")
	warned("regex open repeat", "many wildcards")
	warned("the old good rule (no sample, author or date)", "meta: sample_sha256 is missing")
	warned("no meta at all", "meta: date is missing")
	warned("attack not ids", "meta: attack")
	warned("attack a number", "meta: attack")
	if a := byName["several warnings"]; len(a.Warnings) != 8 {
		t.Errorf("several warnings: %q", a.Warnings)
	}
}

func TestRuleLintFixtures(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("{\"format\": \"heimdall-rulelint/1\", \"from\": \"internal/immunity (go test ./internal/immunity -run TestRuleLintFixtures -update)\", \"cases\": [\n")
	as := lintAnswers()
	for i, a := range as {
		j, _ := json.Marshal(a)
		b.Write(j)
		if i < len(as)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("]}\n")
	path, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "parity", "rulelint.json"))
	if *updateLint {
		if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	old, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/immunity -run TestRuleLintFixtures -update)", err)
	}
	if !bytes.Equal(old, b.Bytes()) {
		t.Error("testdata/parity/rulelint.json is out of date: run go test ./internal/immunity -run TestRuleLintFixtures -update and review the diff")
	}
}

// Every beginning of every case (a draft cut anywhere) is judged without a panic.
func TestRuleLintNeverPanicsOnACutDraft(t *testing.T) {
	for _, c := range lintCases {
		for i := 0; i <= len(c.text); i++ {
			lintRule(c.text[:i])
		}
	}
}
