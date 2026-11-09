package detect

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// The text detectors as they were before the literal prefilter (2026-11-09), kept to prove the prefilter changes nothing.

func oldInjectionInspect(d *InjectionDetector, e Event) []Finding {
	for _, pattern := range injectionPatterns {
		if match := pattern.FindString(e.Text); match != "" {
			return []Finding{{DetectorID: d.ID(), Severity: SeverityCritical,
				Summary: "text reads as an instruction override rather than task content (\"" + match + "\")", Event: e}}
		}
	}
	return nil
}

func oldCredentialInspect(d *CredentialDetector, e Event) []Finding {
	for _, pattern := range credentialPatterns {
		if pattern.MatchString(e.Text) {
			return []Finding{{DetectorID: d.ID(), Severity: SeverityCritical,
				Summary: "text contains what looks like a credential or secret", Event: e}}
		}
	}
	return nil
}

func oldRedactCredentials(text string) string {
	for _, pattern := range credentialPatterns {
		text = pattern.ReplaceAllStringFunc(text, func(m string) string {
			keep := 4
			if len(m) < keep {
				keep = len(m)
			}
			return m[:keep] + "…[redacted]"
		})
	}
	return text
}

func oldUnicodeInspect(d *UnicodeDetector, e Event) []Finding {
	for _, text := range []string{e.Text, decodeEscapes(e.Text)} {
		for _, r := range text {
			if invisibleCodepoints[r] || isBidiOverride(r) || isIsolate(r) || isTagBlock(r) || unicode.Is(unicode.Cf, r) {
				return []Finding{{DetectorID: d.ID(), Severity: SeverityWarning,
					Summary: fmt.Sprintf("text contains an invisible/formatting Unicode character (U+%04X)", r), Event: e}}
			}
		}
	}
	return nil
}

// Every rune whose case-insensitive class holds an ASCII letter must fold, in foldText, to that letter: otherwise a (?i)
// pattern could match text whose folded copy lacks the pattern's words, and the prefilter would hide a finding.
func TestFoldTextCoversEveryFoldOfAnASCIILetter(t *testing.T) {
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < utf8.RuneSelf && unicode.IsLetter(f) {
				if got, want := foldText(string(r)), string(unicode.ToLower(f)); got != want {
					t.Errorf("U+%04X folds to %q under (?i), foldText gives %q", r, f, got)
				}
			}
		}
	}
	// the other characters in the words (space, - _ :) match only themselves
	for _, set := range [][]literals{injectionLiterals, credentialLiterals} {
		for _, l := range set {
			for _, w := range l.any {
				for _, r := range w {
					if !unicode.IsLetter(r) && unicode.SimpleFold(r) != r {
						t.Errorf("%q: %q has case variants", w, r)
					}
					if l.folded && (r >= utf8.RuneSelf || unicode.IsUpper(r)) {
						t.Errorf("%q: a case-insensitive pattern's words must be lowercase ASCII", w)
					}
				}
			}
		}
	}
	if len(injectionLiterals) != len(injectionPatterns) || len(credentialLiterals) != len(credentialPatterns) {
		t.Fatal("every pattern needs its words, in the same order")
	}
	for i, p := range append(append([]*regexp.Regexp{}, injectionPatterns...), credentialPatterns...) {
		ci := strings.HasPrefix(p.String(), "(?i)")
		l := append(append([]literals{}, injectionLiterals...), credentialLiterals...)[i]
		if ci != l.folded {
			t.Errorf("%s: folded=%v", p, l.folded)
		}
	}
}

func TestNoASCIICharacterIsFlagged(t *testing.T) {
	for r := rune(0); r < utf8.RuneSelf; r++ {
		if invisibleCodepoints[r] || isBidiOverride(r) || isIsolate(r) || isTagBlock(r) || unicode.Is(unicode.Cf, r) {
			t.Errorf("U+%04X is flagged: the ASCII fast path in UnicodeDetector.inspect would skip it", r)
		}
	}
}

// gen writes a random string the regular expression re describes; (?i) letters get a random case variant (ſ and K too).
func gen(rng *rand.Rand, re *syntax.Regexp, b *strings.Builder) {
	switch re.Op {
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if re.Flags&syntax.FoldCase != 0 {
				orbit := []rune{r}
				for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
					orbit = append(orbit, f)
				}
				r = orbit[rng.Intn(len(orbit))]
			}
			b.WriteRune(r)
		}
	case syntax.OpCharClass:
		k := rng.Intn(len(re.Rune) / 2)
		lo, hi := re.Rune[2*k], re.Rune[2*k+1]
		if hi-lo > 200 {
			hi = lo + 200 // \S and similar: stay near the start of a wide range
		}
		b.WriteRune(lo + rune(rng.Intn(int(hi-lo)+1)))
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		b.WriteByte(byte('a' + rng.Intn(26)))
	case syntax.OpCapture:
		gen(rng, re.Sub[0], b)
	case syntax.OpConcat:
		for _, s := range re.Sub {
			gen(rng, s, b)
		}
	case syntax.OpAlternate:
		gen(rng, re.Sub[rng.Intn(len(re.Sub))], b)
	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat:
		lo, hi := 0, 3
		switch re.Op {
		case syntax.OpPlus:
			lo = 1
		case syntax.OpQuest:
			hi = 1
		case syntax.OpRepeat:
			lo, hi = re.Min, re.Max
			if hi < 0 {
				hi = lo + 6
			}
		}
		for n := lo + rng.Intn(hi-lo+1); n > 0; n-- {
			gen(rng, re.Sub[0], b)
		}
	}
}

// repoTexts is the repository's own files (the tests' fixtures among them), whole and line by line.
func repoTexts(t *testing.T) []string {
	root, _ := filepath.Abs(".")
	for _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil; _, err = os.Stat(filepath.Join(root, "go.mod")) {
		if root = filepath.Dir(root); root == "/" {
			t.Fatal("no go.mod above the test")
		}
	}
	var out []string
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if n := d.Name(); n == ".git" || n == ".claude" {
				return fs.SkipDir
			}
			return nil
		}
		if info, err := d.Info(); err != nil || !info.Mode().IsRegular() || info.Size() > 256<<10 {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		out = append(out, string(b))
		out = append(out, strings.Split(string(b), "\n")...)
		return nil
	})
	if len(out) < 1000 {
		t.Fatalf("only %d texts from the repository", len(out))
	}
	return out
}

var benignWords = strings.Fields(`the build finished and I checked the log file for errors; nothing stood out. Next step: run go test
	./... in the repo, then look at config.json around line 42. Notes for the team: the meeting moved. The user asked for a summary
	of the message thread. Please do not forget the key points. Secret Santa is on Friday. Password reset links expire.
	The bearer of this letter. task-based risk-assessment ghost_town npm install hf_hub eyJ`)

// hostileTexts are made-up attacks and near misses: every pattern's matches with random case (and ſ, K), set in benign
// text, JSON-escaped, with invisible characters, \u escapes, bidi and tag characters and broken UTF-8 mixed in.
func hostileTexts(rng *rand.Rand, perPattern int) []string {
	var out []string
	words := func(n int) string {
		w := make([]string, n)
		for i := range w {
			w[i] = benignWords[rng.Intn(len(benignWords))]
		}
		return strings.Join(w, " ")
	}
	oddities := []string{"\u200b", "\u200d", "\ufeff", "\u00ad", "\u202e", "\u2066", "\U000E0041", "\u0600", `\u200b`, `\u202E`,
		`\udb40\udc69`, `\ud83d\ude00`, `\u00e9`, `\uZZZZ`, `\u20`, "\xff", "\xc5", "\xe2\x84", "ſ", "K", "é", "İ", "ı", "ß", "\\", "\n", "\t"}
	for _, p := range append(append([]*regexp.Regexp{}, injectionPatterns...), credentialPatterns...) {
		re, err := syntax.Parse(p.String(), syntax.Perl)
		if err != nil {
			panic(err)
		}
		for i := 0; i < perPattern; i++ {
			var b strings.Builder
			gen(rng, re, &b)
			m := b.String()
			switch rng.Intn(6) {
			case 0:
				out = append(out, m)
			case 1:
				out = append(out, words(1+rng.Intn(20))+" "+m+" "+words(rng.Intn(20)))
			case 2: // glued to word characters (the \b cases)
				out = append(out, words(3)+"x"+m+"y"+words(2))
			case 3: // as Sarina stores a tool result: JSON inside a string
				j, _ := json.Marshal(map[string]string{"content": words(5) + "\n" + m})
				out = append(out, string(j))
			case 4: // an oddity inside or next to it
				k := rng.Intn(len(m) + 1)
				out = append(out, m[:k]+oddities[rng.Intn(len(oddities))]+m[k:])
			default:
				out = append(out, strings.ToUpper(words(4))+" "+m+"\n"+m)
			}
		}
	}
	for i := 0; i < 20*perPattern; i++ { // benign text with oddities and random capitals
		s := []byte(words(1 + rng.Intn(60)))
		for k := range s {
			if rng.Intn(5) == 0 && 'a' <= s[k] && s[k] <= 'z' {
				s[k] -= 'a' - 'A'
			}
		}
		for k := rng.Intn(4); k > 0; k-- { // at any byte, so a character may be cut in two as well
			at := rng.Intn(len(s) + 1)
			s = append(s[:at:at], append([]byte(oddities[rng.Intn(len(oddities))]), s[at:]...)...)
		}
		out = append(out, string(s))
	}
	return out
}

// The prefiltered detectors must give exactly the findings (and redactions) the old ones gave, on the repository's files and
// on made-up hostile text.
func TestPrefilteredDetectorsMatchTheOldOnes(t *testing.T) {
	rng := rand.New(rand.NewSource(20261109))
	per := 400
	if testing.Short() {
		per = 50
	}
	corpus := append(repoTexts(t), hostileTexts(rng, per)...)
	inj, cred, uni := NewInjectionDetector(), NewCredentialDetector(), NewUnicodeDetector()
	hits := map[string]int{}
	for _, text := range corpus {
		e := Event{Source: "agent-session", Kind: "message", Text: text, Fields: map[string]string{"role": "tool"}}
		for _, c := range []struct {
			id       string
			old, new []Finding
		}{
			{"injection", oldInjectionInspect(inj, e), inj.Inspect(e)},
			{"credential", oldCredentialInspect(cred, e), cred.Inspect(e)},
			{"unicode", oldUnicodeInspect(uni, e), uni.Inspect(e)},
		} {
			if !reflect.DeepEqual(c.old, c.new) {
				t.Fatalf("%s differs on %q:\nold %+v\nnew %+v", c.id, text, c.old, c.new)
			}
			if len(c.new) > 0 {
				hits[c.id]++
			}
		}
		if o, n := oldRedactCredentials(text), RedactCredentials(text); o != n {
			t.Fatalf("redaction differs on %q:\nold %q\nnew %q", text, o, n)
		}
	}
	// every pattern was exercised with texts it matches, including through ſ and K
	for _, set := range [][]*regexp.Regexp{injectionPatterns, credentialPatterns} {
		for _, p := range set {
			n := 0
			for _, text := range corpus {
				if p.MatchString(text) {
					n++
				}
			}
			if n < 20 {
				t.Errorf("only %d texts match %s", n, p)
			}
		}
	}
	folds := 0
	for _, text := range corpus {
		if strings.ContainsAny(text, "ſK") && len(inj.Inspect(Event{Text: text}))+len(cred.Inspect(Event{Text: text})) > 0 {
			folds++
		}
	}
	if folds < 20 {
		t.Errorf("only %d findings through ſ or K", folds)
	}
	t.Logf("%d texts; texts with findings: %v; through ſ or K: %d", len(corpus), hits, folds)
}

func benignText(n int) string {
	words := strings.Fields("the build finished and I checked the log file for errors; nothing stood out. Next step: run go test ./... in the repo, then look at config.json around line 42.")
	var sb strings.Builder
	for i := 0; sb.Len() < n; i++ {
		sb.WriteString(words[i%len(words)])
		sb.WriteByte(' ')
	}
	return sb.String()
}

// go test -run '^$' -bench TextDetectors ./internal/detect: the three detectors on benign text, before and after.
func BenchmarkTextDetectors(b *testing.B) {
	inj, cred, uni := NewInjectionDetector(), NewCredentialDetector(), NewUnicodeDetector()
	for _, n := range []int{200, 2000, 32000} {
		e := Event{Text: benignText(n)}
		b.Run(fmt.Sprintf("old/%dB", n), func(b *testing.B) {
			b.SetBytes(int64(len(e.Text)))
			for i := 0; i < b.N; i++ {
				oldInjectionInspect(inj, e)
				oldCredentialInspect(cred, e)
				oldUnicodeInspect(uni, e)
			}
		})
		b.Run(fmt.Sprintf("new/%dB", n), func(b *testing.B) {
			b.SetBytes(int64(len(e.Text)))
			for i := 0; i < b.N; i++ {
				inj.Inspect(e)
				cred.Inspect(e)
				uni.Inspect(e)
			}
		})
	}
	conn := "vivaldi-bin (pid 4242) connected to 203.0.113.9:443 (US, Example Net)"
	b.Run("old/redact-conn-alert", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			oldRedactCredentials(conn)
		}
	})
	b.Run("new/redact-conn-alert", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			RedactCredentials(conn)
		}
	})
}
