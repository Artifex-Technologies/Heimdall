package immunity

// The lint of a rule draft (docs/IMMUNITY.md, "Rules", R4 of the reference plan): before a draft is kept, the parts of YARA
// that ClamAV does not load are refused (hard errors), and what makes a rule slow, noisy or hard to trace is noted
// (warnings, kept with the draft and shown by `rule test`). The ClamAV limits were tried on ClamAV 1.5 with a one-rule
// database (clamscan -d) and match its manual: no modules, global rules, xor/base64/private string modifiers, ~ or comments
// in hex strings, regular expression flags, string operators or match lengths (!a) in conditions; at least one string, at most 64; every string at
// least 2 bytes, a hex string with 2 fixed bytes in a row in each part between jumps; every string used by the condition.
//
// The Rust daemon has the same lint (rust/heimdall/src/rulelint.rs); testdata/parity/rulelint.json holds the answers both
// must give (go test ./internal/immunity -run TestRuleLintFixtures -update).

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	lintSectionRx = regexp.MustCompile(`\b(meta|strings|condition)[\t\n\v\f\r ]*:`)
	lintMetaKeyRx = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)[\t\n\v\f\r ]*=`)
	lintStringRx  = regexp.MustCompile(`\$([A-Za-z0-9_]*)[\t\n\v\f\r ]*=[\t\n\v\f\r ]*`)
	lintWordRx    = regexp.MustCompile(`[A-Za-z0-9_]+`)
	lintOpRx      = regexp.MustCompile(`\b(contains|icontains|startswith|istartswith|endswith|iendswith|iequals|matches)\b`)
	lintAttackRx  = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)
	lintThemRx    = regexp.MustCompile(`\bthem\b`)
	lintFilesize  = regexp.MustCompile(`\bfilesize\b`)
	lintSetRx     = regexp.MustCompile(`\$([A-Za-z0-9_]*)\*`)
	lintLengthRx  = regexp.MustCompile(`![A-Za-z0-9_]`)
)

// lintCommon are strings found in most programs, documents and web pages (compared without case): alone they match far
// too much, and YARA-X's atoms for them are poor.
var lintCommon = []string{
	"mz", "pe", "elf", "\x7felf", "pk", "pk\x03\x04", "%pdf", "this program cannot be run in dos mode",
	"this program must be run under win32", "kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll", "msvcrt.dll",
	"getprocaddress", "loadlibrarya", "loadlibraryw", "virtualalloc", "http://", "https://", "www.", ".com", "/bin/sh",
	"/bin/bash", "/tmp/", "#!/bin/sh", "#!/bin/bash", "#!/usr/bin/env", "<script", "<html", "<?php", "libc.so.6",
	"glibc_2.2.5", ".text", ".data", ".rdata", ".rodata", ".bss", "microsoft", "windows", "cmd.exe", "powershell",
}

// lintString is one string of the strings: section, as the lint sees it.
type lintString struct {
	name      string // "$a", or "$" for an anonymous one
	kind      byte   // 't' text, 'h' hex, 'r' regular expression
	fixed     []byte // text: its bytes; hex: its bytes when it has no wildcard, jump or alternative
	longest   int    // the longest run of fixed bytes
	partShort bool   // hex: a part between jumps without 2 fixed bytes in a row
	not       bool   // hex: a ~
	comment   bool   // hex: a comment inside (ClamAV's parser refuses it)
	wild      int    // wildcard bytes and the most a jump or regular expression may skip
	unbounded bool   // an open jump ([n-], [-]) or a regular expression's * or +
	mods      []string
	flags     string // a regular expression's flags (/i, /s)
}

// lintMask blanks a rule's comments and the insides of its text strings and regular expressions, keeping every byte
// where it was: keywords are then looked for in what is left, and the values read from the same places in the original.
// It returns the masked text and where each literal starts and ends (start: its opening quote or slash; end: just after
// its closing one).
func lintMask(text string) (string, map[int]int) {
	m := []byte(text)
	lits := map[int]int{}
	n := len(text)
	prev := byte(0) // the last byte that was not a space or a comment
	for i := 0; i < n; {
		c := text[i]
		switch {
		case c == '/' && i+1 < n && text[i+1] == '/':
			for ; i < n && text[i] != '\n'; i++ {
				m[i] = ' '
			}
		case c == '/' && i+1 < n && text[i+1] == '*':
			end := n
			if j := strings.Index(text[i+2:], "*/"); j >= 0 {
				end = i + 2 + j + 2
			}
			for ; i < end; i++ {
				if m[i] != '\n' {
					m[i] = ' '
				}
			}
		case c == '"' || (c == '/' && prev == '='):
			j := i + 1
			for j < n && text[j] != c {
				if text[j] == '\\' {
					j++
				}
				j++
			}
			end := j + 1
			if end > n {
				end = n
			}
			for k := i + 1; k < end-1; k++ {
				m[k] = 'x'
			}
			lits[i] = end
			prev = c
			i = end
		default:
			if !lintSpace(c) {
				prev = c
			}
			i++
		}
	}
	return string(m), lits
}

func lintSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'
}

// lintUnescape is a text string's bytes: \xHH is one byte, a backslash and any other byte is that byte.
func lintUnescape(s string) []byte {
	var b []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			if s[i+1] == 'x' && i+3 < len(s) && lintHexDigit(s[i+2]) && lintHexDigit(s[i+3]) {
				v, _ := strconv.ParseUint(s[i+2:i+4], 16, 8)
				b = append(b, byte(v))
				i += 3
				continue
			}
			i++
		}
		b = append(b, s[i])
	}
	return b
}

// lintNum is a jump's or a repeat's bound: digits only, at most 1 MiB (anything else counts as 0).
func lintNum(s string) int {
	if s == "" || strings.Trim(s, "0123456789") != "" {
		return 0
	}
	if len(s) > 7 {
		return 1 << 20
	}
	n, _ := strconv.Atoi(s)
	if n > 1<<20 {
		return 1 << 20
	}
	return n
}

// lintLower is ASCII lower case, byte for byte (a rule's bytes need not be UTF-8).
func lintLower(b []byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}

func lintHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// lintHex reads a hex string's inside: fixed bytes, ?? and nibble wildcards, [n], [n-m], [n-], [-] jumps, ( | )
// alternatives, ~. Anything else ends a run of fixed bytes and is left to YARA-X and ClamAV to judge.
func lintHex(s string, ls *lintString) {
	run, part, partMax, plain := 0, 0, 0, true
	var fixed []byte
	endRun := func() {
		if run > ls.longest {
			ls.longest = run
		}
		if run > partMax {
			partMax = run
		}
		run = 0
	}
	endPart := func() {
		endRun()
		if part > 0 && partMax < 2 {
			ls.partShort = true
		}
		part, partMax = 0, 0
	}
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case lintSpace(c):
			i++
		case c == '[':
			j := strings.IndexByte(s[i:], ']')
			if j < 0 {
				j = len(s) - i
			}
			in := strings.Trim(s[i+1:i+j], " \t\n\v\f\r")
			lo, hi, dash := in, "", strings.Contains(in, "-")
			if dash {
				k := strings.IndexByte(in, '-')
				lo, hi = strings.Trim(in[:k], " \t\n\v\f\r"), strings.Trim(in[k+1:], " \t\n\v\f\r")
			}
			switch {
			case dash && hi == "":
				ls.unbounded = true
			case dash:
				ls.wild += lintNum(hi)
			default:
				ls.wild += lintNum(lo)
			}
			plain = false
			endPart()
			i += j + 1
		case c == '(' || c == '|' || c == ')':
			plain = false
			endRun()
			i++
		case c == '~':
			ls.not = true
			plain = false
			endRun()
			i++
		case i+1 < len(s) && lintHexDigit(c) && lintHexDigit(s[i+1]):
			v, _ := strconv.ParseUint(s[i:i+2], 16, 8)
			fixed = append(fixed, byte(v))
			run++
			part++
			i += 2
		case i+1 < len(s) && (c == '?' || lintHexDigit(c)) && (s[i+1] == '?' || lintHexDigit(s[i+1])):
			ls.wild++
			plain = false
			part++
			endRun()
			i += 2
		default:
			plain = false
			endRun()
			i++
		}
	}
	endPart()
	if plain {
		ls.fixed = fixed
	}
}

// lintRegexp reads a regular expression's inside: its longest run of plain characters (a character followed by *, ? or
// {0 is optional and not counted), the dots it may skip, and whether it is open-ended (* or +, or {n,}).
func lintRegexp(s string, ls *lintString) {
	run := 0
	endRun := func() {
		if run > ls.longest {
			ls.longest = run
		}
		run = 0
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			i++
			if strings.IndexByte(`\/.+*?()[]{}|^$-`, s[i]) >= 0 {
				run++
			} else {
				endRun()
			}
		case c == '[':
			endRun()
			for i++; i < len(s) && s[i] != ']'; i++ {
				if s[i] == '\\' {
					i++
				}
			}
		case c == '*' || c == '+':
			if c == '*' && run > 0 {
				run--
			}
			endRun()
			ls.unbounded = true
		case c == '?':
			if run > 0 {
				run--
			}
			endRun()
		case c == '{':
			j := strings.IndexByte(s[i:], '}')
			if j < 0 {
				endRun()
				continue
			}
			in := s[i+1 : i+j]
			if strings.HasPrefix(in, "0") && run > 0 {
				run--
			}
			endRun()
			if strings.HasSuffix(in, ",") {
				ls.unbounded = true
			} else if k := strings.LastIndexByte(in, ','); k >= 0 {
				ls.wild += lintNum(in[k+1:])
			}
			i += j
		case c == '.':
			endRun()
			ls.wild++
		case strings.IndexByte(`()|^$`, c) >= 0:
			endRun()
		default:
			run++
		}
	}
	endRun()
}

// lintSection is where each section's inside starts and ends in the masked text (-1 when absent).
type lintSection struct{ start, end int }

func lintSections(masked string) map[string]lintSection {
	end := strings.LastIndexByte(masked, '}')
	if end < 0 {
		end = len(masked)
	}
	secs := map[string]lintSection{}
	ms := lintSectionRx.FindAllStringSubmatchIndex(masked, -1)
	for i, m := range ms {
		e := end
		if i+1 < len(ms) && ms[i+1][0] < e {
			e = ms[i+1][0]
		}
		if m[1] > e {
			e = m[1]
		}
		secs[masked[m[2]:m[3]]] = lintSection{m[1], e}
	}
	return secs
}

// lintStrings reads the strings: section.
func lintStrings(text, masked string, lits map[int]int, sec lintSection) []lintString {
	body := masked[sec.start:sec.end]
	locs := lintStringRx.FindAllStringSubmatchIndex(body, -1)
	var out []lintString
	for i, m := range locs {
		next := len(body)
		if i+1 < len(locs) {
			next = locs[i+1][0]
		}
		ls := lintString{name: "$" + body[m[2]:m[3]]}
		at := sec.start + m[1] // the value's first byte
		stop := sec.start + next
		rest := at
		if at < len(text) {
			switch text[at] {
			case '"':
				ls.kind = 't'
				end := lits[at]
				if end == 0 {
					end = at + 1
				}
				if end-1 > at {
					ls.fixed = lintUnescape(text[at+1 : end-1])
				}
				ls.longest = len(ls.fixed)
				rest = end
			case '/':
				ls.kind = 'r'
				end := lits[at]
				if end == 0 {
					end = at + 1
				}
				if end-1 > at {
					lintRegexp(text[at+1:end-1], &ls)
				}
				rest = end
				for rest < stop && ((text[rest] >= 'a' && text[rest] <= 'z') || (text[rest] >= 'A' && text[rest] <= 'Z')) {
					rest++
				}
				ls.flags = text[end:rest]
			case '{':
				ls.kind = 'h'
				end := strings.IndexByte(masked[at:stop], '}')
				if end < 0 {
					end = stop - at // no closing brace: to the section's end
				}
				lintHex(masked[at+1:at+end], &ls)
				ls.comment = masked[at:at+end] != text[at:at+end]
				rest = at + end + 1
			}
		}
		if rest < stop {
			ls.mods = lintWordRx.FindAllString(masked[rest:stop], -1)
		}
		out = append(out, ls)
	}
	return out
}

// lintUsed reports whether the condition uses a string: by name ($a, #a, @a, !a), by a $prefix* set, or all of them.
func lintUsed(cond, name string) bool {
	if lintThemRx.MatchString(cond) {
		return true
	}
	id := name[1:]
	if id != "" {
		for _, p := range []string{"$", "#", "@", "!"} {
			if regexp.MustCompile(regexp.QuoteMeta(p+id) + `($|[^A-Za-z0-9_*])`).MatchString(cond) {
				return true
			}
		}
	}
	for _, m := range lintSetRx.FindAllStringSubmatch(cond, -1) {
		if strings.HasPrefix(id, m[1]) {
			return true
		}
	}
	return false
}

// lintRule is the lint of a rule that passed CheckRule's form checks: the first hard error ("" for none) and the warnings.
func lintRule(text string) (string, []string) {
	masked, lits := lintMask(text)
	if h := ruleNameRx.FindString(masked); h != "" {
		if strings.Contains(h, "global") {
			return "ClamAV does not support global rules", nil
		}
		if strings.Contains(h, "private") {
			return "a private rule never reports a match in ClamAV: drop \"private\"", nil
		}
	}
	secs := lintSections(masked)
	sec, ok := secs["strings"]
	var strs []lintString
	if ok {
		strs = lintStrings(text, masked, lits, sec)
	}
	if len(strs) == 0 {
		return "ClamAV loads only a rule with strings: add a strings: section", nil
	}
	if len(strs) > 64 {
		return "at most 64 strings in a rule (ClamAV's limit)", nil
	}
	cond := ""
	if c, ok := secs["condition"]; ok {
		cond = masked[c.start:c.end]
	}
	for _, s := range strs {
		for _, m := range s.mods {
			if m == "xor" || m == "base64" || m == "base64wide" || m == "private" {
				return fmt.Sprintf("%s: ClamAV does not support the %s modifier", s.name, m), nil
			}
		}
		switch s.kind {
		case 't':
			if len(s.fixed) < 2 {
				return s.name + ": ClamAV needs at least 2 bytes", nil
			}
		case 'h':
			if s.comment {
				return s.name + ": ClamAV does not accept comments inside a hex string", nil
			}
			if s.not {
				return s.name + ": ClamAV does not accept ~ (not) in a hex string", nil
			}
			if s.longest < 2 || s.partShort {
				return s.name + ": ClamAV needs 2 fixed bytes in a row in a hex string, and in each part between jumps", nil
			}
		case 'r':
			if s.flags != "" {
				return s.name + ": ClamAV ignores regular expression flags (/i, /s): spell the cases out, e.g. [Dd]", nil
			}
		}
		if !lintUsed(cond, s.name) {
			return s.name + " is not used by the condition (ClamAV refuses the rule)", nil
		}
	}
	if m := lintOpRx.FindStringSubmatch(cond); m != nil {
		return fmt.Sprintf("ClamAV does not support %q in a condition", m[1]), nil
	}
	if lintLengthRx.MatchString(cond) {
		return "ClamAV does not support match lengths (!a) in a condition", nil
	}

	var warn, wild []string
	for _, s := range strs {
		low := lintLower(s.fixed)
		common := false
		for _, c := range lintCommon {
			common = common || (s.fixed != nil && low == c)
		}
		repeated := len(s.fixed) >= 2 && strings.Count(string(s.fixed), string(s.fixed[:1])) == len(s.fixed)
		switch {
		case s.longest < 4:
			warn = append(warn, s.name+": shorter than 4 fixed bytes in a row: slow to search for (YARA-X calls it a slow pattern) and likely to match by chance")
		case repeated:
			warn = append(warn, s.name+" is one byte repeated: common in ordinary files")
		case common:
			warn = append(warn, s.name+" is very common in ordinary programs and documents: pair it with a rarer string")
		}
		if s.unbounded || s.wild >= 16 {
			wild = append(wild, s.name)
		}
	}
	if len(wild) > 0 && !lintFilesize.MatchString(cond) {
		warn = append(warn, strings.Join(wild, ", ")+": many wildcards or jumps and no filesize in the condition: bound it, e.g. filesize < 2MB")
	}
	keys := map[string]int{} // a meta key and where its value starts
	if m, ok := secs["meta"]; ok {
		for _, k := range lintMetaKeyRx.FindAllStringSubmatchIndex(masked[m.start:m.end], -1) {
			v := m.start + k[1]
			for v < len(masked) && lintSpace(masked[v]) {
				v++
			}
			keys[masked[m.start+k[2]:m.start+k[3]]] = v
		}
	}
	for _, k := range []struct{ key, why string }{{"sample_sha256", " (the held sample it was made from)"}, {"author", ""}, {"date", " (YYYY-MM-DD)"}} {
		if _, ok := keys[k.key]; !ok {
			warn = append(warn, "meta: "+k.key+" is missing"+k.why)
		}
	}
	if at, ok := keys["attack"]; ok {
		good := false
		if end := lits[at]; end > at+1 && text[at] == '"' {
			ids := strings.FieldsFunc(text[at+1:end-1], func(r rune) bool { return r == ',' || r == ' ' })
			good = len(ids) > 0
			for _, id := range ids {
				good = good && lintAttackRx.MatchString(id)
			}
		}
		if !good {
			warn = append(warn, "meta: attack is not a list of ATT&CK technique IDs (T1059 or T1059.004, comma-separated)")
		}
	}
	return "", warn
}

// LintRule is CheckRule and the lint's warnings: the rule's name, what to tell the drafter, and the first reason the
// draft is refused.
func LintRule(text string) (string, []string, error) {
	name, err := CheckRule(text)
	if err != nil {
		return "", nil, err
	}
	_, warn := lintRule(text)
	return name, warn, nil
}
