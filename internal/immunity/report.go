package immunity

import (
	"bytes"
	"debug/elf"
	"math"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Report is what a sample is and contains, read and parsed only (never run): enough for the owner, and for Sarina, to judge it.
// Everything in it comes from the sample, so it is evidence, never an instruction.
type Report struct {
	Entropy float64  `json:"entropy"` // bits per byte: near 8 means packed or encrypted
	Head    string   `json:"head,omitempty"`
	Strings []string `json:"strings,omitempty"` // the telling ones first: addresses, paths, commands
	ELF     *ELFInfo `json:"elf,omitempty"`
}

// ELFInfo is the header of a Linux program.
type ELFInfo struct {
	Class    string   `json:"class"`
	Machine  string   `json:"machine"`
	Type     string   `json:"type"`
	Interp   string   `json:"interp,omitempty"`
	Needed   []string `json:"needed,omitempty"`
	Stripped bool     `json:"stripped"`
	Static   bool     `json:"static"`
}

var telling = regexp.MustCompile(`(?i)(https?://|ftp://|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|/bin/|/tmp/|/dev/|/etc/|\.ssh|passwd|shadow|curl|wget|nc |bash|chmod|base64|crontab|systemctl|sudo|LD_PRELOAD|ptrace|mmap|socket|connect|exec)`)

// MakeReport reads the bytes of a sample.
func MakeReport(b []byte, kind string) *Report {
	r := &Report{Entropy: entropy(b)}
	if kind == "Text" || kind == "Script" {
		h := b
		if len(h) > 2048 {
			h = h[:2048]
		}
		r.Head = strings.ToValidUTF8(string(h), "?")
	}
	if kind == "Elf" {
		if f, err := elf.NewFile(bytes.NewReader(b)); err == nil {
			info := &ELFInfo{Class: f.Class.String(), Machine: f.Machine.String(), Type: f.Type.String()}
			for _, p := range f.Progs {
				if p.Type == elf.PT_INTERP {
					buf := make([]byte, min(p.Filesz, 256))
					if _, err := p.ReadAt(buf, 0); err == nil {
						info.Interp = strings.TrimRight(string(buf), "\x00")
					}
				}
			}
			info.Static = info.Interp == ""
			info.Needed, _ = f.ImportedLibraries()
			_, err := f.Symbols()
			info.Stripped = err != nil
			f.Close()
			r.ELF = info
		}
	}
	r.Strings = pickStrings(b, 40)
	return r
}

func entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var n [256]float64
	for _, c := range b {
		n[c]++
	}
	e := 0.0
	for _, c := range n {
		if c > 0 {
			p := c / float64(len(b))
			e -= p * math.Log2(p)
		}
	}
	return math.Round(e*100) / 100
}

// pickStrings finds printable runs of 6 or more characters, the telling ones first, at most max, each at most 160 characters.
func pickStrings(b []byte, max int) []string {
	var all []string
	seen := map[string]bool{}
	start := -1
	flush := func(end int) {
		if start >= 0 && end-start >= 6 {
			s := string(b[start:end])
			if len(s) > 160 {
				s = s[:160]
			}
			if utf8.ValidString(s) && !seen[s] && len(seen) < 5000 {
				seen[s] = true
				all = append(all, s)
			}
		}
		start = -1
	}
	for i, c := range b {
		if c >= 0x20 && c < 0x7f || c == '\t' {
			if start < 0 {
				start = i
			}
		} else {
			flush(i)
		}
	}
	flush(len(b))
	sort.SliceStable(all, func(i, j int) bool { return telling.MatchString(all[i]) && !telling.MatchString(all[j]) })
	if len(all) > max {
		all = all[:max]
	}
	return all
}
