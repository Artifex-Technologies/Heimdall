// Package toolrules is Heimdall's answer to a computer full of security tools (Niflheim OS): a scanner's thousand new
// destinations are what it is for, a password cracker that suddenly connects somewhere is not, and a scanner whose program
// file someone changed is exactly what an attacker would hide behind. The rules (tool-rules.json, docs/TOOL_RULES.md) are in
// force only where /etc/heimdall/security-tools exists.
//
// For each finding about a process (its event names the program file, "exe", or the script an interpreter runs, "script"):
//
//   - not a tool in the catalog: unchanged;
//   - a tool whose file differs from what its package installed: the finding stands, and a critical one says the tool was
//     changed (firm: no maintenance window softens it);
//   - started by an AI agent (Sarina): shown, at least as a warning, saying so: what an agent runs is never quiet;
//   - a tool that works offline, connecting: at least a warning;
//   - what the tool does (its "expects"), for its verified file: written as info, with the tool named; a "quiet" tool's new
//     destinations are summarised, one line per Quiet period with a count, instead of one alert each.
//
// Critical findings are never softened (a scanner touching an address on a threat list is still worth a look).
package toolrules

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

// MarkerPath turns the rules on (Niflheim's image ships it; Labyrinth's does not).
const MarkerPath = "/etc/heimdall/security-tools"

//go:embed tool-rules.json
var catalogJSON []byte

type Tool struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Packages []string `json:"packages"`
	Expects  []string `json:"expects"`
	Quiet    bool     `json:"quiet"`
	Offline  bool     `json:"offline"`
}

type Catalog struct {
	Tools []Tool `json:"tools"`
}

// Builtin is the catalog compiled into Heimdall.
func Builtin() (*Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(catalogJSON, &c); err != nil {
		return nil, fmt.Errorf("toolrules: the built-in catalog does not read: %w", err)
	}
	return &c, nil
}

// Owner answers which package installed a file and the SHA-256 it recorded (pkgverify.Verifier.Expected).
type Owner func(path string) (pkg, sha string, owned bool)

type Policy struct {
	byPackage map[string]*Tool
	owner     Owner
	// Quiet is how long a quiet tool's further new destinations are only counted.
	Quiet time.Duration
	now   func() time.Time
	hash  func(path string) (string, error)

	mu       sync.Mutex
	quietAt  map[string]time.Time
	held     map[string]int
	tampered map[string]time.Time
	hashes   map[string]cachedHash
}

type cachedHash struct {
	size  int64
	mtime time.Time
	sum   string
}

func New(c *Catalog, owner Owner) *Policy {
	p := &Policy{byPackage: map[string]*Tool{}, owner: owner, Quiet: 10 * time.Minute, now: time.Now,
		quietAt: map[string]time.Time{}, held: map[string]int{}, tampered: map[string]time.Time{}, hashes: map[string]cachedHash{}}
	p.hash = p.fileHash
	for i := range c.Tools {
		for _, pkg := range c.Tools[i].Packages {
			p.byPackage[pkg] = &c.Tools[i]
		}
	}
	return p
}

// Enabled reports whether this system asks for the rules.
func Enabled() bool {
	_, err := os.Stat(MarkerPath)
	return err == nil
}

// fileHash is the file's SHA-256, kept while its size and time stay the same (a tool's jar can be hundreds of megabytes).
func (p *Policy) fileHash(path string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	p.mu.Lock()
	c, ok := p.hashes[path]
	p.mu.Unlock()
	if ok && c.size == st.Size() && c.mtime.Equal(st.ModTime()) {
		return c.sum, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	p.mu.Lock()
	p.hashes[path] = cachedHash{st.Size(), st.ModTime(), sum}
	p.mu.Unlock()
	return sum, nil
}

func has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Apply returns what becomes of one finding (none, when a quiet tool's destination is only counted).
func (p *Policy) Apply(f detect.Finding) []detect.Finding {
	if p == nil || f.DetectorID == "tool-rules" {
		return []detect.Finding{f}
	}
	prog := f.Event.Fields["script"]
	if prog == "" {
		prog = f.Event.Fields["exe"]
	}
	if prog == "" || p.owner == nil {
		return []detect.Finding{f}
	}
	pkg, want, owned := p.owner(prog)
	t := p.byPackage[pkg]
	if !owned || t == nil {
		return []detect.Finding{f}
	}
	got, err := p.hash(prog)
	if err != nil || want == "" {
		// nothing to check it against (the file is gone, or the package records no digest): no rule applies
		return []detect.Finding{f}
	}
	if got != want {
		out := []detect.Finding{f}
		key := prog + "|" + got
		p.mu.Lock()
		last, seen := p.tampered[key]
		if !seen || p.now().Sub(last) >= time.Hour {
			p.tampered[key] = p.now()
			out = append(out, detect.Finding{DetectorID: "tool-rules", Severity: detect.SeverityCritical, Firm: true, Event: f.Event,
				Summary: fmt.Sprintf("%s's program %s is not what package %s installed (its SHA-256 differs): a changed security tool, "+
					"which an attacker could hide behind. Find out what changed it; reinstall with: sudo pacman -S %s", t.Name, prog, pkg, pkg)})
		}
		p.mu.Unlock()
		return out
	}
	if agent := f.Event.Fields["agent"]; agent != "" {
		if f.Severity == detect.SeverityInfo {
			f.Severity = detect.SeverityWarning
		}
		f.Summary = fmt.Sprintf("[%s started %s] %s", agent, t.Name, f.Summary)
		return []detect.Finding{f}
	}
	if t.Offline && f.DetectorID == "connection-watch" {
		if f.Severity == detect.SeverityInfo {
			f.Severity = detect.SeverityWarning
		}
		f.Summary = fmt.Sprintf("%s works offline, yet it made a connection: %s", t.Name, f.Summary)
		return []detect.Finding{f}
	}
	if !has(t.Expects, f.DetectorID) || f.Severity == detect.SeverityCritical {
		return []detect.Finding{f}
	}
	if t.Quiet && f.DetectorID == "connection-watch" {
		p.mu.Lock()
		last, seen := p.quietAt[t.ID]
		if seen && p.now().Sub(last) < p.Quiet {
			p.held[t.ID]++
			p.mu.Unlock()
			return nil
		}
		held := p.held[t.ID]
		p.quietAt[t.ID], p.held[t.ID] = p.now(), 0
		p.mu.Unlock()
		more := fmt.Sprintf("; its further new destinations are counted, not listed, for %d minutes", int(p.Quiet.Minutes()))
		if held > 0 {
			more = fmt.Sprintf("; %d more new destinations before this one%s", held, more)
		}
		f.Summary += more
	}
	f.Severity = detect.SeverityInfo
	f.Summary = fmt.Sprintf("[%s, a verified security tool] %s", t.Name, f.Summary)
	return []detect.Finding{f}
}
