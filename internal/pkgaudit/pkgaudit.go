// Package pkgaudit says which installed packages have a known security vulnerability: it matches Arch Linux's security tracker
// (security.archlinux.org, downloaded by heimdall-intel-update as a file) against the versions in pacman's local database. Labyrinth
// is built on Arch packages, so the tracker covers it; a CachyOS rebuild of a fixed version (8.4.27-1.1 for 8.4.27-1) counts as fixed.
// Nothing is changed and nothing is sent: it reads two files and reports.
package pkgaudit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Group is one entry of the tracker (an "AVG"): packages, their status, and the CVEs.
type Group struct {
	Name     string   `json:"name"`
	Packages []string `json:"packages"`
	Status   string   `json:"status"` // Vulnerable (no fix yet), Fixed, Not affected, Unknown, Testing
	Severity string   `json:"severity"`
	Type     string   `json:"type"`
	Affected string   `json:"affected"`
	Fixed    string   `json:"fixed"`
	Issues   []string `json:"issues"`
}

// Finding is one installed package with one known vulnerability.
type Finding struct {
	Package, Installed string
	Group              Group
	NoFix              bool // the tracker has no fixed version yet
}

// Installed reads pacman's local database: package name to version (both the name and its base name, which the tracker sometimes uses).
func Installed(dbDir string) (map[string]string, error) {
	entries, err := os.ReadDir(dbDir)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		f, err := os.Open(filepath.Join(dbDir, e.Name(), "desc"))
		if err != nil {
			continue
		}
		var name, ver, base, field string
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			l := sc.Text()
			switch {
			case strings.HasPrefix(l, "%") && strings.HasSuffix(l, "%"):
				field = l
			case l == "":
				field = ""
			case field == "%NAME%":
				name = l
			case field == "%VERSION%":
				ver = l
			case field == "%BASE%":
				base = l
			}
		}
		f.Close()
		if name != "" && ver != "" {
			out[name] = ver
			if base != "" && base != name {
				if _, taken := out[base]; !taken {
					out["base:"+base] = ver
				}
			}
		}
	}
	return out, nil
}

// LoadTracker reads the tracker's all.json.
func LoadTracker(path string) ([]Group, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var g []Group
	if err := json.Unmarshal(b, &g); err != nil {
		return nil, fmt.Errorf("the security tracker file is not readable: %v", err)
	}
	return g, nil
}

// Check matches the tracker against the installed versions.
func Check(groups []Group, installed map[string]string) []Finding {
	var out []Finding
	for _, g := range groups {
		st := strings.ToLower(g.Status)
		if st == "not affected" || st == "fixed" && g.Fixed == "" {
			continue
		}
		for _, p := range g.Packages {
			ver, ok := installed[p]
			if !ok {
				ver, ok = installed["base:"+p]
			}
			if !ok {
				continue
			}
			switch {
			case g.Fixed != "" && Vercmp(ver, g.Fixed) < 0:
				out = append(out, Finding{Package: p, Installed: ver, Group: g})
			case g.Fixed == "" && st == "vulnerable" && g.Affected != "" && sameUpstream(ver, g.Affected):
				// no fix yet: only when this is the very version known to be affected. The tracker keeps old entries open for years
				// against versions long since replaced; reporting every newer version would be noise the owner learns to ignore.
				out = append(out, Finding{Package: p, Installed: ver, Group: g, NoFix: true})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if r1, r2 := rank(out[i].Group.Severity), rank(out[j].Group.Severity); r1 != r2 {
			return r1 > r2
		}
		return out[i].Package < out[j].Package
	})
	return out
}

// sameUpstream says whether two versions are the same release, ignoring the package release after the dash.
func sameUpstream(a, b string) bool {
	ea, va, _ := evr(a)
	eb, vb, _ := evr(b)
	return rpmvercmp(ea, eb) == 0 && rpmvercmp(va, vb) == 0
}

func rank(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// Key identifies a finding for "already reported".
func (f Finding) Key() string { return f.Group.Name + "|" + f.Package + "|" + f.Installed }
