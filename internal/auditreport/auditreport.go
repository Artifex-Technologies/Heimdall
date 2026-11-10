// Package auditreport builds what GET /v1/audit answers: everything open now (known holes in the installed packages and
// kernels, hardening gaps), computed on each request from files already on the computer. It lives here, not in
// cmd/heimdalld, so the Rust port's fixtures (internal/parity) can call it with a made-up computer.
package auditreport

import (
	"sort"

	"github.com/Artifex-Technologies/Heimdall/internal/hardening"
	"github.com/Artifex-Technologies/Heimdall/internal/kernelaudit"
	"github.com/Artifex-Technologies/Heimdall/internal/pkgaudit"
)

// Package is one installed package with a known hole.
type Package struct {
	Package   string   `json:"package"`
	Installed string   `json:"installed"`
	Fixed     string   `json:"fixed,omitempty"`
	Severity  string   `json:"severity"`
	Advisory  string   `json:"advisory"`
	CVEs      []string `json:"cves"`
	Type      string   `json:"type"`
}

// Hole is one kernel CVE a newer kernel fixes.
type Hole struct {
	ID        string  `json:"id"`
	Score     float64 `json:"score,omitempty"`
	FixedIn   string  `json:"fixed_in"`
	SameLine  bool    `json:"same_line"`
	Exploited bool    `json:"exploited,omitempty"`
	Summary   string  `json:"summary"`
}

// Kernel is one installed kernel's holes.
type Kernel struct {
	Kernel   string `json:"kernel"`
	Running  bool   `json:"running"`
	Count    int    `json:"count"`
	FixAll   string `json:"fixed_all_in,omitempty"`
	Worst    []Hole `json:"worst"` // exploited first, then by score; at most 15
	ListDate string `json:"list_date"`
}

// Report is the whole answer.
type Report struct {
	Packages  []Package       `json:"packages"`
	Kernels   []Kernel        `json:"kernels"`
	Hardening []hardening.Gap `json:"hardening"`
	Missing   []string        `json:"missing,omitempty"` // lists not downloaded yet
}

// Computer is where the report reads: the tracker, pacman's database, the kernel CVE list, the modules folder, the running
// kernel's name and the hardening checks' root.
type Computer struct {
	Tracker, PacmanDB, KernelVulns, Modules, Running string
	System                                           hardening.System
}

// Build computes the report.
func Build(c Computer) Report {
	var r Report
	if groups, err := pkgaudit.LoadTracker(c.Tracker); err != nil {
		r.Missing = append(r.Missing, "the package security tracker")
	} else if inst, err := pkgaudit.Installed(c.PacmanDB); err == nil {
		for _, f := range pkgaudit.Check(groups, inst) {
			fixed := f.Group.Fixed
			if f.NoFix {
				fixed = ""
			}
			r.Packages = append(r.Packages, Package{f.Package, f.Installed, fixed, f.Group.Severity, f.Group.Name, f.Group.Issues, f.Group.Type})
		}
	}
	if list, err := kernelaudit.Load(c.KernelVulns); err != nil {
		r.Missing = append(r.Missing, "the kernel CVE list")
	} else {
		for _, k := range kernelaudit.Installed(c.Modules) {
			holes, fix := kernelaudit.Check(list, k)
			ak := Kernel{Kernel: k, Running: k == c.Running, Count: len(holes), FixAll: fix, ListDate: list.Generated.Format("2006-01-02")}
			for i, h := range holes {
				if i == 15 {
					break
				}
				ak.Worst = append(ak.Worst, Hole{h.ID, h.Score, h.FixedIn, h.SameLine, h.Exploited, h.Summary})
			}
			r.Kernels = append(r.Kernels, ak)
		}
		sort.Slice(r.Kernels, func(i, j int) bool { return r.Kernels[i].Running && !r.Kernels[j].Running })
	}
	r.Hardening = c.System.Check()
	return r
}
