package main

import (
	"sort"

	"github.com/Artifex-Technologies/Heimdall/internal/config"
	"github.com/Artifex-Technologies/Heimdall/internal/hardening"
	"github.com/Artifex-Technologies/Heimdall/internal/kernelaudit"
	"github.com/Artifex-Technologies/Heimdall/internal/pkgaudit"
)

type auditPackage struct {
	Package   string   `json:"package"`
	Installed string   `json:"installed"`
	Fixed     string   `json:"fixed,omitempty"`
	Severity  string   `json:"severity"`
	Advisory  string   `json:"advisory"`
	CVEs      []string `json:"cves"`
	Type      string   `json:"type"`
}

type auditHole struct {
	ID        string  `json:"id"`
	Score     float64 `json:"score,omitempty"`
	FixedIn   string  `json:"fixed_in"`
	SameLine  bool    `json:"same_line"`
	Exploited bool    `json:"exploited,omitempty"`
	Summary   string  `json:"summary"`
}

type auditKernel struct {
	Kernel   string      `json:"kernel"`
	Running  bool        `json:"running"`
	Count    int         `json:"count"`
	FixAll   string      `json:"fixed_all_in,omitempty"`
	Worst    []auditHole `json:"worst"` // exploited first, then by score; at most 15
	ListDate string      `json:"list_date"`
}

type auditReport struct {
	Packages  []auditPackage  `json:"packages"`
	Kernels   []auditKernel   `json:"kernels"`
	Hardening []hardening.Gap `json:"hardening"`
	Missing   []string        `json:"missing,omitempty"` // lists not downloaded yet
}

// audit is what GET /v1/audit answers: everything open now.
func audit(cfg config.Config) any {
	var r auditReport
	if groups, err := pkgaudit.LoadTracker(cfg.SecurityTracker); err != nil {
		r.Missing = append(r.Missing, "the package security tracker")
	} else if inst, err := pkgaudit.Installed(cfg.PacmanDB); err == nil {
		for _, f := range pkgaudit.Check(groups, inst) {
			fixed := f.Group.Fixed
			if f.NoFix {
				fixed = ""
			}
			r.Packages = append(r.Packages, auditPackage{f.Package, f.Installed, fixed, f.Group.Severity, f.Group.Name, f.Group.Issues, f.Group.Type})
		}
	}
	if list, err := kernelaudit.Load(cfg.KernelVulns); err != nil {
		r.Missing = append(r.Missing, "the kernel CVE list")
	} else {
		run := kernelaudit.Running()
		for _, k := range kernelaudit.Installed("/usr/lib/modules") {
			holes, fix := kernelaudit.Check(list, k)
			ak := auditKernel{Kernel: k, Running: k == run, Count: len(holes), FixAll: fix, ListDate: list.Generated.Format("2006-01-02")}
			for i, h := range holes {
				if i == 15 {
					break
				}
				ak.Worst = append(ak.Worst, auditHole{h.ID, h.Score, h.FixedIn, h.SameLine, h.Exploited, h.Summary})
			}
			r.Kernels = append(r.Kernels, ak)
		}
		sort.Slice(r.Kernels, func(i, j int) bool { return r.Kernels[i].Running && !r.Kernels[j].Running })
	}
	r.Hardening = hardening.System{}.Check()
	return r
}
