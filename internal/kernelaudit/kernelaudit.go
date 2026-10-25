// Package kernelaudit says which installed Linux kernels have known vulnerabilities that a newer kernel fixes. Arch's security
// tracker (package pkgaudit) does not follow the kernel's CVEs, and not CachyOS's kernel packages at all, so this uses the Linux
// kernel's own CVE records as osv.dev publishes them (the "Linux" ecosystem: each CVE with the version ranges it affects on every
// stable line). heimdall-intel-update downloads the archive weekly; "heimdalld intel-check kernel" turns it into a small file
// (Compact), and the daemon compares it with the kernels in /usr/lib/modules. Nothing is sent anywhere.
//
// Only holes with a fix are reported: the kernel's CVE team files a CVE for nearly every fixed bug, so the useful question is
// "does an update close something", and the answer names the version that closes all of them.
package kernelaudit

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Range is one affected stretch: introduced <= v < fixed.
type Range struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed,omitempty"`
}

// Vuln is one kernel CVE.
type Vuln struct {
	ID      string  `json:"id"`
	Summary string  `json:"summary"`
	Score   float64 `json:"score,omitempty"` // CVSS 3.x base score; 0 = not scored
	Vector  string  `json:"vector,omitempty"`
	Ranges  []Range `json:"ranges"`
	// Exploited: on CISA's list of vulnerabilities known to be exploited in the wild.
	Exploited bool `json:"exploited,omitempty"`
}

// File is the compact list the daemon reads.
type File struct {
	Generated time.Time `json:"generated"`
	Source    string    `json:"source"`
	Vulns     []Vuln    `json:"vulns"`
}

type osvRecord struct {
	ID       string `json:"id"`
	Summary  string `json:"summary"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string              `json:"type"`
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// Exploited reads CISA's Known Exploited Vulnerabilities catalog (its JSON feed): the CVE ids, any product.
func Exploited(path string) (map[string]bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var k struct {
		Vulnerabilities []struct {
			CveID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(b, &k); err != nil {
		return nil, err
	}
	if len(k.Vulnerabilities) < 100 {
		return nil, fmt.Errorf("only %d entries: not the catalog", len(k.Vulnerabilities))
	}
	out := map[string]bool{}
	for _, v := range k.Vulnerabilities {
		out[v.CveID] = true
	}
	return out, nil
}

// Compact reads osv.dev's Linux archive (all.zip) and keeps, per CVE, the version ranges of the kernel itself and the CVSS score;
// exploited (may be nil) marks the ones known to be exploited.
func Compact(zipPath string, exploited map[string]bool) (*File, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	out := &File{Generated: time.Now().UTC().Truncate(time.Second), Source: "osv.dev, Linux ecosystem (the kernel CVE team's records)"}
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".json") || f.UncompressedSize64 > 8<<20 {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		var r osvRecord
		err = json.NewDecoder(io.LimitReader(rc, 8<<20)).Decode(&r)
		rc.Close()
		if err != nil || r.ID == "" {
			continue
		}
		v := Vuln{ID: r.ID, Summary: oneLine(r.Summary, 200), Exploited: exploited[r.ID]}
		for _, s := range r.Severity {
			if strings.HasPrefix(s.Type, "CVSS_V3") {
				if sc, ok := CVSS3(s.Score); ok {
					v.Score, v.Vector = sc, s.Score
				}
			}
		}
		for _, a := range r.Affected {
			if a.Package.Ecosystem != "Linux" || a.Package.Name != "Kernel" {
				continue
			}
			for _, rg := range a.Ranges {
				if rg.Type != "ECOSYSTEM" {
					continue
				}
				var cur Range
				for _, ev := range rg.Events {
					if x, ok := ev["introduced"]; ok {
						cur = Range{Introduced: x}
					}
					if x, ok := ev["fixed"]; ok {
						cur.Fixed = x
						v.Ranges = append(v.Ranges, cur)
						cur = Range{}
					}
				}
				if cur.Introduced != "" {
					v.Ranges = append(v.Ranges, cur) // open: not fixed on that line yet
				}
			}
		}
		if len(v.Ranges) > 0 {
			out.Vulns = append(out.Vulns, v)
		}
	}
	if len(out.Vulns) < 1000 {
		return nil, fmt.Errorf("only %d kernel records: not the full archive", len(out.Vulns))
	}
	sort.Slice(out.Vulns, func(i, j int) bool { return out.Vulns[i].ID < out.Vulns[j].ID })
	return out, nil
}

// Load reads the compact file.
func Load(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		s = s[:n] + "…"
	}
	return s
}

// Version is a kernel version as numbers (7.3.0-4-cachyos -> [7 3 0]).
func Version(s string) []int {
	s, _, _ = strings.Cut(s, "-")
	var out []int
	for _, p := range strings.Split(s, ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			break
		}
		out = append(out, n)
	}
	for len(out) < 3 {
		out = append(out, 0)
	}
	return out
}

// Compare orders two versions.
func Compare(a, b []int) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		x, y := 0, 0
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// Hole is one CVE that affects a kernel and has a fixed version.
type Hole struct {
	Vuln
	FixedIn string
	// SameLine: the fix is on the kernel's own line (6.18.x for 6.18.55), so an update of that kernel package closes it; otherwise
	// it was fixed only in newer lines (not backported, or not yet).
	SameLine bool
}

// Line is a kernel's stable line (6.18 for 6.18.55).
func Line(v []int) [2]int { return [2]int{v[0], v[1]} }

// Check lists the holes of one kernel version that a newer kernel fixes, worst first (exploited ones before the rest), and the
// version that fixes all of them.
func Check(f *File, kernel string) (holes []Hole, fixAll string) {
	k := Version(kernel)
	var best []int
	for _, v := range f.Vulns {
		if fixedOnLine(v, k) {
			continue
		}
		for _, r := range v.Ranges {
			if r.Fixed == "" || Compare(k, Version(r.Introduced)) < 0 || Compare(k, Version(r.Fixed)) >= 0 {
				continue
			}
			holes = append(holes, Hole{Vuln: v, FixedIn: r.Fixed, SameLine: Line(Version(r.Fixed)) == Line(k)})
			if fx := Version(r.Fixed); best == nil || Compare(fx, best) > 0 {
				best, fixAll = fx, r.Fixed
			}
			break
		}
	}
	sort.SliceStable(holes, func(i, j int) bool {
		if holes[i].Exploited != holes[j].Exploited {
			return holes[i].Exploited
		}
		if holes[i].Score != holes[j].Score {
			return holes[i].Score > holes[j].Score
		}
		return holes[i].ID > holes[j].ID
	})
	return holes, fixAll
}

// fixedOnLine: the fix reached the kernel's own line at or before its version. The records' ranges overlap (a range starting on an
// older line can end on a newer one), so a fix on the kernel's own line settles it whatever the other ranges say.
func fixedOnLine(v Vuln, k []int) bool {
	for _, r := range v.Ranges {
		if r.Fixed != "" && Line(Version(r.Fixed)) == Line(k) && Compare(k, Version(r.Fixed)) >= 0 {
			return true
		}
	}
	return false
}

// Installed lists the kernels in a modules folder (/usr/lib/modules): the folders with a kernel image.
func Installed(modulesDir string) []string {
	ents, _ := os.ReadDir(modulesDir)
	var out []string
	for _, e := range ents {
		if _, err := os.Stat(filepath.Join(modulesDir, e.Name(), "vmlinuz")); err == nil {
			out = append(out, e.Name())
		}
	}
	return out
}

// CVSS3 computes a CVSS 3.0/3.1 base score from its vector.
func CVSS3(vector string) (float64, bool) {
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/") {
		if k, v, ok := strings.Cut(part, ":"); ok {
			m[k] = v
		}
	}
	changed := m["S"] == "C"
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}[m["PR"]]
	if changed && m["PR"] == "L" {
		pr = 0.68
	} else if changed && m["PR"] == "H" {
		pr = 0.5
	}
	ui := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	c, okC := cia[m["C"]]
	i, okI := cia[m["I"]]
	a, okA := cia[m["A"]]
	if av == 0 || ac == 0 || pr == 0 || ui == 0 || !okC || !okI || !okA || (m["S"] != "U" && m["S"] != "C") {
		return 0, false
	}
	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, true
	}
	expl := 8.22 * av * ac * pr * ui
	if changed {
		return roundup(math.Min(1.08*(impact+expl), 10)), true
	}
	return roundup(math.Min(impact+expl, 10)), true
}

func roundup(x float64) float64 {
	n := int64(math.Round(x * 100000))
	if n%10000 == 0 {
		return float64(n) / 100000
	}
	return float64(n/10000+1) / 10
}
