package parity

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
	"github.com/Artifex-Technologies/Heimdall/internal/gametime"
	"github.com/Artifex-Technologies/Heimdall/internal/hardening"
	"github.com/Artifex-Technologies/Heimdall/internal/kernelaudit"
	"github.com/Artifex-Technologies/Heimdall/internal/pkgaudit"
)

// Audits is the fixture of the 6-hourly audits (testdata/parity/audits.json): pacman's version comparison, CVSS scores,
// kernel versions, the package, kernel and hardening watchers over file trees step by step (events and state files), and
// the game-time tool's answers. The Go table tests of internal/pkgaudit, kernelaudit, hardening and gametime are in it,
// with generated cases besides.
type Audits struct {
	Format        string          `json:"format"`
	Vercmp        []VercmpCase    `json:"vercmp"`
	CVSS          []CVSSCase      `json:"cvss"`
	KernelVersion []KVCase        `json:"kernel_version"`
	Packages      []AuditScenario `json:"packages"`
	Kernels       []AuditScenario `json:"kernels"`
	Hardening     []AuditScenario `json:"hardening"`
	Gametime      []GameCase      `json:"gametime"`
}

type VercmpCase struct {
	A   string `json:"a"`
	B   string `json:"b"`
	Out int    `json:"out"`
}

type CVSSCase struct {
	Vector string  `json:"vector"`
	Score  float64 `json:"score"`
	OK     bool    `json:"ok"`
}

type KVCase struct {
	In  string `json:"in"`
	Out []int  `json:"out"`
}

// AuditScenario: a watcher polled once per step, each step over the file tree it names (written fresh into a temporary
// folder; the state file stays between steps).
type AuditScenario struct {
	Name    string      `json:"name"`
	Running string      `json:"running,omitempty"` // kernels: the running kernel
	NonRoot bool        `json:"non_root,omitempty"`
	Steps   []AuditStep `json:"steps"`
}

type AuditStep struct {
	Files  map[string]FileSpec `json:"files"`
	Events []EventOut          `json:"events"`
	State  string              `json:"state"`
	// Error: the poll's error ($TMP for the folder), NotExist: Go's os.IsNotExist of it.
	Error    string `json:"error,omitempty"`
	NotExist bool   `json:"not_exist,omitempty"`
}

type FileSpec struct {
	Content string `json:"content"`
	Mode    uint32 `json:"mode,omitempty"` // 0: 0644
}

type EventOut struct {
	Source string            `json:"source"`
	Kind   string            `json:"kind"`
	Text   string            `json:"text"`
	Fields map[string]string `json:"fields"`
}

type GameCase struct {
	Stdout  []byte `json:"stdout"`
	Exit    int    `json:"exit"`
	Playing bool   `json:"playing"`
	Reason  string `json:"reason"`
}

func writeTree(dir string, files map[string]FileSpec) error {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		f := files[n]
		p := filepath.Join(dir, n)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		mode := os.FileMode(f.Mode)
		if mode == 0 {
			mode = 0o644
		}
		if err := os.WriteFile(p, []byte(f.Content), 0o644); err != nil {
			return err
		}
		if err := os.Chmod(p, mode); err != nil {
			return err
		}
	}
	return nil
}

func events(evs []detect.Event) []EventOut {
	out := []EventOut{}
	for _, e := range evs {
		out = append(out, EventOut{e.Source, e.Kind, e.Text, e.Fields})
	}
	return out
}

// RunAudit runs one scenario's steps through the Go watchers in dir; kind is "packages", "kernels" or "hardening".
func RunAudit(kind string, s AuditScenario, dir string) ([]AuditStep, error) {
	state := filepath.Join(dir, "state.json")
	var out []AuditStep
	var prev map[string]FileSpec
	for i, st := range s.Steps {
		tree := filepath.Join(dir, fmt.Sprintf("step%d", i))
		files := st.Files
		if files == nil { // a step without files looks at the previous step's tree again
			files = prev
		}
		prev = files
		if err := writeTree(tree, files); err != nil {
			return nil, err
		}
		var evs []detect.Event
		var err error
		switch kind {
		case "packages":
			w := &pkgaudit.Watcher{TrackerPath: filepath.Join(tree, "tracker.json"), PacmanDB: filepath.Join(tree, "db"), StatePath: state}
			evs, err = w.Poll()
		case "kernels":
			w := &kernelaudit.Watcher{ListPath: filepath.Join(tree, "list.json"), ModulesDir: filepath.Join(tree, "modules"), StatePath: state, Running: s.Running}
			evs, err = w.Poll()
		case "hardening":
			w := &hardening.Watcher{Sys: hardening.System{Root: tree}, StatePath: state}
			evs = w.Poll()
		}
		got := AuditStep{Files: st.Files, Events: events(evs)}
		if err != nil {
			got.Error = strings.ReplaceAll(err.Error(), dir, "$TMP")
			got.NotExist = os.IsNotExist(err)
		}
		b, _ := os.ReadFile(state)
		got.State = string(b)
		out = append(out, got)
		_ = filepath.Walk(tree, func(p string, _ os.FileInfo, _ error) error { _ = os.Chmod(p, 0o755); return nil })
	}
	return out, nil
}

func desc(name, ver, base string) FileSpec {
	d := "%NAME%\n" + name + "\n\n%VERSION%\n" + ver + "\n\n"
	if base != "" {
		d += "%BASE%\n" + base + "\n\n"
	}
	return FileSpec{Content: d}
}

func pkgdb(pkgs map[string][2]string) map[string]FileSpec {
	files := map[string]FileSpec{}
	for name, vb := range pkgs {
		files["db/"+name+"-"+vb[0]+"/desc"] = desc(name, vb[0], vb[1])
	}
	return files
}

func with(files map[string]FileSpec, path, content string) map[string]FileSpec {
	out := map[string]FileSpec{}
	for k, v := range files {
		out[k] = v
	}
	out[path] = FileSpec{Content: content}
	return out
}

func trackerJSON(groups []pkgaudit.Group) string {
	b, _ := json.Marshal(groups)
	return string(b)
}

func randVersion(r *rand.Rand) string {
	parts := []string{"0", "1", "2", "9", "10", "01", "a", "b", "rc", "alpha", "beta", "git", "20260817", "", "001"}
	seps := []string{".", ".", ".", "-", "_", "+", "~", ":", ".."}
	var b strings.Builder
	if r.Intn(8) == 0 {
		b.WriteString(fmt.Sprint(r.Intn(3)) + ":")
	}
	n := 1 + r.Intn(5)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(seps[r.Intn(len(seps))])
		}
		b.WriteString(parts[r.Intn(len(parts))])
	}
	if r.Intn(2) == 0 {
		b.WriteString("-" + fmt.Sprint(1+r.Intn(3)))
		if r.Intn(3) == 0 {
			b.WriteString("." + fmt.Sprint(r.Intn(3)))
		}
	}
	return b.String()
}

// AllAudits computes the fixture with the Go code.
func AllAudits(tmp func() string) (Audits, error) {
	a := Audits{Format: "heimdall-parity-audits/1"}
	r := rand.New(rand.NewSource(11))

	// pacman's vercmp: the Go test's pairs (checked against pacman there) and generated ones
	pairs := [][2]string{
		{"1.0", "1.0"}, {"1.0", "1.1"}, {"1.0.0", "1.0"}, {"1.0a", "1.0"}, {"1.0alpha", "1.0"}, {"1.0", "1.0.a"}, {"1.0.a", "1.0.1"},
		{"8.4.27-1", "8.4.27-1.1"}, {"8.4.26-2.1", "8.4.27-1"}, {"1:1.0-1", "2.0-1"}, {"2.0-1", "1:1.0"}, {"1.0-1", "1.0-2"}, {"1.0-1", "1.0"},
		{"9.0.1224-1", "9.0.1225-1"}, {"1.0rc1", "1.0"}, {"1.0", "1.0+git"}, {"20260817.0-2.1", "20260817.0-2"}, {"1.001", "1.1"},
		{"1.0_beta", "1.0.beta"}, {"a", "b"}, {"1..0", "1.0"}, {"2.4.0-1.1", "2.4.0-1"}, {"6.1.2-1", "6.10-1"},
		{"", ""}, {"", "1"}, {":1", "1"}, {"x:1", "1"}, {"1-", "1"}, {"-1", "1"}, {"é1", "1"},
	}
	for i := 0; i < 3000; i++ {
		pairs = append(pairs, [2]string{randVersion(r), randVersion(r)})
	}
	for _, p := range pairs {
		a.Vercmp = append(a.Vercmp, VercmpCase{p[0], p[1], pkgaudit.Vercmp(p[0], p[1])})
	}

	// CVSS 3: every combination of the base metrics, the Go test's vectors and broken ones
	vecs := []string{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", "", "CVSS:3.1/AV:X/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H",
		"CVSS:3.1/AV:N/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
	for _, av := range "NALP" {
		for _, ac := range "LH" {
			for _, pr := range "NLH" {
				for _, ui := range "NR" {
					for _, s := range "UC" {
						for _, c := range "HLN" {
							for _, i := range "HLN" {
								for _, av2 := range "HLN" {
									vecs = append(vecs, fmt.Sprintf("CVSS:3.1/AV:%c/AC:%c/PR:%c/UI:%c/S:%c/C:%c/I:%c/A:%c", av, ac, pr, ui, s, c, i, av2))
								}
							}
						}
					}
				}
			}
		}
	}
	for _, v := range vecs {
		sc, ok := kernelaudit.CVSS3(v)
		a.CVSS = append(a.CVSS, CVSSCase{v, sc, ok})
	}

	for _, k := range []string{"7.3.0-4-cachyos", "6.18.55-2-cachyos-lts", "6.18", "6", "", "6.x.1", "+6.-1.2", "6.18.99999999999999999999", "07.03.0", "6.18.1.2.3-rc", "6.18-rc1.2"} {
		a.KernelVersion = append(a.KernelVersion, KVCase{k, kernelaudit.Version(k)})
	}

	// packages: TestInstalledPackagesAreMatchedWithPacmanVersions, as a watcher
	db1 := pkgdb(map[string][2]string{"php": {"8.4.26-1.1", ""}, "vim": {"9.1.0-1", ""}, "openssl": {"3.5.4-1.1", ""},
		"libfoo": {"1.0-1.1", ""}, "libold": {"2.0-1", ""}, "linux-api": {"6.0-1", "linux-headers-src"}})
	groups1 := []pkgaudit.Group{
		{Name: "AVG-2909", Packages: []string{"php"}, Status: "Fixed", Severity: "Critical", Fixed: "8.4.27-1", Issues: []string{"CVE-2026-109618"}},
		{Name: "AVG-1", Packages: []string{"vim"}, Status: "Fixed", Severity: "High", Fixed: "9.0.1225-1"},
		{Name: "AVG-2", Packages: []string{"openssl"}, Status: "Fixed", Severity: "High", Fixed: "3.5.4-1"},
		{Name: "AVG-3", Packages: []string{"libfoo"}, Status: "Vulnerable", Severity: "Medium", Affected: "1.0-1"},
		{Name: "AVG-7", Packages: []string{"libold"}, Status: "Vulnerable", Severity: "High", Affected: "1.2-1"},
		{Name: "AVG-4", Packages: []string{"notinstalled"}, Status: "Vulnerable", Severity: "Critical"},
		{Name: "AVG-5", Packages: []string{"linux-headers-src"}, Status: "Fixed", Severity: "Low", Fixed: "6.1-1"},
		{Name: "AVG-6", Packages: []string{"php"}, Status: "Not affected", Severity: "High", Fixed: "9.0-1"},
	}
	t1 := with(db1, "tracker.json", trackerJSON(groups1))
	a.Packages = append(a.Packages, AuditScenario{Name: "pkgaudit: TestInstalledPackagesAreMatchedWithPacmanVersions", Steps: []AuditStep{{Files: t1}, {}}})
	// TestEachFindingIsReportedOnceUntilTheVersionChanges
	tr := `[{"name":"AVG-2909","packages":["php"],"status":"Fixed","severity":"Critical","fixed":"8.4.27-1","issues":["CVE-2026-109618","CVE-2026-109619"]}]`
	a.Packages = append(a.Packages, AuditScenario{Name: "pkgaudit: TestEachFindingIsReportedOnceUntilTheVersionChanges", Steps: []AuditStep{
		{Files: with(pkgdb(map[string][2]string{"php": {"8.4.26-1", ""}}), "tracker.json", tr)},
		{Files: with(pkgdb(map[string][2]string{"php": {"8.4.26-1", ""}}), "tracker.json", tr)},
		{Files: with(pkgdb(map[string][2]string{"php": {"8.4.27-1.1", ""}}), "tracker.json", tr)},
		{Files: with(pkgdb(map[string][2]string{"php": {"8.4.26-2", ""}}), "tracker.json", tr)}, // a downgrade: open again
	}})
	// files that are missing, broken or odd
	odd := map[string]FileSpec{
		"db/a-1/desc":        {Content: "%NAME%\r\na\r\n\r\n%VERSION%\r\n1.0-1\r\n"}, // CRLF, no final newline
		"db/b-1/desc":        {Content: "%VERSION%\n2.0-1\n%NAME%\nb\n%BASE%\nb\n"},
		"db/c-1/desc":        {Content: "%NAME%\nc\n\n%VERSION%\n\n"}, // no version
		"db/e-1/desc":        {Content: "%NAME%\ne\n%\nx\n%VERSION%\n0.9-1\n%BASE%\nshared\n"},
		"db/f-1/desc":        {Content: "%NAME%\nf\n%VERSION%\n0.8-1\n%BASE%\nshared\n"},
		"db/shared-1/desc":   {Content: "%NAME%\nshared\n%VERSION%\n5-1\n"},
		"db/ALPM_DB_VERSION": {Content: "9\n"},
	}
	oddGroups := `[{"name":"AVG-10","packages":["a","b","c","shared","f"],"status":"FİXED","severity":"HİGH","fixed":"9-1","issues":["CVE-1"],"type":"x"},
	{"name":"AVG-11","packages":["a"],"status":"vulnerable","severity":"critical","affected":"1.0-7"},
	{"name":"AVG-12","packages":["b"],"status":"Unknown","severity":"Low","fixed":"3"},
	{"name":"AVG-13","packages":["a"],"status":"Testing","severity":"Medium","fixed":"1.0-2","issues":null,"extra":1},
	{"NAME":"AVG-14","Packages":["e"],"STATUS":"Fixed","Severity":"weird","fixed":"1"}]`
	a.Packages = append(a.Packages, AuditScenario{Name: "odd databases and trackers", Steps: []AuditStep{
		{Files: with(with(odd, "tracker.json", oddGroups), "db/d-1/desc", "%NAME%\n"+strings.Repeat("d", 70000)+"\n\n%VERSION%\n1-1\n")},
		{Files: odd}, // the tracker is gone: not an error worth logging
		{Files: with(odd, "tracker.json", `[{"name":"x","packages":"php"}]`)},
		{Files: with(odd, "tracker.json", `{"not":"a list"`)},
		{Files: map[string]FileSpec{"tracker.json": {Content: oddGroups}}}, // no database
		{Files: with(odd, "tracker.json", oddGroups)},
	}})
	// generated: random databases and trackers, three steps each (state carried)
	sevs := []string{"Critical", "High", "Medium", "Low", "Unknown", "critical", ""}
	stats := []string{"Fixed", "Vulnerable", "Not affected", "Unknown", "Testing", "fixed", "VULNERABLE"}
	for n := 0; n < 20; n++ {
		var steps []AuditStep
		names := []string{"php", "vim", "openssl", "glibc", "curl", "zlib", "sudo", "linux", "nss", "xz", "gcc", "rust", "go", "ffmpeg", "mesa"}
		var gs []pkgaudit.Group
		for g := 0; g < 25; g++ {
			grp := pkgaudit.Group{Name: fmt.Sprintf("AVG-%d", 100+g), Status: stats[r.Intn(len(stats))], Severity: sevs[r.Intn(len(sevs))],
				Type: "arbitrary code execution", Issues: []string{fmt.Sprintf("CVE-2026-%d", r.Intn(99999))}}
			for k := 0; k < 1+r.Intn(3); k++ {
				grp.Packages = append(grp.Packages, names[r.Intn(len(names))])
			}
			if r.Intn(3) > 0 {
				grp.Fixed = randVersion(r)
			} else {
				grp.Affected = randVersion(r)
			}
			gs = append(gs, grp)
		}
		for s := 0; s < 3; s++ {
			pk := map[string][2]string{}
			for _, nm := range names {
				if r.Intn(4) > 0 {
					pk[nm] = [2]string{randVersion(r), ""}
				}
			}
			if s == 2 {
				gs = gs[:20]
			}
			steps = append(steps, AuditStep{Files: with(pkgdb(pk), "tracker.json", trackerJSON(gs))})
		}
		a.Packages = append(a.Packages, AuditScenario{Name: fmt.Sprintf("generated packages %d", n), Steps: steps})
	}
	for i := range a.Packages {
		got, err := RunAudit("packages", a.Packages[i], tmp())
		if err != nil {
			return a, err
		}
		a.Packages[i].Steps = got
	}

	// kernels: TestOnlyKernelsAnUpdateFixesAreReported and TestCompactAndWatch's watch, as watchers
	jan := kernelaudit.Vuln{ID: "CVE-2026-53359", Score: 8.8, Summary: "Januscape", Ranges: []kernelaudit.Range{
		{Introduced: "2.6.36", Fixed: "5.15.222"}, {Introduced: "5.16.0", Fixed: "6.1.177"}, {Introduced: "6.2.0", Fixed: "6.6.144"}, {Introduced: "6.7.0", Fixed: "6.12.95"}, {Introduced: "6.13.0", Fixed: "6.18.38"}, {Introduced: "6.19.0", Fixed: "7.1.3"}}}
	overlap := kernelaudit.Vuln{ID: "CVE-2025-71295", Ranges: []kernelaudit.Range{{Introduced: "6.7.0", Fixed: "6.18.16"}, {Introduced: "6.13.0", Fixed: "6.19.6"}}}
	listOf := func(v []kernelaudit.Vuln) string {
		b, _ := json.Marshal(kernelaudit.File{Source: "made up", Vulns: v})
		return string(b)
	}
	mods := func(list string, ks ...string) map[string]FileSpec {
		f := map[string]FileSpec{"list.json": {Content: list}, "modules/extramodules-6.18/x.ko": {}}
		for _, k := range ks {
			f["modules/"+k+"/vmlinuz"] = FileSpec{}
		}
		return f
	}
	l1 := listOf([]kernelaudit.Vuln{jan, overlap, {ID: "CVE-open", Ranges: []kernelaudit.Range{{Introduced: "0"}}}})
	all := []string{"7.3.0-4-cachyos", "6.18.55-2-cachyos-lts", "6.18.30-1-lts", "7.1.2-arch1-1", "7.1.3-arch1-1"}
	a.Kernels = append(a.Kernels, AuditScenario{Name: "kernelaudit: TestOnlyKernelsAnUpdateFixesAreReported", Running: "7.1.2-arch1-1",
		Steps: []AuditStep{{Files: mods(l1, all...)}, {}, {Files: mods(l1, all[:3]...)}}})
	var compact []kernelaudit.Vuln
	for i := 0; i < 1000; i++ {
		compact = append(compact, kernelaudit.Vuln{ID: fmt.Sprintf("CVE-2026-%05d", i), Summary: fmt.Sprintf("bug %d", i), Score: 7.8,
			Exploited: i == 3,
			Ranges:    []kernelaudit.Range{{Introduced: "6.13.0", Fixed: fmt.Sprintf("6.18.%d", 40+i%5)}}})
	}
	l2 := listOf(compact)
	a.Kernels = append(a.Kernels, AuditScenario{Name: "kernelaudit: TestCompactAndWatch", Running: "7.3.0-4-cachyos",
		Steps: []AuditStep{{Files: mods(l2, "6.18.42-1-lts", "7.3.0-4-cachyos")}, {}}})
	a.Kernels = append(a.Kernels, AuditScenario{Name: "broken lists", Running: "6.1.1", Steps: []AuditStep{
		{Files: map[string]FileSpec{"modules/6.1.1/vmlinuz": {}}},
		{Files: map[string]FileSpec{"list.json": {Content: `{"generated":"yesterday","vulns":[]}`}, "modules/6.1.1/vmlinuz": {}}},
		{Files: map[string]FileSpec{"list.json": {Content: `{"vulns":[{"id":"CVE-1","score":"9","ranges":[{"introduced":"6.0","fixed":"6.1.5"}]}]}`}, "modules/6.1.1/vmlinuz": {}}},
		{Files: map[string]FileSpec{"list.json": {Content: `{"Generated":"2026-11-01T00:00:00+01:00","VULNS":[{"ID":"CVE-2","Score":9.95,"summary":"a   b <tag> & é","ranges":[{"introduced":"6.0","fixed":"6.1.5"},{"introduced":"5"}]}]}`}, "modules/6.1.1/vmlinuz": {}}},
	}})
	for n := 0; n < 12; n++ {
		var vs []kernelaudit.Vuln
		ver := func() string {
			return fmt.Sprintf("%d.%d.%d", 5+r.Intn(3), r.Intn(20), r.Intn(200))
		}
		for i := 0; i < 100; i++ {
			v := kernelaudit.Vuln{ID: fmt.Sprintf("CVE-2026-%05d", r.Intn(4000)), Summary: fmt.Sprintf("bug %d", i),
				Score: float64(r.Intn(101)) / 10, Exploited: r.Intn(30) == 0}
			if r.Intn(5) == 0 {
				v.Score = float64(r.Intn(1000)) / 100 // 7.25 and the like: %.1f rounding
			}
			for k := 0; k < 1+r.Intn(4); k++ {
				rg := kernelaudit.Range{Introduced: ver()}
				if r.Intn(6) > 0 {
					rg.Fixed = ver()
				}
				if r.Intn(10) == 0 {
					rg.Introduced = "0"
				}
				v.Ranges = append(v.Ranges, rg)
			}
			vs = append(vs, v)
		}
		var ks []string
		for k := 0; k < 4; k++ {
			ks = append(ks, ver()+[]string{"-1-lts", "-arch1-1", "-4-cachyos", ""}[r.Intn(4)])
		}
		list := listOf(vs)
		a.Kernels = append(a.Kernels, AuditScenario{Name: fmt.Sprintf("generated kernels %d", n), Running: ks[r.Intn(4)], Steps: []AuditStep{
			{Files: mods(list, ks...)}, {}, {Files: mods(listOf(vs[:70]), ks...)}}})
	}
	for i := range a.Kernels {
		got, err := RunAudit("kernels", a.Kernels[i], tmp())
		if err != nil {
			return a, err
		}
		a.Kernels[i].Steps = got
	}

	// hardening: TestGapsAreFoundOnceWithTheirFix and TestAnUnreadableSettingIsReportedAsUnchecked, and generated trees
	h := map[string]FileSpec{"dev/kvm": {Content: "\n", Mode: 0o666}, "sys/module/kvm_intel/parameters/nested": {Content: "Y\n"},
		"proc/sys/dev/tty/ldisc_autoload": {Content: "1\n"}, "proc/sys/kernel/kptr_restrict": {Content: "2\n"}}
	h2 := with(h, "dev/kvm", "\n")
	h2["dev/kvm"] = FileSpec{Content: "\n", Mode: 0o660}
	a.Hardening = append(a.Hardening, AuditScenario{Name: "hardening: TestGapsAreFoundOnceWithTheirFix", Steps: []AuditStep{{Files: h}, {}, {Files: h2}, {Files: h}}})
	a.Hardening = append(a.Hardening, AuditScenario{Name: "hardening: TestAnUnreadableSettingIsReportedAsUnchecked", NonRoot: true, Steps: []AuditStep{
		{Files: map[string]FileSpec{"proc/sys/net/core/bpf_jit_harden": {Content: "0\n", Mode: 0o200}}}}})
	vals := []string{"0\n", "1\n", "2\n", "3\n", "-1\n", "", " 2 \n", "10\n", "Y\n", "N\n", "\xff\n"}
	for n := 0; n < 30; n++ {
		var steps []AuditStep
		for s := 0; s < 3; s++ {
			f := map[string]FileSpec{}
			if r.Intn(4) > 0 {
				f["dev/kvm"] = FileSpec{Content: "", Mode: []uint32{0o666, 0o660, 0o600, 0o602, 0o604, 0o640}[r.Intn(6)]}
			}
			for _, p := range []string{"sys/module/kvm_intel/parameters/nested", "sys/module/kvm_amd/parameters/nested",
				"proc/sys/dev/tty/ldisc_autoload", "proc/sys/kernel/kptr_restrict", "proc/sys/fs/protected_fifos",
				"proc/sys/fs/protected_regular", "proc/sys/net/core/bpf_jit_harden"} {
				if r.Intn(5) > 0 {
					f[p] = FileSpec{Content: vals[r.Intn(len(vals))]}
				}
			}
			steps = append(steps, AuditStep{Files: f})
		}
		a.Hardening = append(a.Hardening, AuditScenario{Name: fmt.Sprintf("generated hardening %d", n), Steps: steps})
	}
	for i := range a.Hardening {
		if a.Hardening[i].NonRoot && os.Geteuid() == 0 {
			return a, fmt.Errorf("write the audit fixtures as a normal user (an unreadable file reads fine for root)")
		}
		got, err := RunAudit("hardening", a.Hardening[i], tmp())
		if err != nil {
			return a, err
		}
		a.Hardening[i].Steps = got
	}

	// game time: the tool's answers
	long := "A game is running: " + strings.Repeat("é", 79) + "x" + strings.Repeat("y", 20) + ".\n"
	for _, c := range []GameCase{
		{Stdout: []byte("A game is running: Steam is running a game (AppId 1091500, process 4210).\nmore\n"), Exit: 0},
		{Stdout: []byte("No game is running.\n"), Exit: 1},
		{Stdout: []byte("A game is running: x.\n"), Exit: 2},
		{Stdout: []byte("A game is running: gamescope.."), Exit: 0},
		{Stdout: []byte("  A game is running: tab\there \x1b[31mred​.  \n"), Exit: 0},
		{Stdout: []byte(long), Exit: 0},
		{Stdout: []byte("A game is running: bad \xff\xfe bytes.\n"), Exit: 0},
		{Stdout: []byte(""), Exit: 0},
		{Stdout: []byte("\nA game is running: second line.\n"), Exit: 0},
	} {
		dir := tmp()
		tool := filepath.Join(dir, "yggdrasil-gametime")
		if err := os.WriteFile(tool+".out", c.Stdout, 0o644); err != nil {
			return a, err
		}
		script := fmt.Sprintf("#!/bin/sh\ncat \"$0.out\"\nexit %d\n", c.Exit)
		if err := os.WriteFile(tool, []byte(script), 0o755); err != nil {
			return a, err
		}
		g := &gametime.Gate{Path: tool}
		c.Playing, c.Reason = g.Playing(context.Background())
		a.Gametime = append(a.Gametime, c)
	}
	return a, nil
}
