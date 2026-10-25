package kernelaudit

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestCVSS(t *testing.T) {
	for vec, want := range map[string]float64{
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H": 8.8, // Januscape
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H": 5.5,
	} {
		if got, ok := CVSS3(vec); !ok || got != want {
			t.Errorf("%s: %v, want %v", vec, got, want)
		}
	}
}

var januscape = Vuln{ID: "CVE-2026-53359", Score: 8.8, Ranges: []Range{
	{"2.6.36", "5.15.222"}, {"5.16.0", "6.1.177"}, {"6.2.0", "6.6.144"}, {"6.7.0", "6.12.95"}, {"6.13.0", "6.18.38"}, {"6.19.0", "7.1.3"}}}

func TestOnlyKernelsAnUpdateFixesAreReported(t *testing.T) {
	// overlapping ranges, as the records have them: fixed on 6.18 at .16, so 6.18.55 is fine although "6.13 to 6.19.6" covers it
	overlap := Vuln{ID: "CVE-2025-71295", Ranges: []Range{{"6.7.0", "6.18.16"}, {"6.13.0", "6.19.6"}}}
	f := &File{Vulns: []Vuln{januscape, overlap, {ID: "CVE-open", Ranges: []Range{{Introduced: "0"}}}}}
	for k, hit := range map[string]bool{"7.3.0-4-cachyos": false, "6.18.55-2-cachyos-lts": false, "6.18.30-1-lts": true, "7.1.2-arch1-1": true, "7.1.3-arch1-1": false} {
		holes, fix := Check(f, k)
		if (len(holes) > 0) != hit {
			t.Errorf("%s: %v", k, holes)
		}
		if hit && (holes[len(holes)-1].ID != "CVE-2026-53359" || fix == "") {
			t.Errorf("%s: %v %s", k, holes, fix)
		}
	}
}

func TestCompactAndWatch(t *testing.T) {
	dir := t.TempDir()
	zp := filepath.Join(dir, "all.zip")
	zf, _ := os.Create(zp)
	zw := zip.NewWriter(zf)
	for i := 0; i < 1000; i++ {
		w, _ := zw.Create(fmt.Sprintf("CVE-2026-%05d.json", i))
		fmt.Fprintf(w, `{"id":"CVE-2026-%05d","summary":"bug %d","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}],
		"affected":[{"package":{"name":"Kernel","ecosystem":"Linux"},"ranges":[{"type":"GIT","events":[{"introduced":"abc"}]},{"type":"ECOSYSTEM","events":[{"introduced":"6.13.0"},{"fixed":"6.18.%d"}]}]}]}`, i, i, 40+i%5)
	}
	zw.Close()
	zf.Close()
	f, err := Compact(zp, map[string]bool{"CVE-2026-00003": true})
	if err != nil || len(f.Vulns) != 1000 || f.Vulns[0].Score != 7.8 || f.Vulns[0].Ranges[0].Fixed != "6.18.40" {
		t.Fatal(err, f.Vulns[:1])
	}
	list := filepath.Join(dir, "linux-kernel.json")
	b, _ := json.Marshal(f)
	os.WriteFile(list, b, 0o644)
	mods := filepath.Join(dir, "modules")
	for _, k := range []string{"6.18.42-1-lts", "7.3.0-4-cachyos"} {
		os.MkdirAll(filepath.Join(mods, k), 0o755)
		os.WriteFile(filepath.Join(mods, k, "vmlinuz"), nil, 0o644)
	}
	os.MkdirAll(filepath.Join(mods, "extramodules-6.18"), 0o755)
	w := &Watcher{ListPath: list, ModulesDir: mods, StatePath: filepath.Join(dir, "state"), Running: "7.3.0-4-cachyos"}
	ev, err := w.Poll()
	if err != nil || len(ev) != 1 || ev[0].Fields["kernel"] != "6.18.42-1-lts" || ev[0].Fields["fixed"] != "6.18.44" || ev[0].Fields["running"] != "false" {
		t.Fatal(err, ev)
	}
	if ev[0].Fields["exploited"] != "CVE-2026-00003" || ev[0].Fields["same_line"] != "400" || ev[0].Fields["line_fix"] != "6.18.44" {
		t.Fatal(ev[0].Fields)
	}
	if ev, _ := w.Poll(); len(ev) != 0 {
		t.Fatal("reported once")
	}
}
