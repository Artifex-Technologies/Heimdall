package pkgaudit

import (
	"os"
	"path/filepath"
	"testing"
)

func db(t *testing.T, pkgs map[string][2]string) string {
	d := t.TempDir()
	for name, vb := range pkgs {
		dir := filepath.Join(d, name+"-"+vb[0])
		os.MkdirAll(dir, 0o755)
		desc := "%NAME%\n" + name + "\n\n%VERSION%\n" + vb[0] + "\n\n"
		if vb[1] != "" {
			desc += "%BASE%\n" + vb[1] + "\n\n"
		}
		os.WriteFile(filepath.Join(dir, "desc"), []byte(desc), 0o644)
	}
	return d
}

func TestInstalledPackagesAreMatchedWithPacmanVersions(t *testing.T) {
	inst, err := Installed(db(t, map[string][2]string{
		"php":       {"8.4.26-1.1", ""},
		"vim":       {"9.1.0-1", ""},
		"openssl":   {"3.5.4-1.1", ""},
		"libfoo":    {"1.0-1.1", ""},
		"libold":    {"2.0-1", ""},
		"linux-api": {"6.0-1", "linux-headers-src"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	groups := []Group{
		{Name: "AVG-2909", Packages: []string{"php"}, Status: "Fixed", Severity: "Critical", Fixed: "8.4.27-1", Issues: []string{"CVE-2026-109618"}},
		{Name: "AVG-1", Packages: []string{"vim"}, Status: "Fixed", Severity: "High", Fixed: "9.0.1225-1"},         // older than installed
		{Name: "AVG-2", Packages: []string{"openssl"}, Status: "Fixed", Severity: "High", Fixed: "3.5.4-1"},        // a CachyOS rebuild of the fix
		{Name: "AVG-3", Packages: []string{"libfoo"}, Status: "Vulnerable", Severity: "Medium", Affected: "1.0-1"}, // no fix yet, this very version
		{Name: "AVG-7", Packages: []string{"libold"}, Status: "Vulnerable", Severity: "High", Affected: "1.2-1"},   // a stale entry: a newer version is installed
		{Name: "AVG-4", Packages: []string{"notinstalled"}, Status: "Vulnerable", Severity: "Critical"},            // not here
		{Name: "AVG-5", Packages: []string{"linux-headers-src"}, Status: "Fixed", Severity: "Low", Fixed: "6.1-1"}, // matched by base name
		{Name: "AVG-6", Packages: []string{"php"}, Status: "Not affected", Severity: "High", Fixed: "9.0-1"},
	}
	got := Check(groups, inst)
	if len(got) != 3 {
		t.Fatalf("findings: %+v", got)
	}
	if got[0].Package != "php" || got[0].Group.Name != "AVG-2909" || got[0].NoFix {
		t.Errorf("first (most severe): %+v", got[0])
	}
	if got[1].Package != "libfoo" || !got[1].NoFix || got[2].Group.Name != "AVG-5" {
		t.Errorf("rest: %+v", got[1:])
	}
}

func TestEachFindingIsReportedOnceUntilTheVersionChanges(t *testing.T) {
	dir := t.TempDir()
	tracker := filepath.Join(dir, "arch-security.json")
	os.WriteFile(tracker, []byte(`[{"name":"AVG-2909","packages":["php"],"status":"Fixed","severity":"Critical","fixed":"8.4.27-1","issues":["CVE-2026-109618","CVE-2026-109619"]}]`), 0o644)
	pdb := db(t, map[string][2]string{"php": {"8.4.26-1", ""}})
	w := &Watcher{TrackerPath: tracker, PacmanDB: pdb, StatePath: filepath.Join(dir, "state.json")}
	ev, err := w.Poll()
	if err != nil || len(ev) != 1 || ev[0].Fields["fixed"] != "8.4.27-1" {
		t.Fatalf("first: %+v %v", ev, err)
	}
	if ev, _ := w.Poll(); len(ev) != 0 {
		t.Error("reported twice")
	}
	pdb2 := db(t, map[string][2]string{"php": {"8.4.27-1.1", ""}})
	w.PacmanDB = pdb2
	if ev, _ := w.Poll(); len(ev) != 0 {
		t.Error("the fixed rebuild was reported")
	}
}
