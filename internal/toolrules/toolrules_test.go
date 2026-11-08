package toolrules

import (
	"strings"
	"testing"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

// a fake pacman database: which package owns a file and the digest it recorded, and what the file hashes to now
type fakeFS struct {
	owner map[string][2]string // path -> {package, recorded sha}
	now   map[string]string    // path -> current sha
}

func (f fakeFS) owns(p string) (string, string, bool) {
	o, ok := f.owner[p]
	return o[0], o[1], ok
}

func policy(t *testing.T, fs fakeFS) (*Policy, *time.Time) {
	t.Helper()
	c, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	p := New(c, fs.owns)
	p.hash = func(path string) (string, error) { return fs.now[path], nil }
	clock := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	p.now = func() time.Time { return clock }
	return p, &clock
}

func conn(fields map[string]string, sev detect.Severity) detect.Finding {
	return detect.Finding{DetectorID: "connection-watch", Severity: sev, Summary: fields["process"] + " connected to 192.0.2.7:443 (new destination for it)",
		Event: detect.Event{Kind: "new_connection", Fields: fields}}
}

var fs = fakeFS{
	owner: map[string][2]string{
		"/usr/bin/nmap":             {"nmap", "aa"},
		"/usr/bin/hashcat":          {"hashcat", "bb"},
		"/opt/sqlmap/sqlmap.py":     {"sqlmap", "cc"},
		"/usr/bin/python3.14":       {"python", "dd"},
		"/usr/bin/curl":             {"curl", "ee"},
		"/usr/bin/masscan":          {"masscan", "ff"},
		"/usr/share/burp/burp.jar":  {"burpsuite", "11"},
		"/usr/bin/tampered-example": {"nmap", "aa"},
	},
	now: map[string]string{"/usr/bin/nmap": "aa", "/usr/bin/hashcat": "bb", "/opt/sqlmap/sqlmap.py": "cc", "/usr/bin/python3.14": "dd",
		"/usr/bin/curl": "ee", "/usr/bin/masscan": "ff", "/usr/share/burp/burp.jar": "11", "/usr/bin/tampered-example": "99"},
}

func TestTheCatalogIsWhole(t *testing.T) {
	c, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{"connection-watch": true, "remote-access": true, "network-exposure": true, "inbound": true}
	seen := map[string]bool{}
	for _, tool := range c.Tools {
		if tool.ID == "" || tool.Name == "" || len(tool.Packages) == 0 {
			t.Errorf("incomplete entry %+v", tool)
		}
		for _, d := range tool.Expects {
			if !known[d] {
				t.Errorf("%s expects an unknown detector %q", tool.ID, d)
			}
		}
		if tool.Offline && len(tool.Expects) > 0 {
			t.Errorf("%s works offline but expects %v", tool.ID, tool.Expects)
		}
		for _, p := range tool.Packages {
			if seen[p] {
				t.Errorf("package %s is in two entries", p)
			}
			seen[p] = true
		}
	}
	for _, core := range []string{"nmap", "masscan", "hydra", "sqlmap", "metasploit", "burpsuite", "hashcat", "john", "aircrack-ng", "responder"} {
		if !seen[core] {
			t.Errorf("LykanOS's core tool %s has no rule", core)
		}
	}
}

func TestAVerifiedToolDoingItsJobIsInfoAndAScannerIsSummarised(t *testing.T) {
	p, clock := policy(t, fs)
	out := p.Apply(conn(map[string]string{"process": "nmap", "exe": "/usr/bin/nmap"}, detect.SeverityInfo))
	if len(out) != 1 || out[0].Severity != detect.SeverityInfo || !strings.HasPrefix(out[0].Summary, "[Nmap, a verified security tool]") ||
		!strings.Contains(out[0].Summary, "counted, not listed, for 10 minutes") {
		t.Fatalf("%+v", out)
	}
	for i := 0; i < 500; i++ {
		if got := p.Apply(conn(map[string]string{"process": "nmap", "exe": "/usr/bin/nmap"}, detect.SeverityInfo)); got != nil {
			t.Fatalf("destination %d listed: %+v", i, got)
		}
	}
	*clock = clock.Add(11 * time.Minute)
	out = p.Apply(conn(map[string]string{"process": "nmap", "exe": "/usr/bin/nmap"}, detect.SeverityInfo))
	if len(out) != 1 || !strings.Contains(out[0].Summary, "500 more new destinations before this one") {
		t.Fatalf("%+v", out)
	}
	// an interpreted tool is known by its script, a Java one by its jar
	out = p.Apply(conn(map[string]string{"process": "python3", "exe": "/usr/bin/python3.14", "script": "/opt/sqlmap/sqlmap.py"}, detect.SeverityInfo))
	if len(out) != 1 || !strings.HasPrefix(out[0].Summary, "[sqlmap, a verified security tool]") {
		t.Fatalf("%+v", out)
	}
	out = p.Apply(conn(map[string]string{"process": "java", "exe": "/usr/lib/jvm/bin/java", "script": "/usr/share/burp/burp.jar"}, detect.SeverityWarning))
	if len(out) != 1 || out[0].Severity != detect.SeverityInfo {
		t.Fatalf("%+v", out)
	}
}

func TestAChangedToolIsCriticalAndNothingIsSoftened(t *testing.T) {
	p, clock := policy(t, fs)
	in := conn(map[string]string{"process": "nmap", "exe": "/usr/bin/tampered-example"}, detect.SeverityInfo)
	out := p.Apply(in)
	if len(out) != 2 || out[0].Summary != in.Summary || out[0].Severity != in.Severity || out[1].Severity != detect.SeverityCritical || !out[1].Firm || out[1].DetectorID != "tool-rules" ||
		!strings.Contains(out[1].Summary, "is not what package nmap installed") {
		t.Fatalf("%+v", out)
	}
	if len(p.Apply(in)) != 1 {
		t.Fatal("the changed file is reported once an hour, the finding itself every time")
	}
	*clock = clock.Add(61 * time.Minute)
	if len(p.Apply(in)) != 2 {
		t.Fatal("reported again after an hour")
	}
}

func TestWhatSarinaRunsAndOfflineToolsConnectingAreShown(t *testing.T) {
	p, _ := policy(t, fs)
	out := p.Apply(conn(map[string]string{"process": "nmap", "exe": "/usr/bin/nmap", "agent": "sarina"}, detect.SeverityInfo))
	if len(out) != 1 || out[0].Severity != detect.SeverityWarning || !strings.HasPrefix(out[0].Summary, "[sarina started Nmap]") {
		t.Fatalf("%+v", out)
	}
	out = p.Apply(conn(map[string]string{"process": "hashcat", "exe": "/usr/bin/hashcat"}, detect.SeverityInfo))
	if len(out) != 1 || out[0].Severity != detect.SeverityWarning || !strings.Contains(out[0].Summary, "hashcat works offline, yet it made a connection") {
		t.Fatalf("%+v", out)
	}
}

func TestOtherFindingsAreLeftAlone(t *testing.T) {
	p, _ := policy(t, fs)
	cases := []detect.Finding{
		conn(map[string]string{"process": "curl", "exe": "/usr/bin/curl"}, detect.SeverityInfo),           // not a tool
		conn(map[string]string{"process": "x", "exe": "/home/u/x"}, detect.SeverityInfo),                  // owned by no package
		conn(map[string]string{"process": "nmap"}, detect.SeverityInfo),                                   // no program file known
		conn(map[string]string{"process": "masscan", "exe": "/usr/bin/masscan"}, detect.SeverityCritical), // a threat-listed address
		{DetectorID: "file-integrity", Severity: detect.SeverityWarning, Summary: "x", Event: detect.Event{Fields: map[string]string{"exe": "/usr/bin/nmap"}}},
	}
	for _, f := range cases {
		out := p.Apply(f)
		if len(out) != 1 || out[0].Severity != f.Severity || out[0].Summary != f.Summary {
			t.Errorf("changed: %+v -> %+v", f, out)
		}
	}
	var none *Policy
	if out := none.Apply(cases[0]); len(out) != 1 {
		t.Fatal("no policy: unchanged")
	}
}
