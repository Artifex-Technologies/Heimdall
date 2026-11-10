package parity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/kernelaudit"
	"github.com/Artifex-Technologies/Heimdall/internal/pkgaudit"
)

func textSHA(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }

// moreAPICases: GET /v1/quarantine, GET /v1/lan/devices, GET /v1/audit and GET/POST /v1/rules/drafts on made-up computers
// (the files each reads written into the case's folder), with damaged, odd and limit-sized files.
func moreAPICases(with func(string, func(*APICase))) {
	sha := func(c byte) string { return strings.Repeat(string(c), 64) }
	file := func(content string) FileSpec { return FileSpec{Content: content} }
	get := func(name, path string, files map[string]FileSpec, mod func(*APICase)) {
		with(name, func(c *APICase) {
			c.Path, c.Files = path, files
			if mod != nil {
				mod(c)
			}
		})
	}

	// what is held (immunity's index): Go reads it as []immunity.Entry and writes it back; any error is an empty list
	entry := `{"sha256":"` + sha('a') + `","size":4096,"kind":"Elf","original":"/home/u/Downloads/x <1>","reason":"a & b","source":"owner",
	 "added":"2026-11-05T10:00:00.123456789+01:00","status":"held","held_at":"2026-11-05T10:00:01Z","uid":1000,"gid":1000,"mode":493,
	 "mtime":1762333200,"copies":["/tmp/y"],"report":{"entropy":7.25,"head":"7f454c46","strings":["http://203.0.113.9/x"],
	 "elf":{"class":"ELF64","machine":"x86-64","type":"EXEC","needed":["libc.so.6"],"stripped":true,"static":false}},
	 "analysis":{"time":"2026-11-05T11:00:00Z","profile":"decompile","run_id":"r1","status":"done","output":"strings more"},
	 "unknown":{"x":[1,2]}}`
	entry2 := `{"SHA256":"` + sha('b') + `","Size":-1,"KIND":"Script","status":"immune","clamav":"","confirmed":"2026-11-06T00:00:00-05:00",
	 "report":{"head":"first"},"report":{"entropy":1e-7},"released_by":"\ud800 owner","mode":4294967295}`
	quarantine := func(name, index string) {
		files := map[string]FileSpec{}
		if index != "" {
			files["immunity/immunity.json"] = file(index)
		}
		get("quarantine: "+name, "/v1/quarantine", files, nil)
	}
	quarantine("nothing held", "")
	quarantine("two entries", "["+entry+",\n"+entry2+"]")
	quarantine("empty list", "[]")
	quarantine("null", "null")
	quarantine("damaged", "[{")
	quarantine("wrong type", `[{"sha256":5}]`)
	quarantine("mode too large", `[{"sha256":"`+sha('c')+`","mode":4294967296}]`)
	quarantine("an int written as 1.0", `[{"size":1.0}]`)
	quarantine("not a list", `{"sha256":"x"}`)
	quarantine("large and small numbers", `[{"report":{"entropy":123456789012345678901234},"size":9223372036854775807},{"report":{"entropy":0.000001}},{"report":{"entropy":-0}}]`)
	quarantine("nulls", `[{"report":null,"copies":null,"added":null,"analysis":{"time":null}},null]`)
	quarantine("empty copies and strings", `[{"copies":[],"report":{"strings":[],"elf":{"needed":[]}}}]`)
	quarantine("bad time", `[{"added":"yesterday"}]`)
	quarantine("year zero with an offset", `[{"added":"0000-01-01T00:30:00+01:00"}]`)

	// the device list (internal/lan): a missing file is an empty store, anything unreadable is {"status":"unreadable"}
	store := `{"networks":[{"uuid":"u-1","ssid":"Home <5G>","first_scan":"2026-11-07T08:00:00Z","last_scan":"2026-11-07T09:00:00+01:00",
	 "devices":[{"mac":"02:00:00:00:00:01","ip":"192.0.2.10","name":"tv","names":["tv","TV-1"],"vendor":"Made Up","model":"M1","kind":"tv",
	 "services":["_googlecast._tcp"],"private_mac":true,"first_seen":"2026-11-07T08:00:00Z","last_seen":"2026-11-07T09:00:00Z"},
	 {"mac":"02:00:00:00:00:02","ip":"192.0.2.1","kind":"router","private_mac":false,"first_seen":"2026-11-07T08:00:00Z","last_seen":"2026-11-07T08:00:00Z"}]}],
	 "status":"scanned","status_uuid":"u-1","status_time":"2026-11-07T09:00:00Z","extra":true}`
	devices := func(name string, files map[string]FileSpec, lanOn bool) {
		get("lan devices: "+name, "/v1/lan/devices", files, func(c *APICase) { c.LAN = lanOn })
	}
	devices("not configured", nil, false)
	devices("no file yet", nil, true)
	devices("a network", map[string]FileSpec{"lan/devices.json": file(store)}, true)
	devices("damaged", map[string]FileSpec{"lan/devices.json": file(store[:100])}, true)
	devices("wrong type", map[string]FileSpec{"lan/devices.json": file(`{"networks":[{"devices":[{"private_mac":"yes"}]}]}`)}, true)
	devices("empty lists, keys in other case", map[string]FileSpec{"lan/devices.json": file(`{"NETWORKS":[{"Devices":[],"UUID":"x"}],"Status":"offline"}`)}, true)
	devices("a folder in its place", map[string]FileSpec{"lan/devices.json/x": file("")}, true)
	devices("null", map[string]FileSpec{"lan/devices.json": file("null")}, true)

	// the audit report: the package tracker, pacman's database, the kernel list, the modules folder, the hardening checks
	groups := []pkgaudit.Group{
		{Name: "AVG-1", Packages: []string{"openssl"}, Status: "Fixed", Severity: "High", Type: "arbitrary code execution", Affected: "3.0.1-1", Fixed: "3.0.2-1", Issues: []string{"CVE-2026-1"}},
		{Name: "AVG-2", Packages: []string{"zlib", "openssl"}, Status: "Vulnerable", Severity: "Critical", Type: "denial of service", Affected: "1.3-1", Issues: []string{}},
		{Name: "AVG-3", Packages: []string{"curl"}, Status: "Fixed", Severity: "Low", Type: "unknown <&>", Affected: "8.0-1", Fixed: "8.1-1"},
	}
	db := pkgdb(map[string][2]string{"openssl": {"3.0.1-1", ""}, "zlib": {"1.3-1", ""}, "curl": {"8.0-1", ""}, "bash": {"5.2-1", ""}})
	var vulns []kernelaudit.Vuln
	for i := 0; i < 20; i++ {
		v := kernelaudit.Vuln{ID: fmt.Sprintf("CVE-2026-%04d", i), Summary: fmt.Sprintf("hole %d <b>", i), Score: float64(i%7) * 1.5,
			Exploited: i%9 == 0, Ranges: []kernelaudit.Range{{Introduced: "6.0", Fixed: fmt.Sprintf("6.%d.%d", 1+i%3, 5+i)}}}
		vulns = append(vulns, v)
	}
	list, _ := json.Marshal(kernelaudit.File{Generated: time.Date(2026, 11, 1, 23, 30, 0, 0, time.FixedZone("", -5*3600)), Source: "made up", Vulns: vulns})
	full := map[string]FileSpec{"tracker.json": file(trackerJSON(groups)), "kernel.json": file(string(list)),
		"modules/6.1.2-1-made/vmlinuz": {}, "modules/6.3.0-1-made/vmlinuz": {}, "modules/6.2.9/vmlinuz": {}, "modules/no-image/x": {},
		"root/proc/sys/kernel/kptr_restrict": file("0\n"), "root/proc/sys/kernel/dmesg_restrict": file("1\n"),
		"root/sys/module/kvm_amd/parameters/nested": file("1\n")}
	for k, v := range db {
		full[k] = v
	}
	audit := func(name string, files map[string]FileSpec, running string) {
		get("audit: "+name, "/v1/audit", files, func(c *APICase) { c.Running = running })
	}
	audit("nothing downloaded", nil, "")
	audit("everything", full, "6.2.9")
	audit("running kernel not installed", full, "7.0.0")
	noDB := map[string]FileSpec{}
	for k, v := range full {
		if !strings.HasPrefix(k, "db/") {
			noDB[k] = v
		}
	}
	audit("tracker but no pacman database", noDB, "6.1.2-1-made")
	audit("damaged lists", map[string]FileSpec{"tracker.json": file("[{"), "kernel.json": file(`{"vulns":5}`), "modules/6.1.1/vmlinuz": {}}, "")
	audit("an empty kernel list", map[string]FileSpec{"kernel.json": file(`{}`), "modules/6.1.1/vmlinuz": {}}, "6.1.1")

	// rule drafts: GET lists them; POST keeps one for a held sample
	rule := "rule Heimdall_Test_1\n{\n strings:\n  $a = \"evil\"\n condition:\n  $a\n}\n"
	held := `[{"sha256":"` + sha('a') + `","status":"held"},{"sha256":"abc","status":"held"}]`
	old := `[{"id":"0a0b0c0d","name":"Heimdall_Old","sample_sha256":"` + sha('a') + `","text":"rule Heimdall_Old { condition: true }","text_sha256":"` + textSHA("rule Heimdall_Old { condition: true }") + `",
	 "uid":954,"time":"2026-11-05T11:00:00Z","status":"tested","test":{"time":"2026-11-05T11:05:00Z","text_sha256":"x","matched_sample":true,"fp_count":0,"scanned":["/usr/bin"]},
	 "decided":"0001-01-01T00:00:00Z","note":"from <Sarina> & co"}]`
	drafts := func(name string, files map[string]FileSpec) {
		get("rule drafts: "+name, "/v1/rules/drafts", files, nil)
	}
	drafts("none yet", nil)
	drafts("one", map[string]FileSpec{"rule-drafts.json": file(old)})
	drafts("null", map[string]FileSpec{"rule-drafts.json": file("null")})
	drafts("damaged", map[string]FileSpec{"rule-drafts.json": file("[{")})
	drafts("wrong type", map[string]FileSpec{"rule-drafts.json": file(`[{"uid":-1}]`)})
	with("rule drafts: a link is not followed", func(c *APICase) {
		c.Path, c.Files, c.Links, c.Exact = "/v1/rules/drafts", map[string]FileSpec{"elsewhere.json": file(old)}, map[string]string{"rule-drafts.json": "elsewhere.json"}, true
	})
	post := func(name, body string, files map[string]FileSpec, exact bool) {
		with("rule drafts: post, "+name, func(c *APICase) {
			c.Method, c.Path, c.Body, c.Files, c.Exact = "POST", "/v1/rules/drafts", body, files, exact
		})
	}
	body := func(sample, text, note string) string {
		b, _ := json.Marshal(map[string]string{"sample_sha256": sample, "rule": text, "note": note})
		return string(b)
	}
	heldOnly := map[string]FileSpec{"immunity/immunity.json": file(held)}
	withOld := map[string]FileSpec{"immunity/immunity.json": file(held), "rule-drafts.json": file(old)}
	post("a new draft", body(sha('a'), rule, "Sarina's <note>"), heldOnly, true)
	post("after an old one", body(sha('a'), rule, ""), withOld, true)
	post("the same text again", body(sha('a'), "rule Heimdall_Old { condition: true }", "again"), withOld, true)
	post("a sample not held", body(sha('d'), rule, ""), heldOnly, true)
	post("nothing held", body(sha('a'), rule, ""), nil, true)
	post("a held name that is not a hash", body("abc", rule, ""), heldOnly, true)
	for _, bad := range []struct{ name, text string }{
		{"empty rule", ""}, {"too long", "rule Heimdall_X { condition: true }" + strings.Repeat(" ", 16<<10)},
		{"a control character", "rule Heimdall_X { condition: true }\x01"}, {"import", "import \"pe\"\n" + rule},
		{"include after spaces", "  \t include \"x\"\n" + rule}, {"two rules", rule + "private rule Heimdall_Two { condition: true }"},
		{"no rule", "condition: true"}, {"another name", "rule Evil { condition: true }"}, {"name too long", "rule Heimdall_" + strings.Repeat("a", 65) + " { condition: true }"},
		{"no condition", "rule Heimdall_X { strings: $a = \"x\" }"}, {"global private", "global private rule Heimdall_G { condition: true }"},
		{"rule on a later line", "// c\n\n   rule Heimdall_L : tag { condition: true }"}, {"imports is not import", "importsx\nrule Heimdall_I { condition: true }"},
		{"vertical tab", "\vrule Heimdall_V { condition: true }"}, {"form feed and CR", "\f\rrule Heimdall_F {\r\n condition: true }"},
		{"a tab before rule", "\trule Heimdall_T { condition: true }"},
	} {
		post(bad.name, body(sha('a'), bad.text, ""), heldOnly, true)
	}
	post("a long note cut inside a letter", body(sha('a'), rule, strings.Repeat("é", 1500)), heldOnly, true)
	post("malformed", `{"rule":`, heldOnly, false)
	post("oversized", body(sha('a'), rule, strings.Repeat("n", 33<<10)), heldOnly, false)
	post("damaged drafts file", body(sha('a'), rule, ""), map[string]FileSpec{"immunity/immunity.json": file(held), "rule-drafts.json": file("[{")}, false)
	post("keys in other case, trailing data", `{"SAMPLE_SHA256":"`+sha('a')+`","Rule":"rule Heimdall_C { condition: true }"} {"x":1}`, heldOnly, true)
	var many []string
	for i := 0; i < 100; i++ {
		t := fmt.Sprintf("rule Heimdall_N%d { condition: true }", i)
		many = append(many, fmt.Sprintf(`{"id":"%08x","name":"Heimdall_N%d","sample_sha256":"%s","text":%q,"text_sha256":"%s","uid":0,"time":"2026-11-05T11:00:00Z","status":"draft"}`,
			i, i, sha('a'), t, textSHA(t)))
	}
	post("the 101st draft pushes out the oldest", body(sha('a'), rule, ""), map[string]FileSpec{"immunity/immunity.json": file(held), "rule-drafts.json": file("[" + strings.Join(many, ",") + "]")}, true)
	with("rule drafts: PUT", func(c *APICase) { c.Method, c.Path = "PUT", "/v1/rules/drafts" })
}
