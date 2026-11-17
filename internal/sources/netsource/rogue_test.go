package netsource

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var updateRogue = flag.Bool("update", false, "rewrite testdata/netsource/rogue-router.json (the Rust port replays it)")

// rogueStep is one poll of a scenario: the dispatcher lines written since the last poll, heimdall-wifi-check's current.json
// (empty: none), the kernel's IPv6 table, and the alerts expected.
type rogueStep struct {
	Now     int64               `json:"now"`
	NetID   []string            `json:"netid,omitempty"`
	Current string              `json:"current,omitempty"`
	Routes  string              `json:"ipv6_route"`
	Want    []map[string]string `json:"want"`
}

type rogueScenario struct {
	Name  string      `json:"name"`
	Steps []rogueStep `json:"steps"`
}

func nl(t int64, action, uuid, server, router, dns4, dns6 string) string {
	return fmt.Sprintf(`{"t":%d,"action":"%s","iface":"wlan0","uuid":"%s","dhcp4_server":"%s","dhcp4_routers":"%s","dns4":"%s","dns6":"%s"}`,
		t, action, uuid, server, router, dns4, dns6)
}

func r6(dest string, plen int, hop string) string {
	return fmt.Sprintf("%s %02x 00000000000000000000000000000000 00 %s 00000100 00000001 00000000 00000003 wlan0", dest, plen, hop)
}

const (
	zero32  = "00000000000000000000000000000000"
	ll1     = "fe800000000000000000000000000001"
	ll66    = "fe800000000000000000000000000066"
	pfx1    = "20010db8000100000000000000000000"
	pfx66   = "20010db8006600000000000000000000"
	uHome   = "00000000-0000-4000-8000-000000000001"
	uCafe   = "00000000-0000-4000-8000-000000000002"
	curHome = `{"ssid":"Example-Home","uuid":"` + uHome + `","trusted":false,"level":"trusted"}`
)

func rogueScenarios() []rogueScenario {
	ra1 := r6(zero32, 0, ll1) + "\n" + r6(pfx1, 64, zero32) + "\n" + r6("fe800000000000000000000000000000", 64, zero32)
	var learnSteps []rogueStep
	t := int64(10000)
	learnSteps = append(learnSteps, rogueStep{Now: t, NetID: []string{nl(t, "up", uHome, "192.0.2.1", "192.0.2.1", "192.0.2.1", "")}, Current: curHome})
	for i := 0; i < 4; i++ {
		t += 1000
		learnSteps = append(learnSteps, rogueStep{Now: t, NetID: []string{nl(t-1, "down", uHome, "", "", "", ""), nl(t, "up", uHome, "192.0.2.66", "192.0.2.66", "192.0.2.66", "")}, Current: curHome})
	}
	var v6Steps []rogueStep
	t = 20000
	for i := 0; i < 3; i++ {
		v6Steps = append(v6Steps, rogueStep{Now: t, NetID: []string{nl(t, "up", uHome, "192.0.2.1", "192.0.2.1", "192.0.2.1", "")}, Current: curHome})
		t += 1000
		v6Steps = append(v6Steps, rogueStep{Now: t, NetID: []string{nl(t, "down", uHome, "", "", "", "")}, Current: curHome})
		t += 1000
	}
	v6Steps = append(v6Steps, rogueStep{Now: t, NetID: []string{nl(t, "up", uHome, "192.0.2.1", "192.0.2.1", "192.0.2.1", "")}, Current: curHome, Routes: ra1})
	return []rogueScenario{
		{"a second DHCP server during a connection (untrusted)", []rogueStep{
			{Now: 1000, NetID: []string{nl(1000, "up", uCafe, "192.0.2.1", "192.0.2.1", "192.0.2.1", "")}},
			{Now: 1010, NetID: []string{nl(1010, "dhcp4-change", uCafe, "192.0.2.66", "192.0.2.1", "192.0.2.66", "")}},
			{Now: 1020, NetID: []string{nl(1020, "dhcp4-change", uCafe, "192.0.2.66", "192.0.2.1", "192.0.2.66", "")}},
		}},
		{"a trusted network's DHCP server replaced: critical, learned after 3 connections", learnSteps},
		{"a second IPv6 router and a new prefix during a connection (untrusted)", []rogueStep{
			{Now: 1000, NetID: []string{nl(1000, "up", uCafe, "192.0.2.1", "192.0.2.1", "192.0.2.1", "2001:db8:1::1")}},
			{Now: 1005, Routes: ra1},
			{Now: 1100, Routes: ra1 + "\n" + r6(zero32, 0, ll66)},
			{Now: 1200, Routes: ra1 + "\n" + r6(zero32, 0, ll66) + "\n" + r6(pfx66, 64, zero32)},
			{Now: 1210, NetID: []string{nl(1210, "down", uCafe, "", "", "", "")}, Routes: ra1},
		}},
		{"an IPv6 router appears late on a network that had none (untrusted)", []rogueStep{
			{Now: 1000, NetID: []string{nl(1000, "up", uCafe, "192.0.2.1", "192.0.2.1", "192.0.2.1", "")}},
			{Now: 1300, Routes: ra1},
		}},
		{"IPv6 appears on a trusted network that never had it", v6Steps},
		{"lines from before heimdalld started only rebuild the connection", []rogueStep{
			{Now: 5000, NetID: []string{nl(1000, "up", uCafe, "192.0.2.1", "192.0.2.1", "192.0.2.1", ""), nl(1010, "dhcp4-change", uCafe, "192.0.2.66", "192.0.2.1", "192.0.2.1", "")}},
			{Now: 5010, NetID: []string{nl(5010, "dhcp4-change", uCafe, "192.0.2.77", "192.0.2.1", "192.0.2.1", "")}},
		}},
	}
}

// runRogue replays a scenario in a temporary folder and returns each step's alerts.
func runRogue(t *testing.T, sc rogueScenario) [][]map[string]string {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "proc/net"), 0o755)
	w := NewRogueRouterWatcher(filepath.Join(dir, "netid.jsonl"), filepath.Join(dir, "current.json"), filepath.Join(dir, "routers.json"))
	w.procRoot = filepath.Join(dir, "proc")
	var out [][]map[string]string
	for _, st := range sc.Steps {
		if len(st.NetID) > 0 {
			f, _ := os.OpenFile(w.NetIDPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
			f.WriteString(strings.Join(st.NetID, "\n") + "\n")
			f.Close()
		}
		os.Remove(w.CurrentPath)
		if st.Current != "" {
			os.WriteFile(w.CurrentPath, []byte(st.Current), 0o644)
		}
		os.WriteFile(filepath.Join(dir, "proc/net/ipv6_route"), []byte(st.Routes), 0o644)
		now := time.Unix(st.Now, 0)
		w.now = func() time.Time { return now }
		got := []map[string]string{}
		for _, e := range w.Poll() {
			m := map[string]string{"kind": e.Kind, "text": e.Text}
			for k, v := range e.Fields {
				m[k] = v
			}
			got = append(got, m)
		}
		out = append(out, got)
	}
	if st, err := os.Stat(w.StatePath); err == nil && st.Mode().Perm() != 0o600 {
		t.Errorf("%s: state file mode %v, want 0600", sc.Name, st.Mode().Perm())
	}
	return out
}

// TestRogueRouterScenarios replays the scenarios against the committed fixture, which the Rust port replays too.
func TestRogueRouterScenarios(t *testing.T) {
	path := filepath.Join("..", "..", "..", "testdata", "netsource", "rogue-router.json")
	scs := rogueScenarios()
	if *updateRogue {
		for i := range scs {
			got := runRogue(t, scs[i])
			for j := range scs[i].Steps {
				scs[i].Steps[j].Want = got[j]
			}
		}
		b, _ := json.MarshalIndent(scs, "", " ")
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var want []rogueScenario
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	if len(want) != len(scs) {
		t.Fatalf("fixture has %d scenarios, the test %d: run go test ./internal/sources/netsource -run Rogue -update", len(want), len(scs))
	}
	for i, sc := range want {
		got := runRogue(t, sc)
		for j := range sc.Steps {
			w := sc.Steps[j].Want
			if w == nil {
				w = []map[string]string{}
			}
			if !reflect.DeepEqual(got[j], w) {
				t.Errorf("%s, step %d:\n got %v\nwant %v", sc.Name, j, got[j], w)
			}
		}
		_ = i
	}
}

func TestHexIPv6(t *testing.T) {
	for in, want := range map[string]string{
		"fe800000000000000000000000000001": "fe80::1",
		"20010db8000100000000000000000000": "2001:db8:1::",
		"00000000000000000000000000000000": "::",
		"20010db8000000010000000000000001": "2001:db8:0:1::1",
		"20010db8000000000001000000000001": "2001:db8::1:0:0:1",
	} {
		if got := hexIPv6(in); got != want {
			t.Errorf("hexIPv6(%s) = %s, want %s", in, got, want)
		}
	}
}
