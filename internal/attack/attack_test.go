package attack

import (
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestTheEmbeddedFilesParse(t *testing.T) {
	tab, err := Parse(tableText, tagsText)
	if err != nil {
		t.Fatal(err)
	}
	if tab.Version != "20.1" || len(tab.Order) != 511 {
		t.Errorf("version %q, %d techniques; a new release changes these on purpose (docs/ATTACK.md)", tab.Version, len(tab.Order))
	}
	id := regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)
	for i, k := range tab.Order {
		if !id.MatchString(k) {
			t.Errorf("odd ID %q", k)
		}
		if i > 0 && tab.Order[i-1] >= k {
			t.Errorf("the table is not sorted at %s", k)
		}
		if parent, _, sub := strings.Cut(k, "."); sub && !strings.HasPrefix(tab.Techniques[k].Name, tab.Techniques[parent].Name+": ") {
			t.Errorf("%s is not named after its parent %s", k, parent)
		}
	}
	if Embedded().Version != "20.1" {
		t.Error("the daemon's copy did not load")
	}
}

// Every ID in the detector map is in the table (Parse refuses one that is not; this says so in a test of its own).
func TestEveryMappedIDIsInTheTable(t *testing.T) {
	tab := Embedded()
	if len(tab.Tags) == 0 {
		t.Fatal("no detector map")
	}
	for _, tag := range tab.Tags {
		for _, id := range tag.IDs {
			if _, ok := tab.Techniques[id]; !ok {
				t.Errorf("%s: %s is not in the table", tag.Detector, id)
			}
		}
	}
}

// Each map row names a detector Heimdall has (an alert's detector_id); a typo would silently tag nothing.
func TestEveryMappedDetectorExists(t *testing.T) {
	known := map[string]bool{}
	src, _ := os.ReadFile("../explain/explain.go")
	for _, m := range regexp.MustCompile(`case "([a-z-]+)":`).FindAllStringSubmatch(string(src), -1) {
		known[m[1]] = true
	}
	for _, tag := range Embedded().Tags {
		if !known[tag.Detector] {
			t.Errorf("%q is not a detector explain.For knows", tag.Detector)
		}
	}
}

func TestTags(t *testing.T) {
	for _, c := range []struct {
		det, kind string
		fields    map[string]string
		want      []string
	}{
		{"lan-watch", "router_changed", nil, []string{"T1557.002"}},
		{"lan-watch", "new_listener", nil, nil},
		{"remote-access", "new_connection", map[string]string{"ra_kind": "tunnel"}, []string{"T1572"}},
		{"remote-access", "remote_access", map[string]string{"ra_kind": "c2"}, nil},
		{"remote-access", "remote_access", map[string]string{"signal": "tunnel"}, []string{"T1572"}},
		{"inbound", "firewall_block", map[string]string{"ports": "12"}, []string{"T1046"}},
		{"inbound", "firewall_block", map[string]string{"ports": ""}, nil},
		{"inbound", "login_failure", map[string]string{"block_command": "sudo ufw ..."}, []string{"T1110"}},
		{"limbo-network", "net.anomaly", map[string]string{"reason": "host_probe"}, nil},
		{"injection-phrase", "message", nil, nil},
		{"", "", nil, nil},
	} {
		if got := For(c.det, c.kind, c.fields); !reflect.DeepEqual(got, c.want) {
			t.Errorf("For(%q, %q, %v) = %v, want %v", c.det, c.kind, c.fields, got, c.want)
		}
	}
	got := Names([]string{"T1557.002", "T9999", "T1110"})
	want := []Ref{{"T1557.002", "Adversary-in-the-Middle: ARP Cache Poisoning"}, {"T1110", "Brute Force"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Names = %v", got)
	}
	if Names(nil) != nil {
		t.Error("no IDs, no names")
	}
}

func TestParseRefusesWhatIsNotOurs(t *testing.T) {
	table := "# version 1\nT1000\tA\tdiscovery\n"
	for _, c := range []struct{ table, tags string }{
		{"T1000\tA\tdiscovery\n", ""},                     // no version
		{"# version 1\n", ""},                             // no technique
		{"# version 1\nT1000\tA\n", ""},                   // two columns
		{table + "T1000\tB\tdiscovery\n", ""},             // twice
		{table, "x\t*\t*\tT1001\n"},                       // not in the table
		{table, "x\t*\t*\n"},                              // three columns
		{table, "*\t*\t*\tT1000\n"},                       // any detector
		{table, "x\t*\tkey\tT1000\n"},                     // no value
		{table, "x\t*\t=v\tT1000\n"},                      // no key
		{table, "x\t*\t*\tT1000,\n"},                      // empty ID
		{table + "T1000.001\tA: B\tdiscovery,impact", ""}, // fine: no newline at the end
	} {
		_, err := Parse(c.table, c.tags)
		if (err == nil) != strings.HasPrefix(c.table, table+"T1000.001") {
			t.Errorf("Parse(%q, %q): %v", c.table, c.tags, err)
		}
	}
}
