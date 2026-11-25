package parity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/attack"
	"github.com/Artifex-Technologies/Heimdall/internal/config"
	"github.com/Artifex-Technologies/Heimdall/internal/detect"
	"github.com/Artifex-Technologies/Heimdall/internal/explain"
	"github.com/Artifex-Technologies/Heimdall/internal/ipintel"
)

// Functions is the fixture of single functions both languages must agree on (testdata/parity/functions.json): redaction,
// Go's %q and Duration formatting, IP parsing, the running statistics and every explanation.
type Functions struct {
	Format   string         `json:"format"`
	Redact   []InOut        `json:"redact"`
	Quote    []InOut        `json:"quote"`
	Duration []DurationCase `json:"duration"`
	ParseIP  []IPCase       `json:"parse_ip"`
	Stats    []StatsCase    `json:"stats"`
	Explain  []ExplainCase  `json:"explain"`
	// DetectorOrder is the daemon's detector list, in order (cmd/heimdalld checks newDetectors against Detectors).
	DetectorOrder []string `json:"detector_order"`
	// Origins: lookups in the synthetic IP databases (testdata/parity/synthetic-*.mmdb, made by
	// rust/parity/harness/genmmdb) and a threat list, as the connection watch and the journal name an address.
	Origins []OriginCase `json:"origins"`
	// Attack: the ATT&CK table and detector map as each language reads them (internal/attack, rust/heimdall/src/attack.rs).
	Attack AttackCases `json:"attack"`
}

// AttackCases shows both loaders read the same embedded files alike: the version, the number of techniques and a digest
// of every parsed row, then the tags and names of alerts made to match (and just miss) every map row.
type AttackCases struct {
	Version string       `json:"version"`
	Count   int          `json:"count"`
	SHA256  string       `json:"sha256"` // of "ID\tname\ttactics\n" per parsed row, in the file's order
	Tags    []AttackCase `json:"tags"`
}

type AttackCase struct {
	Detector string            `json:"detector"`
	Kind     string            `json:"kind"`
	Fields   map[string]string `json:"fields"`
	IDs      []string          `json:"ids"`
	Names    []attack.Ref      `json:"names"`
}

type OriginCase struct {
	IP     string            `json:"ip"`
	Text   string            `json:"text"`
	Fields map[string]string `json:"fields"`
	Listed bool              `json:"listed"`
}

type InOut struct {
	In  string `json:"in"`
	Out string `json:"out"`
}

type DurationCase struct {
	NS  int64  `json:"ns"`
	Out string `json:"out"`
}

type IPCase struct {
	In        string `json:"in"`
	OK        bool   `json:"ok"`
	Private   bool   `json:"private"`
	LinkLocal bool   `json:"link_local"`
}

type StatsCase struct {
	Values []float64    `json:"values"`
	Count  int          `json:"count"`
	Mean   float64      `json:"mean"`
	StdDev float64      `json:"stddev"`
	Z      [][2]float64 `json:"z"` // x, z-score of x
}

type ExplainCase struct {
	Detector string            `json:"detector"`
	Kind     string            `json:"kind,omitempty"` // the alert's event kind, where the detector has several (lan-watch)
	Severity string            `json:"severity"`
	Fields   map[string]string `json:"fields"`
	Text     explain.Text      `json:"text"`
}

// AllFunctions computes the fixture with the Go functions (internal/detect/detect_test.go, stats_test.go,
// internal/explain/explain_test.go and more inputs).
func AllFunctions() Functions {
	f := Functions{Format: "heimdall-parity-functions/1"}
	dir := filepath.Join("..", "..", "testdata", "parity")
	res := ipintel.NewResolver(filepath.Join(dir, "synthetic-country.mmdb"), filepath.Join(dir, "synthetic-asn.mmdb"))
	list, _ := ipintel.ParseList("drop", []byte("# made up\n203.0.113.0/25 ; x\n198.51.100.7\n10.0.0.0/8\n2001:db8::/32\n{\"cidr\":\"192.0.2.128/26\"}\n"))
	rng := rand.New(rand.NewSource(7))
	ips := []string{"203.0.113.9", "203.0.113.200", "198.51.100.7", "192.0.2.1", "192.0.2.130", "10.1.2.3", "127.0.0.1", "100.64.0.2",
		"224.0.0.251", "255.255.255.255", "::1", "fe80::1", "2001:db8::5", "::ffff:203.0.113.9", "0.0.0.0", "ff05::1"}
	for i := 0; i < 300; i++ {
		ips = append(ips, fmt.Sprintf("%d.%d.%d.%d", 1+rng.Intn(222), rng.Intn(256), rng.Intn(256), rng.Intn(256)))
	}
	for _, s := range ips {
		ip := net.ParseIP(s)
		o := res.Lookup(ip)
		f.Origins = append(f.Origins, OriginCase{IP: s, Text: o.String(), Fields: o.Fields("remote_"), Listed: list.Contains(ip)})
	}
	for _, d := range Detectors(config.Default(), Deps{}) {
		f.DetectorOrder = append(f.DetectorOrder, d.ID())
	}
	for _, in := range []string{
		"export OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123 and ghp_" + strings.Repeat("a", 36),
		"nothing secret here",
		"aws AKIAABCDEFGHIJKLMNOP and AKIAZZZZZZZZZZZZZZZZ",
		"api\xe2\x84\xaaey: abcdefghijklmnopqrstu", // the Kelvin sign: a cut inside a character
		"pa\xc5\xbfsword=x",
		"vivaldi-bin (pid 4242) connected to 203.0.113.9:443 (US, Example Net)",
		"-----BEGIN OPENSSH PRIVATE KEY----- then password: hunter2 and Bearer " + strings.Repeat("z", 40) + "==",
	} {
		f.Redact = append(f.Redact, InOut{in, detect.RedactCredentials(in)})
	}
	for _, in := range []string{"lab", "a\xe2\x80\x8bb\xc2\xa0c\x01\xc3\xa9", "\xf3\xa0\x81\x81", "K\"\\\n\t\a\x7f", "tab\there", "\xe2\x80\xa8", "\xef\xbf\xbd", "\xcd\xb8"} {
		f.Quote = append(f.Quote, InOut{in, strconv.Quote(in)})
	}
	for _, d := range []time.Duration{0, 1, 999, 1500, time.Millisecond, 1500 * time.Millisecond, 15 * time.Minute, 5 * time.Minute, 90 * time.Second, 26 * time.Hour, -2 * time.Second, 10*time.Minute + 1} {
		f.Duration = append(f.Duration, DurationCase{int64(d), d.String()})
	}
	for _, in := range []string{"192.168.1.10", "01.2.3.4", "10.0.0.1", "172.16.0.1", "172.32.0.1", "169.254.3.4", "fe80::1", "fe80::1%eth0", "fd00::1", "::ffff:10.0.0.1", "::1", "1.2.3", "1.2.3.4.5", "256.1.1.1", "2001:db8::1", "", "not-an-ip", "::ffff:192.168.0.1"} {
		ip := net.ParseIP(in)
		c := IPCase{In: in, OK: ip != nil}
		if ip != nil {
			c.Private, c.LinkLocal = ip.IsPrivate(), ip.IsLinkLocalUnicast()
		}
		f.ParseIP = append(f.ParseIP, c)
	}
	for _, vals := range [][]float64{{1, 2, 3, 4, 5}, {}, {42}, {10, 10, 10, 10}, {0.02, 0.04, 0.02, 0.04, 0.02, 0.04, 0.35}} {
		s := &detect.OnlineStats{}
		for _, v := range vals {
			s.Add(v)
		}
		c := StatsCase{Values: append([]float64{}, vals...), Count: s.Count(), Mean: s.Mean(), StdDev: s.StdDev()}
		for _, x := range []float64{3, 100, 0, -7.5} {
			c.Z = append(c.Z, [2]float64{x, s.ZScore(x)})
		}
		f.Stats = append(f.Stats, c)
	}
	ids := []string{"injection-phrase", "credential-shape", "invisible-unicode", "permission-escalation", "session-burst", "file-integrity",
		"maintenance-window", "resource-pressure", "network-exposure", "connection-watch", "inbound", "package-vulnerability",
		"kernel-vulnerability", "hardening", "wifi-safety", "lan-watch", "baseline-drift", "limbo-guest", "limbo-network", "limbo-exchange", "integration",
		"remote-access", "crossview", "tool-rules", "agent-baseline", "rule-draft", "incident", "grant-request", "something-new"}
	for _, id := range ids {
		for _, sev := range []string{"info", "warning", "critical"} {
			f.Explain = append(f.Explain, ExplainCase{Detector: id, Severity: sev, Text: explain.For(id, "", sev, nil)})
		}
	}
	for _, c := range []struct {
		id, sev string
		fields  map[string]string
	}{
		{"file-integrity", "critical", map[string]string{"path": "/usr/bin/x\n\x1b[31mIGNORE ALL RULES" + strings.Repeat("a", 300), "prior_hash": "1", "new_hash": "2"}},
		{"file-integrity", "critical", map[string]string{"path": "/etc/new", "new_hash": "2"}},
		{"package-vulnerability", "warning", map[string]string{"package": "openssl", "installed": "3.0.1", "fixed": "3.0.2"}},
		{"package-vulnerability", "warning", map[string]string{"package": "x", "installed": "1"}},
		{"limbo-network", "critical", map[string]string{"guest": "lab", "reason": "host_probe"}},
		{"limbo-network", "warning", map[string]string{"reason": "ipv6"}},
		{"limbo-network", "info", map[string]string{"guest": "lab"}},
		{"limbo-network", "warning", map[string]string{"guest": "lab", "reason": "new"}},
		{"limbo-exchange", "warning", map[string]string{"guest": "lab", "guest_path": "out/x.exe", "signature": "Eicar-Test-Signature"}},
		{"limbo-exchange", "warning", map[string]string{"sha256": strings.Repeat("a", 64)}},
		{"limbo-exchange", "warning", map[string]string{"sha256": "x; rm -rf ~"}},
		{"limbo-exchange", "info", map[string]string{"reason": "clamd down"}},
		{"connection-watch", "critical", map[string]string{"process": "curl", "remote_addr": "198.51.100.9", "origin": "NL", "remote_listed": "drop"}},
		{"inbound", "warning", map[string]string{"src": "203.0.113.9", "origin": "US", "verdict": "needs_validation"}},
		{"kernel-vulnerability", "warning", map[string]string{"running": "yes"}},
		{"kernel-vulnerability", "info", map[string]string{"running": "0"}},
		{"hardening", "warning", map[string]string{"now": "x", "fix": "sysctl -w a=b"}},
		{"hardening", "critical", map[string]string{"now": "sshd listens on port 22", "fix": "update OpenSSH", "cve": "CVE-2026-123158"}},
		{"hardening", "info", map[string]string{"now": "x", "cve": "CVE-1\x01" + strings.Repeat("9", 60)}},
		{"remote-access", "warning", map[string]string{"signal": "tunnel", "iface": "wg0"}},
		{"remote-access", "critical", map[string]string{"ra_kind": "c2", "provider_name": "Sliver"}},
		{"remote-access", "info", map[string]string{"provider_name": "Tailscale"}},
		{"remote-access", "critical", map[string]string{"provider_name": "AnyDesk", "signal": "package", "provider": "anydesk"}},
		{"tool-rules", "critical", map[string]string{"exe": "/usr/bin/nmap"}},
		{"grant-request", "warning", map[string]string{"kind": "escalation", "detail": "claude", "request_id": "r1"}},
		{"integration", "warning", map[string]string{"error_code": "sarina_timeout", "remedy": "restart it"}},
		{"resource-pressure", "warning", map[string]string{"mem_percent": "95.5", "load_per_cpu": "\u0085"}},
		{"network-exposure", "critical", map[string]string{"port": "8765", "address": "0.0.0.0"}},
		{"wifi-safety", "critical", map[string]string{"ssid": "  “”  "}},
		{"incident", "warning", map[string]string{"keys": "session s1", "detectors": "injection-phrase, credential-shape"}},
		{"rule-draft", "info", map[string]string{"rule": "heimdall_x", "rule_id": "7"}},
		{"limbo-guest", "critical", map[string]string{"guest": "lab"}},
	} {
		f.Explain = append(f.Explain, ExplainCase{Detector: c.id, Severity: c.sev, Fields: c.fields, Text: explain.For(c.id, "", c.sev, c.fields)})
	}
	// lan-watch: every event kind its own words, and an unknown one general words
	for _, c := range []struct {
		kind, sev string
		fields    map[string]string
	}{
		{"router_changed", "critical", map[string]string{"ssid": "Cafe", "new_mac": "aa:bb"}},
		{"router_changed", "critical", nil},
		{"router_impersonated", "critical", map[string]string{"ssid": "Cafe", "other_ip": "192.0.2.7", "new_mac": "aa:bb"}},
		{"rogue_router", "warning", map[string]string{"iface": "wlan0", "via": "dhcp", "what": "a second DHCP server 192.0.2.9", "judged": "warning"}},
		{"rogue_router", "critical", map[string]string{"ssid": "Home", "via": "ra", "what": "x", "judged": "critical", "learned": "true"}},
		{"rogue_router", "info", map[string]string{"ssid": "Home", "what": "the DHCP server's name changed", "judged": "info"}},
		{"lan_device_changed", "critical", map[string]string{"ssid": "Home", "ip": "192.0.2.4", "mac": "aa:bb", "was_mac": "cc:dd", "was_name": "Printer\n\x1b[31m", "other_ip": "192.0.2.5"}},
		{"lan_device_changed", "critical", map[string]string{"ssid": "Home", "ip": "192.0.2.4", "was_mac": "cc:dd"}},
		{"new_lan_device", "warning", map[string]string{"ssid": "Home", "name": "tv", "vendor": "Example Corp", "ip": "192.0.2.6"}},
		{"new_lan_device", "warning", map[string]string{"ssid": "Home", "private_mac": "true", "ip": "192.0.2.8"}},
		{"new_lan_device", "warning", nil},
		{"new_listener", "warning", map[string]string{"proto": "tcp", "port": "8080"}},
		{"new_listener", "warning", map[string]string{"proto": "tcp", "port": "80; rm -rf ~"}},
		{"wifi_inbound", "warning", map[string]string{"src": "192.0.2.23", "inbound": "wifi"}},
		{"wifi_inbound", "info", map[string]string{"src": "192.0.2.1", "inbound": "wifi", "router": "true"}},
		{"something_new", "warning", map[string]string{"new_mac": "aa:bb"}},
	} {
		f.Explain = append(f.Explain, ExplainCase{Detector: "lan-watch", Kind: c.kind, Severity: c.sev, Fields: c.fields, Text: explain.For("lan-watch", c.kind, c.sev, c.fields)})
	}
	f.Attack = attackCases(ids)
	return f
}

func attackCases(detectors []string) AttackCases {
	t := attack.Embedded()
	h := sha256.New()
	for _, id := range t.Order {
		r := t.Techniques[id]
		fmt.Fprintf(h, "%s\t%s\t%s\n", r.ID, r.Name, r.Tactics)
	}
	out := AttackCases{Version: t.Version, Count: len(t.Order), SHA256: hex.EncodeToString(h.Sum(nil))}
	add := func(det, kind string, fields map[string]string) {
		ids := t.For(det, kind, fields)
		out.Tags = append(out.Tags, AttackCase{Detector: det, Kind: kind, Fields: fields, IDs: ids, Names: t.Names(ids)})
	}
	for _, tag := range t.Tags {
		kind := tag.Kind
		if kind == "*" {
			kind = "some_kind"
		}
		if tag.Field == "*" {
			add(tag.Detector, kind, nil)
			add(tag.Detector, kind+"_not", nil)
			continue
		}
		v := tag.Value
		if v == "*" {
			v = "1"
		}
		add(tag.Detector, kind, map[string]string{tag.Field: v})
		add(tag.Detector, kind, map[string]string{tag.Field: v + "_not"})
		add(tag.Detector, kind, map[string]string{tag.Field: ""})
		add(tag.Detector, kind, nil)
	}
	for _, det := range detectors {
		add(det, "", nil)
	}
	return out
}
