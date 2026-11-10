package parity

import (
	"fmt"
	"math/rand"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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
		"remote-access", "tool-rules", "agent-baseline", "rule-draft", "incident", "grant-request", "something-new"}
	for _, id := range ids {
		for _, sev := range []string{"info", "warning", "critical"} {
			f.Explain = append(f.Explain, ExplainCase{Detector: id, Severity: sev, Text: explain.For(id, sev, nil)})
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
		{"lan-watch", "critical", map[string]string{"new_mac": "aa:bb"}},
		{"incident", "warning", map[string]string{"keys": "session s1", "detectors": "injection-phrase, credential-shape"}},
		{"rule-draft", "info", map[string]string{"rule": "heimdall_x", "rule_id": "7"}},
		{"limbo-guest", "critical", map[string]string{"guest": "lab"}},
	} {
		f.Explain = append(f.Explain, ExplainCase{Detector: c.id, Severity: c.sev, Fields: c.fields, Text: explain.For(c.id, c.sev, c.fields)})
	}
	return f
}
