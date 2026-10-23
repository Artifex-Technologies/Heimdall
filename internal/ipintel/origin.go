package ipintel

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Origin is where an address belongs, as far as the database knows.
type Origin struct {
	Scope       string // "public", or why it is not: "private", "loopback", "link-local", "carrier-grade NAT", "multicast", "reserved"
	CountryCode string // e.g. "NL"
	Country     string // e.g. "Netherlands"
	ASN         string // e.g. "AS16509"
	ASName      string // the network's owner, e.g. "Amazon.com, Inc."
	ASDomain    string
}

// String is a short description for an alert: "Netherlands, AS16509 Amazon.com, Inc." or "private network".
func (o Origin) String() string {
	if o.Scope != "public" {
		return o.Scope + " network"
	}
	var parts []string
	if o.Country != "" {
		parts = append(parts, o.Country)
	} else if o.CountryCode != "" {
		parts = append(parts, o.CountryCode)
	}
	if o.ASN != "" || o.ASName != "" {
		parts = append(parts, strings.TrimSpace(o.ASN+" "+o.ASName))
	}
	if len(parts) == 0 {
		return "unknown origin"
	}
	return strings.Join(parts, ", ")
}

// Fields are the alert fields for this origin (empty values left out).
func (o Origin) Fields(prefix string) map[string]string {
	out := map[string]string{}
	for k, v := range map[string]string{"scope": o.Scope, "country_code": o.CountryCode, "country": o.Country, "asn": o.ASN, "as_name": o.ASName, "as_domain": o.ASDomain} {
		if v != "" {
			out[prefix+k] = v
		}
	}
	return out
}

var cgnat = mustCIDR("100.64.0.0/10")

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// scope says whether an address can have an origin at all.
func scope(ip net.IP) string {
	switch {
	case ip.IsLoopback():
		return "loopback"
	case ip.IsPrivate():
		return "private"
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return "link-local"
	case cgnat.Contains(ip):
		return "carrier-grade NAT"
	case ip.IsMulticast(), ip.IsInterfaceLocalMulticast():
		return "multicast"
	case ip.IsUnspecified(), !ip.IsGlobalUnicast():
		return "reserved"
	}
	return "public"
}

// FromRecord reads the fields IPinfo Lite uses (country, country_code, asn, as_name, as_domain), or the
// GeoLite2/DB-IP shape (country.iso_code, country.names.en, autonomous_system_number/organization).
func FromRecord(m map[string]any) Origin {
	o := Origin{Scope: "public"}
	str := func(v any) string { s, _ := v.(string); return s }
	o.CountryCode = str(m["country_code"])
	o.Country = str(m["country"])
	if c, ok := m["country"].(map[string]any); ok {
		o.Country = ""
		o.CountryCode = str(c["iso_code"])
		if n, ok := c["names"].(map[string]any); ok {
			o.Country = str(n["en"])
		}
	}
	o.ASN = str(m["asn"])
	if n, ok := m["autonomous_system_number"].(uint64); ok && n > 0 {
		o.ASN = fmt.Sprintf("AS%d", n)
	}
	o.ASName = str(m["as_name"])
	if o.ASName == "" {
		o.ASName = str(m["autonomous_system_organization"])
	}
	o.ASDomain = str(m["as_domain"])
	return o
}

// Resolver answers origins from the first database file found among its paths. It notices a replaced file
// (a monthly update) and reopens it, and works without any file: public addresses then have an unknown origin.
type Resolver struct {
	paths []string
	mu    sync.Mutex
	dbs   []*DB
	mtime []time.Time
	check time.Time
}

// NewResolver uses these files, in order (for example a country+ASN file, then an ASN-only one).
func NewResolver(paths ...string) *Resolver {
	return &Resolver{paths: paths}
}

func (r *Resolver) reload() {
	if time.Since(r.check) < time.Minute && r.dbs != nil {
		return
	}
	r.check = time.Now()
	var dbs []*DB
	var mt []time.Time
	changed := len(r.mtime) != 0 && len(r.paths) != len(r.mtime)
	for i, p := range r.paths {
		st, err := os.Stat(p)
		if err != nil {
			if i < len(r.mtime) && !r.mtime[i].IsZero() {
				changed = true
			}
			mt = append(mt, time.Time{})
			continue
		}
		mt = append(mt, st.ModTime())
		if i >= len(r.mtime) || !st.ModTime().Equal(r.mtime[i]) {
			changed = true
		}
	}
	if r.dbs != nil && !changed {
		return
	}
	for _, p := range r.paths {
		if db, err := Open(p); err == nil {
			dbs = append(dbs, db)
		}
	}
	r.dbs, r.mtime = dbs, mt
}

// Available says whether any database file could be read.
func (r *Resolver) Available() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reload()
	return len(r.dbs) > 0
}

// Lookup returns the origin of an address. Non-public addresses are answered without a database.
func (r *Resolver) Lookup(ip net.IP) Origin {
	o := Origin{Scope: scope(ip)}
	if o.Scope != "public" {
		return o
	}
	r.mu.Lock()
	r.reload()
	dbs := r.dbs
	r.mu.Unlock()
	for _, db := range dbs {
		m, err := db.Lookup(ip)
		if err != nil || m == nil {
			continue
		}
		f := FromRecord(m)
		if o.CountryCode == "" {
			o.CountryCode, o.Country = f.CountryCode, f.Country
		}
		if o.ASN == "" && o.ASName == "" {
			o.ASN, o.ASName, o.ASDomain = f.ASN, f.ASName, f.ASDomain
		}
	}
	return o
}

// BlockCommand is the firewall command that would block an address, for the owner to run (Heimdall never runs it).
func BlockCommand(ip net.IP) string {
	return "sudo ufw insert 1 deny from " + ip.String() + " comment 'blocked after a Heimdall alert'"
}
