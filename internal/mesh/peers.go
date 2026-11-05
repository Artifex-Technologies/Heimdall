package mesh

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
)

// DefaultPeers is the owner's list of enrolled peers (root's file).
const DefaultPeers = "/etc/heimdall/mesh-peers.json"

// Peer is another Heimdall the owner enrolled: a name for display, its key's fingerprint, and where it listens (an IP
// address and port: never a host name, so no DNS answer can redirect alerts).
type Peer struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	Address     string `json:"address"`
}

var (
	nameRx = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	fpRx   = regexp.MustCompile(`^hm1-[a-z2-7]{32}$`)
)

// Validate checks a peer entry.
func (p Peer) Validate() error {
	if !nameRx.MatchString(p.Name) {
		return errors.New("name: 1-32 of a-z, 0-9 and -, starting with a letter or digit")
	}
	if !fpRx.MatchString(p.Fingerprint) {
		return errors.New("fingerprint: hm1- and 32 characters, as `heimdalld mesh id` prints it on that computer")
	}
	host, port, err := net.SplitHostPort(p.Address)
	if err != nil || net.ParseIP(host) == nil || port == "" || port == "0" {
		return errors.New("address: an IP address and port, e.g. 100.64.0.2:8931 (no host names)")
	}
	if ip := net.ParseIP(host); ip.IsUnspecified() || ip.IsMulticast() {
		return errors.New("address: not a usable peer address")
	}
	return nil
}

// LoadPeers reads the enrolled peers. A missing file is no peers. The file decides whom Heimdall trusts, so it is refused
// when anyone but root (or the reading account itself, for tests) owns it or when others can write it; an invalid entry is
// skipped, never guessed.
func LoadPeers(path string) ([]Peer, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || (st.Uid != 0 && int(st.Uid) != os.Geteuid()) || fi.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%s must be root's and writable by nobody else", path)
	}
	var ps []Peer
	if err := json.NewDecoder(f).Decode(&ps); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var out []Peer
	for _, p := range ps {
		if p.Validate() == nil {
			out = append(out, p)
		}
	}
	return out, nil
}

// SetPeer adds or replaces (by name) one peer, or removes it when remove is set, and writes the file (0644).
func SetPeer(path string, p Peer, remove bool) ([]Peer, error) {
	if !remove {
		if err := p.Validate(); err != nil {
			return nil, err
		}
	}
	ps, err := LoadPeers(path)
	if err != nil {
		return nil, err
	}
	var out []Peer
	for _, o := range ps {
		if o.Name != p.Name && (remove || o.Fingerprint != p.Fingerprint) {
			out = append(out, o)
		}
	}
	if !remove {
		out = append(out, p)
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".mesh-peers-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return nil, err
	}
	tmp.Chmod(0o644)
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	return out, os.Rename(tmp.Name(), path)
}

// IsPeerHost reports whether ip is the address of an enrolled peer (for the connection watch: Heimdall talking to its own
// peers is expected, not an ecosystem program breaking the loopback rule).
func IsPeerHost(path, ip string) (string, bool) {
	ps, _ := LoadPeers(path)
	want := net.ParseIP(ip)
	for _, p := range ps {
		host, _, _ := net.SplitHostPort(p.Address)
		if h := net.ParseIP(host); h != nil && want != nil && h.Equal(want) {
			return p.Name, true
		}
	}
	return "", false
}
