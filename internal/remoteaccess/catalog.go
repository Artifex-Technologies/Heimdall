// Package remoteaccess knows the remote-access, tunnel and command-and-control tools Heimdall looks for (docs/REMOTE_ACCESS.md):
// a catalog matched by package, program, Go module (from the program's own build info), network interface and service, and
// the owner's approvals. A tool on this list is only a danger when it holds a socket or can come back after a restart; the
// sources report those moments and the remote-access detector judges them.
package remoteaccess

import (
	"debug/buildinfo"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

//go:embed remote-access.json
var builtin []byte

// Provider is one tool.
type Provider struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Kind      string   `json:"kind"` // mesh-vpn | tunnel | remote-desktop | rmm | anonymizer | c2
	Packages  []string `json:"packages"`
	Exes      []string `json:"exes"`
	GoModules []string `json:"go_modules"`
	Units     []string `json:"units"`
	Ifaces    []string `json:"ifaces"` // shell patterns (zt*)
	Ports     []int    `json:"ports"`
}

// Approvable: a command-and-control implant never is.
func (p Provider) Approvable() bool { return p.Kind != "c2" }

type Catalog struct {
	Providers []Provider `json:"providers"`
}

// Builtin is the catalog compiled into heimdalld.
func Builtin() Catalog {
	c, err := Parse(builtin)
	if err != nil {
		panic("remote-access catalog: " + err.Error())
	}
	return c
}

// Parse reads a catalog and refuses an entry without an id, a kind, or anything to match it by.
func Parse(data []byte) (Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(data, &c); err != nil {
		return c, err
	}
	seen := map[string]bool{}
	for i, p := range c.Providers {
		if p.ID == "" || p.Kind == "" || seen[p.ID] {
			return c, fmt.Errorf("entry %d: needs a unique id and a kind", i+1)
		}
		if len(p.Packages)+len(p.Exes)+len(p.GoModules)+len(p.Units)+len(p.Ifaces) == 0 {
			return c, fmt.Errorf("%s: nothing to recognise it by", p.ID)
		}
		seen[p.ID] = true
	}
	return c, nil
}

func (c Catalog) find(match func(Provider) bool) *Provider {
	for i := range c.Providers {
		if match(c.Providers[i]) {
			return &c.Providers[i]
		}
	}
	return nil
}

func has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func (c Catalog) MatchPackage(name string) *Provider {
	return c.find(func(p Provider) bool { return has(p.Packages, name) })
}

func (c Catalog) MatchUnit(name string) *Provider {
	return c.find(func(p Provider) bool { return has(p.Units, name) })
}

// MatchIface matches an interface name against the providers' patterns (zt*, tailscale*).
func (c Catalog) MatchIface(name string) *Provider {
	return c.find(func(p Provider) bool {
		for _, pat := range p.Ifaces {
			if ok, _ := filepath.Match(pat, name); ok {
				return true
			}
		}
		return false
	})
}

// MatchExe matches a running program by its file name or its process name.
func (c Catalog) MatchExe(exePath, comm string) *Provider {
	base := filepath.Base(strings.TrimSuffix(exePath, " (deleted)"))
	return c.find(func(p Provider) bool { return has(p.Exes, base) || (comm != "" && has(p.Exes, comm)) })
}

// MatchGoModules matches a Go program's main module and its dependencies (module paths from its build info).
func (c Catalog) MatchGoModules(mods []string) *Provider {
	return c.find(func(p Provider) bool {
		for _, want := range p.GoModules {
			for _, m := range mods {
				if m == want || strings.HasPrefix(m, want+"/") {
					return true
				}
			}
		}
		return false
	})
}

// goModules reads a program's Go build info (main module and dependencies); nil for a program that is not Go.
func goModules(path string) (main, deps []string) {
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return nil, nil
	}
	for _, d := range bi.Deps {
		deps = append(deps, d.Path)
	}
	return []string{bi.Main.Path, bi.Path}, deps
}

type identified struct {
	p   *Provider
	sig string
}

// Identifier matches running programs, reading each executable's Go build info once (cached by path, size and time), so a
// renamed Go tool is still recognised.
type Identifier struct {
	Catalog Catalog
	mu      sync.Mutex
	cache   map[string]identified
}

func (id *Identifier) Identify(exePath, comm string) (*Provider, string) {
	if p := id.Catalog.MatchExe(exePath, comm); p != nil {
		return p, "exe"
	}
	path := strings.TrimSuffix(exePath, " (deleted)")
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return nil, ""
	}
	key := fmt.Sprintf("%s|%d|%d", path, fi.Size(), fi.ModTime().UnixNano())
	id.mu.Lock()
	defer id.mu.Unlock()
	if id.cache == nil {
		id.cache = map[string]identified{}
	}
	if r, ok := id.cache[key]; ok {
		return r.p, r.sig
	}
	// The tool itself ("gomod"), or a program that only contains some of a tool's code ("gomod-dep": ngrok's library or
	// Tailscale's tsnet embed a tunnel, but some programs borrow one small utility package).
	main, deps := goModules(path)
	r := classify(id.Catalog, main, deps)
	id.cache[key] = r
	return r.p, r.sig
}

func classify(c Catalog, main, deps []string) identified {
	if p := c.MatchGoModules(main); p != nil {
		return identified{p, "gomod"}
	}
	if p := c.MatchGoModules(deps); p != nil {
		return identified{p, "gomod-dep"}
	}
	return identified{}
}

// Approvals is the owner's list of approved provider ids (/etc/heimdall/remote-access-approved.json, written by
// `heimdalld remote approve`), read again when the file changes.
type Approvals struct {
	Path  string
	mu    sync.Mutex
	mtime int64
	ids   map[string]bool
}

func (a *Approvals) Approved(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	fi, err := os.Stat(a.Path)
	if err != nil {
		a.ids, a.mtime = nil, 0
		return false
	}
	if fi.ModTime().UnixNano() != a.mtime {
		a.ids, a.mtime = map[string]bool{}, fi.ModTime().UnixNano()
		var f struct {
			Approved []string `json:"approved"`
		}
		if b, err := os.ReadFile(a.Path); err == nil && json.Unmarshal(b, &f) == nil {
			for _, x := range f.Approved {
				a.ids[x] = true
			}
		}
	}
	return a.ids[id]
}

// SetApproved writes the approvals file (root): ids added or removed.
func SetApproved(path, id string, approve bool) ([]string, error) {
	var f struct {
		Approved []string `json:"approved"`
	}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &f)
	}
	set := map[string]bool{}
	for _, x := range f.Approved {
		set[x] = true
	}
	if approve {
		set[id] = true
	} else {
		delete(set, id)
	}
	f.Approved = f.Approved[:0]
	for x := range set {
		f.Approved = append(f.Approved, x)
	}
	sort.Strings(f.Approved)
	b, _ := json.MarshalIndent(f, "", " ")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return nil, err
	}
	return f.Approved, os.Rename(tmp, path)
}
