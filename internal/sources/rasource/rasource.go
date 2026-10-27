// Package rasource reports remote-access tools by what is on the computer rather than what it does: a package from the
// remote-access catalog being installed (read again only when pacman's database folder changes), and a tunnel interface
// appearing (a catalog interface such as tailscale0 or zt*, or any new WireGuard, TUN or TAP device). Programs holding
// connections are matched by the connection watcher (netsource) with the same catalog. Two directory listings per poll; no
// packet is read.
package rasource

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
	"github.com/Artifex-Technologies/Heimdall/internal/remoteaccess"
)

type Watcher struct {
	Catalog   remoteaccess.Catalog
	PacmanDir string // /var/lib/pacman/local
	NetDir    string // /sys/class/net

	pkgSeen   map[string]bool
	pkgMtime  int64
	ifaceSeen map[string]bool
	started   bool
}

func New(c remoteaccess.Catalog) *Watcher {
	return &Watcher{Catalog: c, PacmanDir: "/var/lib/pacman/local", NetDir: "/sys/class/net"}
}

// PackageName is the name in a pacman database entry ("tailscale-1.104.2-1" -> "tailscale").
func PackageName(entry string) string {
	parts := strings.Split(entry, "-")
	if len(parts) < 3 {
		return ""
	}
	return strings.Join(parts[:len(parts)-2], "-")
}

func event(text string, f map[string]string) detect.Event {
	return detect.Event{Source: "remote-access", Time: time.Now(), Kind: "remote_access", Text: text, Fields: f}
}

func (w *Watcher) packages() []detect.Event {
	fi, err := os.Stat(w.PacmanDir)
	if err != nil || fi.ModTime().UnixNano() == w.pkgMtime {
		return nil
	}
	w.pkgMtime = fi.ModTime().UnixNano()
	entries, err := os.ReadDir(w.PacmanDir)
	if err != nil {
		return nil
	}
	now := map[string]bool{}
	var out []detect.Event
	for _, e := range entries {
		name := PackageName(e.Name())
		if name == "" {
			continue
		}
		now[name] = true
		if w.pkgSeen[name] {
			continue
		}
		if p := w.Catalog.MatchPackage(name); p != nil {
			// reported on the first poll too: a remote-access tool already installed matters as much as a new one
			out = append(out, event("the package "+name+" ("+p.Name+") is installed",
				map[string]string{"provider": p.ID, "provider_name": p.Name, "ra_kind": p.Kind, "signal": "package", "package": name}))
		}
	}
	w.pkgSeen = now
	return out
}

// tunnelKind says what kind of tunnel an interface is ("wireguard", "tun"), or "" for an ordinary one.
func tunnelKind(dir string) string {
	if b, err := os.ReadFile(filepath.Join(dir, "uevent")); err == nil && strings.Contains(string(b), "DEVTYPE=wireguard") {
		return "wireguard"
	}
	if _, err := os.Stat(filepath.Join(dir, "tun_flags")); err == nil {
		return "tun"
	}
	return ""
}

func (w *Watcher) interfaces() []detect.Event {
	entries, err := os.ReadDir(w.NetDir)
	if err != nil {
		return nil
	}
	now := map[string]bool{}
	var out []detect.Event
	for _, e := range entries {
		name := e.Name()
		now[name] = true
		if w.ifaceSeen[name] {
			continue
		}
		if p := w.Catalog.MatchIface(name); p != nil {
			out = append(out, event("the network interface "+name+" ("+p.Name+") appeared",
				map[string]string{"provider": p.ID, "provider_name": p.Name, "ra_kind": p.Kind, "signal": "iface", "iface": name}))
		} else if k := tunnelKind(filepath.Join(w.NetDir, name)); k != "" && w.started {
			// a tunnel that was already there when Heimdall started is the computer's own; a new one is worth knowing about
			out = append(out, event("a new "+k+" tunnel interface "+name+" appeared",
				map[string]string{"signal": "tunnel", "iface": name, "tunnel": k}))
		}
	}
	w.ifaceSeen = now
	return out
}

func (w *Watcher) Poll() []detect.Event {
	out := append(w.packages(), w.interfaces()...)
	w.started = true
	return out
}

func (w *Watcher) Run(ctx context.Context, interval time.Duration, emit func(detect.Event)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		for _, e := range w.Poll() {
			emit(e)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
