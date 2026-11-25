package rasource

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
	"github.com/Artifex-Technologies/Heimdall/internal/remoteaccess"
)

// Footholds (HEI-11): what makes a program start again by itself, in the system-wide places Heimdall's daemon can read:
// systemd units and their drop-ins (/etc/systemd/system, /etc/systemd/user), autostart entries (/etc/xdg/autostart), cron
// (/etc/crontab, /etc/cron.d), /etc/ld.so.preload and Python's .pth files. One is reported when a path in it is a
// remote-access tool of the catalog, a program in a temporary place (/tmp, /var/tmp, /dev/shm, /run/user) or one under a
// hidden folder; any ld.so.preload entry is reported (every program loads it). A file is read again only when its size or
// time changed. Per-user places (~/.config/autostart, a user's crontab, ~/.config/systemd/user) are not readable by the
// daemon and are not watched.

// footholdWatch is the footholds' state: the root the places are under ("" for /), each file's last size and time, and
// what was reported of each file while it held it.
type footholdWatch struct {
	Root  string
	seen  map[string]bool
	stamp map[string]string
}

// footholdKind is where a file sits and how its commands are found.
type footholdKind string

const (
	kindUnit      footholdKind = "service"
	kindAutostart footholdKind = "autostart"
	kindCron      footholdKind = "cron"
	kindPreload   footholdKind = "preload"
	kindPth       footholdKind = "pth"
)

// placeWords says what kind of place a file is, for people.
var placeWords = map[footholdKind]string{kindUnit: "a service", kindAutostart: "an autostart entry", kindCron: "a cron job",
	kindPreload: "the preload list", kindPth: "a Python startup file"}

// maxFoothold is the most of one file read (a unit, a crontab and a .pth are small).
const maxFoothold = 1 << 20

// footholdFiles lists the files to look at, sorted, with their kind (paths under w.Root).
func (w *footholdWatch) footholdFiles() [][2]string {
	root := w.Root
	if root == "" {
		root = "/"
	}
	j := func(p ...string) string { return filepath.Join(append([]string{root}, p...)...) }
	var out [][2]string
	add := func(kind footholdKind, paths ...string) {
		for _, p := range paths {
			out = append(out, [2]string{p, string(kind)})
		}
	}
	for _, base := range []string{j("etc/systemd/system"), j("etc/systemd/user")} {
		units, _ := filepath.Glob(filepath.Join(base, "*.service"))
		dropins, _ := filepath.Glob(filepath.Join(base, "*.service.d", "*.conf"))
		add(kindUnit, units...)
		add(kindUnit, dropins...)
	}
	auto, _ := filepath.Glob(j("etc/xdg/autostart", "*.desktop"))
	add(kindAutostart, auto...)
	add(kindCron, j("etc/crontab"))
	cron, _ := filepath.Glob(j("etc/cron.d", "*"))
	add(kindCron, cron...)
	add(kindPreload, j("etc/ld.so.preload"))
	pth, _ := filepath.Glob(j("usr/lib/python3*", "site-packages", "*.pth"))
	add(kindPth, pth...)
	sort.Slice(out, func(a, b int) bool { return out[a][0] < out[b][0] })
	return out
}

// footholdCommands are the command lines a file holds, by its kind.
func footholdCommands(kind footholdKind, text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		switch kind {
		case kindUnit:
			if k, v, ok := strings.Cut(line, "="); ok && strings.HasPrefix(strings.TrimSpace(k), "Exec") {
				out = append(out, v)
			}
		case kindAutostart:
			if k, v, ok := strings.Cut(line, "="); ok && (strings.TrimSpace(k) == "Exec" || strings.TrimSpace(k) == "TryExec") {
				out = append(out, v)
			}
		case kindCron:
			f := strings.Fields(line)
			// an environment line (NAME=value) sets, it does not run
			if len(f) > 0 && strings.Contains(f[0], "=") {
				continue
			}
			n := 6 // five time fields and the user
			if len(f) > 0 && strings.HasPrefix(f[0], "@") {
				n = 2 // @reboot and the user
			}
			if len(f) > n {
				out = append(out, strings.Join(f[n:], " "))
			}
		case kindPreload:
			out = append(out, strings.Fields(line)...)
		case kindPth:
			if strings.HasPrefix(line, "import ") || strings.HasPrefix(line, "import\t") {
				out = append(out, line)
			}
		}
	}
	return out
}

// pathTokens are the absolute paths in a command line (split on white space, quotes and shell punctuation).
func pathTokens(cmd string) []string {
	var out []string
	for _, t := range strings.FieldsFunc(cmd, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '"' || r == '\'' || r == ';' || r == '|' || r == '&' || r == '(' || r == ')' || r == '`' || r == '=' || r == ','
	}) {
		t = strings.TrimLeft(t, "-@+!:")
		if strings.HasPrefix(t, "/") {
			out = append(out, t)
		}
	}
	return out
}

// whyFoothold says why a path is worth reporting: "temporary", "hidden" or "" (neither).
func whyFoothold(p string) string {
	for _, t := range []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"} {
		if strings.HasPrefix(p, t) {
			return "temporary"
		}
	}
	for _, c := range strings.Split(p, "/") {
		if len(c) > 1 && c[0] == '.' && c != ".." {
			return "hidden"
		}
	}
	return ""
}

// footholds reports each file's commands that point at a catalog tool, a temporary place or a hidden folder (once per file
// and path while the file holds it), and every ld.so.preload entry.
func (w *footholdWatch) poll(c remoteaccess.Catalog) []detect.Event {
	if w.seen == nil {
		w.seen = map[string]bool{}
		w.stamp = map[string]string{}
	}
	var out []detect.Event
	files := w.footholdFiles()
	present := map[string]bool{}
	for _, f := range files {
		path, kind := f[0], footholdKind(f[1])
		present[path] = true
		fi, err := os.Stat(path)
		if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxFoothold {
			delete(w.stamp, path)
			continue
		}
		stamp := fmt.Sprintf("%d %d", fi.Size(), fi.ModTime().UnixNano())
		if w.stamp[path] == stamp {
			continue
		}
		w.stamp[path] = stamp
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		shown := strings.TrimPrefix(path, strings.TrimSuffix(w.Root, "/"))
		for k := range w.seen {
			if strings.HasPrefix(k, path+"|") {
				delete(w.seen, k) // read again: what it holds now decides
			}
		}
		for _, cmd := range footholdCommands(kind, string(b)) {
			for _, p := range pathTokens(cmd) {
				why := whyFoothold(p)
				prov := c.MatchExe(p, "")
				if why == "" && prov == nil && kind != kindPreload {
					continue
				}
				key := path + "|" + p
				if w.seen[key] {
					continue
				}
				w.seen[key] = true
				fields := map[string]string{"signal": "foothold", "place": string(kind), "file": shown, "target": p, "why": why, "ra_kind": "foothold"}
				text := fmt.Sprintf("%s (%s) points at %s", shown, placeWords[kind], p)
				if kind == kindPreload {
					text = fmt.Sprintf("%s makes every program load %s", shown, p)
					if why == "" {
						fields["why"] = "preload"
					}
				}
				if prov != nil && why == "" {
					fields["why"] = "tool"
					fields["provider"], fields["provider_name"], fields["ra_kind"] = prov.ID, prov.Name, prov.Kind
					text += " (" + prov.Name + ")"
				}
				out = append(out, event(text, fields))
			}
		}
	}
	for path := range w.stamp {
		if !present[path] {
			delete(w.stamp, path)
		}
	}
	return out
}
