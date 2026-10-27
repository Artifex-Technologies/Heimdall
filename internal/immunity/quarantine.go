package immunity

import (
	"errors"
	"fmt"
	"github.com/Artifex-Technologies/Heimdall/internal/safefs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Holding a file: Heimdall keeps it (Keep), asks ClamAV at once (no one needs to approve a comparison), and moves the original
// away. ClamAV knows it: it is malware (Reference) and stays held. ClamAV does not: it is held, the owner is told, and the owner (or
// a proof that it was there before, see Proof) decides.

// MinAge: the inventory must have seen the exact file this long before it was held, for that to count as proof.
const MinAge = 24 * time.Hour

// OwnedByPackage says whether an installed package owns a path (pacman). Such files are never held: they are the system's, and the
// package manager checks them itself.
var OwnedByPackage = func(path string) (string, bool) {
	out, err := exec.Command("pacman", "-Qoq", path).Output()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}

// never are places whose files are never moved, whatever is asked.
var never = []string{"/usr/", "/boot/", "/proc/", "/sys/", "/dev/", "/run/", "/var/lib/pacman/"}

// Hold quarantines a file: read from `from` (a path, or /proc/PID/exe for a running program), known and restored as `original`.
func (s Store) Hold(from, original, reason, source string, ref ReferenceScanner) (Entry, error) {
	abs, err := filepath.Abs(original)
	if err != nil {
		return Entry{}, err
	}
	for _, p := range never {
		if strings.HasPrefix(abs, p) {
			return Entry{}, fmt.Errorf("%s: files under %s are never moved", abs, p)
		}
	}
	if pkg, owned := OwnedByPackage(abs); owned {
		return Entry{}, fmt.Errorf("%s belongs to the package %s: never moved (sudo pacman -Qkk %s checks it)", abs, pkg, pkg)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return Entry{}, err
	}
	if !info.Mode().IsRegular() {
		return Entry{}, fmt.Errorf("%s: not a regular file", abs)
	}
	e, err := s.KeepAs(from, abs, reason, source)
	if err != nil {
		return Entry{}, err
	}
	es, err := s.Load()
	if err != nil {
		return Entry{}, err
	}
	i := find(es, e.SHA256)
	if es[i].Status == Held || es[i].Status == Immune || es[i].Status == Reference {
		// the same content again (another copy): moved as well, remembered with the first record
		if abs != es[i].Original {
			if err := os.Remove(abs); err != nil {
				return es[i], err
			}
			es[i].Copies = append(es[i].Copies, abs)
		}
		return es[i], s.save(es)
	}
	if es[i].Status == Released && es[i].Original == abs {
		return es[i], fmt.Errorf("%s was judged good and released before: left alone", abs)
	}
	st, _ := info.Sys().(*syscall.Stat_t)
	es[i].Status, es[i].HeldAt, es[i].Mode, es[i].MTime = Held, time.Now().UTC().Truncate(time.Second), uint32(info.Mode().Perm()), info.ModTime().UnixNano()
	es[i].Original, es[i].Reason, es[i].Source = abs, oneLine(reason), source
	if st != nil {
		es[i].UID, es[i].GID = int(st.Uid), int(st.Gid)
	}
	if seen, ok := s.Inventory()[abs]; ok && seen.SHA256 == e.SHA256 {
		es[i].SeenSince = seen.FirstSeen
	}
	if b, err := s.sampleBytes(e.SHA256); err == nil {
		es[i].Report = MakeReport(b, e.Kind)
	}
	if ref != nil {
		tmp, err := os.MkdirTemp("", "heimdall-immunity-")
		if err == nil {
			p := filepath.Join(tmp, "sample")
			if s.Extract(e.SHA256, p) == nil {
				if sig, err := ref(p); err == nil && sig != "" && !strings.HasPrefix(sig, "Heimdall.Immunity.") {
					es[i].Status, es[i].ClamAV, es[i].Confirmed = Reference, sig, time.Now().UTC().Truncate(time.Second)
				}
			}
			os.RemoveAll(tmp)
		}
	}
	if err := os.Remove(abs); err != nil && !os.IsNotExist(err) {
		return es[i], fmt.Errorf("kept, but the original could not be moved: %w", err)
	}
	return es[i], s.save(es)
}

// Release puts a held file back where it was, exactly (content, owner, mode, time), never over a file that is there now.
func (s Store) Release(sha, by string) (Entry, error) {
	es, err := s.Load()
	if err != nil {
		return Entry{}, err
	}
	i := find(es, sha)
	if i < 0 {
		return Entry{}, fmt.Errorf("no sample %s", sha)
	}
	e := es[i]
	if e.Status != Held && e.Status != Suspect {
		return e, fmt.Errorf("%s is %s: only a held file can be released (forget it first if this was a mistake)", e.Original, e.Status)
	}
	if e.Status == Held {
		b, err := s.sampleBytes(e.SHA256)
		if err != nil {
			return e, err
		}
		// written as the user who owned it (root only into root-only folders), never through a link, never over a file there now
		f := safefs.File{Data: b, Mode: os.FileMode(e.Mode), MTime: time.Unix(0, e.MTime), Exclusive: true}
		if err := safefs.PutAs(e.Original, f, uint32(e.UID), uint32(e.GID)); err != nil {
			return e, fmt.Errorf("%s: %w (if something is there now, move it away first)", e.Original, err)
		}
		for _, c := range e.Copies {
			_ = safefs.PutAs(c, f, uint32(e.UID), uint32(e.GID))
		}
	}
	es[i].Status, es[i].Released, es[i].ReleasedBy = Released, time.Now().UTC().Truncate(time.Second), by
	return es[i], s.save(es)
}

// Proof says whether a held file is shown to be good without anyone's word: the owner signed exactly this content (signed), or the
// inventory had exactly this file at this path at least a day before it was held. For files that decide how the AI agents behave
// (behaviour), only the owner's signature counts: a planted skill could have lain there for a day.
func Proof(e Entry, signed func(path, sha string) bool, behaviour func(path string) bool) (string, bool) {
	if e.Status != Held {
		return "", false
	}
	if signed != nil && signed(e.Original, e.SHA256) {
		return "the owner signed exactly this content (trust list)", true
	}
	if behaviour != nil && behaviour(e.Original) {
		return "", false
	}
	if !e.SeenSince.IsZero() && e.HeldAt.Sub(e.SeenSince) >= MinAge {
		return "exactly this file was on the computer since " + e.SeenSince.Local().Format("2006-01-02 15:04") + " (Heimdall's inventory)", true
	}
	return "", false
}

// ReleaseIfProven releases a held file when Proof holds; otherwise it says why not (the owner decides then).
func (s Store) ReleaseIfProven(sha string, signed func(path, sha string) bool, behaviour func(path string) bool) (Entry, error) {
	es, err := s.Load()
	if err != nil {
		return Entry{}, err
	}
	i := find(es, sha)
	if i < 0 {
		return Entry{}, fmt.Errorf("no sample %s", sha)
	}
	why, ok := Proof(es[i], signed, behaviour)
	if !ok {
		return es[i], errors.New("no proof that it was there before: the owner decides (Settings > Security, or sudo heimdalld immunity release)")
	}
	return s.Release(es[i].SHA256, "proof: "+why)
}
