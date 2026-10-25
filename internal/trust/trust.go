// Package trust keeps the signed list of approved files: the files that decide how the AI agents on this computer behave (Sarina's
// rules, skills, tool connections and agents; Heimdall's own settings). Each entry is a path and the SHA-256 of its approved content;
// the list is signed with an Ed25519 key only root can read, so a program running as the user cannot approve its own change, while
// anyone can check a file against the list (Sarina does, before she uses one; Heimdall's file watch does, to tell an approved change
// from an attack).
//
// Everything lives in one root-owned folder (Dir, /etc/heimdall/trust):
//
//	owner.key      the signing key (root only, 0600)
//	owner.pub      its public half (0644)
//	manifest.json  {"version":1,"signed_at":...,"files":{"/abs/path":"sha256"}} (0644)
//	manifest.sig   base64 Ed25519 signature over the exact bytes of manifest.json (0644)
//	mode           off | watch | enforce (0644): off, nothing changes; watch, an unsigned change to a watched file is a critical alert
//	               and a signed one is quiet; enforce, Sarina also refuses to use an unsigned file
//	watch.json     {"files":[...],"dirs":[...]}: what is watched (0644)
//	approved/      a copy of every approved content, named by its SHA-256 (root only): what "heimdalld trust restore" puts back
//	               when a watched file was changed or deleted without approval, so the agents come back as they were approved
package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// DefaultDir is where the trust files live.
const DefaultDir = "/etc/heimdall/trust"

// Mode says what an unsigned change means.
type Mode string

const (
	Off     Mode = "off"
	Watch   Mode = "watch"
	Enforce Mode = "enforce"
)

// ParseMode reads a mode; anything else is an error.
func ParseMode(s string) (Mode, error) {
	switch Mode(strings.TrimSpace(s)) {
	case Off, Watch, Enforce:
		return Mode(strings.TrimSpace(s)), nil
	}
	return Off, fmt.Errorf("unknown trust mode %q (off, watch or enforce)", s)
}

// Store is one trust folder.
type Store struct{ Dir string }

// Manifest is the signed list.
type Manifest struct {
	Version  int               `json:"version"`
	SignedAt time.Time         `json:"signed_at"`
	Files    map[string]string `json:"files"`
}

// WatchList is what the file watch looks at, besides Heimdall's own list.
type WatchList struct {
	Files []string `json:"files"`
	Dirs  []string `json:"dirs"`
}

// MaxDirFiles caps the files signed or watched under one folder (a folder with more is not one of these).
const MaxDirFiles = 5000

func (s Store) path(name string) string { return filepath.Join(s.Dir, name) }

// Mode is the current mode; a missing or unreadable file is Off.
func (s Store) Mode() Mode {
	b, err := os.ReadFile(s.path("mode"))
	if err != nil {
		return Off
	}
	m, err := ParseMode(string(b))
	if err != nil {
		return Off
	}
	return m
}

// SetMode writes the mode (root).
func (s Store) SetMode(m Mode) error {
	if _, err := ParseMode(string(m)); err != nil {
		return err
	}
	return writeFile(s.path("mode"), []byte(string(m)+"\n"), 0o644)
}

// Watch is the watch list; missing means nothing extra.
func (s Store) Watch() WatchList {
	var w WatchList
	if b, err := os.ReadFile(s.path("watch.json")); err == nil {
		_ = json.Unmarshal(b, &w)
	}
	return w
}

// SetWatch writes the watch list (root).
func (s Store) SetWatch(w WatchList) error {
	b, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(s.path("watch.json"), append(b, '\n'), 0o644)
}

// Init makes the key pair; an existing key is never replaced (that would void every signature).
func (s Store) Init() (created bool, err error) {
	if _, err := os.Stat(s.path("owner.key")); err == nil {
		return false, nil
	}
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return false, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return false, err
	}
	if err := writeFile(s.path("owner.key"), []byte(base64.StdEncoding.EncodeToString(priv)+"\n"), 0o600); err != nil {
		return false, err
	}
	if err := writeFile(s.path("owner.pub"), []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644); err != nil {
		return false, err
	}
	if _, err := os.Stat(s.path("mode")); err != nil {
		if err := s.SetMode(Off); err != nil {
			return true, err
		}
	}
	return true, s.write(&Manifest{Version: 1, Files: map[string]string{}}, priv)
}

func readKey(path string, size int) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(k) != size {
		return nil, fmt.Errorf("%s is not a key", path)
	}
	return k, nil
}

// Load reads the list and checks its signature. A list that does not verify is an error: nothing in it can be trusted.
func (s Store) Load() (*Manifest, error) {
	pub, err := readKey(s.path("owner.pub"), ed25519.PublicKeySize)
	if err != nil {
		return nil, err
	}
	body, err := os.ReadFile(s.path("manifest.json"))
	if err != nil {
		return nil, err
	}
	sigText, err := os.ReadFile(s.path("manifest.sig"))
	if err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigText)))
	if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), body, sig) {
		return nil, errors.New("the signed list of approved files does not match its signature (changed by someone without the key)")
	}
	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, err
	}
	if m.Files == nil {
		m.Files = map[string]string{}
	}
	return &m, nil
}

func (s Store) write(m *Manifest, priv ed25519.PrivateKey) error {
	m.Version = 1
	m.SignedAt = time.Now().UTC().Truncate(time.Second)
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	sig := ed25519.Sign(priv, body)
	// the signature first under a temporary name, then both renamed: a reader sees the old pair or the new one
	if err := writeFile(s.path("manifest.json.new"), body, 0o644); err != nil {
		return err
	}
	if err := writeFile(s.path("manifest.sig.new"), []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644); err != nil {
		return err
	}
	if err := os.Rename(s.path("manifest.json.new"), s.path("manifest.json")); err != nil {
		return err
	}
	return os.Rename(s.path("manifest.sig.new"), s.path("manifest.sig"))
}

func (s Store) key() (ed25519.PrivateKey, error) {
	k, err := readKey(s.path("owner.key"), ed25519.PrivateKeySize)
	if err != nil {
		return nil, fmt.Errorf("the signing key cannot be read (run as root, after heimdalld trust init): %w", err)
	}
	return ed25519.PrivateKey(k), nil
}

// Sign approves the current content of the given files (a folder: every file under it), adding or updating their entries. It
// returns the paths signed.
func (s Store) Sign(paths []string) ([]string, error) {
	priv, err := s.key()
	if err != nil {
		return nil, err
	}
	m, err := s.Load()
	if err != nil {
		return nil, err
	}
	var done []string
	for _, p := range paths {
		files, err := Expand(p)
		if err != nil {
			return done, err
		}
		for _, f := range files {
			sum, err := HashFile(f)
			if err != nil {
				return done, err
			}
			if err := s.keepCopy(f, sum); err != nil {
				return done, err
			}
			m.Files[f] = sum
			done = append(done, f)
		}
	}
	if err := s.write(m, priv); err != nil {
		return done, err
	}
	s.pruneCopies(m)
	return done, nil
}

// keepCopy stores the approved content under approved/<sha256> (root only), unless it is there already.
func (s Store) keepCopy(path, sum string) error {
	dir := s.path("approved")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	dst := filepath.Join(dir, sum)
	if _, err := os.Stat(dst); err == nil {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if fmt.Sprintf("%x", sha256.Sum256(b)) != sum {
		return fmt.Errorf("%s changed while it was being signed; sign it again", path)
	}
	return writeFile(dst, b, 0o600)
}

// pruneCopies removes copies no entry needs any more.
func (s Store) pruneCopies(m *Manifest) {
	need := map[string]bool{}
	for _, sum := range m.Files {
		need[sum] = true
	}
	entries, _ := os.ReadDir(s.path("approved"))
	for _, e := range entries {
		if !need[e.Name()] && len(e.Name()) == 64 {
			os.Remove(filepath.Join(s.path("approved"), e.Name()))
		}
	}
}

// Restored is one file put back.
type Restored struct {
	Path string
	Why  string // "changed" or "deleted"
}

// Restore puts back the approved content of watched, listed files that were changed or deleted (only those under paths, or all when
// paths is empty), owned as their folder is. Files the list does not know are not touched: they are reported by the watch, and
// removing them is the owner's decision.
func (s Store) Restore(paths []string) ([]Restored, error) {
	m, err := s.Load()
	if err != nil {
		return nil, err
	}
	var abs []string
	for _, p := range paths {
		a, err := filepath.Abs(p)
		if err != nil {
			return nil, err
		}
		abs = append(abs, a)
	}
	within := func(f string) bool {
		if len(abs) == 0 {
			return true
		}
		for _, a := range abs {
			if f == a || strings.HasPrefix(f, a+string(filepath.Separator)) {
				return true
			}
		}
		return false
	}
	var files []string
	for f := range m.Files {
		if within(f) {
			files = append(files, f)
		}
	}
	sort.Strings(files)
	var out []Restored
	for _, f := range files {
		want := m.Files[f]
		have, err := HashFile(f)
		why := "changed"
		if os.IsNotExist(err) {
			why = "deleted"
		} else if err == nil && have == want {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.path("approved"), want))
		if err != nil {
			return out, fmt.Errorf("no approved copy of %s: %w", f, err)
		}
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			return out, err
		}
		if err := writeFile(f, b, 0o644); err != nil {
			return out, err
		}
		if st, err := os.Stat(filepath.Dir(f)); err == nil {
			chownLike(f, st)
		}
		out = append(out, Restored{f, why})
	}
	return out, nil
}

// Forget removes entries (a folder: every entry under it), so a deleted file stops being expected. Returns the paths removed.
func (s Store) Forget(paths []string) ([]string, error) {
	priv, err := s.key()
	if err != nil {
		return nil, err
	}
	m, err := s.Load()
	if err != nil {
		return nil, err
	}
	var gone []string
	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			return gone, err
		}
		for f := range m.Files {
			if f == abs || strings.HasPrefix(f, abs+string(filepath.Separator)) {
				delete(m.Files, f)
				gone = append(gone, f)
			}
		}
	}
	sort.Strings(gone)
	return gone, s.write(m, priv)
}

// Matches reports whether path is approved with exactly this content hash.
func (m *Manifest) Matches(path, sha string) bool {
	return m != nil && sha != "" && m.Files[path] == sha
}

// Has reports whether path is on the list at all.
func (m *Manifest) Has(path string) bool {
	if m == nil {
		return false
	}
	_, ok := m.Files[path]
	return ok
}

// Expand turns a path into the regular files it names: itself, or every regular file under a folder (symbolic links are not
// followed; at most MaxDirFiles).
func Expand(p string) ([]string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	if info.Mode().IsRegular() {
		return []string{abs}, nil
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a regular file or a folder", abs)
	}
	var out []string
	err = filepath.WalkDir(abs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type().IsRegular() {
			if len(out) >= MaxDirFiles {
				return fmt.Errorf("%s has more than %d files", abs, MaxDirFiles)
			}
			out = append(out, path)
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

// HashFile is the hex SHA-256 of a file's content.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// watches reports whether path is one of the watch list's files or under one of its folders.
func (w WatchList) watches(path string) bool {
	for _, f := range w.Files {
		if f == path {
			return true
		}
	}
	for _, d := range w.Dirs {
		if strings.HasPrefix(path, strings.TrimSuffix(d, "/")+"/") {
			return true
		}
	}
	return false
}

// Judge answers the file watch (detect.TrustJudge): whether a change to a watched behaviour file was approved.
type Judge struct{ Store Store }

func (j Judge) Judge(path, newHash string, deleted bool) (verdict, why string) {
	if j.Store.Mode() == Off || !j.Store.Watch().watches(path) {
		return "", ""
	}
	m, err := j.Store.Load()
	if err != nil {
		return "unsigned", "the signed list cannot be checked: " + err.Error()
	}
	switch {
	case deleted && m.Has(path):
		return "unsigned", "the signed list still expects it"
	case deleted:
		return "approved", ""
	case m.Matches(path, newHash):
		return "approved", ""
	case m.Has(path):
		return "unsigned", "its content differs from the signed version"
	}
	return "unsigned", "it is not on the signed list"
}

// Unapproved lists the watched files whose content is not what was signed: changed, or new in a watched folder (not on the list).
func (s Store) Unapproved() []string {
	m, err := s.Load()
	if err != nil {
		return nil
	}
	w := s.Watch()
	files := append([]string{}, w.Files...)
	for _, d := range w.Dirs {
		if exp, err := Expand(d); err == nil {
			files = append(files, exp...)
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, f := range files {
		if seen[f] {
			continue
		}
		seen[f] = true
		sum, err := HashFile(f)
		if err == nil && !m.Matches(f, sum) {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}

// Watches reports whether a path is one of the watched behaviour files (listed, or inside a watched folder).
func (w WatchList) Watches(path string) bool { return w.watches(path) }

// Judges for other packages (immunity's release proof): whether the owner signed exactly this content, and whether a path decides
// how an AI agent behaves.
func (s Store) SignedFunc() func(path, sha string) bool {
	m, err := s.Load()
	return func(path, sha string) bool { return err == nil && m.Matches(path, sha) }
}

func (s Store) BehaviourFunc() func(path string) bool {
	w := s.Watch()
	return w.Watches
}
