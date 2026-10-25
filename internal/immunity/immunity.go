// Package immunity is what Heimdall has learned about malware that ClamAV (the reference) does not know.
//
// A sample comes in as a suspect: a file the owner names, or what a containment saved as evidence (an unapproved behaviour file, the
// program a suspicious process ran). It is kept, compressed and unrunnable, in a root-only store. When it is confirmed (the owner,
// with sudo), it is first checked against ClamAV: if ClamAV already knows it, nothing is learned (its signature is noted). If ClamAV
// does not, its fingerprint (SHA-256 and size) goes into a signature file that ClamAV loads with its own database
// (/var/lib/clamav/heimdall-immunity.hsb), so every scan from then on (the downloads watch, Settings' scan, heimdalld scan-files)
// catches any copy of it, anywhere, under the name Heimdall.Immunity.<kind>.<id>.
//
// Fingerprints catch exact copies. Variants need rules built from what the sample does (the analysis step, not here). Nothing is
// ever learned without confirmation: a wrong fingerprint would quarantine a good file.
package immunity

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultDir is the root-only store: samples/<sha256>.gz and immunity.json.
	DefaultDir = "/var/lib/heimdall-immunity"
	// DefaultSignatures is the file ClamAV loads (its database folder).
	DefaultSignatures = "/var/lib/clamav/heimdall-immunity.hsb"
	// MinSize: smaller files are never fingerprinted (an empty or tiny file matches far too much that is harmless).
	MinSize = 64
	// MaxSize: larger samples are not kept.
	MaxSize = 256 << 20
)

// Status of an entry.
const (
	Suspect   = "suspect"   // kept, the original left where it is
	Held      = "held"      // quarantined: the original was moved here; waiting for the owner (or a proof that it was there before)
	Immune    = "immune"    // malware ClamAV does not know: fingerprinted (stays held)
	Reference = "reference" // malware ClamAV knows (stays held; no fingerprint needed)
	Released  = "released"  // judged good: put back where it was
)

// Entry is one sample.
type Entry struct {
	SHA256    string    `json:"sha256"`
	Size      int64     `json:"size"`
	Kind      string    `json:"kind"` // Elf, Script, Pe, Archive, Document, Text, Data
	Original  string    `json:"original"`
	Reason    string    `json:"reason"`
	Source    string    `json:"source"` // owner, containment
	Added     time.Time `json:"added"`
	Status    string    `json:"status"`
	Confirmed time.Time `json:"confirmed,omitempty"`
	ClamAV    string    `json:"clamav,omitempty"` // the reference's signature, when it knew the sample

	// while held: what is needed to put it back exactly
	HeldAt time.Time `json:"held_at,omitempty"`
	UID    int       `json:"uid,omitempty"`
	GID    int       `json:"gid,omitempty"`
	Mode   uint32    `json:"mode,omitempty"`
	MTime  int64     `json:"mtime,omitempty"`
	// SeenSince: Heimdall's inventory had this exact content at this path since then (before it was held)
	SeenSince time.Time `json:"seen_since,omitempty"`
	Released  time.Time `json:"released,omitempty"`
	// ReleasedBy: "owner", or the proof Heimdall checked ("signed by the owner", "on this computer since ...")
	ReleasedBy string `json:"released_by,omitempty"`
	// Copies: other paths the same content was held from (put back too on release)
	Copies []string `json:"copies,omitempty"`
	// Report: what the file is and contains, for the owner and Sarina (never run: read and parsed only)
	Report *Report `json:"report,omitempty"`
	// Analysis: what Limbo found taking it apart in a sealed guest (queued after every hold)
	Analysis *Analysis `json:"analysis,omitempty"`
}

// Name is the signature name ClamAV reports.
func (e Entry) Name() string { return "Heimdall.Immunity." + e.Kind + "." + e.SHA256[:12] }

// Reference asks the reference scanner about a file: its signature when it knows the file, "" when not.
type ReferenceScanner func(path string) (signature string, err error)

// Store is the immunity store. The folder and its index are readable by the heimdall group (the daemon shows what is held on its
// local API); the samples are root's only.
type Store struct {
	Dir        string
	Signatures string
}

// Default is the store at its usual place (HEIMDALL_IMMUNITY_DIR and HEIMDALL_IMMUNITY_SIGNATURES for tests).
func Default() Store {
	s := Store{Dir: DefaultDir, Signatures: DefaultSignatures}
	if d := os.Getenv("HEIMDALL_IMMUNITY_DIR"); d != "" {
		s.Dir = d
	}
	if f := os.Getenv("HEIMDALL_IMMUNITY_SIGNATURES"); f != "" {
		s.Signatures = f
	}
	return s
}

func (s Store) index() string { return filepath.Join(s.Dir, "immunity.json") }

// Load reads the entries, newest first.
func (s Store) Load() ([]Entry, error) {
	b, err := os.ReadFile(s.index())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var es []Entry
	if err := json.Unmarshal(b, &es); err != nil {
		return nil, err
	}
	return es, nil
}

func (s Store) save(es []Entry) error {
	sort.Slice(es, func(i, j int) bool { return es[i].Added.After(es[j].Added) })
	b, _ := json.MarshalIndent(es, "", "  ")
	if err := os.MkdirAll(s.Dir, 0o750); err != nil {
		return err
	}
	shareWithDaemon(s.Dir, 0o750)
	tmp := s.index() + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o640); err != nil {
		return err
	}
	shareWithDaemon(tmp, 0o640)
	return os.Rename(tmp, s.index())
}

// shareWithDaemon gives the heimdall group read access (as root; elsewhere, in tests, only the mode is set).
func shareWithDaemon(path string, mode os.FileMode) {
	_ = os.Chmod(path, mode)
	if os.Geteuid() != 0 {
		return
	}
	if g, err := user.LookupGroup("heimdall"); err == nil {
		if gid, err := strconv.Atoi(g.Gid); err == nil {
			_ = os.Chown(path, 0, gid)
		}
	}
}

// Kind names what a file is from its first bytes.
func Kind(head []byte) string {
	switch {
	case bytes.HasPrefix(head, []byte("\x7fELF")):
		return "Elf"
	case bytes.HasPrefix(head, []byte("MZ")):
		return "Pe"
	case bytes.HasPrefix(head, []byte("#!")):
		return "Script"
	case bytes.HasPrefix(head, []byte("PK\x03\x04")), bytes.HasPrefix(head, []byte("\x1f\x8b")), bytes.HasPrefix(head, []byte("7z\xbc\xaf")), bytes.HasPrefix(head, []byte("Rar!")):
		return "Archive"
	case bytes.HasPrefix(head, []byte("%PDF")), bytes.HasPrefix(head, []byte("\xd0\xcf\x11\xe0")):
		return "Document"
	}
	for _, c := range head {
		if c == 0 || (c < 0x09) || (c > 0x0d && c < 0x20) {
			return "Data"
		}
	}
	return "Text"
}

// Keep stores a sample as a suspect (or returns the entry it already has). The file is read once: what is stored, hashed and later
// fingerprinted is exactly the same bytes.
func (s Store) Keep(path, reason, source string) (Entry, error) {
	return s.KeepAs(path, path, reason, source)
}

// KeepAs is Keep for a file read from one path (/proc/PID/exe) and known by another (the program's real path).
func (s Store) KeepAs(path, original, reason, source string) (Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return Entry{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return Entry{}, err
	}
	if !info.Mode().IsRegular() {
		return Entry{}, fmt.Errorf("%s: not a regular file", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
	if err != nil {
		return Entry{}, err
	}
	if len(b) > MaxSize {
		return Entry{}, fmt.Errorf("%s: larger than %d MiB", path, MaxSize>>20)
	}
	if len(b) < MinSize {
		return Entry{}, fmt.Errorf("%s: only %d bytes; a fingerprint that small would match harmless files", path, len(b))
	}
	sum := sha256.Sum256(b)
	e := Entry{SHA256: hex.EncodeToString(sum[:]), Size: int64(len(b)), Kind: Kind(b[:min(len(b), 512)]), Original: original,
		Reason: oneLine(reason), Source: source, Added: time.Now().UTC().Truncate(time.Second), Status: Suspect}
	es, err := s.Load()
	if err != nil {
		return Entry{}, err
	}
	for _, old := range es {
		if old.SHA256 == e.SHA256 {
			return old, nil
		}
	}
	if err := os.MkdirAll(filepath.Join(s.Dir, "samples"), 0o700); err != nil {
		return Entry{}, err
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Name = filepath.Base(original)
	_, _ = zw.Write(b)
	_ = zw.Close()
	if err := os.WriteFile(s.sample(e.SHA256), gz.Bytes(), 0o400); err != nil && !os.IsExist(err) {
		return Entry{}, err
	}
	return e, s.save(append(es, e))
}

func (s Store) sample(sha string) string { return filepath.Join(s.Dir, "samples", sha+".gz") }

// sampleBytes reads a stored sample back, checking it still matches its fingerprint.
func (s Store) sampleBytes(sha string) ([]byte, error) {
	gzb, err := os.ReadFile(s.sample(sha))
	if err != nil {
		return nil, err
	}
	zr, err := gzip.NewReader(bytes.NewReader(gzb))
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(zr, MaxSize+1))
	if err != nil {
		return nil, err
	}
	if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != sha {
		return nil, errors.New("the stored sample does not match its fingerprint")
	}
	return b, nil
}

// Extract writes a sample out (uncompressed, not executable, owner-only) for the reference check or an analysis.
func (s Store) Extract(sha, to string) error {
	b, err := s.sampleBytes(sha)
	if err != nil {
		return err
	}
	return os.WriteFile(to, b, 0o600)
}

// Confirm makes a suspect known: checked against the reference, then fingerprinted unless the reference knows it already.
func (s Store) Confirm(sha string, ref ReferenceScanner) (Entry, error) {
	es, err := s.Load()
	if err != nil {
		return Entry{}, err
	}
	i := find(es, sha)
	if i < 0 {
		return Entry{}, fmt.Errorf("no sample %s (heimdalld immunity list)", sha)
	}
	if ref != nil {
		tmp, err := os.MkdirTemp("", "heimdall-immunity-")
		if err != nil {
			return Entry{}, err
		}
		defer os.RemoveAll(tmp)
		p := filepath.Join(tmp, "sample")
		if err := s.Extract(es[i].SHA256, p); err != nil {
			return Entry{}, err
		}
		sig, err := ref(p)
		if err != nil {
			return Entry{}, fmt.Errorf("the reference (ClamAV) could not check it: %w", err)
		}
		if sig != "" && !strings.HasPrefix(sig, "Heimdall.Immunity.") {
			es[i].Status, es[i].ClamAV, es[i].Confirmed = Reference, sig, time.Now().UTC().Truncate(time.Second)
			return es[i], s.save(es)
		}
	}
	es[i].Status, es[i].Confirmed = Immune, time.Now().UTC().Truncate(time.Second)
	if err := s.save(es); err != nil {
		return Entry{}, err
	}
	return es[i], s.Export()
}

// Forget removes a sample and its fingerprint (a mistake, or the reference learned it).
func (s Store) Forget(sha string) error {
	es, err := s.Load()
	if err != nil {
		return err
	}
	i := find(es, sha)
	if i < 0 {
		return fmt.Errorf("no sample %s", sha)
	}
	full := es[i].SHA256
	es = append(es[:i], es[i+1:]...)
	if err := s.save(es); err != nil {
		return err
	}
	_ = os.Remove(s.sample(full))
	return s.Export()
}

// Export writes ClamAV's signature file from the confirmed entries (ClamAV's .hsb format: SHA256:size:name), or removes it when there
// are none (an empty signature file makes ClamAV complain).
func (s Store) Export() error {
	es, err := s.Load()
	if err != nil {
		return err
	}
	var lines []string
	for _, e := range es {
		if e.Status == Immune {
			lines = append(lines, fmt.Sprintf("%s:%d:%s", e.SHA256, e.Size, e.Name()))
		}
	}
	if len(lines) == 0 {
		err := os.Remove(s.Signatures)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	sort.Strings(lines)
	tmp := s.Signatures + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.Signatures)
}

// find accepts a full fingerprint or a unique prefix of at least 8 characters.
func find(es []Entry, sha string) int {
	sha = strings.ToLower(strings.TrimSpace(sha))
	at := -1
	for i, e := range es {
		if e.SHA256 == sha {
			return i
		}
		if len(sha) >= 8 && strings.HasPrefix(e.SHA256, sha) {
			if at >= 0 {
				return -1
			}
			at = i
		}
	}
	return at
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}
