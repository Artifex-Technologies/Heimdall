package immunity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/safefs"
)

// LimboHeldDir is where Limbo keeps a file ClamAV knew when a guest tried to hand it out (Limbo's docs/EVENTS.md,
// exchange.held): root-only, the file named by its SHA-256.
const LimboHeldDir = "/var/lib/limbo/state/exchange-held"

var fullSHA = regexp.MustCompile(`^[0-9a-f]{64}$`)

// TakeFromLimbo keeps a copy of a file Limbo held at a guest's exchange, so Heimdall's store has the sample too (for rules,
// analysis, and the owner's record). Root only: Limbo's folder and this store are root's.
//
// It is asked for by SHA-256 only: the path is built from heldDir and that name, never taken from an event (a guest chose
// the path in exchange.held). The file is opened without following links, and its content must hash to its name before
// anything is stored, so only exactly what Limbo held can come in. Nothing is run: the bytes are hashed, compressed into the
// store, and given to ClamAV (the reference) to read. Limbo's copy is left where it is; it is Limbo's evidence.
//
// ClamAV knowing the sample makes it a Reference entry (nothing new to learn). If ClamAV here does not know it (Limbo's
// ClamAV had other signatures), it stays a suspect for the owner to confirm.
func (s Store) TakeFromLimbo(heldDir, sha string, ref ReferenceScanner) (Entry, error) {
	sha = strings.ToLower(strings.TrimSpace(sha))
	if !fullSHA.MatchString(sha) {
		return Entry{}, fmt.Errorf("%q is not a full SHA-256 (64 hex characters)", sha)
	}
	path := filepath.Join(heldDir, sha)
	if err := hashIs(path, sha); err != nil {
		return Entry{}, err
	}
	e, err := s.KeepAs(path, path, "Limbo held it: a guest tried to hand it out and ClamAV knew it", "limbo")
	if err != nil {
		return Entry{}, err
	}
	if e.SHA256 != sha {
		return e, fmt.Errorf("%s changed while it was read (now %s): kept as a suspect, check Limbo's folder", path, e.SHA256)
	}
	if e.Status != Suspect || e.Source != "limbo" {
		return e, nil // already in the store from elsewhere: left as it is
	}
	es, err := s.Load()
	if err != nil {
		return e, err
	}
	i := find(es, sha)
	if i < 0 {
		return e, fmt.Errorf("sample %s missing from the index right after it was kept", sha)
	}
	if b, err := s.sampleBytes(sha); err == nil {
		es[i].Report = MakeReport(b, e.Kind)
	}
	if ref != nil {
		tmp, err := os.MkdirTemp("", "heimdall-immunity-")
		if err == nil {
			p := filepath.Join(tmp, "sample")
			if s.Extract(sha, p) == nil {
				if sig, err := ref(p); err == nil && sig != "" && !strings.HasPrefix(sig, "Heimdall.Immunity.") {
					es[i].Status, es[i].ClamAV, es[i].Confirmed = Reference, sig, time.Now().UTC().Truncate(time.Second)
				}
			}
			os.RemoveAll(tmp)
		}
	}
	return es[i], s.save(es)
}

// hashIs checks a file's content against the SHA-256 it is named by, reading at most MaxSize, never through a link.
func hashIs(path, sha string) error {
	f, err := safefs.OpenNoLinks(path, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s: not a regular file", path)
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, MaxSize+1))
	if err != nil {
		return err
	}
	if n > MaxSize {
		return fmt.Errorf("%s: larger than %d MiB, not kept", path, MaxSize>>20)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != sha {
		return fmt.Errorf("%s does not hash to its name (it hashes to %s): not taken", path, got)
	}
	return nil
}
