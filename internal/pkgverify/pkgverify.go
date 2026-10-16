// Package pkgverify answers "does pacman own this file, and is it what the package shipped?" from pacman's own
// database (/var/lib/pacman/local/<pkg>/{files,mtree}), read-only. It lets the file-integrity detector tell a
// package update (the file now matches the new package's recorded SHA-256) from a change nobody can explain.
package pkgverify

import (
	"bufio"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
)

type Verifier struct{ dir string }

func New(dir string) *Verifier { return &Verifier{dir: dir} }

// Expected returns the owning package of path and the SHA-256 pacman recorded for it. owned is false when no package
// lists the file; sha is empty when the package has no digest for it (a directory, or a file the package marks as backup).
func (v *Verifier) Expected(path string) (pkg, sha string, owned bool) {
	if v == nil || v.dir == "" {
		return "", "", false
	}
	rel := strings.TrimPrefix(path, "/")
	entries, err := os.ReadDir(v.dir)
	if err != nil {
		return "", "", false
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if listed(filepath.Join(v.dir, e.Name(), "files"), rel) {
			return e.Name(), digest(filepath.Join(v.dir, e.Name(), "mtree"), rel), true
		}
	}
	return "", "", false
}

func listed(filesPath, rel string) bool {
	f, err := os.Open(filesPath)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if sc.Text() == rel {
			return true
		}
	}
	return false
}

// mtree lines look like "./usr/bin/foo time=... size=... sha256digest=HEX" (spaces and such in names are \040 escapes).
func digest(mtreePath, rel string) string {
	f, err := os.Open(mtreePath)
	if err != nil {
		return ""
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return ""
	}
	defer gz.Close()
	want := "./" + rel
	sc := bufio.NewScanner(gz)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, want+" ") {
			continue
		}
		for _, field := range strings.Fields(line) {
			if v, ok := strings.CutPrefix(field, "sha256digest="); ok {
				return v
			}
		}
		return ""
	}
	return ""
}
