package immunity

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// limboHeld writes a file into a fake Limbo held folder under its SHA-256, as Limbo does.
func limboHeld(t *testing.T, body string) (dir, sha string) {
	dir = t.TempDir()
	sum := sha256.Sum256([]byte(body))
	sha = hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(dir, sha), []byte(body), 0o400); err != nil {
		t.Fatal(err)
	}
	return dir, sha
}

func TestTakeFromLimboKeepsExactlyWhatLimboHeld(t *testing.T) {
	s := store(t)
	body := strings.Repeat("EICAR-STANDARD-ANTIVIRUS-TEST-FILE ", 3)
	dir, sha := limboHeld(t, body)
	var scanned string
	e, err := s.TakeFromLimbo(dir, strings.ToUpper(sha), func(p string) (string, error) {
		b, _ := os.ReadFile(p)
		scanned = string(b)
		return "Eicar-Test-Signature", nil
	})
	if err != nil || e.Status != Reference || e.ClamAV != "Eicar-Test-Signature" || e.SHA256 != sha || e.Source != "limbo" {
		t.Fatal(e, err)
	}
	if scanned != body {
		t.Fatal("the reference was not given the sample")
	}
	if e.Report == nil {
		t.Fatal("no report")
	}
	if b, err := os.ReadFile(filepath.Join(dir, sha)); err != nil || string(b) != body {
		t.Fatal("Limbo's copy must stay where it is")
	}
	if b, err := s.sampleBytes(sha); err != nil || string(b) != body {
		t.Fatal("stored sample differs", err)
	}
	// asking again changes nothing
	again, err := s.TakeFromLimbo(dir, sha, nil)
	if err != nil || again.Status != Reference {
		t.Fatal(again, err)
	}
}

func TestTakeFromLimboUnknownToTheReferenceStaysASuspect(t *testing.T) {
	s := store(t)
	dir, sha := limboHeld(t, planted)
	e, err := s.TakeFromLimbo(dir, sha, func(string) (string, error) { return "", nil })
	if err != nil || e.Status != Suspect {
		t.Fatal(e, err)
	}
}

func TestTakeFromLimboRefuses(t *testing.T) {
	s := store(t)
	dir, sha := limboHeld(t, planted)
	other := strings.Repeat("b", 64)
	// a file whose content is not what its name says
	if err := os.WriteFile(filepath.Join(dir, other), []byte(planted), 0o400); err != nil {
		t.Fatal(err)
	}
	// a link named like a held file, pointing at a file outside Limbo's folder
	outside := sample(t, planted+"outside")
	sum := sha256.Sum256([]byte(planted + "outside"))
	linked := hex.EncodeToString(sum[:])
	if err := os.Symlink(outside, filepath.Join(dir, linked)); err != nil {
		t.Fatal(err)
	}
	for name, ask := range map[string]string{
		"not a SHA-256":        "../../etc/shadow",
		"short":                sha[:16],
		"path inside the name": "x/" + sha[2:],
		"wrong content":        other,
		"a link":               linked,
		"missing":              strings.Repeat("c", 64),
	} {
		if _, err := s.TakeFromLimbo(dir, ask, nil); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
	if es, _ := s.Load(); len(es) != 0 {
		t.Fatalf("something was stored: %+v", es)
	}
}
