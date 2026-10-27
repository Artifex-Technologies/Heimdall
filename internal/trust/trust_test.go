package trust

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignVerifyAndTamper(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if created, err := s.Init(); err != nil || !created {
		t.Fatal(created, err)
	}
	if created, _ := s.Init(); created {
		t.Fatal("an existing key is never replaced")
	}
	if s.Mode() != Off {
		t.Fatal("off until switched on")
	}
	files := t.TempDir()
	skill := filepath.Join(files, "skills", "fix", "SKILL.md")
	os.MkdirAll(filepath.Dir(skill), 0o755)
	os.WriteFile(skill, []byte("approved"), 0o644)
	done, err := s.Sign([]string{filepath.Join(files, "skills")})
	if err != nil || len(done) != 1 || done[0] != skill {
		t.Fatal(done, err)
	}
	m, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	sum, _ := HashFile(skill)
	if !m.Matches(skill, sum) {
		t.Fatal("the signed content matches")
	}
	os.WriteFile(skill, []byte("changed by someone"), 0o644)
	sum2, _ := HashFile(skill)
	if m.Matches(skill, sum2) {
		t.Fatal("a change is not approved")
	}
	// editing the list without the key breaks the signature
	body, _ := os.ReadFile(filepath.Join(s.Dir, "manifest.json"))
	os.WriteFile(filepath.Join(s.Dir, "manifest.json"), []byte(strings.Replace(string(body), sum, sum2, 1)), 0o644)
	if _, err := s.Load(); err == nil {
		t.Fatal("a list changed without the key must not load")
	}
}

func TestForgetAndMode(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	s.Init()
	f := filepath.Join(t.TempDir(), "policy.json")
	os.WriteFile(f, []byte("{}"), 0o644)
	s.Sign([]string{f})
	if gone, err := s.Forget([]string{f}); err != nil || len(gone) != 1 {
		t.Fatal(gone, err)
	}
	if m, _ := s.Load(); m.Has(f) {
		t.Fatal("forgotten")
	}
	if err := s.SetMode(Enforce); err != nil || s.Mode() != Enforce {
		t.Fatal(err)
	}
	if err := s.SetMode("loose"); err == nil {
		t.Fatal("unknown modes are refused")
	}
}

func TestSigningNeedsTheKey(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	s.Init()
	os.Remove(filepath.Join(s.Dir, "owner.key"))
	f := filepath.Join(t.TempDir(), "x")
	os.WriteFile(f, []byte("x"), 0o644)
	if _, err := s.Sign([]string{f}); err == nil {
		t.Fatal("without the key nothing is signed")
	}
}

func TestJudge(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	s.Init()
	dir := t.TempDir()
	skills := filepath.Join(dir, "skills")
	os.MkdirAll(skills, 0o755)
	ok := filepath.Join(skills, "ok.md")
	os.WriteFile(ok, []byte("fine"), 0o644)
	s.Sign([]string{ok})
	s.SetWatch(WatchList{Dirs: []string{skills}})
	j := Judge{s}
	sum, _ := HashFile(ok)
	if v, _ := j.Judge(ok, sum, false); v != "" {
		t.Fatal("off: no say")
	}
	s.SetMode(Watch)
	if v, _ := j.Judge(ok, sum, false); v != "approved" {
		t.Fatal(v)
	}
	if v, why := j.Judge(filepath.Join(skills, "planted.md"), "abc", false); v != "unsigned" || why == "" {
		t.Fatal(v)
	}
	if v, _ := j.Judge(ok, "", true); v != "unsigned" {
		t.Fatal("deleting a file the list expects is not approved")
	}
	if v, _ := j.Judge("/elsewhere/file", "x", false); v != "" {
		t.Fatal("not a watched path: no say")
	}
}

// asOwner stands in for the child process in tests (they do not run as root): it records who the write was for.
func asOwner(t *testing.T) *[]uint32 {
	var uids []uint32
	old := writeAsOwner
	writeAsOwner = func(path string, data []byte, uid, gid uint32) error {
		uids = append(uids, uid)
		return writeOwned(path, data)
	}
	t.Cleanup(func() { writeAsOwner = old })
	return &uids
}

func TestRestoreWritesAsTheFoldersOwnerAndNeverThroughALink(t *testing.T) {
	uids := asOwner(t)
	s := Store{Dir: t.TempDir()}
	s.Init()
	home := t.TempDir()
	f := filepath.Join(home, "skills", "fix.md")
	os.MkdirAll(filepath.Dir(f), 0o755)
	os.WriteFile(f, []byte("approved"), 0o644)
	s.Sign([]string{f})
	os.WriteFile(f, []byte("tampered"), 0o644)
	if _, err := s.Restore(nil); err != nil {
		t.Fatal(err)
	}
	if len(*uids) != 1 || (*uids)[0] != uint32(os.Getuid()) {
		t.Fatalf("not written as the folder's owner: %v", *uids)
	}
	// the user swaps the folder for a link to somewhere else: the restore refuses instead of following it
	elsewhere := t.TempDir()
	os.RemoveAll(filepath.Join(home, "skills"))
	os.Symlink(elsewhere, filepath.Join(home, "skills"))
	if _, err := s.Restore(nil); err == nil || !strings.Contains(err.Error(), "is a link") {
		t.Fatalf("followed a link: %v", err)
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Fatal("wrote through the link")
	}
}

func TestRootWritesOnlyIntoRootOnlyFolders(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("needs a folder not owned by root")
	}
	if err := rootOnly(t.TempDir()); err == nil {
		t.Fatal("a folder owned by a user passed as root-only")
	}
	if err := rootOnly("/usr/share"); err != nil {
		t.Fatalf("/usr/share should be root-only: %v", err)
	}
}

func TestRestorePutsTheApprovedContentBack(t *testing.T) {
	asOwner(t)
	s := Store{Dir: t.TempDir()}
	s.Init()
	dir := t.TempDir()
	a := filepath.Join(dir, "policy.json")
	b := filepath.Join(dir, "skills", "fix.md")
	os.MkdirAll(filepath.Dir(b), 0o755)
	os.WriteFile(a, []byte("approved policy"), 0o644)
	os.WriteFile(b, []byte("approved skill"), 0o644)
	s.Sign([]string{a, b})
	os.WriteFile(a, []byte("tampered"), 0o644)
	os.Remove(b)
	got, err := s.Restore(nil)
	if err != nil || len(got) != 2 {
		t.Fatal(got, err)
	}
	if x, _ := os.ReadFile(a); string(x) != "approved policy" {
		t.Fatal(string(x))
	}
	if x, _ := os.ReadFile(b); string(x) != "approved skill" {
		t.Fatal(string(x))
	}
	if got, _ := s.Restore(nil); len(got) != 0 {
		t.Fatal("nothing left to restore")
	}
	// a copy no entry needs goes when the list changes
	os.WriteFile(a, []byte("new approved policy"), 0o644)
	s.Sign([]string{a})
	entries, _ := os.ReadDir(filepath.Join(s.Dir, "approved"))
	if len(entries) != 2 {
		t.Fatalf("%d copies", len(entries))
	}
}
