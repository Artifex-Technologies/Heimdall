package pkgverify

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func fixture(t *testing.T) string {
	dir := t.TempDir()
	pkg := filepath.Join(dir, "demo-1.0-1")
	os.MkdirAll(pkg, 0o755)
	os.WriteFile(filepath.Join(pkg, "files"), []byte("%FILES%\nusr/\nusr/bin/\nusr/bin/demo\n"), 0o644)
	f, _ := os.Create(filepath.Join(pkg, "mtree"))
	gz := gzip.NewWriter(f)
	gz.Write([]byte("#mtree\n/set type=file uid=0 gid=0 mode=644\n./usr time=1 type=dir\n./usr/bin/demo time=1 size=3 sha256digest=abc123 mode=755\n./usr/bin/other time=1 size=3 sha256digest=zzz\n"))
	gz.Close()
	f.Close()
	return dir
}

func TestExpected(t *testing.T) {
	v := New(fixture(t))
	pkg, sha, owned := v.Expected("/usr/bin/demo")
	if !owned || pkg != "demo-1.0-1" || sha != "abc123" {
		t.Fatalf("got %q %q %v", pkg, sha, owned)
	}
	if _, _, owned := v.Expected("/usr/bin/other"); owned {
		t.Fatal("not listed in files, so not owned")
	}
	if _, _, owned := v.Expected("/home/x/file"); owned {
		t.Fatal("unowned")
	}
	if _, _, owned := New("").Expected("/usr/bin/demo"); owned {
		t.Fatal("no db")
	}
}
