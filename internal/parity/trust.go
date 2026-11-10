package parity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/Artifex-Technologies/Heimdall/internal/trust"
)

// TrustCases is the trust store's fixture (testdata/parity/trust.json): trust folders (the files as bytes; owner.key is
// never in it) and what the Go code reads from each: the mode, the watch list, the signed list (or why it cannot be
// read), and the judge's answer for changes to paths. The store folder is written as DIR in messages.
type TrustCases struct {
	Format string      `json:"format"`
	Cases  []TrustCase `json:"cases"`
}

type TrustCase struct {
	Name  string            `json:"name"`
	Files map[string]string `json:"files"` // name in the trust folder -> content (absent: no such file)
	Asks  []TrustAsk        `json:"asks"`
	// golden
	Mode  string    `json:"mode"`
	Watch string    `json:"watch"` // the watch list as JSON
	Load  TrustLoad `json:"load"`
}

type TrustLoad struct {
	Error    string            `json:"error,omitempty"`
	Version  int               `json:"version"`
	SignedAt string            `json:"signed_at"`
	Files    map[string]string `json:"files"`
}

type TrustAsk struct {
	Path    string `json:"path"`
	Hash    string `json:"hash"`
	Deleted bool   `json:"deleted,omitempty"`
	// golden
	Verdict string `json:"verdict"`
	Why     string `json:"why"`
}

// RunTrust fills in what the Go trust store reads from the case's folder.
func RunTrust(c TrustCase, dir string) (TrustCase, error) {
	for name, content := range c.Files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			return c, err
		}
	}
	s := trust.Store{Dir: dir}
	norm := func(x string) string { return strings.ReplaceAll(x, dir, "DIR") }
	c.Mode = string(s.Mode())
	w, _ := json.Marshal(s.Watch())
	c.Watch = string(w)
	if m, err := s.Load(); err != nil {
		c.Load = TrustLoad{Error: norm(err.Error())}
	} else {
		c.Load = TrustLoad{Version: m.Version, SignedAt: m.SignedAt.Format("2006-01-02T15:04:05.999999999Z07:00"), Files: m.Files}
	}
	j := trust.Judge{Store: s}
	for i := range c.Asks {
		a := &c.Asks[i]
		a.Verdict, a.Why = j.Judge(a.Path, a.Hash, a.Deleted)
		a.Why = norm(a.Why)
	}
	return c, nil
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// AllTrust computes the fixture: the cases of internal/trust's tests (a list Go's own signer wrote, tampering, the judge)
// and generated stores: modes, watch lists, keys, signatures and signed lists of every odd shape.
func AllTrust(tmp func() string) (TrustCases, error) {
	f := TrustCases{Format: "heimdall-parity-trust/1"}
	// Go's own signer: Init, Sign two real files, a watch list, the mode
	real := tmp()
	tree := tmp()
	skills := filepath.Join(tree, "skills")
	if err := os.MkdirAll(skills, 0o755); err != nil {
		return f, err
	}
	ok, rules := filepath.Join(skills, "ok.md"), filepath.Join(tree, "rules.md")
	os.WriteFile(ok, []byte("fine"), 0o644)
	os.WriteFile(rules, []byte("be careful"), 0o644)
	s := trust.Store{Dir: real}
	if _, err := s.Init(); err != nil {
		return f, err
	}
	if _, err := s.Sign([]string{ok, rules}); err != nil {
		return f, err
	}
	s.SetWatch(trust.WatchList{Files: []string{rules}, Dirs: []string{skills}})
	s.SetMode(trust.Watch)
	files := map[string]string{}
	for _, n := range []string{"owner.pub", "manifest.json", "manifest.sig", "mode", "watch.json"} {
		b, err := os.ReadFile(filepath.Join(real, n))
		if err != nil {
			return f, err
		}
		files[n] = string(b)
	}
	asks := []TrustAsk{
		{Path: ok, Hash: sum("fine")}, {Path: ok, Hash: sum("changed")}, {Path: ok, Hash: ""}, {Path: ok, Deleted: true},
		{Path: rules, Hash: sum("be careful")}, {Path: rules, Hash: strings.ToUpper(sum("be careful"))}, {Path: rules, Deleted: true},
		{Path: filepath.Join(skills, "planted.md"), Hash: "abc"}, {Path: filepath.Join(skills, "gone.md"), Deleted: true},
		{Path: filepath.Join(skills, "deep", "x.md"), Hash: "abc"}, {Path: skills, Hash: "abc"}, {Path: skills + "x/a.md", Hash: "abc"},
		{Path: "/elsewhere/file", Hash: "x"}, {Path: "", Hash: ""}, {Path: tree + "/rules.md/", Hash: sum("be careful")},
	}
	with := func(base map[string]string, k, v string) map[string]string {
		out := map[string]string{}
		for a, b := range base {
			out[a] = b
		}
		if v == "\x00drop" {
			delete(out, k)
		} else {
			out[k] = v
		}
		return out
	}
	one := func(name string, files map[string]string) {
		f.Cases = append(f.Cases, TrustCase{Name: name, Files: files, Asks: append([]TrustAsk{}, asks...)})
	}
	one("Go's own signer, watch", files)
	for _, m := range []string{"off", "off\n", "enforce\n", " watch ", "\u00a0watch\u2003", "WATCH", "", "watch\nenforce", "\x00drop"} {
		one("mode "+strings.ReplaceAll(m, "\x00", "no file: "), with(files, "mode", m))
	}
	// tampering (TestSignVerifyAndTamper)
	one("a changed list", with(files, "manifest.json", strings.Replace(files["manifest.json"], "\"version\": 1", "\"version\": 2", 1)))
	one("a list with a space more", with(files, "manifest.json", files["manifest.json"]+" "))
	one("no signature", with(files, "manifest.sig", "\x00drop"))
	one("no list", with(files, "manifest.json", "\x00drop"))
	one("no public key", with(files, "owner.pub", "\x00drop"))
	one("a public key that is not base64", with(files, "owner.pub", "not base64!\n"))
	one("a public key of the wrong size", with(files, "owner.pub", base64.StdEncoding.EncodeToString(make([]byte, 31))+"\n"))
	one("another key", with(files, "owner.pub", base64.StdEncoding.EncodeToString(make([]byte, 32))+"\n"))
	sig := strings.TrimSpace(files["manifest.sig"])
	one("a signature without its newline", with(files, "manifest.sig", sig))
	one("a signature with spaces around", with(files, "manifest.sig", "  \n"+sig+"\n\n"))
	one("a signature broken by a newline", with(files, "manifest.sig", sig[:20]+"\r\n"+sig[20:]))
	one("a signature without padding", with(files, "manifest.sig", strings.TrimRight(sig, "=")))
	one("a signature in URL base64", with(files, "manifest.sig", strings.NewReplacer("+", "-", "/", "_").Replace(sig)))
	one("a signature cut short", with(files, "manifest.sig", sig[:40]))
	// watch lists
	for _, w := range []string{`{"files":[],"dirs":[]}`, `{"FILES":["/a"],"Dirs":["/d/"]}`, `{"files":["/a",1,"/b"],"dirs":"x"}`, `not json`,
		`{"files":null}`, `[]`, `{"dirs":["/d//"]}`, "\x00drop"} {
		c := with(files, "watch.json", w)
		f.Cases = append(f.Cases, TrustCase{Name: "watch " + strings.ReplaceAll(w, "\x00", "no file: "), Files: c, Asks: []TrustAsk{
			{Path: "/a", Hash: "x"}, {Path: "/b", Hash: "x"}, {Path: "/d/x", Hash: "x"}, {Path: "/d/", Hash: "x"}, {Path: "/d//x", Hash: "x"}, {Path: "", Hash: "x"},
			{Path: rules, Hash: sum("be careful")}, {Path: ok, Hash: sum("fine")},
		}})
	}
	// lists signed with a key of our own, in shapes Go's signer never writes
	pub, priv, _ := ed25519.GenerateKey(zeroReader{})
	signed := func(body string) map[string]string {
		return map[string]string{"owner.pub": base64.StdEncoding.EncodeToString(pub) + "\n", "manifest.json": body,
			"manifest.sig": base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(body))) + "\n", "mode": "watch\n",
			"watch.json": `{"files":["/a","/b","/c"],"dirs":["/d"]}`}
	}
	h := sum("x")
	for _, body := range []string{
		`{"version":1,"signed_at":"2026-11-10T08:00:00Z","files":{"/a":"` + h + `"}}`,
		`{"VERSION":1,"Signed_At":"2026-11-10T08:00:00.5+01:00","FILES":{"/a":"` + h + `","/b":null}}`,
		`{"files":{"/a":"one","/a":"` + h + `"}}`,
		`{"files":{"/a":"` + h + `"},"files":{"/b":"` + h + `"}}`,
		`{"files":null}`, `null`, `{}`, `{"version":"1","files":{"/a":"` + h + `"}}`, `{"signed_at":"yesterday"}`,
		`{"files":["/a"]}`, `{"files":{"/a":5}}`, `{"files":{"/a":"` + h + `"}} x`, `[]`, ``, `{"files":{"/d/x":"` + h + `","/c":""}}`,
		`{"version":1.5}`, `{"files":{"/a":"` + h + `"},"extra":{"nested":[1,2,{"x":null}]}}`,
	} {
		f.Cases = append(f.Cases, TrustCase{Name: "signed list " + body, Files: signed(body), Asks: []TrustAsk{
			{Path: "/a", Hash: h}, {Path: "/a", Hash: "one"}, {Path: "/b", Hash: h}, {Path: "/b", Hash: ""}, {Path: "/b", Deleted: true},
			{Path: "/c", Hash: ""}, {Path: "/c", Deleted: true}, {Path: "/d/x", Hash: h}, {Path: "/d/y", Deleted: true},
		}})
	}
	for i := range f.Cases {
		var err error
		if f.Cases[i], err = RunTrust(f.Cases[i], tmp()); err != nil {
			return f, err
		}
	}
	return f, nil
}

// zeroReader makes the fixture's own key the same on every run.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 7
	}
	return len(p), nil
}
