package parity

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/mesh"
	"github.com/Artifex-Technologies/Heimdall/internal/trust"
)

// CLITrust is the fixture of the owner's side of trust (testdata/parity/cli-trust.json), what `heimdalld trust` writes:
// the key files Go makes from a seed, the exact bytes of signed lists and their signatures (Go's write, at a known time),
// the watch list and the mode as Go's SetWatch and SetMode write them, and Go's answers to ParseMode. Everything is fixed
// (no random key, no clock), so the file is the same on every run. rust/heimdall/tests/cli_trust.rs runs it.
type CLITrust struct {
	Format string           `json:"format"`
	Keys   []CLITrustKey    `json:"keys"`
	Lists  []CLITrustList   `json:"lists"`
	Watch  []CLITrustWatch  `json:"watch"`
	Modes  []CLITrustMode   `json:"modes"`
	Base64 []CLITrustBase64 `json:"base64"`
	Mesh   CLIMesh          `json:"mesh"`
}

type CLITrustKey struct {
	Seed string `json:"seed"` // hex
	// golden
	Key string `json:"key"` // owner.key's content
	Pub string `json:"pub"` // owner.pub's content
}

type CLITrustList struct {
	Seed     string      `json:"seed"`      // hex
	SignedAt string      `json:"signed_at"` // RFC 3339
	Files    [][2]string `json:"files"`     // hex of the path's bytes, the hash
	// golden
	Body string `json:"body"` // manifest.json
	Sig  string `json:"sig"`  // manifest.sig
}

type CLITrustWatch struct {
	Files *[]string `json:"files"` // null: nil
	Dirs  *[]string `json:"dirs"`
	// golden
	JSON string `json:"json"` // watch.json
}

type CLITrustMode struct {
	In string `json:"in"`
	// golden
	Mode  string `json:"mode"`
	Error string `json:"error"`
	File  string `json:"file"` // what SetMode writes, when it is a mode
}

// CLIMesh is the mesh half of the fixture: identities from seeds (the key file Go writes and the fingerprint), Go's answers
// to Peer.Validate, and sequences of SetPeer with the peers file after each step.
type CLIMesh struct {
	Identities []CLIMeshIdentity `json:"identities"`
	Validate   []CLIMeshValidate `json:"validate"`
	Sequences  []CLIMeshSequence `json:"sequences"`
}

type CLIMeshIdentity struct {
	Seed string `json:"seed"` // hex
	// golden
	KeyPEM      string `json:"key_pem"`
	Fingerprint string `json:"fingerprint"`
}

type CLIMeshValidate struct {
	Peer mesh.Peer `json:"peer"`
	// golden
	Error string `json:"error"`
}

type CLIMeshSequence struct {
	Start string         `json:"start"` // the peers file before (absent: no file)
	Steps []CLIMeshEntry `json:"steps"`
}

type CLIMeshEntry struct {
	Peer   mesh.Peer `json:"peer"`
	Remove bool      `json:"remove,omitempty"`
	// golden
	Error string   `json:"error"`
	Names []string `json:"names"`
	File  string   `json:"file"` // the peers file after the step (absent: none)
}

type CLITrustBase64 struct {
	Hex string `json:"hex"`
	// golden
	Text string `json:"text"`
}

// AllCLITrust computes the fixture.
func AllCLITrust(tmp string) (CLITrust, error) {
	f := CLITrust{Format: "heimdall-parity-cli-trust/1"}
	seeds := [][]byte{make([]byte, 32), bytesOf(7, 32), counting(32, 1), counting(32, 200)}
	for _, s := range seeds {
		priv := ed25519.NewKeyFromSeed(s)
		f.Keys = append(f.Keys, CLITrustKey{Seed: hex.EncodeToString(s),
			Key: base64.StdEncoding.EncodeToString(priv) + "\n", Pub: base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)) + "\n"})
	}
	h := sum("x")
	lists := []struct {
		at    string
		files [][2]string
	}{
		{"2026-11-10T08:00:00Z", nil},
		{"2026-11-10T08:00:00Z", [][2]string{{"/home/owner/.sarina/policy.json", h}}},
		{"0001-01-01T00:00:00Z", [][2]string{{"/b", h}, {"/a", sum("a")}, {"/a/b", h}, {"/a.txt", h}, {"/a-b", h}}},
		{"2026-01-31T23:59:59Z", [][2]string{{"/x/<script>&\"quote\"\\", h}, {"/x/ünï cödé ✓", h}, {"/x/  ", h}, {"/x/\x01\x1f\x7f", h}}},
		{"2026-06-01T12:00:00Z", [][2]string{{"/x/\xff\xfe", h}, {"/x/a\xe2\x84b", h}, {"/x/�", h}, {"/x/tab\there", ""}}},
		{"9999-12-31T23:59:59Z", [][2]string{{"/x/emoji 😀", "not a hash <&>"}}},
	}
	for i, l := range lists {
		at, err := time.Parse(time.RFC3339, l.at)
		if err != nil {
			return f, err
		}
		seed := seeds[i%len(seeds)]
		m := trust.Manifest{Version: 1, SignedAt: at, Files: map[string]string{}}
		var files [][2]string
		for _, x := range l.files {
			m.Files[x[0]] = x[1]
			files = append(files, [2]string{hex.EncodeToString([]byte(x[0])), x[1]})
		}
		// exactly Store.write's body
		body, err := json.MarshalIndent(&m, "", "  ")
		if err != nil {
			return f, err
		}
		body = append(body, '\n')
		sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), body)
		f.Lists = append(f.Lists, CLITrustList{Seed: hex.EncodeToString(seed), SignedAt: l.at, Files: files, Body: string(body),
			Sig: base64.StdEncoding.EncodeToString(sig) + "\n"})
	}
	list := func(x ...string) *[]string { return &x }
	empty := []string{}
	for _, w := range []CLITrustWatch{
		{}, {Files: &empty, Dirs: &empty}, {Files: list("/a"), Dirs: nil}, {Files: list("/a", "/b <&>"), Dirs: list("/d", "/e/ünï")},
		{Files: list("/home/owner/.sarina/policy.json", "/home/owner/.sarina/mcp.json", "/home/owner/.sarina/skills.json", "/etc/heimdall/config.json"),
			Dirs: list("/home/owner/.sarina/skills", "/home/owner/.sarina/agents", "/home/owner/.sarina/vendor", "/etc/sarina")},
	} {
		s := trust.Store{Dir: filepath.Join(tmp, "watch")}
		os.MkdirAll(s.Dir, 0o755)
		var wl trust.WatchList
		if w.Files != nil {
			wl.Files = *w.Files
		}
		if w.Dirs != nil {
			wl.Dirs = *w.Dirs
		}
		if err := s.SetWatch(wl); err != nil {
			return f, err
		}
		b, err := os.ReadFile(filepath.Join(s.Dir, "watch.json"))
		if err != nil {
			return f, err
		}
		w.JSON = string(b)
		f.Watch = append(f.Watch, w)
	}
	for _, in := range []string{"off", "watch", "enforce", " watch\n", " enforce　", "WATCH", "", "on", "watch enforce", "\"x\"\x01é"} {
		c := CLITrustMode{In: in}
		m, err := trust.ParseMode(in)
		if err != nil {
			c.Error = err.Error()
		} else {
			c.Mode = string(m)
			s := trust.Store{Dir: filepath.Join(tmp, "mode")}
			os.MkdirAll(s.Dir, 0o755)
			if err := s.SetMode(m); err != nil {
				return f, err
			}
			b, _ := os.ReadFile(filepath.Join(s.Dir, "mode"))
			c.File = string(b)
		}
		f.Modes = append(f.Modes, c)
	}
	for n := 0; n <= 70; n++ {
		b := counting(n, n*3)
		f.Base64 = append(f.Base64, CLITrustBase64{Hex: hex.EncodeToString(b), Text: base64.StdEncoding.EncodeToString(b)})
	}
	return f, allCLIMesh(&f.Mesh, seeds, tmp)
}

func allCLIMesh(m *CLIMesh, seeds [][]byte, tmp string) error {
	for _, s := range seeds {
		der, err := x509.MarshalPKCS8PrivateKey(ed25519.NewKeyFromSeed(s))
		if err != nil {
			return err
		}
		// what LoadOrCreate writes, read back by LoadOrCreate itself
		dir := filepath.Join(tmp, "mesh-"+hex.EncodeToString(s[:4]))
		os.MkdirAll(dir, 0o700)
		key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if err := os.WriteFile(filepath.Join(dir, "key.pem"), key, 0o600); err != nil {
			return err
		}
		id, err := mesh.LoadOrCreate(dir)
		if err != nil {
			return err
		}
		m.Identities = append(m.Identities, CLIMeshIdentity{Seed: hex.EncodeToString(s), KeyPEM: string(key), Fingerprint: id.Fingerprint})
	}
	fp := m.Identities[0].Fingerprint
	fp2 := m.Identities[1].Fingerprint
	for _, p := range []mesh.Peer{
		{Name: "laptop", Fingerprint: fp, Address: "100.64.0.2:8931"},
		{Name: "", Fingerprint: fp, Address: "100.64.0.2:8931"},
		{Name: "Laptop", Fingerprint: fp, Address: "100.64.0.2:8931"},
		{Name: "-x", Fingerprint: fp, Address: "100.64.0.2:8931"},
		{Name: "a23456789012345678901234567890123", Fingerprint: fp, Address: "100.64.0.2:8931"},
		{Name: "a2345678901234567890123456789012", Fingerprint: fp, Address: "[fd00::2]:8931"},
		{Name: "pc", Fingerprint: strings.ToUpper(fp), Address: "100.64.0.2:8931"},
		{Name: "pc", Fingerprint: fp[:35], Address: "100.64.0.2:8931"},
		{Name: "pc", Fingerprint: "hm1-" + strings.Repeat("1", 32), Address: "100.64.0.2:8931"},
		{Name: "pc", Fingerprint: fp + "\n", Address: "100.64.0.2:8931"},
		{Name: "pc\n", Fingerprint: fp, Address: "100.64.0.2:8931"},
		{Name: "pc", Fingerprint: fp, Address: "pc.lan:8931"},
		{Name: "pc", Fingerprint: fp, Address: "100.64.0.2"},
		{Name: "pc", Fingerprint: fp, Address: "100.64.0.2:"},
		{Name: "pc", Fingerprint: fp, Address: "100.64.0.2:0"},
		{Name: "pc", Fingerprint: fp, Address: "100.64.0.2:http"},
		{Name: "pc", Fingerprint: fp, Address: "0.0.0.0:8931"},
		{Name: "pc", Fingerprint: fp, Address: "[::]:8931"},
		{Name: "pc", Fingerprint: fp, Address: "224.0.0.1:8931"},
		{Name: "pc", Fingerprint: fp, Address: "[ff02::1]:8931"},
		{Name: "pc", Fingerprint: fp, Address: "[fe80::1%eth0]:8931"},
		{Name: "pc", Fingerprint: fp, Address: "127.0.0.1:8931"},
		{Name: "pc", Fingerprint: fp, Address: "::1:8931"},
	} {
		v := CLIMeshValidate{Peer: p}
		if err := p.Validate(); err != nil {
			v.Error = err.Error()
		}
		m.Validate = append(m.Validate, v)
	}
	a := mesh.Peer{Name: "laptop", Fingerprint: fp, Address: "100.64.0.2:8931"}
	b := mesh.Peer{Name: "desk", Fingerprint: fp2, Address: "[fd00::2]:8931"}
	sequences := []struct {
		start string
		steps []CLIMeshEntry
	}{
		{"\x00none", []CLIMeshEntry{{Peer: a}, {Peer: b}, {Peer: mesh.Peer{Name: "laptop", Fingerprint: fp, Address: "100.64.0.3:8931"}},
			{Peer: mesh.Peer{Name: "other", Fingerprint: fp2, Address: "100.64.0.4:8931"}}, {Peer: mesh.Peer{Name: "bad"}},
			{Peer: mesh.Peer{Name: "nobody"}, Remove: true}, {Peer: mesh.Peer{Name: "laptop"}, Remove: true}, {Peer: mesh.Peer{Name: "other"}, Remove: true}}},
		{`[{"name":"x","fingerprint":"` + fp + `","address":"1.2.3.4:5"},{"name":"Bad","fingerprint":"` + fp + `","address":"1.2.3.4:5"},{"NAME":"y","Fingerprint":"` + fp2 + `","address":"[::1]:9","extra":1}] trailing`,
			[]CLIMeshEntry{{Peer: mesh.Peer{Name: "x"}, Remove: true}}},
		{`null`, []CLIMeshEntry{{Peer: a}}},
		{`{"name":"x"}`, []CLIMeshEntry{{Peer: a}}},
		{`[{"name":5}]`, []CLIMeshEntry{{Peer: a}}},
		{``, []CLIMeshEntry{{Peer: a}}},
	}
	for _, start := range []string{`["x"]`, `[1, {"name":"x"}]`, `[{"name":"a","address":[1]}]`, `[{"address":{"x":1},"name":true}]`, `5`, `"s"`,
		`true`, `[null, {"name":"x","fingerprint":"` + fp + `","address":"1.2.3.4:5"}]`, `[{"name":null,"fingerprint":"x"}]`, `[`, `[{"name":"a"},]`,
		`[{"name":"a" "x"}]`, `{}`, `[{"name":"\ud800x"}]`, `[] [`, " \n[]", `[{"name":"a","name":"b"}]`, `[{"name":1.5e3}]`, `[[]]`} {
		sequences = append(sequences, struct {
			start string
			steps []CLIMeshEntry
		}{start, []CLIMeshEntry{{Peer: mesh.Peer{Name: "x"}, Remove: true}}})
	}
	for i, sq := range sequences {
		path := filepath.Join(tmp, fmt.Sprintf("peers-%d.json", i))
		if sq.start != "\x00none" {
			if err := os.WriteFile(path, []byte(sq.start), 0o644); err != nil {
				return err
			}
		}
		out := CLIMeshSequence{Start: sq.start}
		for _, st := range sq.steps {
			ps, err := mesh.SetPeer(path, st.Peer, st.Remove)
			if err != nil {
				st.Error = strings.ReplaceAll(err.Error(), tmp, "TMP")
			}
			for _, p := range ps {
				st.Names = append(st.Names, p.Name)
			}
			b, _ := os.ReadFile(path)
			st.File = string(b)
			out.Steps = append(out.Steps, st)
		}
		m.Sequences = append(m.Sequences, out)
	}
	return nil
}

func bytesOf(v byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = v
	}
	return b
}

func counting(n, from int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(from + i*37)
	}
	return b
}
