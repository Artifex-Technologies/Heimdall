package macvendor

// Every name and prefix here is invented (no real company's block); private addresses are locally administered ones (02:...).

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const ouiTxt = "OUI/MA-L\t\t\tOrganization\ncompany_id\t\t\tOrganization\n\t\t\t\tAddress\n\n" +
	"0C-00-01   (hex)\t\tEXAMPLE NETWORKS CORP\n" +
	"0C0001     (base 16)\t\tEXAMPLE NETWORKS CORP\n" +
	"\t\t\t\t1 Example Road\n\t\t\t\tSomewhere\n\n" +
	"0C-00-02   (hex)\t\tSample Radio Co.,Ltd\n" +
	"0C0002     (base 16)\t\tSample Radio Co.,Ltd\n\n" +
	"0C-00-03   (hex)\t\tIEEE Registration Authority\n" +
	"0C0003     (base 16)\t\tIEEE Registration Authority\n\n" +
	"0C-00-01   (hex)\t\tA Second Claim On The Same Prefix\n"

const iabTxt = "OUI                                                         Organization\n" +
	"IAB Range                                                   Organization\n" +
	"                                                            Address\n\n" +
	"0C-00-03                      (hex)                         Tiny Sensors Inc.\n" +
	"ABC000-ABCFFF                 (base 16)                     Tiny Sensors Inc.\n" +
	"                                                            Somewhere\n"

const mamCSV = "\xef\xbb\xbfRegistry,Assignment,Organization Name,Organization Address\r\n" +
	"MA-M,0C00030,\"Middle Block Devices, Inc.\",\"1 Way\r\nTown\"\r\n" +
	"MA-M,0C00031,\"The \"\"Quoted\"\" Company\",Somewhere\r\n"

const oui36CSV = "Registry,Assignment,Organization Name,Organization Address\n" +
	"MA-S,0C0003ABD,Smallest Things GmbH,Somewhere\n" +
	"MA-S,0C0003ABC,Shadowed By The IAB Block,Somewhere\n"

func build(files ...string) *Table {
	b := NewBuilder()
	regs := []Registry{IAB, MaS, MaM, MaL}
	for i, f := range files {
		b.Read(strings.NewReader(f), regs[i%len(regs)])
	}
	return b.Finish()
}

func TestTheLongestBlockWins(t *testing.T) {
	tb := build(iabTxt, oui36CSV, mamCSV, ouiTxt)
	cases := []struct {
		mac, short string
		reg        Registry
		bits       uint8
	}{
		{"0c:00:01:12:34:56", "Example Networks", MaL, 24},
		{"0c:00:03:ab:c1:23", "Tiny Sensors", IAB, 36},
		{"0c:00:03:ab:d1:23", "Smallest Things", MaS, 36},
		{"0c:00:03:01:23:45", "Middle Block Devices", MaM, 28},
		{"0c:00:03:12:34:56", "The \"Quoted\" Company", MaM, 28},
		{"0c:00:03:ab:e1:23", "IEEE Registration Authority", MaL, 24},
	}
	for _, c := range cases {
		a := tb.LookupString(c.mac)
		if a.Kind != KindVendor || a.Short != c.short || a.Registry != c.reg || a.Bits != c.bits {
			t.Errorf("%s: %+v", c.mac, a)
		}
	}
	if a := tb.LookupString("0c:00:01:00:00:00"); a.Name != "EXAMPLE NETWORKS CORP" {
		t.Errorf("the first claim must stay: %+v", a)
	}
	if tb.Len() != 7 {
		t.Errorf("len %d", tb.Len())
	}
	if a, ok := tb.LookupOUI([3]byte{0x0c, 0, 2}); !ok || a.Short != "Sample Radio" {
		t.Errorf("%+v", a)
	}
}

func TestAddressesThatSayWhatTheyAre(t *testing.T) {
	tb := build("", "", "", ouiTxt)
	for mac, want := range map[string]string{
		"ff:ff:ff:ff:ff:ff": "special Broadcast", "01:00:5e:00:00:fb": "special IPv4 multicast", "33:33:00:00:00:fb": "special IPv6 multicast",
		"00:00:5e:00:01:07": "special VRRP router", "0d:00:01:00:00:00": "multicast ", "02:00:00:00:00:01": "private ",
		"0e:00:01:00:00:01": "private ", "0c:00:04:00:00:00": "unknown ", "0c:00:01:00:00": "invalid ", "zz:zz:zz:00:00:00": "invalid ",
	} {
		a := tb.LookupString(mac)
		if got := a.Kind + " " + a.Label(); got != want {
			t.Errorf("%s: %q, want %q", mac, got, want)
		}
	}
}

func TestShortNames(t *testing.T) {
	for full, want := range map[string]string{
		"ASKEY COMPUTER CORP": "Askey Computer", "Intel Corporate": "Intel", "Amazon Technologies Inc.": "Amazon", "Apple, Inc.": "Apple",
		"Nokia Shanghai Bell Co., Ltd.": "Nokia Shanghai Bell", "eero inc.": "eero", "LG ELECTRONICS": "LG Electronics",
		"ZTE CORPORATION": "ZTE", "Incom Ltd": "Incom", "Foo Incom": "Foo Incom", "Co.,Ltd X": "Co", "...": "...", "": "",
	} {
		if got := Short(full); got != want {
			t.Errorf("Short(%q) = %q, want %q", full, got, want)
		}
	}
	if got := Clean([]byte("Good\u202e Name\x07")); got != "Good Name" {
		t.Errorf("%q", got)
	}
	// not UTF-8: read byte by byte
	if got := Clean([]byte("\xc9cole \u00e9")); got != "\ufffdcole \ufffd\ufffd" {
		t.Errorf("%q", got)
	}
}

func TestLoadPrefersTheIEEEFiles(t *testing.T) {
	d := t.TempDir()
	paths := DataPaths{IEEEDir: filepath.Join(d, "ieee"), HwdataDir: filepath.Join(d, "hwdata")}
	os.MkdirAll(paths.IEEEDir, 0o755)
	os.MkdirAll(paths.HwdataDir, 0o755)
	if Load(paths).Len() != 0 {
		t.Fatal("no files must give an empty table")
	}
	os.WriteFile(filepath.Join(paths.HwdataDir, "oui.txt"), []byte(ouiTxt), 0o644)
	os.WriteFile(filepath.Join(paths.HwdataDir, "iab.txt"), []byte(iabTxt), 0o644)
	if a := Load(paths).LookupString("0c:00:03:ab:c0:01"); a.Registry != IAB {
		t.Errorf("%+v", a)
	}
	os.WriteFile(filepath.Join(paths.IEEEDir, "oui.csv"), []byte("Registry,Assignment,Organization Name\nMA-L,0C0001,Fresher Name Ltd\n"), 0o644)
	os.WriteFile(filepath.Join(paths.IEEEDir, "mam.csv"), []byte(mamCSV), 0o644)
	os.WriteFile(filepath.Join(paths.IEEEDir, "oui36.csv"), []byte(oui36CSV), 0o644)
	tb := Load(paths)
	if a := tb.LookupString("0c:00:01:00:00:01"); a.Short != "Fresher Name" {
		t.Errorf("%+v", a)
	}
	if a := tb.LookupString("0c:00:02:00:00:01"); a.Kind != KindUnknown {
		t.Errorf("hwdata's MA-L list must not be read when the IEEE's is there: %+v", a)
	}
	if a := tb.LookupString("0c:00:03:ab:c0:01"); a.Registry != MaS {
		t.Errorf("the MA-S file comes before the IAB list: %+v", a)
	}
	os.WriteFile(filepath.Join(paths.IEEEDir, "oui.csv"), []byte("<html>not found</html>\n"), 0o644)
	if a := Load(paths).LookupString("0c:00:02:00:00:01"); a.Short != "Sample Radio" {
		t.Errorf("a damaged download falls back to hwdata: %+v", a)
	}
	os.Remove(filepath.Join(paths.IEEEDir, "oui.csv"))
	if exec.Command("mkfifo", filepath.Join(paths.IEEEDir, "oui.csv")).Run() == nil {
		if a := Load(paths).LookupString("0c:00:02:00:00:01"); a.Short != "Sample Radio" {
			t.Errorf("a FIFO is skipped: %+v", a)
		}
	}
}

// The real lists, where hwdata is installed.
func TestHwdataWhenInstalled(t *testing.T) {
	if _, err := os.Stat(filepath.Join(HwdataDir, "oui.txt")); err != nil {
		t.Skip("no hwdata")
	}
	if n := Load(DataPaths{IEEEDir: "/nonexistent", HwdataDir: HwdataDir}).Len(); n < 30000 {
		t.Errorf("only %d blocks", n)
	}
}

func FuzzRead(f *testing.F) {
	for _, s := range []string{ouiTxt, iabTxt, mamCSV, oui36CSV} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		b := NewBuilder()
		n := b.Read(strings.NewReader(string(data)), MaL)
		tb := b.Finish()
		if tb.Len() > n || (tb.Len() == 0) != (n == 0) {
			t.Fatal(n, tb.Len())
		}
		for i := 0; i+6 <= len(data) && i < 256; i++ {
			a := tb.Lookup([6]byte(data[i : i+6]))
			if a.Kind == KindVendor && (a.Name == "" || a.Short == "" || len(a.Name) > MaxName) {
				t.Fatalf("%+v", a)
			}
		}
		c := Clean(data)
		if len(c) > MaxName || Clean([]byte(c)) != c || (Short(c) == "") != (c == "") {
			t.Fatalf("%q", c)
		}
	})
}
