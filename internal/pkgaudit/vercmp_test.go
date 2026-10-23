package pkgaudit

import (
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

var pairs = [][2]string{
	{"1.0", "1.0"}, {"1.0", "1.1"}, {"1.0.0", "1.0"}, {"1.0a", "1.0"}, {"1.0alpha", "1.0"}, {"1.0", "1.0.a"}, {"1.0.a", "1.0.1"},
	{"8.4.27-1", "8.4.27-1.1"}, {"8.4.26-2.1", "8.4.27-1"}, {"1:1.0-1", "2.0-1"}, {"2.0-1", "1:1.0"}, {"1.0-1", "1.0-2"}, {"1.0-1", "1.0"},
	{"9.0.1224-1", "9.0.1225-1"}, {"1.0rc1", "1.0"}, {"1.0", "1.0+git"}, {"20260817.0-2.1", "20260817.0-2"}, {"1.001", "1.1"},
	{"1.0_beta", "1.0.beta"}, {"a", "b"}, {"1..0", "1.0"}, {"2.4.0-1.1", "2.4.0-1"}, {"6.1.2-1", "6.10-1"},
}

func TestVercmpAgreesWithPacman(t *testing.T) {
	bin, err := exec.LookPath("vercmp")
	if err != nil {
		t.Skip("pacman's vercmp is not installed")
	}
	for _, p := range pairs {
		out, err := exec.Command(bin, p[0], p[1]).Output()
		if err != nil {
			t.Fatal(err)
		}
		want, _ := strconv.Atoi(strings.TrimSpace(string(out)))
		if got := Vercmp(p[0], p[1]); got != want {
			t.Errorf("Vercmp(%q, %q) = %d, pacman says %d", p[0], p[1], got, want)
		}
	}
}
