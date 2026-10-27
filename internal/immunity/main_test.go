package immunity

import (
	"os"
	"testing"

	"github.com/Artifex-Technologies/Heimdall/internal/safefs"
)

// Tests do not run as root and must not start heimdalld again: a write "as the owner" is done directly.
func TestMain(m *testing.M) {
	safefs.WriteAs = func(path string, f safefs.File, uid, gid uint32) error { return safefs.WriteForTest(path, f) }
	os.Exit(m.Run())
}
