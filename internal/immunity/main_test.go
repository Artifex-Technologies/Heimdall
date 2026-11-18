package immunity

import (
	"os"
	"testing"

	"github.com/Artifex-Technologies/Heimdall/internal/safefs"
)

// Tests do not run as root and must not start heimdalld again: a write "as the owner" is done directly.
func TestMain(m *testing.M) {
	// YARA-X's checker is never the one installed on this computer: tests that want one set their own stand-in
	os.Setenv("HEIMDALL_YARA_CHECK", "/nonexistent/heimdall-yara-check")
	safefs.WriteAs = func(path string, f safefs.File, uid, gid uint32) error { return safefs.WriteForTest(path, f) }
	os.Exit(m.Run())
}
