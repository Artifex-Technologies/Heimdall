package kernelaudit

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// Run asks Hold before every check (heimdalld: not while a game runs) and stops when Hold says so.
func TestRunAsksHoldBeforeEachCheck(t *testing.T) {
	dir := t.TempDir()
	asked := 0
	w := &Watcher{ListPath: filepath.Join(dir, "none.json"), ModulesDir: dir, StatePath: filepath.Join(dir, "s.json"),
		Hold: func(context.Context) bool { asked++; return asked < 3 }}
	done := make(chan struct{})
	go func() { w.Run(context.Background(), time.Millisecond, func(error) {}, nil); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not stop when Hold said no")
	}
	if asked != 3 {
		t.Fatalf("Hold asked %d times", asked)
	}
}
