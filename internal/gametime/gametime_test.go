package gametime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeTool writes a stand-in yggdrasil-gametime: its k-th call exits with codes[k] (the last code repeats), printing what the
// real one prints for a game.
func fakeTool(t *testing.T, codes ...int) (path string, calls func() int) {
	t.Helper()
	dir := t.TempDir()
	var cases strings.Builder
	for i, c := range codes {
		fmt.Fprintf(&cases, "  %d) code=%d ;;\n", i+1, c)
	}
	script := fmt.Sprintf(`#!/bin/sh
d=%s
[ "$1" = status ] || exit 2
n=$(cat $d/n 2>/dev/null || echo 0); n=$((n+1)); echo $n > $d/n
case $n in
%s  *) code=%d ;;
esac
if [ $code = 0 ]; then
  echo "A game is running: Steam is running a game (AppId 1091500, process 4210)."
  echo "Nothing is waiting for a game to end."
else
  echo "No game is running."
fi
exit $code
`, dir, cases.String(), codes[len(codes)-1])
	path = filepath.Join(dir, "yggdrasil-gametime")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path, func() int {
		b, _ := os.ReadFile(filepath.Join(dir, "n"))
		var n int
		fmt.Sscan(string(b), &n)
		return n
	}
}

func TestPlayingAsksTheTool(t *testing.T) {
	game, _ := fakeTool(t, 0)
	none, _ := fakeTool(t, 1)
	broken, _ := fakeTool(t, 101) // a crash
	for _, c := range []struct {
		path   string
		want   bool
		reason string
	}{
		{game, true, "Steam is running a game (AppId 1091500, process 4210)"},
		{none, false, ""},
		{broken, false, ""},
		{filepath.Join(t.TempDir(), "missing"), false, ""}, // no Yggdrasil: run as before
	} {
		playing, why := (&Gate{Path: c.path}).Playing(context.Background())
		if playing != c.want || why != c.reason {
			t.Errorf("%s: %v %q", c.path, playing, why)
		}
	}
}

// A job waits while a game runs, says so once, and goes as soon as the game is over.
func TestWaitHoldsAJobUntilTheGameIsOver(t *testing.T) {
	path, calls := fakeTool(t, 0, 0, 0, 1)
	var logged []string
	g := &Gate{Path: path, Retry: 20 * time.Millisecond, Log: func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }}
	if !g.Wait(context.Background(), "the package audit") {
		t.Fatal("Wait gave up")
	}
	if calls() != 4 {
		t.Errorf("asked %d times", calls())
	}
	if len(logged) != 1 || !strings.HasPrefix(logged[0], "the package audit waits until the game is over (Steam is running a game (AppId 1091500") {
		t.Errorf("logged %q", logged)
	}
	// no game: no wait, no line
	path, _ = fakeTool(t, 1)
	logged = nil
	g.Path = path
	if !g.Wait(context.Background(), "the kernel audit") || len(logged) != 0 {
		t.Errorf("waited or logged without a game: %q", logged)
	}
	// stopping heimdalld ends the wait
	path, _ = fakeTool(t, 0)
	g.Path = path
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if g.Wait(ctx, "the hardening checks") {
		t.Error("Wait returned true after ctx ended")
	}
	var none *Gate
	if !none.Wait(context.Background(), "x") {
		t.Error("a nil Gate must not wait")
	}
}
