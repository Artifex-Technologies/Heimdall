// Package gametime holds back heimdalld's own long jobs while a game runs: the package audit, the kernel audit and the
// hardening checks, each every 6 hours. Games and a local AI model share this computer and should get all of it, and an
// audit a few hours late changes nothing. Watching never waits: alerts, every detector and the Limbo responder keep running
// during games.
//
// What counts as a game is Yggdrasil's to say (its game time, Yggdrasil docs/GAME_TIME.md): `yggdrasil-gametime status`
// exits 0 while a game runs (Steam's launcher, gamescope, Lutris, or names in /etc/yggdrasil/gametime.conf) and 1 when none
// does. It reads /proc only and starts no program. Without Yggdrasil (the tool is missing), or when it fails, the jobs run
// as before.
package gametime

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode"
)

// Command is Yggdrasil's game-time tool.
const Command = "/usr/bin/yggdrasil-gametime"

// Retry is how often a waiting job asks again; Yggdrasil catches up its own waiting chores every 5 minutes too.
const Retry = 5 * time.Minute

// Gate asks before a long job whether a game runs.
type Gate struct {
	Path  string        // the tool; empty: Command
	Retry time.Duration // how often to ask again while a game runs; 0: Retry
	// Log gets one line when a job starts waiting.
	Log func(format string, args ...any)
}

// Playing asks the tool once: true while a game runs, with the tool's reason ("Steam is running a game (AppId 1091500, ...)").
// A missing tool, one that fails or does not answer within 10 seconds, means no game: the job runs as before.
func (g *Gate) Playing(ctx context.Context) (bool, string) {
	path := g.Path
	if path == "" {
		path = Command
	}
	if _, err := os.Stat(path); err != nil {
		return false, ""
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "status")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil { // exit 1: no game; anything else: trouble, so run as before
		return false, ""
	}
	// "A game is running: Steam is running a game (AppId 1091500, process 4210)." -- the reason, kept short and printable
	first, _, _ := strings.Cut(out.String(), "\n")
	reason := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(first), "A game is running: "), ".")
	reason = strings.Map(func(r rune) rune {
		if !unicode.IsPrint(r) {
			return '?'
		}
		return r
	}, reason)
	if len(reason) > 160 {
		reason = reason[:160] + "..."
	}
	return true, reason
}

// Wait returns true once no game runs: at once when none does, else after asking again every Retry. It logs one line when
// the job starts waiting, and returns false if ctx ends first. A nil Gate never waits.
func (g *Gate) Wait(ctx context.Context, job string) bool {
	if g == nil {
		return ctx.Err() == nil
	}
	every := g.Retry
	if every <= 0 {
		every = Retry
	}
	for waiting := false; ; waiting = true {
		playing, why := g.Playing(ctx)
		if !playing {
			return ctx.Err() == nil
		}
		if !waiting && g.Log != nil {
			g.Log("%s waits until the game is over (%s); asking again every %s", job, why, every)
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(every):
		}
	}
}
