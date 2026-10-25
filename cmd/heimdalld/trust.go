package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Artifex-Technologies/Heimdall/internal/trust"
)

// defaultWatch is what decides how the AI agents behave, for one user: Sarina's rules, tool connections and skill list, her skills,
// agents and skill collections; and the settings of Sarina's service and of Heimdall itself.
func defaultWatch(home string) trust.WatchList {
	s := filepath.Join(home, ".sarina")
	return trust.WatchList{
		Files: []string{filepath.Join(s, "policy.json"), filepath.Join(s, "mcp.json"), filepath.Join(s, "skills.json"), "/etc/heimdall/config.json"},
		Dirs:  []string{filepath.Join(s, "skills"), filepath.Join(s, "agents"), filepath.Join(s, "vendor"), "/etc/sarina"},
	}
}

func cmdTrust(args []string) int {
	if len(args) == 0 {
		trustUsage()
		return 2
	}
	st := trust.Store{Dir: trust.DefaultDir}
	if d := os.Getenv("HEIMDALL_TRUST_DIR"); d != "" {
		st.Dir = d // tests
	}
	needRoot := func() bool {
		if os.Geteuid() != 0 && os.Getenv("HEIMDALL_TRUST_DIR") == "" {
			fmt.Fprintln(os.Stderr, "heimdalld trust: this needs root (sudo): only root holds the signing key")
			return false
		}
		return true
	}
	switch args[0] {
	case "init":
		fs := flag.NewFlagSet("trust init", flag.ContinueOnError)
		who := fs.String("user", "", "the account whose Sarina files are watched (default: the one that ran sudo)")
		if fs.Parse(args[1:]) != nil || !needRoot() {
			return 2
		}
		created, err := st.Init()
		if err != nil {
			fmt.Fprintln(os.Stderr, "heimdalld trust:", err)
			return 1
		}
		name := *who
		if name == "" {
			name = os.Getenv("SUDO_USER")
		}
		if name != "" && len(st.Watch().Files)+len(st.Watch().Dirs) == 0 {
			u, err := user.Lookup(name)
			if err != nil {
				fmt.Fprintln(os.Stderr, "heimdalld trust:", err)
				return 1
			}
			if err := st.SetWatch(defaultWatch(u.HomeDir)); err != nil {
				fmt.Fprintln(os.Stderr, "heimdalld trust:", err)
				return 1
			}
		}
		if created {
			fmt.Println("made the signing key; trust is off until you choose: heimdalld trust mode watch")
		} else {
			fmt.Println("the signing key exists already (kept)")
		}
		return 0
	case "status":
		m, err := st.Load()
		fmt.Printf("mode: %s\n", st.Mode())
		if err != nil {
			fmt.Printf("signed list: cannot be checked (%v)\n", err)
		} else {
			fmt.Printf("signed list: %d file(s), signed %s\n", len(m.Files), m.SignedAt.Local().Format("2006-01-02 15:04"))
		}
		w := st.Watch()
		fmt.Printf("watched: %d file(s), %d folder(s)\n", len(w.Files), len(w.Dirs))
		for _, f := range w.Files {
			fmt.Println("  file   " + f)
		}
		for _, d := range w.Dirs {
			fmt.Println("  folder " + d)
		}
		return 0
	case "mode":
		if len(args) != 2 {
			trustUsage()
			return 2
		}
		m, err := trust.ParseMode(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "heimdalld trust:", err)
			return 2
		}
		if !needRoot() {
			return 2
		}
		if m != trust.Off {
			if _, err := st.Load(); err != nil {
				fmt.Fprintln(os.Stderr, "heimdalld trust: the signed list cannot be checked; run heimdalld trust init first:", err)
				return 1
			}
		}
		if err := st.SetMode(m); err != nil {
			fmt.Fprintln(os.Stderr, "heimdalld trust:", err)
			return 1
		}
		fmt.Printf("trust mode: %s\n", m)
		// the daemon reads the mode and the watch list when it starts
		if os.Getenv("HEIMDALL_TRUST_DIR") == "" {
			_ = exec.Command("systemctl", "try-restart", "heimdall.service").Run()
		}
		return 0
	case "sign", "forget", "restore":
		if !needRoot() {
			return 2
		}
		paths := args[1:]
		if args[0] != "restore" && len(paths) == 0 {
			trustUsage()
			return 2
		}
		if args[0] == "sign" && len(paths) == 1 && paths[0] == "--watched" {
			// everything watched now, as it is: the starting point when trust is switched on
			w := st.Watch()
			paths = nil
			for _, p := range append(append([]string{}, w.Files...), w.Dirs...) {
				if _, err := os.Stat(p); err == nil {
					paths = append(paths, p)
				}
			}
		}
		switch args[0] {
		case "sign":
			done, err := st.Sign(paths)
			for _, f := range done {
				fmt.Println("signed   " + f)
			}
			if err != nil {
				fmt.Fprintln(os.Stderr, "heimdalld trust:", err)
				return 1
			}
		case "forget":
			gone, err := st.Forget(paths)
			for _, f := range gone {
				fmt.Println("forgotten " + f)
			}
			if err != nil {
				fmt.Fprintln(os.Stderr, "heimdalld trust:", err)
				return 1
			}
		case "restore":
			back, err := st.Restore(paths)
			for _, r := range back {
				fmt.Printf("restored %s (it was %s)\n", r.Path, r.Why)
			}
			if err != nil {
				fmt.Fprintln(os.Stderr, "heimdalld trust:", err)
				return 1
			}
			if len(back) == 0 {
				fmt.Println("every signed file is as approved")
			}
		}
		return 0
	case "verify":
		// any user: is each watched file (or each path given) as approved?
		m, err := st.Load()
		if err != nil {
			fmt.Fprintln(os.Stderr, "heimdalld trust:", err)
			return 1
		}
		var files []string
		if len(args) > 1 {
			for _, p := range args[1:] {
				exp, err := trust.Expand(p)
				if err != nil {
					fmt.Fprintln(os.Stderr, "heimdalld trust:", err)
					return 1
				}
				files = append(files, exp...)
			}
		} else {
			w := st.Watch()
			files = append(files, w.Files...)
			for _, d := range w.Dirs {
				if exp, err := trust.Expand(d); err == nil {
					files = append(files, exp...)
				}
			}
			for f := range m.Files {
				files = append(files, f)
			}
		}
		sort.Strings(files)
		bad := 0
		seen := map[string]bool{}
		for _, f := range files {
			if seen[f] {
				continue
			}
			seen[f] = true
			sum, err := trust.HashFile(f)
			switch {
			case os.IsNotExist(err) && m.Has(f):
				fmt.Println("MISSING  " + f)
				bad++
			case err != nil:
				continue
			case m.Matches(f, sum):
				fmt.Println("ok       " + f)
			case m.Has(f):
				fmt.Println("CHANGED  " + f)
				bad++
			default:
				fmt.Println("UNSIGNED " + f)
				bad++
			}
		}
		if bad > 0 {
			return 1
		}
		return 0
	case "watch":
		if len(args) < 3 || (args[1] != "add" && args[1] != "remove") {
			trustUsage()
			return 2
		}
		if !needRoot() {
			return 2
		}
		w := st.Watch()
		for _, p := range args[2:] {
			abs, err := filepath.Abs(p)
			if err != nil {
				return 1
			}
			info, err := os.Stat(abs)
			isDir := err == nil && info.IsDir()
			w.Files = without(w.Files, abs)
			w.Dirs = without(w.Dirs, abs)
			if args[1] == "add" {
				if isDir {
					w.Dirs = append(w.Dirs, abs)
				} else {
					w.Files = append(w.Files, abs)
				}
			}
		}
		if err := st.SetWatch(w); err != nil {
			fmt.Fprintln(os.Stderr, "heimdalld trust:", err)
			return 1
		}
		fmt.Println("watch list updated; heimdalld picks it up when it restarts")
		return 0
	}
	trustUsage()
	return 2
}

func without(list []string, x string) []string {
	var out []string
	for _, v := range list {
		if v != x {
			out = append(out, v)
		}
	}
	return out
}

func trustUsage() {
	fmt.Fprint(os.Stderr, strings.TrimLeft(`
heimdalld trust: the signed list of files that decide how the AI agents behave (see docs/TRUST.md)
  heimdalld trust init [--user NAME]     make the signing key (root) and the default watch list for that user's Sarina files
  heimdalld trust status                 mode, how many files are signed, what is watched
  heimdalld trust mode off|watch|enforce off: nothing changes; watch: an unsigned change is a critical alert, a signed one quiet;
                                         enforce: Sarina also refuses an unsigned file (root)
  heimdalld trust sign PATH...           approve the current content of files or folders (root)
  heimdalld trust sign --watched         approve everything watched, as it is now (the starting point) (root)
  heimdalld trust forget PATH...         take files off the list, e.g. after deleting them (root)
  heimdalld trust restore [PATH...]      put back the approved content of changed or deleted signed files (root)
  heimdalld trust verify [PATH...]       is each file as approved? (exit 1 when not)
  heimdalld trust watch add|remove PATH... change what is watched (root)
`, "\n"))
}
