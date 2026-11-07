package netsource

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// What the tool rules (internal/toolrules) need to know about the process behind a connection, read from /proc: the script an
// interpreter runs, and whether an AI agent started it. Never the other arguments: a password cracker takes passwords there.

// interpreters run a script given as an argument; the script, not the interpreter, is the program to verify.
var interpreters = map[string]bool{"python": true, "python3": true, "ruby": true, "perl": true, "java": true, "node": true, "bash": true, "sh": true}

// scriptOf returns the file an interpreter (exe) runs, from its arguments (argv[0] first): the argument after -jar for Java,
// else the first argument that is not an option, taken from cwd when relative (`cd /opt/sqlmap; python sqlmap.py`). "" when exe
// is no interpreter or no script is named.
func scriptOf(exe string, argv []string, cwd string) string {
	base := filepath.Base(exe)
	if !interpreters[base] && !interpreters[strings.TrimRight(base, "0123456789.")] {
		return ""
	}
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if a == "-jar" && i+1 < len(argv) {
			if j := argv[i+1]; !filepath.IsAbs(j) && cwd != "" {
				return filepath.Join(cwd, j)
			}
			return argv[i+1]
		}
		if a == "-m" || a == "-c" || a == "-e" {
			return "" // a module name or inline code: no file to verify
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		if filepath.IsAbs(a) {
			return filepath.Clean(a)
		}
		if cwd != "" && filepath.IsAbs(cwd) {
			return filepath.Join(cwd, a)
		}
		return ""
	}
	return ""
}

// agents are the AI agents whose descendants the tool rules never treat as the person's own (their commands are shown).
var agents = map[string]bool{"sarina": true}

// agentAncestor names the AI agent among pid's ancestors ("" when none), walking at most 64 parents.
func agentAncestor(procRoot string, pid int) string {
	for i := 0; i < 64 && pid > 1; i++ {
		stat, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "stat"))
		if err != nil {
			return ""
		}
		// "pid (comm) state ppid ...": comm may hold spaces and parentheses, so the last ')' ends it
		s := string(stat)
		open, close := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
		if open < 0 || close < open {
			return ""
		}
		if comm := s[open+1 : close]; agents[comm] {
			return comm
		}
		rest := strings.Fields(s[close+1:])
		if len(rest) < 2 {
			return ""
		}
		next, err := strconv.Atoi(rest[1])
		if err != nil || next == pid {
			return ""
		}
		pid = next
	}
	return ""
}

// argvOf reads a process's arguments (argv[0] first).
func argvOf(procRoot string, pid int) []string {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
}
