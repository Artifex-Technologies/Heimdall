package grants

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// AgentPrograms are the programs whose descendants may never decide a request: Sarina's CLI and service (their shell tool,
// sub-agents and anything they start run below them).
var AgentPrograms = []string{"sarina", "sarina-service"}

// AgentAccounts are the accounts that may never decide a request, wherever the command runs.
var AgentAccounts = []string{"sarina"}

// Guard returns nil when the calling process may decide a request: root (checked by the caller), a terminal on standard
// input, sudo not used by an agent account, and no agent program or agent account among its ancestors. procRoot is "/proc"
// except in tests. The main barrier stays the owner's sudo password; this names an agent that got past it.
func Guard(procRoot string, terminal bool) error {
	if !terminal {
		return errors.New("a decision is made by a person at a terminal (standard input is not one)")
	}
	for _, a := range AgentAccounts {
		if os.Getenv("SUDO_USER") == a {
			return fmt.Errorf("the account %s asked through sudo: an agent never decides its own requests", a)
		}
	}
	agentUIDs := map[string]bool{}
	for _, a := range AgentAccounts {
		if u, err := user.Lookup(a); err == nil {
			agentUIDs[u.Uid] = true
		}
	}
	pid := os.Getpid()
	for i := 0; i < 64 && pid > 1; i++ {
		ppid, uids, err := status(procRoot, pid)
		if err != nil {
			return fmt.Errorf("cannot check who started this command (%v); refusing", err)
		}
		for _, u := range uids {
			if agentUIDs[u] {
				return fmt.Errorf("process %d runs as an agent account: an agent never decides its own requests", pid)
			}
		}
		if name := program(procRoot, pid); name != "" {
			for _, a := range AgentPrograms {
				if name == a {
					return fmt.Errorf("this command was started (through process %d) by %s: an agent never decides its own requests", pid, a)
				}
			}
		}
		pid = ppid
	}
	return nil
}

// status reads a process's parent and its real, effective, saved and filesystem user ids.
func status(procRoot string, pid int) (int, []string, error) {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "status"))
	if err != nil {
		return 0, nil, err
	}
	ppid := -1
	var uids []string
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch k {
		case "PPid":
			ppid, _ = strconv.Atoi(strings.TrimSpace(v))
		case "Uid":
			uids = strings.Fields(v)
		}
	}
	if ppid < 0 {
		return 0, nil, errors.New("no parent in " + filepath.Join(procRoot, strconv.Itoa(pid), "status"))
	}
	return ppid, uids, nil
}

// program is the base name of the process's executable, else of its first argument (an interpreter running a script named
// sarina shows the script there).
func program(procRoot string, pid int) string {
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		base := filepath.Base(strings.TrimSuffix(exe, " (deleted)"))
		for _, a := range AgentPrograms {
			if base == a {
				return base
			}
		}
	}
	if cmd, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
		if i := bytes.IndexByte(cmd, 0); i >= 0 {
			cmd = cmd[:i]
		}
		return filepath.Base(string(cmd))
	}
	return ""
}

// StdinIsTerminal reports whether standard input is a terminal (TCGETS succeeds).
func StdinIsTerminal() bool {
	var t syscall.Termios
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, 0, syscall.TCGETS, uintptr(unsafe.Pointer(&t)))
	return e == 0
}
