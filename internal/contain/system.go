package contain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/trust"
)

// Real is the computer (run as root).
type Real struct {
	Ollama string // the model server's address (default http://127.0.0.1:11434)
	Trust  trust.Store
	// SessionDirs: where her sessions are saved (the newest are kept as evidence).
	SessionDirs []string
	// EvidenceDir overrides EvidenceDir (tests).
	EvidenceDir string
}

func (s Real) ollama() string {
	if s.Ollama != "" {
		return strings.TrimRight(s.Ollama, "/")
	}
	return "http://127.0.0.1:11434"
}

// ModelsLoaded asks the model server which models are in memory.
func (s Real) ModelsLoaded() []string {
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get(s.ollama() + "/api/ps")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var out struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if json.NewDecoder(resp.Body).Decode(&out) != nil {
		return nil
	}
	var names []string
	for _, m := range out.Models {
		names = append(names, m.Name)
	}
	return names
}

// UnloadModels asks the model server to unload every model now (keep_alive 0): its graphics memory is freed.
func (s Real) UnloadModels() ([]string, error) {
	names := s.ModelsLoaded()
	c := &http.Client{Timeout: 30 * time.Second}
	var errs []string
	for _, n := range names {
		body, _ := json.Marshal(map[string]any{"model": n, "keep_alive": 0})
		resp, err := c.Post(s.ollama()+"/api/generate", "application/json", bytes.NewReader(body))
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		resp.Body.Close()
	}
	if len(errs) > 0 {
		return names, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return names, nil
}

// sarinaProcs lists Sarina's processes: the program sarina (wherever it was installed) and its helpers (sarina-*).
func sarinaProcs() map[int]string {
	out := map[int]string{}
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		comm, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		name := strings.TrimSpace(string(comm))
		exe, _ := os.Readlink(filepath.Join("/proc", e.Name(), "exe"))
		base := filepath.Base(strings.TrimSuffix(exe, " (deleted)"))
		if name == "sarina" || strings.HasPrefix(name, "sarina-") || base == "sarina" || strings.HasPrefix(base, "sarina-") {
			out[pid] = name
		}
	}
	return out
}

// SarinaRunning lists Sarina's processes still alive.
func (s Real) SarinaRunning() []string {
	var out []string
	for pid, name := range sarinaProcs() {
		out = append(out, fmt.Sprintf("%s (%d)", name, pid))
	}
	sort.Strings(out)
	return out
}

// StopSarina stops her service and her timers, then kills every Sarina process of any user.
func (s Real) StopSarina() []string {
	_ = exec.Command("systemctl", "stop", "sarina-service.service").Run()
	_ = exec.Command("systemctl", "stop", "sarina-*.timer", "sarina-*.service").Run()
	var out []string
	for pid, name := range sarinaProcs() {
		if syscall.Kill(pid, syscall.SIGKILL) == nil {
			out = append(out, fmt.Sprintf("%s (%d)", name, pid))
		}
	}
	sort.Strings(out)
	return out
}

// RestoreApproved puts back the approved behaviour files (when trust has been set up).
func (s Real) RestoreApproved() ([]string, error) {
	if _, err := s.Trust.Load(); err != nil {
		return nil, fmt.Errorf("no signed list to restore from (%v)", err)
	}
	back, err := s.Trust.Restore(nil)
	var out []string
	for _, r := range back {
		out = append(out, r.Path)
	}
	return out, err
}

// StopDisplayAndModels stops the login screen (and with it the desktop) and the model server, so neither starts again on the card.
func (s Real) StopDisplayAndModels() error {
	var errs []string
	for _, u := range []string{"display-manager.service", "ollama.service"} {
		if out, err := exec.Command("systemctl", "stop", u).CombinedOutput(); err != nil {
			errs = append(errs, u+": "+strings.TrimSpace(string(out)))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// KillGraphicsUsers kills every process with the graphics card open (games, the desktop, anything left).
func (s Real) KillGraphicsUsers() []string {
	devs, _ := filepath.Glob("/dev/nvidia*")
	dri, _ := filepath.Glob("/dev/dri/*")
	devs = append(devs, dri...)
	if len(devs) == 0 {
		return nil
	}
	out, _ := exec.Command("fuser", append([]string{"-k", "-KILL"}, devs...)...).CombinedOutput()
	return strings.Fields(string(out))
}

// ResetGraphics resets an NVIDIA card (its memory is cleared). Other cards: an error, and the restart clears them.
func (s Real) ResetGraphics() error {
	if _, err := exec.LookPath("nvidia-smi"); err != nil {
		return fmt.Errorf("no NVIDIA tools; the restart clears the card")
	}
	time.Sleep(2 * time.Second) // let the killed processes let go of the card
	out, err := exec.Command("nvidia-smi", "--gpu-reset").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// Reboot restarts the computer.
func (s Real) Reboot() error {
	return exec.Command("systemctl", "reboot").Run()
}

// Notify tells every signed-in user (a critical desktop notification), as root through their session bus.
func (s Real) Notify(summary string) {
	out, err := exec.Command("loginctl", "list-sessions", "--no-legend").Output()
	if err != nil {
		return
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || seen[f[1]] {
			continue
		}
		uid := f[1]
		seen[uid] = true
		bus := "unix:path=/run/user/" + uid + "/bus"
		if _, err := os.Stat("/run/user/" + uid + "/bus"); err != nil {
			continue
		}
		gid := uid
		if u, err := user.LookupId(uid); err == nil {
			gid = u.Gid
		}
		cmd := exec.Command("setpriv", "--reuid="+uid, "--regid="+gid, "--init-groups", "--",
			"notify-send", "-u", "critical", "-a", "Heimdall", "Heimdall", summary)
		cmd.Env = []string{"DBUS_SESSION_BUS_ADDRESS=" + bus, "PATH=/usr/bin:/bin"}
		_ = cmd.Run()
	}
}
