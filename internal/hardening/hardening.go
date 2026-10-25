// Package hardening looks for settings that leave a known kind of hole open when closing it costs the user nothing they would
// notice: no game, app, VM or developer tool stops working. Each gap is reported with why it matters and the exact fix; nothing
// is changed here (the owner decides, and Sarina can explain it first). Read-only: /dev, /sys and /proc only.
package hardening

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

// Gap is one setting that could be safer.
type Gap struct {
	ID    string // stable name
	Now   string // what it is
	Why   string // what the hole is
	Fix   string // the commands that close it
	Level string // "warning" or "info"
}

// System is where the checks read (a temporary tree in the tests).
type System struct{ Root string }

func (s System) read(p string) (string, bool) {
	b, err := os.ReadFile(filepath.Join(s.Root, p))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

// sysctl reads one setting; ok is false when the kernel does not have it.
func (s System) sysctl(name string) (string, bool) {
	return s.read(filepath.Join("/proc/sys", strings.ReplaceAll(name, ".", "/")))
}

const sysctlFile = "/etc/sysctl.d/60-heimdall-hardening.conf"

func sysctlFix(name, want string) string {
	return fmt.Sprintf("echo '%s = %s' | sudo tee -a %s && sudo sysctl -w %s=%s", name, want, sysctlFile, name, want)
}

// Check returns the gaps found now.
func (s System) Check() []Gap {
	var gaps []Gap
	// KVM: a world-writable /dev/kvm lets any program, even one without a login, reach the kernel's virtualisation code, where
	// guest-to-host escapes keep being found (Januscape, CVE-2026-53359, was an unprivileged root exploit through exactly this).
	if info, err := os.Stat(filepath.Join(s.Root, "/dev/kvm")); err == nil && info.Mode().Perm()&0o006 != 0 {
		gaps = append(gaps, Gap{ID: "kvm-world-writable", Now: fmt.Sprintf("/dev/kvm is %04o (every account)", info.Mode().Perm()), Level: "warning",
			Why: "any program can use the kernel's virtual machine code; bugs there (Januscape, CVE-2026-53359) turn that into root. Only the kvm group needs it",
			Fix: "printf 'KERNEL==\"kvm\", GROUP=\"kvm\", MODE=\"0660\"\\n' | sudo tee /etc/udev/rules.d/65-kvm.rules && sudo usermod -aG kvm $USER && sudo udevadm control --reload && sudo udevadm trigger -s misc (sign out and in again so the new group applies; virtual machines keep working)"})
	}
	// nested virtualisation: needed only to run a virtual machine inside a virtual machine
	for _, mod := range []string{"kvm_intel", "kvm_amd"} {
		if v, ok := s.read("/sys/module/" + mod + "/parameters/nested"); ok && (v == "Y" || v == "1") {
			gaps = append(gaps, Gap{ID: "kvm-nested", Now: mod + " nested=" + v, Level: "info",
				Why: "a guest can run its own hypervisor on this one, the path most KVM escapes (Januscape among them) need; only VMs inside VMs use it",
				Fix: fmt.Sprintf("echo 'options %s nested=0' | sudo tee /etc/modprobe.d/60-heimdall-nested.conf (applies at the next restart; undo by deleting the file)", mod)})
		}
	}
	// sysctls with no visible cost on a desktop
	// lowerIsStricter: 0 is the safe value (ldisc_autoload); for the rest higher numbers are stricter
	type sc struct {
		name, want      string
		lowerIsStricter bool
		why             string
	}
	for _, c := range []sc{
		{"dev.tty.ldisc_autoload", "0", true, "any user can make the kernel load old serial-line modules, a recurring source of root exploits; nothing on a desktop needs it"},
		{"kernel.kptr_restrict", "1", false, "kernel addresses are not hidden from programs without the syslog right in every case, and a known address helps an exploit aim; 1 hides them from those programs, root still sees them"},
		{"fs.protected_fifos", "2", false, "programs can be tricked into writing to a planted pipe in shared folders like /tmp"},
		{"fs.protected_regular", "2", false, "programs can be tricked into writing to a planted file in shared folders like /tmp"},
		{"net.core.bpf_jit_harden", "2", false, "the kernel's BPF compiler output can be used to smuggle exploit code; hardening it costs a little speed only for BPF"},
	} {
		now, ok := s.sysctl(c.name)
		if !ok || (c.lowerIsStricter && now <= c.want) || (!c.lowerIsStricter && now >= c.want) { // single digits: text order is number order
			continue
		}
		gaps = append(gaps, Gap{ID: "sysctl-" + c.name, Now: c.name + " = " + now, Why: c.why, Fix: sysctlFix(c.name, c.want), Level: "info"})
	}
	return gaps
}

// Watcher reports each gap once (again when it comes back after being closed).
type Watcher struct {
	Sys       System
	StatePath string
}

func (w *Watcher) Poll() []detect.Event {
	seen := map[string]bool{}
	if b, err := os.ReadFile(w.StatePath); err == nil {
		_ = json.Unmarshal(b, &seen)
	}
	current := map[string]bool{}
	var events []detect.Event
	for _, g := range w.Sys.Check() {
		key := g.ID + "|" + g.Now
		current[key] = true
		if seen[key] {
			continue
		}
		events = append(events, detect.Event{Source: "host-hardening", Time: time.Now(), Kind: "hardening_gap",
			Text:   g.Now + ": " + g.Why,
			Fields: map[string]string{"check": g.ID, "now": g.Now, "why": g.Why, "fix": g.Fix, "level": g.Level}})
	}
	b, _ := json.Marshal(current)
	tmp := w.StatePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		_ = os.Rename(tmp, w.StatePath)
	}
	return events
}

func (w *Watcher) Run(ctx context.Context, interval time.Duration, emit func(detect.Event)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		for _, e := range w.Poll() {
			emit(e)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
