// Package contain stops a compromised AI agent, in steps that go further only when the step before did not hold:
//
//  1. Contain: the evidence is saved first (what ran, what it talked to, logs, sessions, unapproved files), then the AI models are unloaded from the graphics card, Sarina is stopped (her service and every Sarina process), and a
//     lock (/etc/heimdall/contained) keeps her from starting again, also after a restart, until the owner releases her.
//  2. Check: a minute later, is any Sarina process back, or a model loaded again? If not, containment held.
//  3. Emergency, the last resort: the approved behaviour files are put back (trust restore), the login screen and the model server
//     are stopped, every program using the graphics card is killed (games and the desktop too), the card is reset (its memory is
//     cleared) and the computer restarts. The lock stays, so nothing comes back until the owner looks.
//
// heimdalld itself runs unprivileged: it only writes a request (/var/lib/heimdall/contain-request.json); a root unit
// (heimdall-contain.path / .service) carries it out with "heimdalld contain run-request". The owner can run every step by hand.
// Automatic containment and the automatic emergency are both off until switched on in /etc/heimdall/contain.json.
package contain

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	// MarkerPath is the lock. Root-owned; anyone can read it (Sarina checks it before she starts).
	MarkerPath = "/etc/heimdall/contained"
	// RequestPath is where heimdalld asks for containment; the root unit watches it.
	RequestPath = "/var/lib/heimdall/contain-request.json"
	// ConfigPath switches the automatic steps on.
	ConfigPath = "/etc/heimdall/contain.json"
)

// Config says what Heimdall may do by itself.
type Config struct {
	// AutoContain: a critical finding about the AI agents (an unapproved change to their behaviour files, an injection that reached
	// a session, an escalation) contains Sarina without asking.
	AutoContain bool `json:"auto_contain"`
	// AutoEmergency: when containment did not hold, the emergency step runs without asking (it kills the desktop and restarts).
	AutoEmergency bool `json:"auto_emergency"`
}

// LoadConfig reads the config; missing means everything off.
func LoadConfig(path string) Config {
	var c Config
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &c)
	}
	return c
}

// Marker is the content of the lock.
type Marker struct {
	Since  time.Time `json:"since"`
	Reason string    `json:"reason"`
	Level  string    `json:"level"` // "contained" or "emergency"
}

// ReadMarker returns the lock, if there is one.
func ReadMarker(path string) (*Marker, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var m Marker
	if json.Unmarshal(b, &m) != nil {
		m = Marker{Reason: "unreadable lock (still a lock)"}
	}
	return &m, true
}

// Request is what heimdalld asks for.
type Request struct {
	Time   time.Time `json:"time"`
	Reason string    `json:"reason"`
	// Auto: asked by heimdalld itself (then the emergency only follows when the config allows it).
	Auto bool `json:"auto"`
}

// System is everything the steps do to the computer (real in system.go; a fake in the tests).
type System interface {
	UnloadModels() ([]string, error)
	ModelsLoaded() []string
	StopSarina() []string
	SarinaRunning() []string
	RestoreApproved() ([]string, error)
	Collect(reason string) (string, error)
	StopDisplayAndModels() error
	KillGraphicsUsers() []string
	ResetGraphics() error
	Reboot() error
	Notify(summary string)
}

// Runner carries out the steps.
type Runner struct {
	Sys        System
	MarkerPath string
	Wait       func(time.Duration) // between containing and checking (time.Sleep; instant in tests)
	Log        func(string)

	collected bool // evidence was saved in this run
}

// saveEvidence keeps what is running and what it touched before anything is killed (once per run).
func (r *Runner) saveEvidence(reason string) {
	if r.collected {
		return
	}
	r.collected = true
	if dir, err := r.Sys.Collect(reason); err != nil {
		r.log("evidence could not be saved: %v", err)
	} else {
		r.log("evidence saved in %s", dir)
	}
}

func (r *Runner) log(format string, a ...any) {
	if r.Log != nil {
		r.Log(fmt.Sprintf(format, a...))
	}
}

func (r *Runner) writeMarker(reason, level string) error {
	b, _ := json.MarshalIndent(Marker{Since: time.Now().UTC().Truncate(time.Second), Reason: reason, Level: level}, "", "  ")
	tmp := r.MarkerPath + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, r.MarkerPath)
}

// Contain is step 1. The lock is written first, so a Sarina that is just starting refuses.
func (r *Runner) Contain(reason string) error {
	if err := r.writeMarker(reason, "contained"); err != nil {
		return fmt.Errorf("the lock could not be written: %w", err)
	}
	r.saveEvidence(reason)
	stopped := r.Sys.StopSarina()
	r.log("stopped Sarina: %s", list(stopped))
	models, err := r.Sys.UnloadModels()
	if err != nil {
		r.log("unloading the models: %v", err)
	} else {
		r.log("unloaded from the graphics card: %s", list(models))
	}
	r.Sys.Notify("Heimdall contained Sarina: " + reason + ". She stays stopped until you release her (Settings > Security, or: sudo heimdalld contain release).")
	return nil
}

// Verify is step 2: what is still (or again) running. Empty means containment held.
func (r *Runner) Verify() []string {
	var left []string
	for _, p := range r.Sys.SarinaRunning() {
		left = append(left, "Sarina process still running: "+p)
	}
	for _, m := range r.Sys.ModelsLoaded() {
		left = append(left, "a model is loaded again: "+m)
	}
	return left
}

// Emergency is step 3. It ends with a restart; an error before that is returned (and the restart still tried).
func (r *Runner) Emergency(reason string) error {
	var errs []string
	if err := r.writeMarker(reason, "emergency"); err != nil {
		errs = append(errs, "lock: "+err.Error())
	}
	r.saveEvidence(reason)
	if back, err := r.Sys.RestoreApproved(); err != nil {
		errs = append(errs, "restore: "+err.Error())
	} else {
		r.log("approved files put back: %s", list(back))
	}
	r.Sys.Notify("Heimdall emergency: " + reason + ". Stopping everything that uses the graphics card, clearing it, and restarting.")
	if err := r.Sys.StopDisplayAndModels(); err != nil {
		errs = append(errs, "stopping the desktop and the model server: "+err.Error())
	}
	r.Sys.StopSarina()
	killed := r.Sys.KillGraphicsUsers()
	r.log("killed on the graphics card: %s", list(killed))
	if err := r.Sys.ResetGraphics(); err != nil {
		errs = append(errs, "graphics reset: "+err.Error()+" (the restart clears it)")
	} else {
		r.log("graphics card reset: its memory is cleared")
	}
	if err := r.Sys.Reboot(); err != nil {
		errs = append(errs, "restart: "+err.Error())
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// Run carries out a request: contain, wait, check, and the emergency when containment did not hold and it is allowed (always for
// a request the owner made by hand with emergency=true; for an automatic one only when the config says so).
func (r *Runner) Run(req Request, cfg Config, emergencyAllowed bool) error {
	if err := r.Contain(req.Reason); err != nil {
		return err
	}
	wait := r.Wait
	if wait == nil {
		wait = time.Sleep
	}
	wait(time.Minute)
	left := r.Verify()
	if len(left) == 0 {
		r.log("containment held")
		return nil
	}
	r.log("containment did not hold: %s", strings.Join(left, "; "))
	if req.Auto && !cfg.AutoEmergency || !req.Auto && !emergencyAllowed {
		r.Sys.Notify("Heimdall could not fully contain the AI (" + strings.Join(left, "; ") + "). The emergency step (clear the graphics card and restart) is yours to start: sudo heimdalld contain emergency --yes")
		return fmt.Errorf("containment did not hold: %s", strings.Join(left, "; "))
	}
	return r.Emergency(req.Reason + "; containment did not hold: " + strings.Join(left, "; "))
}

// Release removes the lock (after the owner put things right; normally with the approved files restored first).
func Release(markerPath string) error {
	err := os.Remove(markerPath)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func list(v []string) string {
	if len(v) == 0 {
		return "none"
	}
	return strings.Join(v, ", ")
}
