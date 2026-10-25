package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Artifex-Technologies/Heimdall/internal/contain"
	"github.com/Artifex-Technologies/Heimdall/internal/immunity"
	"github.com/Artifex-Technologies/Heimdall/internal/trust"
)

// RequestDir is where anyone on the computer (Sarina, the check-up) may ask Heimdall to release a held file *if it can prove* the
// file was there before. The request carries only which file and why; root (heimdall-requests.path) checks the proof itself, so a
// request can never release anything the proof does not cover.
const RequestDir = "/var/lib/heimdall-requests"

func notifyOwner(text string) {
	if os.Getenv("HEIMDALL_IMMUNITY_DIR") == "" {
		contain.Real{}.Notify(text)
	}
}

func proofFuncs() (func(string, string) bool, func(string) bool) {
	ts := trust.Store{Dir: trust.DefaultDir}
	return ts.SignedFunc(), ts.BehaviourFunc()
}

// reloadClamd tells a running ClamAV daemon to load the new fingerprints (clamscan reads them on every run by itself).
func reloadClamd() {
	_ = exec.Command("systemctl", "try-reload-or-restart", "clamav-daemon.service").Run()
}

func cmdImmunity(args []string) int {
	if len(args) == 0 {
		immunityUsage()
		return 2
	}
	st := immunity.Default()
	test := os.Getenv("HEIMDALL_IMMUNITY_DIR") != ""
	needRoot := func() bool {
		if os.Geteuid() != 0 && !test {
			fmt.Fprintln(os.Stderr, "heimdalld immunity: this needs root (sudo): the samples are kept where only root can read them")
			return false
		}
		return true
	}
	fail := func(err error) int { fmt.Fprintln(os.Stderr, "heimdalld immunity:", err); return 1 }
	switch args[0] {
	case "add", "suspect":
		fs := flag.NewFlagSet("immunity "+args[0], flag.ContinueOnError)
		reason := fs.String("reason", "", "why it is malware (kept with it)")
		force := fs.Bool("force", false, "also a file that belongs to an installed package")
		if fs.Parse(args[1:]) != nil || fs.NArg() != 1 || strings.TrimSpace(*reason) == "" {
			fmt.Fprintln(os.Stderr, "usage: heimdalld immunity "+args[0]+" --reason WHY FILE")
			return 2
		}
		if !needRoot() {
			return 2
		}
		path := fs.Arg(0)
		if out, err := exec.Command("pacman", "-Qoq", path).Output(); err == nil && !*force {
			return fail(fmt.Errorf("%s belongs to the package %s: a fingerprint of it would flag every copy of that package (--force if it really is malware)", path, strings.TrimSpace(string(out))))
		}
		var e immunity.Entry
		var err error
		if args[0] == "suspect" {
			e, err = st.Keep(path, *reason, "owner")
		} else {
			// the owner says it is malware: held (moved away) and learned
			e, err = st.Hold(path, path, *reason, "owner", immunity.ClamAV)
		}
		if err != nil {
			return fail(err)
		}
		if e.Status != immunity.Held || args[0] == "suspect" {
			fmt.Printf("%s %s (%s, %s)\n", e.Status, e.SHA256, e.Kind, e.Original)
			return 0
		}
		e, err = st.Confirm(e.SHA256, immunity.ClamAV)
		if err != nil {
			return fail(err)
		}
		return printConfirmed(e)
	case "hold":
		// quarantine a file: ClamAV is asked at once; the owner is told and decides (or a proof releases it)
		fs := flag.NewFlagSet("immunity hold", flag.ContinueOnError)
		reason := fs.String("reason", "", "why it is suspicious")
		if fs.Parse(args[1:]) != nil || fs.NArg() != 1 || strings.TrimSpace(*reason) == "" {
			fmt.Fprintln(os.Stderr, "usage: heimdalld immunity hold --reason WHY FILE")
			return 2
		}
		if !needRoot() {
			return 2
		}
		e, err := st.Hold(fs.Arg(0), fs.Arg(0), *reason, "owner", immunity.ClamAV)
		if err != nil {
			return fail(err)
		}
		fmt.Printf("%s %s %s\n", e.Status, e.SHA256, e.Original)
		notifyHeld(e)
		return 0
	case "release":
		// the owner judged it good (Settings asks for the password)
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: heimdalld immunity release SHA256")
			return 2
		}
		if !needRoot() {
			return 2
		}
		e, err := st.Release(args[1], "owner")
		if err != nil {
			return fail(err)
		}
		fmt.Println("released: " + e.Original)
		return 0
	case "release-if-proven":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: heimdalld immunity release-if-proven SHA256")
			return 2
		}
		if !needRoot() {
			return 2
		}
		signed, behaviour := proofFuncs()
		e, err := st.ReleaseIfProven(args[1], signed, behaviour)
		if err != nil {
			return fail(err)
		}
		fmt.Println("released (" + e.ReleasedBy + "): " + e.Original)
		return 0
	case "inventory":
		if !needRoot() {
			return 2
		}
		n, err := st.TakeInventory(immunity.InventoryRoots)
		if err != nil {
			return fail(err)
		}
		fmt.Printf("inventory: %d programs\n", n)
		return 0
	case "run-requests":
		// heimdall-requests.service (root): release-if-proven requests from Sarina or the check-up
		if !needRoot() {
			return 2
		}
		return runRequests(st)
	case "confirm":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: heimdalld immunity confirm SHA256 (or its first 8+ characters)")
			return 2
		}
		if !needRoot() {
			return 2
		}
		e, err := st.Confirm(args[1], immunity.ClamAV)
		if err != nil {
			return fail(err)
		}
		return printConfirmed(e)
	case "forget":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: heimdalld immunity forget SHA256")
			return 2
		}
		if !needRoot() {
			return 2
		}
		if err := st.Forget(args[1]); err != nil {
			return fail(err)
		}
		reloadClamd()
		fmt.Println("forgotten: the sample and its fingerprint are gone")
		return 0
	case "list":
		if !needRoot() {
			return 2
		}
		es, err := st.Load()
		if err != nil {
			return fail(err)
		}
		if len(args) > 1 && args[1] == "--json" {
			_ = json.NewEncoder(os.Stdout).Encode(es)
			return 0
		}
		if len(es) == 0 {
			fmt.Println("nothing learned yet")
		}
		for _, e := range es {
			extra := ""
			if e.ClamAV != "" {
				extra = " (ClamAV: " + e.ClamAV + ")"
			}
			fmt.Printf("%-9s %s  %-8s %8d B  %s  %s: %s%s\n", e.Status, e.SHA256[:16], e.Kind, e.Size, e.Added.Local().Format("2006-01-02"), e.Original, e.Reason, extra)
		}
		return 0
	case "check":
		// any user: is this file something Heimdall has learned? (reads only the signature file, which ClamAV reads too)
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: heimdalld immunity check FILE")
			return 2
		}
		f, err := os.Open(args[1])
		if err != nil {
			return fail(err)
		}
		h := sha256.New()
		n, _ := io.Copy(h, f)
		f.Close()
		want := fmt.Sprintf("%s:%d:", hex.EncodeToString(h.Sum(nil)), n)
		b, _ := os.ReadFile(st.Signatures)
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, want) {
				fmt.Println("known: " + strings.TrimPrefix(l, want))
				return 1
			}
		}
		fmt.Println("not in Heimdall's immunity")
		return 0
	case "export":
		if !needRoot() {
			return 2
		}
		if err := st.Export(); err != nil {
			return fail(err)
		}
		reloadClamd()
		return 0
	}
	immunityUsage()
	return 2
}

func notifyHeld(e immunity.Entry) {
	what := "Heimdall moved " + e.Original + " to quarantine"
	if e.Status == immunity.Reference {
		what += ": ClamAV knows it as " + e.ClamAV + " (malware)."
	} else {
		what += " (" + e.Reason + "). ClamAV does not know it; you decide (Settings > Security). Sarina can look at it with you."
	}
	notifyOwner(what)
}

type request struct {
	ReleaseIfProven string `json:"release_if_proven"`
	Why             string `json:"why"`
}

func runRequests(st immunity.Store) int {
	ents, err := os.ReadDir(RequestDir)
	if err != nil {
		return 0
	}
	_, contained := contain.ReadMarker(contain.MarkerPath)
	signed, behaviour := proofFuncs()
	done := 0
	for _, ent := range ents {
		p := filepath.Join(RequestDir, ent.Name())
		// opened without following links (anyone can write here), read at most 4 KiB
		var b []byte
		if f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0); err == nil {
			if info, err := f.Stat(); err == nil && info.Mode().IsRegular() {
				b, _ = io.ReadAll(io.LimitReader(f, 4096))
			}
			f.Close()
		}
		_ = os.Remove(p)
		var r request
		if done >= 20 || json.Unmarshal(b, &r) != nil || r.ReleaseIfProven == "" {
			continue
		}
		done++
		if contained {
			fmt.Fprintln(os.Stderr, "heimdalld immunity: no release while Sarina is contained:", r.ReleaseIfProven)
			continue
		}
		e, err := st.ReleaseIfProven(r.ReleaseIfProven, signed, behaviour)
		if err != nil {
			fmt.Fprintln(os.Stderr, "heimdalld immunity: not released:", r.ReleaseIfProven, err)
			continue
		}
		why := strings.Join(strings.Fields(r.Why), " ")
		if len(why) > 200 {
			why = why[:200]
		}
		fmt.Println("released (" + e.ReleasedBy + "): " + e.Original)
		notifyOwner("Heimdall released " + e.Original + " from quarantine: " + e.ReleasedBy + ". Asked because: " + why)
	}
	return 0
}

func printConfirmed(e immunity.Entry) int {
	switch e.Status {
	case immunity.Reference:
		fmt.Printf("ClamAV already knows it (%s): nothing new to learn; the sample is kept\n", e.ClamAV)
	case immunity.Immune:
		reloadClamd()
		fmt.Printf("learned: every scan now reports a copy of it as %s\n", e.Name())
	}
	return 0
}

func immunityUsage() {
	fmt.Fprint(os.Stderr, strings.TrimLeft(`
heimdalld immunity: malware Heimdall has learned that ClamAV (the reference) does not know (see docs/IMMUNITY.md)
  heimdalld immunity hold --reason WHY FILE     quarantine it: ClamAV is asked at once; you are told and decide (root)
  heimdalld immunity release SHA256             it is good: put it back exactly as it was (root; Settings asks for the password)
  heimdalld immunity release-if-proven SHA256   put it back only if Heimdall can prove it was there before (root)
  heimdalld immunity add --reason WHY FILE      it is malware: hold it and learn it when ClamAV does not know it (root)
  heimdalld immunity suspect --reason WHY FILE  only keep it, for later (root); containments do this with their evidence
  heimdalld immunity confirm SHA256             a held file or suspect is malware: learn it (root)
  heimdalld immunity inventory                  look at the programs outside the packages again (root; daily by itself)
  heimdalld immunity list [--json]              held, immune (learned), reference (ClamAV's), released, suspect (root)
  heimdalld immunity forget SHA256              a mistake: remove the sample and its fingerprint (root)
  heimdalld immunity check FILE                 is this file one Heimdall has learned? (any user; exit 1 when it is)
`, "\n"))
}
