package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/immunity"
	"github.com/Artifex-Technologies/Heimdall/internal/scan"
)

// clamReference asks ClamAV (the reference) about one file.
func clamReference(path string) (string, error) {
	c := scan.NewClamAV()
	if !c.Available() {
		return "", fmt.Errorf("ClamAV is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	r, err := c.ScanFile(ctx, path)
	if err != nil {
		return "", err
	}
	if r.Infected {
		return r.Signature, nil
	}
	return "", nil
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
		e, err := st.Keep(path, *reason, "owner")
		if err != nil {
			return fail(err)
		}
		if e.Status != immunity.Suspect || args[0] == "suspect" {
			fmt.Printf("%s %s (%s, %s)\n", e.Status, e.SHA256, e.Kind, e.Original)
			return 0
		}
		e, err = st.Confirm(e.SHA256, clamReference)
		if err != nil {
			return fail(err)
		}
		return printConfirmed(e)
	case "confirm":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: heimdalld immunity confirm SHA256 (or its first 8+ characters)")
			return 2
		}
		if !needRoot() {
			return 2
		}
		e, err := st.Confirm(args[1], clamReference)
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
  heimdalld immunity add --reason WHY FILE      keep it, check it against ClamAV, and fingerprint it when ClamAV does not know it (root)
  heimdalld immunity suspect --reason WHY FILE  only keep it, for later (root); containments do this with their evidence
  heimdalld immunity confirm SHA256             a kept suspect is malware: check it against ClamAV and fingerprint it (root)
  heimdalld immunity list [--json]              what is kept: suspect, immune (fingerprinted) or reference (ClamAV knew it) (root)
  heimdalld immunity forget SHA256              a mistake: remove the sample and its fingerprint (root)
  heimdalld immunity check FILE                 is this file one Heimdall has learned? (any user; exit 1 when it is)
`, "\n"))
}
