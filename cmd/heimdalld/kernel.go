package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Artifex-Technologies/Heimdall/internal/config"
	"github.com/Artifex-Technologies/Heimdall/internal/kernelaudit"
)

// cmdKernelCheck prints, for each installed kernel, the known holes a newer kernel fixes (any user; offline).
func cmdKernelCheck(args []string) int {
	fs := flag.NewFlagSet("kernel-check", flag.ContinueOnError)
	list := fs.String("list", "", "the kernel CVE list (default: kernel_vulns from the config)")
	all := fs.Bool("all", false, "every hole, not only the ten worst")
	modules := fs.String("modules", "/usr/lib/modules", "where the kernels are")
	if fs.Parse(args) != nil {
		return 2
	}
	if *list == "" {
		cfg, _ := config.Load("/etc/heimdall/config.json")
		*list = cfg.KernelVulns
	}
	f, err := kernelaudit.Load(*list)
	if err != nil {
		fmt.Fprintln(os.Stderr, "heimdalld kernel-check: no kernel CVE list yet (heimdall-intel-update fetches it):", err)
		return 2
	}
	bad := 0
	for _, k := range kernelaudit.Installed(*modules) {
		holes, fix := kernelaudit.Check(f, k)
		if len(holes) == 0 {
			fmt.Printf("%s: no known hole that an update fixes\n", k)
			continue
		}
		bad++
		same := 0
		for _, h := range holes {
			if h.SameLine {
				same++
			}
		}
		fmt.Printf("%s: %d known hole(s): %d fixed on its own line, the rest only in newer lines (%s or later fixes all; ! = exploited in the wild)\n", k, len(holes), same, fix)
		for i, h := range holes {
			if i == 10 && !*all {
				fmt.Printf("  … and %d more (--all)\n", len(holes)-10)
				break
			}
			mark := " "
			if h.Exploited {
				mark = "!"
			}
			fmt.Printf("  %s %-16s %4.1f  fixed in %-9s %s\n", mark, h.ID, h.Score, h.FixedIn, h.Summary)
		}
	}
	fmt.Printf("(list from %s, %d records)\n", f.Generated.Local().Format("2006-01-02"), len(f.Vulns))
	if bad > 0 {
		return 1
	}
	return 0
}
