package main

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Artifex-Technologies/Heimdall/internal/grants"
	"github.com/Artifex-Technologies/Heimdall/internal/mesh"
)

const meshUsage = `usage:
  heimdalld mesh id [--dir D]                         this computer's mesh fingerprint (give it to your other computers)
  sudo heimdalld mesh init [--dir D]                  make this computer's mesh key (once)
  heimdalld mesh list [--peers F]                     the enrolled peers
  sudo heimdalld mesh enroll NAME FINGERPRINT IP:PORT [--peers F]
                                                      trust another of your computers (compare the fingerprint on its screen)
  sudo heimdalld mesh forget NAME [--peers F]         stop trusting it (at once for new connections)
Off until mesh_listen is set in config.json or a peer is enrolled. See docs/MESH.md.`

func cmdMesh(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, meshUsage)
		return 2
	}
	action := args[0]
	fs := flag.NewFlagSet("mesh", flag.ContinueOnError)
	dir := fs.String("dir", "/var/lib/heimdall/mesh", "the key's folder")
	peers := fs.String("peers", mesh.DefaultPeers, "the enrolled peers file")
	if err := fs.Parse(flagsFirst(args[1:])); err != nil {
		return 2
	}
	switch action {
	case "id":
		b, err := os.ReadFile(filepath.Join(*dir, "fingerprint"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "no mesh key yet: sudo heimdalld mesh init")
			return 1
		}
		fmt.Print(string(b))
		return 0
	case "init":
		if *dir == "/var/lib/heimdall/mesh" && os.Geteuid() != 0 {
			fmt.Fprintln(os.Stderr, "heimdalld mesh init: needs root (sudo)")
			return 1
		}
		id, err := mesh.LoadOrCreate(*dir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "heimdalld mesh:", err)
			return 1
		}
		if os.Geteuid() == 0 { // the daemon's account reads the key
			if u, err := user.Lookup("heimdall"); err == nil {
				uid, _ := strconv.Atoi(u.Uid)
				gid, _ := strconv.Atoi(u.Gid)
				for _, p := range []string{*dir, filepath.Join(*dir, "key.pem"), filepath.Join(*dir, "fingerprint")} {
					_ = os.Lchown(p, uid, gid)
				}
			}
		}
		fmt.Println(id.Fingerprint)
		return 0
	case "list":
		ps, err := mesh.LoadPeers(*peers)
		if err != nil {
			fmt.Fprintln(os.Stderr, "heimdalld mesh:", err)
			return 1
		}
		if len(ps) == 0 {
			fmt.Println("no peers enrolled")
		}
		for _, p := range ps {
			fmt.Printf("%-16s %s  %s\n", p.Name, p.Fingerprint, p.Address)
		}
		return 0
	case "enroll", "forget":
		if (action == "enroll" && fs.NArg() != 3) || (action == "forget" && fs.NArg() != 1) {
			fmt.Fprintln(os.Stderr, meshUsage)
			return 2
		}
		// whom Heimdall trusts is the owner's decision: root at a terminal for the real list, and never under an AI agent
		if *peers == mesh.DefaultPeers {
			if os.Geteuid() != 0 {
				fmt.Fprintln(os.Stderr, "heimdalld mesh: enrolling needs root (sudo)")
				return 1
			}
			if err := grants.Guard("/proc", grants.StdinIsTerminal()); err != nil {
				fmt.Fprintln(os.Stderr, "heimdalld mesh: refused:", err)
				return 1
			}
		} else if err := grants.Guard("/proc", true); err != nil {
			fmt.Fprintln(os.Stderr, "heimdalld mesh: refused:", err)
			return 1
		}
		p := mesh.Peer{Name: fs.Arg(0)}
		if action == "enroll" {
			p.Fingerprint, p.Address = strings.ToLower(fs.Arg(1)), fs.Arg(2)
		}
		ps, err := mesh.SetPeer(*peers, p, action == "forget")
		if err != nil {
			fmt.Fprintln(os.Stderr, "heimdalld mesh:", err)
			return 1
		}
		fmt.Printf("%d peer(s) enrolled. Restart Heimdall to start sending to a new peer (sudo systemctl restart heimdall).\n", len(ps))
		return 0
	}
	fmt.Fprintln(os.Stderr, meshUsage)
	return 2
}

// flagsFirst moves "--name value" / "--name=value" pairs ahead of the positional arguments, so `enroll A B C --peers F`
// works as well as `enroll --peers F A B C` (Go's flag package stops at the first positional argument).
func flagsFirst(args []string) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			flags = append(flags, a)
			if !strings.Contains(a, "=") && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		pos = append(pos, a)
	}
	return append(flags, pos...)
}
