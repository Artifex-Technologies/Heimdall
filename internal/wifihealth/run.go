package wifihealth

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/lan"
)

// Options for one check.
type Options struct {
	Iface    string // empty: the Wi-Fi interface carrying the default route
	Speed    bool   // also run the speed test (sends and receives up to a few hundred MB)
	API      string // Heimdall's API for the device count ("127.0.0.1:8930"); empty skips it
	Internet string // address to ping past the router (default 1.1.1.1)
	ProcRoot string
}

// Mirrorlist is where the download test finds a server: the Arch mirrors this computer already updates from. Mirrors are
// there for big downloads, and none of them learns anything new about the computer. They take no uploads, so only the
// download is measured. (Public speed test sites turn programs away, and M-Lab publishes each tester's address.)
var Mirrorlist = "/etc/pacman.d/mirrorlist"

// mirrorFiles are the big files tried on each mirror (the installer image, then a large package database as a fallback).
func mirrorFiles(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() && len(out) < 3 {
		line := strings.TrimSpace(sc.Text())
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(k) != "Server" {
			continue
		}
		v = strings.TrimSpace(v)
		i := strings.Index(v, "/$repo")
		if i < 0 || !strings.HasPrefix(v, "https://") {
			continue
		}
		out = append(out, v[:i]+"/iso/latest/archlinux-x86_64.iso")
	}
	return out
}

func run(ctx context.Context, name string, args ...string) string {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	out, _ := cmd.Output()
	return string(out)
}

// wifiRoute finds the default route's interface and gateway, if that interface is Wi-Fi.
func wifiRoute(procRoot, want string) (iface string, gw net.IP) {
	f, err := os.Open(filepath.Join(procRoot, "net/route"))
	if err != nil {
		return "", nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		x := strings.Fields(sc.Text())
		if len(x) < 3 || x[1] != "00000000" {
			continue
		}
		if want != "" && x[0] != want {
			continue
		}
		if _, err := os.Stat(filepath.Join("/sys/class/net", x[0], "wireless")); err != nil && want == "" {
			continue
		}
		var g uint32
		if _, err := fmt.Sscanf(x[2], "%X", &g); err == nil && g != 0 {
			return x[0], net.IPv4(byte(g), byte(g>>8), byte(g>>16), byte(g>>24)).To4()
		}
	}
	return "", nil
}

func ping(ctx context.Context, target string, count int) Ping {
	if target == "" {
		return Ping{Target: target, LossPct: 100}
	}
	out := run(ctx, "ping", "-n", "-c", fmt.Sprint(count), "-i", "0.25", "-W", "1", target)
	return ParsePing(target, out)
}

// Run measures for about ten seconds (half a minute with the speed test) and judges.
func Run(o Options) (Report, error) {
	if o.ProcRoot == "" {
		o.ProcRoot = "/proc"
	}
	if o.Internet == "" {
		o.Internet = "1.1.1.1"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	r := Report{Time: time.Now().UTC().Truncate(time.Second), DevicesHere: -1}
	iface, gw := wifiRoute(o.ProcRoot, o.Iface)
	if iface == "" {
		// Wi-Fi may be up without the default route (a cable in too); then say so plainly
		r.Judge()
		return r, nil
	}
	r.Iface = iface
	if _, err := exec.LookPath("iw"); err != nil {
		return r, errors.New("the iw program is missing (pacman -S iw)")
	}
	station := func() string {
		return run(ctx, "iw", "dev", iface, "link") + run(ctx, "iw", "dev", iface, "station", "dump")
	}
	r.PowerSave = strings.Contains(run(ctx, "iw", "dev", iface, "get", "power_save"), "Power save: on")
	before, ok := ParseLink(station())
	if !ok {
		r.Judge()
		return r, nil
	}
	r.Connected = true

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); r.Router = ping(ctx, gw.String(), 30) }()
	go func() { defer wg.Done(); r.Internet = ping(ctx, o.Internet, 30) }()
	scan := run(ctx, "nmcli", "-t", "-f", "IN-USE,SSID,BSSID,FREQ,SIGNAL", "device", "wifi", "list", "ifname", iface)
	if o.API != "" {
		r.DevicesHere = devicesHere(o.API)
	}
	wg.Wait()

	if o.Speed {
		r.Speed = speedTest(ctx, o.Internet)
	}
	after, ok := ParseLink(station())
	if !ok {
		after = before
	}
	r.Link = after
	// resending during the check, when enough was sent to say; otherwise since connecting
	if sent := after.TxPackets - before.TxPackets; after.TxPackets >= before.TxPackets && sent >= 300 {
		r.RetriesPct = round1(100 * float64(after.TxRetries-before.TxRetries) / float64(sent))
		r.RetriesSpan = "check"
	} else if after.TxPackets >= 1000 {
		r.RetriesPct = round1(100 * float64(after.TxRetries) / float64(after.TxPackets))
		r.RetriesSpan = "connection"
	}
	r.Neighbourhood(ParseScan(scan, after.SSID))
	r.Judge()
	return r, nil
}

// devicesHere counts the devices Heimdall saw in its last look at the network it last looked at.
func devicesHere(api string) int {
	c := http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + api + "/v1/lan/devices")
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	var st lan.Store
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&st) != nil || st.Status != "scanned" {
		return -1
	}
	for _, n := range st.Networks {
		if n.UUID != st.StatusUUID {
			continue
		}
		here := 0
		for _, d := range n.Devices {
			if n.LastScan.Sub(d.LastSeen) < time.Minute {
				here++
			}
		}
		return here
	}
	return -1
}

// speedTest downloads from a mirror for about 8 seconds over two connections, pinging the internet meanwhile to see how answers
// slow down when the line is full.
func speedTest(ctx context.Context, internet string) *Speed {
	s := &Speed{}
	urls := mirrorFiles(Mirrorlist)
	if len(urls) == 0 {
		s.Error = "no download server: no https mirror in " + Mirrorlist
		return s
	}
	client := http.Client{}
	var lastErr error
	for _, url := range urls {
		var loaded Ping
		var wg sync.WaitGroup
		wg.Add(1)
		go func() { defer wg.Done(); time.Sleep(1500 * time.Millisecond); loaded = ping(ctx, internet, 24) }()
		dctx, dcancel := context.WithTimeout(ctx, 9*time.Second)
		var got int64
		var mu sync.Mutex
		var streams sync.WaitGroup
		start := time.Now()
		for k := 0; k < 2; k++ {
			streams.Add(1)
			go func(k int) {
				defer streams.Done()
				req, _ := http.NewRequestWithContext(dctx, "GET", url, nil)
				req.Header.Set("User-Agent", "heimdall-wifi-health")
				req.Header.Set("Range", fmt.Sprintf("bytes=%d-", k*400<<20)) // the two streams read different parts
				resp, err := client.Do(req)
				if err != nil {
					mu.Lock()
					lastErr = err
					mu.Unlock()
					return
				}
				defer resp.Body.Close()
				if resp.StatusCode != 200 && resp.StatusCode != 206 {
					mu.Lock()
					lastErr = fmt.Errorf("the server answered %s", resp.Status)
					mu.Unlock()
					return
				}
				buf := make([]byte, 256<<10)
				for {
					n, err := resp.Body.Read(buf)
					mu.Lock()
					got += int64(n)
					mu.Unlock()
					if err != nil {
						return
					}
				}
			}(k)
		}
		streams.Wait()
		took := time.Since(start).Seconds()
		dcancel()
		wg.Wait()
		if got < 1<<20 {
			continue // under a megabyte: this mirror did not serve it; try the next
		}
		s.DownMbps = round1(float64(got) * 8 / took / 1e6)
		s.Server = strings.SplitN(strings.TrimPrefix(url, "https://"), "/", 2)[0]
		s.Loaded = &loaded
		return s
	}
	s.Error = "the download servers could not be reached"
	if lastErr != nil {
		s.Error += " (" + shortErr(lastErr) + ")"
	}
	return s
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 {
		s = s[i+2:]
	}
	return s
}
