// Package netsource watches the ecosystem's own claimed ports (Sarina's
// docs/ECOSYSTEM.md port registry, extended by this repo with 8930) for
// violations of the ecosystem-wide rule every repo's CLAUDE.md already
// states: "loopback only, no ecosystem service binds a routable interface
// by default." It reads /proc/net/tcp and /proc/net/tcp6 -- the same
// source `ss`/`netstat` read from -- rather than ever reaching for packet
// capture. See docs/ARCHITECTURE.md's Phase 3 section for why: Zeek is the
// reference for *how* to observe a connection, not a reason to embed a
// protocol-analysis engine into a tool whose actual job here is much
// smaller -- "is anything bound or connected to one of these specific
// ports from somewhere that isn't loopback."
package netsource

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

// TCP socket states from the Linux kernel's tcp_states enum
// (include/net/tcp_states.h). Only the two states this package acts on.
const (
	tcpEstablished = 0x01
	tcpListen      = 0x0A
)

type socketEntry struct {
	LocalIP    net.IP
	LocalPort  int
	RemoteIP   net.IP
	RemotePort int
	State      int
}

// ParseProcNetTCP parses /proc/net/tcp or /proc/net/tcp6's text format.
// Both files share the same column layout; only the address column width
// differs (8 hex chars for IPv4, 32 for IPv6), which parseHexIP detects
// from the string length rather than needing the caller to say which file
// this is.
func ParseProcNetTCP(r io.Reader) ([]socketEntry, error) {
	scanner := bufio.NewScanner(r)
	scanner.Scan() // header line ("sl local_address rem_address st ..."); discard
	var entries []socketEntry
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		localIP, localPort, err := parseHexAddr(fields[1])
		if err != nil {
			continue
		}
		remoteIP, remotePort, err := parseHexAddr(fields[2])
		if err != nil {
			continue
		}
		state, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil {
			continue
		}
		entries = append(entries, socketEntry{
			LocalIP: localIP, LocalPort: localPort,
			RemoteIP: remoteIP, RemotePort: remotePort,
			State: int(state),
		})
	}
	return entries, scanner.Err()
}

// parseHexAddr parses one "IP:PORT" column, e.g. "0100007F:1F90".
func parseHexAddr(field string) (net.IP, int, error) {
	parts := strings.SplitN(field, ":", 2)
	if len(parts) != 2 {
		return nil, 0, fmt.Errorf("netsource: malformed address field %q", field)
	}
	ip, err := parseHexIP(parts[0])
	if err != nil {
		return nil, 0, err
	}
	port, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return nil, 0, fmt.Errorf("netsource: parse port in %q: %w", field, err)
	}
	return ip, int(port), nil
}

// parseHexIP decodes the kernel's on-disk address encoding. IPv4 (8 hex
// chars) is 4 bytes in little-endian order -- reverse them for network
// order. IPv6 (32 hex chars) is 4 32-bit words, each independently
// little-endian -- reverse each 4-byte group in place, same technique
// procfs-reading tools use generally.
func parseHexIP(hexStr string) (net.IP, error) {
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("netsource: decode address %q: %w", hexStr, err)
	}
	switch len(raw) {
	case 4:
		return net.IPv4(raw[3], raw[2], raw[1], raw[0]), nil
	case 16:
		ip := make(net.IP, 16)
		for group := 0; group < 4; group++ {
			base := group * 4
			ip[base], ip[base+1], ip[base+2], ip[base+3] = raw[base+3], raw[base+2], raw[base+1], raw[base]
		}
		return ip, nil
	default:
		return nil, fmt.Errorf("netsource: unexpected address length %d in %q", len(raw), hexStr)
	}
}

// PortWatcher polls /proc/net/tcp{,6} for exposure of a fixed set of
// watched ports. State-transition detection lives here, not in a
// detector, the same split Phase 2's FIMWatcher uses: a bound or connected
// violation is remembered only for as long as it's actually observed, so
// it alerts once when it appears and again if it disappears and later
// reappears, rather than once per poll for as long as it persists.
type PortWatcher struct {
	procPaths    []string
	watchedPorts map[int]bool
	flaggedBinds map[int]bool
	flaggedPeers map[string]bool
}

func NewPortWatcher(ports []int) *PortWatcher {
	return newPortWatcherWithPaths(ports, []string{"/proc/net/tcp", "/proc/net/tcp6"})
}

// newPortWatcherWithPaths lets tests point Poll at fixture files instead
// of real /proc, which doesn't exist on the non-Linux platforms this is
// developed and tested on.
func newPortWatcherWithPaths(ports []int, procPaths []string) *PortWatcher {
	watched := make(map[int]bool, len(ports))
	for _, p := range ports {
		watched[p] = true
	}
	return &PortWatcher{
		procPaths:    procPaths,
		watchedPorts: watched,
		flaggedBinds: make(map[int]bool),
		flaggedPeers: make(map[string]bool),
	}
}

// Poll checks current socket state once. Returns an error only when every
// configured /proc/net/tcp{,6} path is missing (os.IsNotExist matches it),
// so callers can distinguish "no /proc on this platform" from a real read
// failure on an individual file, which Poll otherwise tolerates (e.g. tcp6
// missing because IPv6 is disabled is not an error).
func (w *PortWatcher) Poll() ([]detect.Event, error) {
	var entries []socketEntry
	var lastErr error
	opened := 0
	for _, path := range w.procPaths {
		f, err := os.Open(path)
		if err != nil {
			lastErr = err
			continue
		}
		opened++
		parsed, err := ParseProcNetTCP(f)
		f.Close()
		if err != nil {
			continue
		}
		entries = append(entries, parsed...)
	}
	if opened == 0 {
		return nil, lastErr
	}

	now := time.Now()
	var events []detect.Event
	currentBinds := make(map[int]bool)
	currentPeers := make(map[string]bool)

	for _, e := range entries {
		if !w.watchedPorts[e.LocalPort] {
			continue
		}
		switch e.State {
		case tcpListen:
			if e.LocalIP.IsLoopback() {
				continue
			}
			currentBinds[e.LocalPort] = true
			if !w.flaggedBinds[e.LocalPort] {
				events = append(events, detect.Event{
					Source: "host-network",
					Time:   now,
					Kind:   "non_loopback_bind",
					Text:   fmt.Sprintf("port %d bound on %s", e.LocalPort, e.LocalIP),
					Fields: map[string]string{"port": strconv.Itoa(e.LocalPort), "address": e.LocalIP.String()},
				})
			}
		case tcpEstablished:
			if e.RemoteIP.IsLoopback() {
				continue
			}
			key := fmt.Sprintf("%d|%s|%d", e.LocalPort, e.RemoteIP, e.RemotePort)
			currentPeers[key] = true
			if !w.flaggedPeers[key] {
				events = append(events, detect.Event{
					Source: "host-network",
					Time:   now,
					Kind:   "non_loopback_peer",
					Text:   fmt.Sprintf("port %d connected from %s:%d", e.LocalPort, e.RemoteIP, e.RemotePort),
					Fields: map[string]string{
						"local_port":  strconv.Itoa(e.LocalPort),
						"remote_addr": e.RemoteIP.String(),
						"remote_port": strconv.Itoa(e.RemotePort),
					},
				})
			}
		}
	}

	w.flaggedBinds = currentBinds
	w.flaggedPeers = currentPeers
	return events, nil
}

// Run polls on an interval until ctx is done. Like TelemetryWatcher.Run,
// it logs once and stops instead of retrying forever if /proc doesn't
// exist on this platform at all.
func (w *PortWatcher) Run(ctx context.Context, interval time.Duration, onUnavailable func(error), onErr func(error), emit func(detect.Event)) {
	if _, err := w.Poll(); err != nil {
		if os.IsNotExist(err) {
			if onUnavailable != nil {
				onUnavailable(err)
			}
			return
		}
		if onErr != nil {
			onErr(err)
		}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			events, err := w.Poll()
			if err != nil {
				if onErr != nil {
					onErr(err)
				}
				continue
			}
			for _, e := range events {
				emit(e)
			}
		}
	}
}
