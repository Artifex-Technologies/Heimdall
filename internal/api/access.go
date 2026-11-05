package api

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/user"
	"strconv"
	"sync"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/sources/netsource"
)

// Access decides which local accounts may use the API. Loopback binding keeps the network out, but every program on this
// computer can reach 127.0.0.1, so without this any account (a game, a daemon, an AI agent's sandboxed helper) could read the
// alert feed or flood POST /v1/review until the alerts that matter fall out of the ring.
//
// The caller is identified by the kernel, not by anything it sends: on Linux /proc/net/tcp lists every TCP socket with the
// account that created it, so the client end of a loopback connection names its owner (the identd method). Clients need no
// token and no change. Allowed: root, Heimdall's own account, the accounts in Users and the members of Groups. Everything
// but /healthz is checked; an account that cannot be identified is refused.
type Access struct {
	Users  []string // account names, e.g. "sarina"
	Groups []string // group names whose members may use the API, e.g. "wheel" (the computer's administrators)

	// PeerUID finds the account behind a request; nil means the kernel's socket table (procPeerUID).
	PeerUID func(r *http.Request) (uint32, error)
	// Member reports whether uid is in Users or Groups; nil means the system's account database (os/user).
	Member func(uid uint32) bool

	mu    sync.Mutex
	cache map[uint32]cached
}

type cached struct {
	ok   bool
	when time.Time
}

// cacheFor bounds how long an answer about an account is reused: group changes take effect within a minute, and the account
// database is not read on every request a panel makes.
const cacheFor = time.Minute

// Allowed reports whether r comes from an account that may use the API, and which account it was (for the record).
func (a *Access) Allowed(r *http.Request) (uint32, bool) {
	peer := a.PeerUID
	if peer == nil {
		peer = procPeerUID
	}
	uid, err := peer(r)
	if err != nil {
		return 0, false
	}
	if uid == 0 || uid == uint32(os.Getuid()) {
		return uid, true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if c, ok := a.cache[uid]; ok && time.Since(c.when) < cacheFor {
		return uid, c.ok
	}
	member := a.Member
	if member == nil {
		member = a.systemMember
	}
	ok := member(uid)
	if a.cache == nil {
		a.cache = map[uint32]cached{}
	}
	a.cache[uid] = cached{ok, time.Now()}
	return uid, ok
}

// systemMember looks uid up in the account database (/etc/passwd and /etc/group; pure Go, no cgo).
func (a *Access) systemMember(uid uint32) bool {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return false
	}
	for _, name := range a.Users {
		if u.Username == name {
			return true
		}
	}
	if len(a.Groups) == 0 {
		return false
	}
	gids, err := u.GroupIds()
	if err != nil {
		return false
	}
	for _, name := range a.Groups {
		g, err := user.LookupGroup(name)
		if err != nil {
			continue
		}
		for _, gid := range gids {
			if gid == g.Gid {
				return true
			}
		}
	}
	return false
}

// procTCP are the kernel's socket tables; a variable so tests can point it at fixtures.
var procTCP = []string{"/proc/net/tcp", "/proc/net/tcp6"}

// procPeerUID finds the account that owns the client end of the request's TCP connection: the socket whose local address is
// the request's remote address and whose remote address is the server's own.
func procPeerUID(r *http.Request) (uint32, error) {
	local, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if local == nil {
		return 0, fmt.Errorf("no server address on the request")
	}
	server, err := netAddrPort(local.String())
	if err != nil {
		return 0, err
	}
	client, err := netAddrPort(r.RemoteAddr)
	if err != nil {
		return 0, err
	}
	return lookupPeer(procTCP, client, server)
}

type hostPort struct {
	ip   net.IP
	port int
}

func netAddrPort(s string) (hostPort, error) {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return hostPort{}, err
	}
	ip := net.ParseIP(h)
	port, err := strconv.Atoi(p)
	if ip == nil || err != nil {
		return hostPort{}, fmt.Errorf("not an address: %q", s)
	}
	return hostPort{ip, port}, nil
}

func lookupPeer(files []string, client, server hostPort) (uint32, error) {
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		entries, err := netsource.ParseProcNetTCP(f)
		f.Close()
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.LocalPort == client.port && e.RemotePort == server.port && e.LocalIP.Equal(client.ip) && e.RemoteIP.Equal(server.ip) {
				return uint32(e.UID), nil
			}
		}
	}
	return 0, fmt.Errorf("no socket for %s:%d in the kernel's table", client.ip, client.port)
}
