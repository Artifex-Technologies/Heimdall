package hardening

// The SSH server check: is an SSH server (OpenSSH's sshd, or dropbear) running or set to start, and does it take passwords?
// A server reachable with password logins on is the door SSHole (CVE-2026-123158, disclosed 2026-11-05) came through: OpenSSH
// before 10.6p2, built on musl, without PAM, took an over-long password for a locked account (stored hash "*"). glibc builds
// with PAM were never open to it, but password logins on a listening server are worth a word on any computer Heimdall watches.
// Read-only and without the network: /proc/net, the systemd/OpenRC start links, /etc/ssh and the sshd program file itself
// (its version string and ELF interpreter). `sshd -T` (the settings sshd would really use) runs only on the real system and
// only as root; otherwise the config files are read, with Include followed and Match blocks counted as on.

import (
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SSHoleCVE is the hole the SSH check names when every part of it is there.
const SSHoleCVE = "CVE-2026-123158"

// sshConfig is sshd's settings as sshd reads them: the first value of a keyword wins; values inside Match blocks apply to some
// connections only, so they are kept apart and a "yes" there counts as on.
type sshConfig struct {
	global map[string]string // lower-case keyword -> lower-case first value
	match  map[string]bool   // "keyword=value" seen inside any Match block
	ports  []string
	read   bool // the main file (or sshd -T) could be read
}

// sshLine splits one config line into its lower-case keyword and its value ("Keyword value" or "Keyword=value").
func sshLine(line string) (string, string) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' {
		return "", ""
	}
	i := strings.IndexAny(line, " \t=")
	if i < 0 {
		return strings.ToLower(line), ""
	}
	key := strings.ToLower(line[:i])
	val := strings.TrimLeft(line[i:], " \t")
	if strings.HasPrefix(val, "=") {
		val = strings.TrimLeft(val[1:], " \t")
	}
	val = strings.TrimSpace(val)
	if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
		val = val[1 : len(val)-1]
	}
	if key == "challengeresponseauthentication" { // the old name sshd still reads
		key = "kbdinteractiveauthentication"
	}
	return key, val
}

// globMatch matches a file name against a pattern with * and ? (no brackets), as sshd's glob does for Include; a leading dot
// must be matched by a dot.
func globMatch(pat, name string) bool {
	if strings.HasPrefix(name, ".") && !strings.HasPrefix(pat, ".") {
		return false
	}
	var m func(p, n string) bool
	m = func(p, n string) bool {
		for p != "" {
			switch p[0] {
			case '*':
				for i := len(n); i >= 0; i-- {
					if m(p[1:], n[i:]) {
						return true
					}
				}
				return false
			case '?':
				if n == "" {
					return false
				}
			default:
				if n == "" || n[0] != p[0] {
					return false
				}
			}
			p, n = p[1:], n[1:]
		}
		return n == ""
	}
	return m(pat, name)
}

// includeFiles expands one Include pattern (relative to /etc/ssh; wildcards in the last part only), sorted as glob sorts.
func (s System) includeFiles(pat string) []string {
	if !strings.HasPrefix(pat, "/") {
		pat = "/etc/ssh/" + pat
	}
	dir, base := pat[:strings.LastIndex(pat, "/")+1], pat[strings.LastIndex(pat, "/")+1:]
	if !strings.ContainsAny(base, "*?") {
		return []string{pat}
	}
	entries, err := os.ReadDir(filepath.Join(s.Root, dir))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if globMatch(base, e.Name()) {
			out = append(out, dir+e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// parseSSH reads one config file into c; inMatch says it was included from inside a Match block. A Match block ends at the end
// of the file it starts in, as in sshd; "Match all" is counted as a Match block too (the cautious reading).
func (s System) parseSSH(p string, inMatch bool, depth int, c *sshConfig) bool {
	b, err := os.ReadFile(filepath.Join(s.Root, p))
	if err != nil {
		return false
	}
	match := inMatch
	for _, line := range strings.Split(string(b), "\n") {
		key, val := sshLine(line)
		switch key {
		case "":
			continue
		case "match":
			match = true
			continue
		case "include":
			if depth < 16 {
				for _, pat := range strings.Fields(val) {
					for _, f := range s.includeFiles(pat) {
						s.parseSSH(f, match, depth+1, c)
					}
				}
			}
			continue
		}
		c.set(key, val, match)
	}
	return true
}

func (c *sshConfig) set(key, val string, match bool) {
	val = strings.ToLower(val)
	if match {
		c.match[key+"="+val] = true
		return
	}
	if key == "port" {
		c.ports = append(c.ports, val)
		return
	}
	if _, ok := c.global[key]; !ok {
		c.global[key] = val
	}
}

func (c sshConfig) val(key, def string) string {
	if v, ok := c.global[key]; ok {
		return v
	}
	return def
}

// on: the keyword is "yes" in the global part (def when unset) or in any Match block.
func (c sshConfig) on(key, def string) bool {
	return c.val(key, def) == "yes" || c.match[key+"=yes"]
}

// sshdT asks sshd itself (sshd -T) for its settings: on the real system and as root only (it reads the host keys).
func (s System) sshdT(bin string) (string, bool) {
	if s.Root != "" || os.Geteuid() != 0 {
		return "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "-T").Output()
	if err != nil {
		return "", false
	}
	return string(out), true
}

func (s System) readSSHConfig(bin string) sshConfig {
	c := sshConfig{global: map[string]string{}, match: map[string]bool{}}
	c.read = s.parseSSH("/etc/ssh/sshd_config", false, 0, &c)
	if out, ok := s.sshdT(bin); ok {
		c.global, c.ports, c.read = map[string]string{}, nil, true
		for _, line := range strings.Split(out, "\n") {
			if key, val := sshLine(line); key != "" {
				c.set(key, val, false)
			}
		}
	}
	if len(c.ports) == 0 {
		c.ports = []string{"22"}
	}
	return c
}

// sshVersion reads an OpenSSH version as program and packages write it ("OpenSSH_10.6p2", "10.6p2-1", "1:10.6p2-1",
// "10.6_p2-r0"): major, minor and the portable release (0 when there is none).
func sshVersion(v string) ([3]int, bool) {
	v = strings.TrimPrefix(v, "OpenSSH_")
	if i := strings.IndexByte(v, ':'); i > 0 {
		if _, err := strconv.Atoi(v[:i]); err == nil {
			v = v[i+1:]
		}
	}
	v = strings.ReplaceAll(v, "_p", "p")
	var out [3]int
	num := func() (int, bool) {
		i := 0
		for i < len(v) && i < 6 && v[i] >= '0' && v[i] <= '9' {
			i++
		}
		if i == 0 {
			return 0, false
		}
		n, _ := strconv.Atoi(v[:i])
		v = v[i:]
		return n, true
	}
	var ok bool
	if out[0], ok = num(); !ok || !strings.HasPrefix(v, ".") {
		return out, false
	}
	v = v[1:]
	if out[1], ok = num(); !ok {
		return out, false
	}
	if strings.HasPrefix(v, "p") {
		v = v[1:]
		out[2], _ = num()
	}
	return out, true
}

func versionLess(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// ssholeFixed is the first OpenSSH that rejects a stored hash too short to be a real one.
var ssholeFixed = [3]int{10, 6, 2}

// binaryVersion finds the newest "OpenSSH_x.y[pN]" in the program file (it also carries older names, for its compatibility
// table, so the newest one is its own).
func binaryVersion(b []byte) (string, [3]int) {
	best, bestV := "", [3]int{}
	rest := b
	for {
		i := strings.Index(string(rest), "OpenSSH_")
		if i < 0 {
			return best, bestV
		}
		rest = rest[i+len("OpenSSH_"):]
		j := 0
		for j < len(rest) && j < 16 && (rest[j] >= '0' && rest[j] <= '9' || rest[j] == '.' || rest[j] == 'p') {
			j++
		}
		if v, ok := sshVersion(string(rest[:j])); ok && (best == "" || versionLess(bestV, v)) {
			best, bestV = string(rest[:j]), v
		}
	}
}

// elfInterp returns the program interpreter an ELF file asks for (PT_INTERP), "" when there is none or the file is not ELF.
func elfInterp(b []byte) string {
	if len(b) < 52 || string(b[:4]) != "\x7fELF" || (b[4] != 1 && b[4] != 2) {
		return ""
	}
	is64 := b[4] == 2
	var bo binary.ByteOrder = binary.LittleEndian
	if b[5] == 2 {
		bo = binary.BigEndian
	}
	var phoff, phentsize, phnum, need uint64
	if is64 {
		if len(b) < 64 {
			return ""
		}
		phoff, phentsize, phnum, need = bo.Uint64(b[0x20:]), uint64(bo.Uint16(b[0x36:])), uint64(bo.Uint16(b[0x38:])), 40
	} else {
		phoff, phentsize, phnum, need = uint64(bo.Uint32(b[0x1c:])), uint64(bo.Uint16(b[0x2a:])), uint64(bo.Uint16(b[0x2c:])), 20
	}
	n := uint64(len(b))
	if phentsize < need || phoff > n {
		return ""
	}
	for i := uint64(0); i < phnum && i < 256; i++ {
		o := phoff + i*phentsize
		if o+need > n {
			return ""
		}
		if bo.Uint32(b[o:]) != 3 { // PT_INTERP
			continue
		}
		var off, size uint64
		if is64 {
			off, size = bo.Uint64(b[o+8:]), bo.Uint64(b[o+32:])
		} else {
			off, size = uint64(bo.Uint32(b[o+4:])), uint64(bo.Uint32(b[o+16:]))
		}
		if off > n || size > n-off {
			return ""
		}
		return strings.TrimRight(string(b[off:off+size]), "\x00")
	}
	return ""
}

// libcOf names the C library an interpreter belongs to: "musl", "glibc" or "" (static, or unknown).
func libcOf(interp string) string {
	switch {
	case strings.Contains(interp, "ld-musl"):
		return "musl"
	case strings.Contains(interp, "ld-linux"):
		return "glibc"
	}
	return ""
}

// listening returns the first of ports something listens on over TCP (IPv4 or IPv6), "" when none.
func (s System) listening(ports []string) string {
	want := map[string]bool{}
	for _, p := range ports {
		want[p] = true
	}
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		text, _ := s.read(f)
		for _, line := range strings.Split(text, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[3] != "0A" {
				continue
			}
			i := strings.LastIndexByte(fields[1], ':')
			if i < 0 {
				continue
			}
			if port, err := strconv.ParseUint(fields[1][i+1:], 16, 16); err == nil && want[strconv.FormatUint(port, 10)] {
				return strconv.FormatUint(port, 10)
			}
		}
	}
	return ""
}

// startsAtBoot returns the first start link (systemd's *.wants folders, OpenRC's runlevels) for one of names, "" when none.
func (s System) startsAtBoot(names ...string) string {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	for _, base := range []string{"/etc/systemd/system", "/etc/runlevels"} {
		dirs, _ := os.ReadDir(filepath.Join(s.Root, base))
		for _, d := range dirs {
			if base == "/etc/systemd/system" && !strings.HasSuffix(d.Name(), ".wants") {
				continue
			}
			entries, _ := os.ReadDir(filepath.Join(s.Root, base, d.Name()))
			for _, e := range entries {
				if want[e.Name()] {
					return e.Name()
				}
			}
		}
	}
	return ""
}

func (s System) firstFile(paths ...string) string {
	for _, p := range paths {
		if info, err := os.Stat(filepath.Join(s.Root, p)); err == nil && info.Mode().IsRegular() {
			return p
		}
	}
	return ""
}

const sshFixKeys = "put 'PasswordAuthentication no' and 'KbdInteractiveAuthentication no' at the top of /etc/ssh/sshd_config (sshd keeps the first value it reads; a Match block that turns them on needs the same), check with sudo sshd -t, then sudo systemctl reload sshd. Copy your key over first (ssh-copy-id) so you are not locked out"

// sshGaps is the SSH server check (see the top of this file).
func (s System) sshGaps() []Gap {
	var gaps []Gap
	if bin := s.firstFile("/usr/bin/sshd", "/usr/sbin/sshd"); bin != "" {
		c := s.readSSHConfig(filepath.Join(s.Root, bin))
		state, level := "sshd is installed but not started", "info"
		if p := s.listening(c.ports); p != "" {
			state, level = "sshd listens on port "+p, "warning"
		} else if u := s.startsAtBoot("sshd.service", "sshd.socket", "ssh.service", "ssh.socket", "sshd"); u != "" {
			state, level = "sshd starts at boot ("+u+")", "warning"
		}
		if !c.read {
			if level == "warning" {
				gaps = append(gaps, Gap{ID: "ssh-settings-unread", Now: state + "; Heimdall may not read /etc/ssh/sshd_config", Level: "info",
					Why: "could not be checked whether it takes passwords; an SSH server that does can be guessed at by anyone who reaches it",
					Fix: "sudo sshd -T | grep -iE '^(passwordauthentication|kbdinteractiveauthentication|permitrootlogin|permitemptypasswords|usepam) ' (passwordauthentication yes means passwords are taken: " + sshFixKeys + ")"})
			}
			return gaps
		}
		b, _ := os.ReadFile(filepath.Join(s.Root, bin))
		ver, v := binaryVersion(b)
		libc := libcOf(elfInterp(b))
		pam := c.val("usepam", "no") == "yes"
		pw := c.on("passwordauthentication", "yes")
		kbd := pam && c.on("kbdinteractiveauthentication", "yes")
		var on []string
		switch {
		case c.val("passwordauthentication", "yes") == "yes":
			on = append(on, "PasswordAuthentication yes")
		case pw:
			on = append(on, "PasswordAuthentication yes in a Match block")
		}
		if kbd {
			on = append(on, "KbdInteractiveAuthentication yes with UsePAM yes")
		}
		if !pam {
			on = append(on, "UsePAM no")
		}
		sshole := ver != "" && versionLess(v, ssholeFixed) && libc == "musl" && !pam && pw
		if sshole {
			l := "info"
			if level == "warning" {
				l = "critical"
			}
			gaps = append(gaps, Gap{ID: "ssh-sshole", CVE: SSHoleCVE, Level: l,
				Now: state + ": OpenSSH " + ver + " built on musl, " + strings.Join(on, ", "),
				Why: "this is the build SSHole (" + SSHoleCVE + ") is in: it takes an over-long password for a locked account (one whose stored password is \"*\"), so anyone who reaches the server may sign in as that account. OpenSSH 10.6p2 fixes it",
				Fix: "update OpenSSH to 10.6p2 or newer; until then turn password logins off: " + sshFixKeys})
		}
		if pw || kbd {
			why := "anyone who reaches the server can keep guessing passwords, and a weak or reused one is then all that stands between them and a shell; keys cannot be guessed"
			if !sshole {
				switch {
				case pam:
					why += ". Not open to SSHole (" + SSHoleCVE + "): it signs in through PAM"
				case libc == "glibc":
					why += ". Not open to SSHole (" + SSHoleCVE + "): it is built on glibc"
				case ver != "" && libc == "musl":
					why += ". Not open to SSHole (" + SSHoleCVE + "): OpenSSH " + ver + " has the fix"
				}
			}
			gaps = append(gaps, Gap{ID: "ssh-password-login", Now: state + " with password logins on (" + strings.Join(on, ", ") + ")", Level: level,
				Why: why, Fix: "PasswordAuthentication no; use keys: " + sshFixKeys})
			if c.on("permitrootlogin", "prohibit-password") {
				gaps = append(gaps, Gap{ID: "ssh-root-password", Now: state + " and lets root sign in with a password (PermitRootLogin yes)", Level: level,
					Why: "root's password alone opens the whole computer to anyone who reaches the server",
					Fix: "put 'PermitRootLogin prohibit-password' (or no) at the top of /etc/ssh/sshd_config, check with sudo sshd -t, then sudo systemctl reload sshd"})
			}
			if c.on("permitemptypasswords", "no") {
				gaps = append(gaps, Gap{ID: "ssh-empty-passwords", Now: state + " and lets accounts with an empty password sign in (PermitEmptyPasswords yes)", Level: level,
					Why: "an account without a password can be signed in to by anyone who reaches the server",
					Fix: "put 'PermitEmptyPasswords no' at the top of /etc/ssh/sshd_config, check with sudo sshd -t, then sudo systemctl reload sshd"})
			}
		}
	}
	if s.firstFile("/usr/bin/dropbear", "/usr/sbin/dropbear") != "" {
		state, level := "dropbear is installed but not started", "info"
		if u := s.startsAtBoot("dropbear.service", "dropbear.socket", "dropbear"); u != "" {
			state, level = "dropbear starts at boot ("+u+")", "warning"
		}
		opts := ""
		for _, f := range []string{"/etc/conf.d/dropbear", "/etc/default/dropbear"} {
			t, _ := s.read(f)
			opts += " " + t
		}
		noPasswords := false
		for _, tok := range strings.FieldsFunc(opts, func(r rune) bool { return r == ' ' || r == '\t' || r == '\n' || r == '"' || r == '\'' || r == '=' }) {
			if len(tok) > 1 && tok[0] == '-' && tok[1] != '-' && strings.Trim(tok[1:], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") == "" && strings.ContainsRune(tok, 's') {
				noPasswords = true
			}
		}
		if !noPasswords {
			gaps = append(gaps, Gap{ID: "ssh-dropbear-password", Now: state + " with password logins on (no -s in its options)", Level: level,
				Why: "anyone who reaches the server can keep guessing passwords, and a weak or reused one is then all that stands between them and a shell; keys cannot be guessed",
				Fix: "add -s to DROPBEAR_OPTS in /etc/conf.d/dropbear (or DROPBEAR_EXTRA_ARGS in /etc/default/dropbear) and restart dropbear, after copying your key to ~/.ssh/authorized_keys"})
		}
	}
	return gaps
}
