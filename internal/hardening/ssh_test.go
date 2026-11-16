package hardening

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeELF builds a small ELF program file asking for interp (none when ""), carrying the given text after it. Every byte is
// below 0x80, so the parity fixtures can hold it as a JSON string.
func fakeELF(is64 bool, interp, text string) string {
	b := make([]byte, 120)
	copy(b, "\x7fELF")
	b[5] = 1 // little-endian
	if is64 {
		b[4] = 2
		binary.LittleEndian.PutUint64(b[0x20:], 64)
		binary.LittleEndian.PutUint16(b[0x36:], 56)
		binary.LittleEndian.PutUint16(b[0x38:], 1)
		if interp != "" {
			binary.LittleEndian.PutUint32(b[64:], 3)
			binary.LittleEndian.PutUint64(b[64+8:], 120)
			binary.LittleEndian.PutUint64(b[64+32:], uint64(len(interp)+1))
		}
	} else {
		b[4] = 1
		binary.LittleEndian.PutUint32(b[0x1c:], 52)
		binary.LittleEndian.PutUint16(b[0x2a:], 32)
		binary.LittleEndian.PutUint16(b[0x2c:], 1)
		if interp != "" {
			binary.LittleEndian.PutUint32(b[52:], 3)
			binary.LittleEndian.PutUint32(b[52+4:], 120)
			binary.LittleEndian.PutUint32(b[52+16:], uint32(len(interp)+1))
		}
	}
	return string(b) + interp + "\x00" + text
}

const (
	muslInterp  = "/lib/ld-musl-x86_64.so.1"
	glibcInterp = "/lib64/ld-linux-x86-64.so.2"
	listen22    = "  sl  local_address rem_address   st\n   0: 00000000:0016 00000000:0000 0A 00000000:00000000\n"
)

func tree(t *testing.T, files map[string]string) string {
	root := t.TempDir()
	for p, v := range files {
		full := filepath.Join(root, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestSSHConfigFirstValueIncludeAndMatch(t *testing.T) {
	for _, c := range []struct {
		name  string
		files map[string]string
		key   string
		val   string
		on    bool
	}{
		{"unset: sshd's default", map[string]string{"etc/ssh/sshd_config": "Port 22\n"}, "passwordauthentication", "", true},
		{"first value wins", map[string]string{"etc/ssh/sshd_config": "PasswordAuthentication no\nPasswordAuthentication yes\n"}, "passwordauthentication", "no", false},
		{"keyword=value and case", map[string]string{"etc/ssh/sshd_config": "passwordAUTHENTICATION=No\n"}, "passwordauthentication", "no", false},
		{"an Include before wins", map[string]string{"etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\n",
			"etc/ssh/sshd_config.d/50-x.conf": "PasswordAuthentication yes\n"}, "passwordauthentication", "yes", true},
		{"included files in name order", map[string]string{"etc/ssh/sshd_config": "Include sshd_config.d/*.conf\n",
			"etc/ssh/sshd_config.d/20-b.conf": "PasswordAuthentication yes\n", "etc/ssh/sshd_config.d/10-a.conf": "PasswordAuthentication no\n",
			"etc/ssh/sshd_config.d/.hidden.conf": "PasswordAuthentication yes\n", "etc/ssh/sshd_config.d/05-c.txt": "PasswordAuthentication yes\n"},
			"passwordauthentication", "no", false},
		{"a Match block counts as on", map[string]string{"etc/ssh/sshd_config": "PasswordAuthentication no\nMatch Group admins\n  PasswordAuthentication yes\n"},
			"passwordauthentication", "no", true},
		{"a Match ends with its included file", map[string]string{"etc/ssh/sshd_config": "Include /etc/ssh/m.conf\nPasswordAuthentication no\n",
			"etc/ssh/m.conf": "Match User x\n"}, "passwordauthentication", "no", false},
		{"an Include inside a Match is Match", map[string]string{"etc/ssh/sshd_config": "PasswordAuthentication no\nMatch User x\nInclude /etc/ssh/m.conf\n",
			"etc/ssh/m.conf": "PasswordAuthentication yes\n"}, "passwordauthentication", "no", true},
		{"the old name", map[string]string{"etc/ssh/sshd_config": "ChallengeResponseAuthentication no\n"}, "kbdinteractiveauthentication", "no", false},
		{"an Include loop ends", map[string]string{"etc/ssh/sshd_config": "Include /etc/ssh/sshd_config\nUsePAM yes\n"}, "usepam", "yes", true},
	} {
		cfg := System{Root: tree(t, c.files)}.readSSHConfig("")
		if got := cfg.global[c.key]; got != c.val || cfg.on(c.key, "yes") != c.on {
			t.Errorf("%s: %s = %q (on %v), want %q (on %v)", c.name, c.key, got, cfg.on(c.key, "yes"), c.val, c.on)
		}
	}
}

func TestSSHVersions(t *testing.T) {
	for _, c := range []struct {
		in   string
		less bool // below 10.6p2
		ok   bool
	}{
		{"10.6p1", true, true}, {"10.6p2", false, true}, {"10.6p10", false, true}, {"10.6", true, true}, {"10.7", false, true},
		{"9.9p2", true, true}, {"11.0p1", false, true}, {"OpenSSH_10.6p2", false, true}, {"10.6p2-1", false, true},
		{"1:10.6p1-3", true, true}, {"10.6_p2-r0", false, true}, {"10.6_p1-r0", true, true}, {"x10.6", false, false}, {"10", false, false},
	} {
		v, ok := sshVersion(c.in)
		if ok != c.ok || (ok && versionLess(v, ssholeFixed) != c.less) {
			t.Errorf("%q: %v %v", c.in, v, ok)
		}
	}
	if ver, _ := binaryVersion([]byte("OpenSSH_2.*,OpenSSH_3.0*\x00OpenSSH_10.6\x00OpenSSH_10.5p1\x00OpenSSH_7.4*")); ver != "10.6" {
		t.Fatal(ver)
	}
}

func TestELFInterpreter(t *testing.T) {
	for _, c := range []struct {
		name, bin, libc string
	}{
		{"64-bit musl", fakeELF(true, muslInterp, ""), "musl"},
		{"32-bit musl", fakeELF(false, "/lib/ld-musl-armhf.so.1", ""), "musl"},
		{"64-bit glibc", fakeELF(true, glibcInterp, ""), "glibc"},
		{"static", fakeELF(true, "", ""), ""},
		{"not ELF", "#!/bin/sh\n", ""},
		{"cut short", fakeELF(true, muslInterp, "")[:100], ""},
	} {
		if got := libcOf(elfInterp([]byte(c.bin))); got != c.libc {
			t.Errorf("%s: %q", c.name, got)
		}
	}
}

func TestSSHGaps(t *testing.T) {
	sshole := map[string]string{"usr/sbin/sshd": fakeELF(true, muslInterp, "OpenSSH_10.6p1"), "etc/ssh/sshd_config": "UsePAM no\n", "proc/net/tcp": listen22}
	with := func(base map[string]string, k, v string) map[string]string {
		m := map[string]string{}
		for a, b := range base {
			m[a] = b
		}
		if v == "" {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	for _, c := range []struct {
		name  string
		files map[string]string
		want  string // id:level, sorted as found
	}{
		{"no server", map[string]string{"proc/net/tcp": listen22}, ""},
		{"SSHole", sshole, "ssh-sshole:critical ssh-password-login:warning"},
		{"SSHole, fixed version", with(sshole, "usr/sbin/sshd", fakeELF(true, muslInterp, "OpenSSH_10.6p2")), "ssh-password-login:warning"},
		{"glibc", with(sshole, "usr/sbin/sshd", fakeELF(true, glibcInterp, "OpenSSH_10.6p1")), "ssh-password-login:warning"},
		{"PAM", with(sshole, "etc/ssh/sshd_config", "UsePAM yes\n"), "ssh-password-login:warning"},
		{"passwords off", with(sshole, "etc/ssh/sshd_config", "PasswordAuthentication no\nUsePAM no\n"), ""},
		{"passwords off, PAM keyboard on", with(sshole, "etc/ssh/sshd_config", "PasswordAuthentication no\nUsePAM yes\n"), "ssh-password-login:warning"},
		{"installed but off", with(sshole, "proc/net/tcp", ""), "ssh-sshole:info ssh-password-login:info"},
		{"starts at boot", with(with(sshole, "proc/net/tcp", ""), "etc/systemd/system/multi-user.target.wants/sshd.service", "x"), "ssh-sshole:critical ssh-password-login:warning"},
		{"another port", with(sshole, "etc/ssh/sshd_config", "Port 2222\nUsePAM yes\n"), "ssh-password-login:info"},
		{"root and empty", with(sshole, "etc/ssh/sshd_config", "UsePAM yes\nPermitRootLogin yes\nPermitEmptyPasswords yes\n"),
			"ssh-password-login:warning ssh-root-password:warning ssh-empty-passwords:warning"},
		{"settings unread", with(sshole, "etc/ssh/sshd_config", ""), "ssh-settings-unread:info"},
		{"dropbear", map[string]string{"usr/sbin/dropbear": "x", "etc/runlevels/default/dropbear": ""}, "ssh-dropbear-password:warning"},
		{"dropbear -s", map[string]string{"usr/sbin/dropbear": "x", "etc/conf.d/dropbear": "DROPBEAR_OPTS=\"-w -s\"\n"}, ""},
	} {
		var got []string
		for _, g := range (System{Root: tree(t, c.files)}).sshGaps() {
			got = append(got, g.ID+":"+g.Level)
			if (g.ID == "ssh-sshole") != (g.CVE == SSHoleCVE) || g.Fix == "" {
				t.Errorf("%s: %+v", c.name, g)
			}
		}
		if strings.Join(got, " ") != c.want {
			t.Errorf("%s: %v, want %s", c.name, got, c.want)
		}
	}
}
