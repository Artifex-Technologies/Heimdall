package netsource

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestScriptOfNamesTheInterpretedFileOnly(t *testing.T) {
	cases := []struct {
		exe  string
		argv []string
		cwd  string
		want string
	}{
		{"/usr/bin/nmap", []string{"nmap", "-sV", "10.0.0.1"}, "/", ""},
		{"/usr/bin/python3.14", []string{"python", "/opt/sqlmap/sqlmap.py", "-u", "http://x"}, "/", "/opt/sqlmap/sqlmap.py"},
		{"/usr/bin/python3.14", []string{"python", "-O", "sqlmap.py", "--batch"}, "/opt/sqlmap", "/opt/sqlmap/sqlmap.py"},
		{"/usr/lib/jvm/java-21-openjdk/bin/java", []string{"java", "-Xmx4g", "-jar", "/usr/share/burpsuite/burpsuite.jar"}, "/", "/usr/share/burpsuite/burpsuite.jar"},
		{"/usr/bin/ruby", []string{"ruby", "/opt/metasploit/msfconsole", "-q"}, "/", "/opt/metasploit/msfconsole"},
		{"/usr/bin/python3", []string{"python3", "-c", "import socket"}, "/", ""},
		{"/usr/bin/python3", []string{"python3", "-m", "http.server"}, "/", ""},
	}
	for _, c := range cases {
		if got := scriptOf(c.exe, c.argv, c.cwd); got != c.want {
			t.Errorf("scriptOf(%s, %v) = %q, want %q", c.exe, c.argv, got, c.want)
		}
	}
}

func TestAgentAncestorFollowsParents(t *testing.T) {
	root := t.TempDir()
	stat := func(pid int, comm string, ppid int) {
		d := filepath.Join(root, strconv.Itoa(pid))
		os.MkdirAll(d, 0o755)
		os.WriteFile(filepath.Join(d, "stat"), []byte(strconv.Itoa(pid)+" ("+comm+") S "+strconv.Itoa(ppid)+" 1 1 0"), 0o644)
	}
	stat(100, "systemd", 1)
	stat(200, "sarina", 100)
	stat(300, "bash (x)", 200)
	stat(400, "nmap", 300)
	stat(500, "ghostty", 100)
	stat(600, "nmap", 500)
	if got := agentAncestor(root, 400); got != "sarina" {
		t.Fatalf("started by Sarina through a shell: %q", got)
	}
	if got := agentAncestor(root, 600); got != "" {
		t.Fatalf("started from a terminal: %q", got)
	}
	if got := agentAncestor(root, 999); got != "" {
		t.Fatal("a gone process has no agent")
	}
}
