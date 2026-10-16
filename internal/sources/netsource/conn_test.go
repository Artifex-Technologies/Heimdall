package netsource

import (
	"os"
	"path/filepath"
	"testing"
)

// A fake /proc: one process (pid 4242, "curl", in app slice lapp_demo) holding socket 777, which is an established
// connection to 5.0.0.10:443 (hex 0A000005:01BB); and a loopback connection that must be ignored.
func fakeProc(t *testing.T) string {
	root := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "net"), 0o755))
	must(os.WriteFile(filepath.Join(root, "net/tcp"), []byte(`  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:C000 0A000005:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 777 1 0000000000000000 20 4 30 10 -1
   1: 0100007F:C001 0100007F:223D 01 00000000:00000000 00:00000000 00000000  1000        0 778 1 0000000000000000 20 4 30 10 -1
`), 0o644))
	pid := filepath.Join(root, "4242")
	must(os.MkdirAll(filepath.Join(pid, "fd"), 0o755))
	must(os.Symlink("socket:[777]", filepath.Join(pid, "fd", "5")))
	must(os.WriteFile(filepath.Join(pid, "comm"), []byte("curl\n"), 0o644))
	must(os.WriteFile(filepath.Join(pid, "cgroup"), []byte("0::/user.slice/user-1000.slice/user@1000.service/lapp_demo.slice/x.scope\n"), 0o644))
	return root
}

func TestConnWatcherLearnsThenReportsNew(t *testing.T) {
	root := fakeProc(t)
	state := filepath.Join(t.TempDir(), "state.json")
	policy := filepath.Join(t.TempDir(), "policy.json")
	os.WriteFile(policy, []byte(`{"rules":{"1000":{"demo":"block"}}}`), 0o644)

	w := newConnWatcher(root, state, policy)
	ev, err := w.Poll()
	if err != nil || len(ev) != 1 {
		t.Fatalf("first poll: %v %+v", err, ev)
	}
	f := ev[0].Fields
	if f["process"] != "curl" || f["app"] != "demo" || f["remote_addr"] != "5.0.0.10" || f["remote_port"] != "443" || f["learning"] != "1" || f["blocked"] != "1" {
		t.Fatalf("fields: %+v", f)
	}
	if ev, _ = w.Poll(); len(ev) != 0 {
		t.Fatalf("a known connection must not be reported again: %+v", ev)
	}
	// A restart keeps the memory and is no longer learning.
	w2 := newConnWatcher(root, state, policy)
	if ev, _ = w2.Poll(); len(ev) != 0 {
		t.Fatalf("state was not kept: %+v", ev)
	}
	os.Remove(filepath.Join(root, "4242/fd/5"))
	os.Symlink("socket:[999]", filepath.Join(root, "4242/fd/5"))
	w3 := newConnWatcher(root, state, policy)
	ev, _ = w3.Poll() // owner now unknown: a new (process, destination) pair, and no longer learning
	if len(ev) != 1 || ev[0].Fields["process"] != "unknown" || ev[0].Fields["learning"] != "" {
		t.Fatalf("unknown owner: %+v", ev)
	}
}
