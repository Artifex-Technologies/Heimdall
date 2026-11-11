#!/usr/bin/env python3
"""Old against new for every program ported to Rust: the Go heimdalld, the Python Wi-Fi helpers, and the Rust heimdalld that
replaces both (rust/README.md, "Why Rust: measured"). Made-up input only; nothing on this computer or its network changes.

    python3 -I rust/parity/bench-port.py [--runs N] [--only daemon,engine,cli,wifi] [--window S] [--events N] [--json FILE]

OLD: the Go heimdalld built from the source of --go-commit (git archive, then `go build -trimpath -ldflags "-s -w"` as the
PKGBUILD builds it), and the Python Wi-Fi helpers of --py-commit (git show). NEW: rust/target/release/heimdalld-rs (build it
first: cd rust && scripts/nicecargo.sh build --release --locked); the helpers are links to it, as the package installs them.

How (the same for every program):
- each case runs OLD and NEW alternately (old then new, then new then old), RUNS times each after one unmeasured run of
  each, one process at a time, at nice 19;
- a small C launcher (bench-launch, built here with cc) starts each program and reports its wall time, its user + system
  CPU and its peak RSS from wait4(2). Python cannot do this itself: Linux counts the memory a process had before exec in its
  peak, so a program started by Python would show Python's own ~12 MB;
- the programs run in a user, mount and network namespace of this script's own: no network at all (only a loopback), a
  made-up /etc/heimdall, /var/lib/heimdall and /run, and a stand-in (bench-fake, C, ~1 MB) laid over every outside tool a
  program starts (nmcli, ip, ss, systemctl, nft, ping, notify-send, clamscan, iw), which answers from a file;
- reported per case: median and p10-p90 wall time, median CPU (the program and the stand-ins it starts: the same calls for
  both), median peak RSS (the largest of the program and its stand-ins), and whether both gave the same output;
- the daemon: the two running services (heimdall = Go in charge, heimdall-shadow = Rust in shadow mode) read from /proc
  over the same WINDOW seconds, read-only; and the engine's throughput on the engine differential's synthetic events
  (gen-events.py) through each engine (Go: rust/gotools/replay; Rust: heimdalld-rs replay).
"""
import argparse
import ctypes
import fcntl
import json
import os
import random
import re
import shutil
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
RUST_BIN = os.path.join(ROOT, "rust", "target", "release", "heimdalld-rs")
HELPERS = {"heimdall-wifi-check": "packaging/arch/heimdall-wifi-check", "heimdall-wifi-guard": "packaging/net/heimdall-wifi-guard",
           "heimdall-wifi-notify": "packaging/net/heimdall-wifi-notify"}
OLD_COMMIT = "9cfdeca"  # main on 2026-11-11, before the switch: the Go daemon in charge, the Python helpers installed
TOOLS = ("nmcli", "ip", "ss", "systemctl", "nft", "ping", "notify-send", "clamscan", "clamdscan", "iw")

LAUNCH_C = r"""
#define _GNU_SOURCE
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/wait.h>
/* bench-launch RESULT PROGRAM [ARGS...]: run PROGRAM with this process's standard input, output and error, then write to
   RESULT: wall_ns user_us sys_us maxrss_kb wait_status. The child is forked from this small program, so its peak RSS is its
   own (and that of the children it waited for), not the peak of whatever started the launcher. */
int main(int argc, char **argv) {
    struct timespec a, b;
    struct rusage ru;
    int st;
    if (argc < 3) return 125;
    clock_gettime(CLOCK_MONOTONIC, &a);
    pid_t pid = fork();
    if (pid < 0) return 126;
    if (pid == 0) { execv(argv[2], argv + 2); _exit(127); }
    if (wait4(pid, &st, 0, &ru) < 0) return 126;
    clock_gettime(CLOCK_MONOTONIC, &b);
    FILE *f = fopen(argv[1], "w");
    if (!f) return 126;
    fprintf(f, "%lld %lld %lld %ld %d\n", (long long)(b.tv_sec - a.tv_sec) * 1000000000LL + (b.tv_nsec - a.tv_nsec),
            (long long)ru.ru_utime.tv_sec * 1000000LL + ru.ru_utime.tv_usec,
            (long long)ru.ru_stime.tv_sec * 1000000LL + ru.ru_stime.tv_usec, ru.ru_maxrss, st);
    return fclose(f) == 0 ? 0 : 126;
}
"""

FAKE_C = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
/* bench-fake: a stand-in for an outside program. Its answer is the file $BENCH_FAKES/NAME_ARG1_ARG2... (default folder
   /run/bench-fakes) for the longest run of its first arguments that has one, '/' written as '%'; with none it prints nothing.
   It reads its standard input to the end (a program may write to it) and exits 0. */
int main(int argc, char **argv) {
    const char *dir = getenv("BENCH_FAKES");
    const char *name = strrchr(argv[0], '/');
    char key[4096], buf[65536];
    size_t n;
    if (!dir) dir = "/run/bench-fakes";
    name = name ? name + 1 : argv[0];
    for (int k = argc - 1; k >= 0; k--) {
        int len = snprintf(key, sizeof key, "%s/%s", dir, name);
        for (int i = 1; i <= k && len < (int)sizeof key; i++) len += snprintf(key + len, sizeof key - len, "_%s", argv[i]);
        if (len >= (int)sizeof key) continue;
        for (char *p = key + strlen(dir) + 1; *p; p++) if (*p == '/') *p = '%';
        FILE *f = fopen(key, "r");
        if (!f) continue;
        while ((n = fread(buf, 1, sizeof buf, f)) > 0) fwrite(buf, 1, n, stdout);
        fclose(f);
        break;
    }
    fflush(stdout);
    if (!isatty(0)) while (read(0, buf, sizeof buf) > 0) {}
    return 0;
}
"""


# ---- building the two sides

def run(cmd, **kw):
    return subprocess.run(cmd, check=True, **kw)


def git(*args):
    return subprocess.run(["git", "-C", ROOT] + list(args), check=True, capture_output=True).stdout


def build_c(tmp, name, src):
    path = os.path.join(tmp, name)
    with open(path + ".c", "w") as f:
        f.write(src)
    for static in (["-static"], []):
        if subprocess.run(["cc", "-O2"] + static + ["-o", path, path + ".c"], capture_output=True).returncode == 0:
            return path, bool(static)
    sys.exit("bench-port: needs a C compiler (cc) for the launcher")


def build_old(tmp, go_commit, py_commit):
    """The Go heimdalld and its replay tool from go_commit's source; the Python helpers from py_commit."""
    src = os.path.join(tmp, "go-src")
    os.makedirs(src)
    archive = git("archive", go_commit)
    run(["tar", "-x", "-C", src], input=archive)
    env = dict(os.environ, GOTOOLCHAIN="local", GOFLAGS="")
    go = os.path.join(tmp, "heimdalld-go")
    run(["go", "build", "-trimpath", "-ldflags", "-s -w", "-o", go, "./cmd/heimdalld"], cwd=src, env=env)
    replay = os.path.join(tmp, "replay-go")
    run(["go", "build", "-trimpath", "-ldflags", "-s -w", "-o", replay, "./rust/gotools/replay"], cwd=src, env=env)
    py = os.path.join(tmp, "py-bin")
    os.makedirs(py)
    for name, path in HELPERS.items():
        with open(os.path.join(py, name), "wb") as f:
            f.write(git("show", "%s:%s" % (py_commit, path)))
        os.chmod(os.path.join(py, name), 0o755)
    return go, replay, py


def link_new(tmp, rust_bin):
    d = os.path.join(tmp, "rs-bin")
    os.makedirs(d)
    for name in HELPERS:
        os.symlink(rust_bin, os.path.join(d, name))
    return d


# ---- measuring one run

class Launcher:
    def __init__(self, path, tmp):
        self.path = path
        self.result = os.path.join(tmp, "launch.result")

    def run(self, argv, env, stdin=None, stdout=None, cwd=None):
        with open(stdin or os.devnull, "rb") as si:
            out = open(stdout, "wb") if stdout else subprocess.PIPE
            try:
                p = subprocess.run([self.path, self.result] + argv, stdin=si, stdout=out, stderr=subprocess.PIPE, env=env, cwd=cwd)
            finally:
                if stdout:
                    out.close()
        if p.returncode != 0:
            raise RuntimeError("bench-launch failed (%d) for %s" % (p.returncode, argv))
        with open(self.result) as f:
            wall, ut, st, rss, status = f.read().split()
        return {"wall": int(wall) / 1e9, "cpu": (int(ut) + int(st)) / 1e6, "rss": int(rss), "rc": os.waitstatus_to_exitcode(int(status)),
                "out": p.stdout if not stdout else b"", "err": p.stderr}


def stats(runs):
    wall = sorted(r["wall"] for r in runs)
    q = statistics.quantiles(wall, n=10, method="inclusive") if len(wall) > 1 else [wall[0]] * 9
    return {"runs": len(runs), "wall_ms": statistics.median(wall) * 1e3, "p10_ms": q[0] * 1e3, "p90_ms": q[8] * 1e3,
            "cpu_ms": statistics.median(r["cpu"] for r in runs) * 1e3, "rss_kb": statistics.median(r["rss"] for r in runs)}


TIME_RE = re.compile(rb"\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:?\d\d)?( UTC)?")


TOOK_RE = re.compile(rb" in [0-9.]+(ns|\xc2\xb5s|us|ms|s)\b")


def normal(b, tmp):
    """Output with what may differ between two correct runs blanked: times, durations, each side's own folder."""
    b = TOOK_RE.sub(b" in <took>", TIME_RE.sub(b"<time>", b))
    b = re.sub(rb"([/-])(go|rust)([/-])", rb"\1<side>\3", b)
    return b.replace(tmp.encode(), b"<tmp>")


def bench(launcher, case, runs, tmp):
    """One unmeasured run of each (their output compared), then runs of each, alternating which goes first."""
    first = {s: launcher.run(**case[s]) for s in ("old", "new")}
    same = all(normal(first["old"][k], tmp) == normal(first["new"][k], tmp) for k in ("out", "err")) and first["old"]["rc"] == first["new"]["rc"]
    res = {"old": [], "new": []}
    for i in range(runs):
        for s in (("old", "new") if i % 2 == 0 else ("new", "old")):
            res[s].append(launcher.run(**case[s]))
    out = {"case": case["name"], "group": case["group"], "same_output": same, "rc": [first["old"]["rc"], first["new"]["rc"]],
           "old": stats(res["old"]), "new": stats(res["new"])}
    if not same:
        lines = {s: normal(first[s]["out"] + b"\n--stderr--\n" + first[s]["err"], tmp).decode(errors="replace").splitlines() for s in ("old", "new")}
        i = next((i for i, (x, y) in enumerate(zip(lines["old"], lines["new"])) if x != y), min(len(lines["old"]), len(lines["new"])))
        out["first_difference"] = {s: lines[s][i] if i < len(lines[s]) else "<end>" for s in ("old", "new")}
    return out


def bench_one(launcher, name, spec, runs):
    return {"case": name, "only": stats([launcher.run(**spec) for _ in range(runs)])}


# ---- namespaces (a user, mount and network namespace of our own: nothing outside sees what happens in it)

libc = ctypes.CDLL(None, use_errno=True)
MS_BIND, MS_REC, MS_PRIVATE = 4096, 16384, 1 << 18


def mount(src, dst, fstype=None, flags=0, data=None):
    enc = lambda s: s.encode() if isinstance(s, str) else s
    if libc.mount(enc(src), enc(dst), enc(fstype), ctypes.c_ulong(flags), enc(data)) != 0:
        e = ctypes.get_errno()
        raise OSError(e, "mount %s: %s" % (dst, os.strerror(e)))


def enter_namespaces(as_root):
    uid, gid = os.getuid(), os.getgid()
    os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNS | os.CLONE_NEWNET)
    with open("/proc/self/setgroups", "w") as f:
        f.write("deny")
    with open("/proc/self/uid_map", "w") as f:
        f.write("%d %d 1\n" % (0 if as_root else uid, uid))
    with open("/proc/self/gid_map", "w") as f:
        f.write("%d %d 1\n" % (0 if as_root else gid, gid))
    mount(None, "/", None, MS_REC | MS_PRIVATE)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    flags = struct.unpack_from("16sH", fcntl.ioctl(s, 0x8913, struct.pack("16sH22x", b"lo", 0)))[1]  # SIOCGIFFLAGS
    fcntl.ioctl(s, 0x8914, struct.pack("16sH22x", b"lo", flags | 1))  # SIOCSIFFLAGS: lo up
    s.close()


def fake_system(tmp, fake):
    """A made-up /run, /etc/heimdall, /var/lib/heimdall and /sys/class/net (one Wi-Fi interface, wlan0), and the stand-in
    over every outside tool."""
    mount("tmpfs", "/run", "tmpfs", 0, "mode=755")
    os.makedirs("/run/bench-fakes")
    for real, mine in (("/etc/heimdall", "etc-heimdall"), ("/var/lib/heimdall", "var-lib-heimdall")):
        os.makedirs(os.path.join(tmp, mine), exist_ok=True)
        if not os.path.isdir(real):
            sys.exit("bench-port: %s does not exist here, so a made-up one cannot be laid over it" % real)
        mount(os.path.join(tmp, mine), real, None, MS_BIND)
    mount("tmpfs", "/sys/class/net", "tmpfs", 0, "mode=755")
    os.makedirs("/sys/class/net/wlan0/wireless")
    os.makedirs("/sys/class/net/lo")
    for t in TOOLS:
        if os.path.exists("/usr/bin/" + t):
            mount(fake, "/usr/bin/" + t, None, MS_BIND)


def answers(d):
    for key, text in d.items():
        with open("/run/bench-fakes/" + key.replace(" ", "_").replace("/", "%"), "w") as f:
            f.write(text)


def in_namespace(fn, as_root, tmp, fake, out):
    """fn's results, run in a child in namespaces of its own."""
    pid = os.fork()
    if pid == 0:
        code = 1
        try:
            enter_namespaces(as_root)
            fake_system(tmp, fake)
            with open(out, "w") as f:
                json.dump(fn(), f)
            code = 0
        except BaseException:
            import traceback
            traceback.print_exc()
        finally:
            os._exit(code)
    _, st = os.waitpid(pid, 0)
    if st != 0:
        sys.exit("bench-port: the namespace part failed")
    with open(out) as f:
        return json.load(f)


# ---- the daemon, live (read-only /proc of the two running services)

def main_pid(unit):
    p = subprocess.run(["systemctl", "show", "-p", "MainPID", "--value", unit], capture_output=True, text=True)
    pid = int(p.stdout.strip() or 0)
    return pid if pid > 0 else None


def snapshot(pid):
    ns = cs = 0
    for t in os.listdir("/proc/%d/task" % pid):
        try:
            with open("/proc/%d/task/%s/schedstat" % (pid, t)) as f:
                ns += int(f.read().split()[0])
            with open("/proc/%d/task/%s/status" % (pid, t)) as f:
                cs += sum(int(l.split()[1]) for l in f if l.startswith(("voluntary_ctxt", "nonvoluntary_ctxt")))
        except (FileNotFoundError, ProcessLookupError):
            pass
    with open("/proc/%d/status" % pid) as f:
        st = dict(l.split(":", 1) for l in f if ":" in l)
    with open("/proc/%d/stat" % pid) as f:
        fields = f.read().rsplit(")", 1)[1].split()
    with open("/proc/uptime") as f:
        uptime = float(f.read().split()[0])
    kb = lambda k: int(st[k].split()[0])
    tick = os.sysconf("SC_CLK_TCK")
    return {"comm": st["Name"].strip(), "cpu_ns": ns, "ctxsw": cs, "rss_kb": kb("VmRSS"), "anon_kb": kb("RssAnon"), "hwm_kb": kb("VmHWM"),
            "threads": int(st["Threads"]), "cpu_total_s": (int(fields[11]) + int(fields[12])) / tick,
            "running_s": uptime - int(fields[19]) / tick, "t": time.monotonic()}


def daemon_live(window):
    pids = {"old": main_pid("heimdall"), "new": main_pid("heimdall-shadow")}
    if not all(pids.values()):
        return {"skipped": "heimdall and heimdall-shadow must both be running", "pids": pids}
    a = {s: snapshot(p) for s, p in pids.items()}
    time.sleep(window)
    b = {s: snapshot(p) for s, p in pids.items()}
    out = {"window_s": window}
    for s in pids:
        dt = b[s]["t"] - a[s]["t"]
        out[s] = {"comm": b[s]["comm"], "window_cpu_ms": (b[s]["cpu_ns"] - a[s]["cpu_ns"]) / 1e6,
                  "window_core_pct": (b[s]["cpu_ns"] - a[s]["cpu_ns"]) / 1e9 / dt * 100, "window_ctxsw_per_s": (b[s]["ctxsw"] - a[s]["ctxsw"]) / dt,
                  "rss_kb": b[s]["rss_kb"], "anon_kb": b[s]["anon_kb"], "hwm_kb": b[s]["hwm_kb"], "threads": b[s]["threads"],
                  "since_start_h": b[s]["running_s"] / 3600, "since_start_cpu_s": b[s]["cpu_total_s"],
                  "since_start_core_pct": b[s]["cpu_total_s"] / b[s]["running_s"] * 100, "since_start_ctxsw": b[s]["ctxsw"]}
    return out


# ---- the made-up inputs

def make_inputs(tmp):
    env = os.path.join(tmp, "env")
    run([sys.executable, "-I", os.path.join(HERE, "harness", "setup-env.py"), env, "--audits"], stdout=subprocess.DEVNULL)
    ipdb = os.path.join(env, "ipdb")
    os.makedirs(ipdb)
    dbs = []
    for n in ("synthetic-country.mmdb", "synthetic-asn.mmdb"):
        shutil.copy(os.path.join(ROOT, "testdata", "parity", n), ipdb)
        dbs.append(os.path.join(ipdb, n))
    for side in ("go", "rust"):
        p = os.path.join(env, side, "config.json")
        with open(p) as f:
            cfg = json.load(f)
        cfg["ip_databases"] = dbs
        with open(p, "w") as f:
            json.dump(cfg, f, indent=1)
    with open(os.path.join(ROOT, "testdata", "parity", "functions.json")) as f:
        ips = [o["ip"] for o in json.load(f)["origins"]][:40]
    rng = random.Random(11)
    nets = sorted({"%d.%d.%d.0/24" % (rng.randint(1, 223), rng.randint(0, 255), rng.randint(0, 255)) for _ in range(5000)})
    lists = os.path.join(tmp, "lists")
    os.makedirs(lists)
    with open(os.path.join(lists, "new.txt"), "w") as f:
        f.write("; made-up threat list\n" + "".join("%s ; SBL%06d\n" % (n, i) for i, n in enumerate(nets)))
    with open(os.path.join(lists, "last.txt"), "w") as f:
        f.write("; made-up threat list\n" + "".join("%s ; SBL%06d\n" % (n, i) for i, n in enumerate(nets[:4800])))
    devices = [{"mac": "02:00:00:00:%02x:%02x" % (i // 256, i % 256), "ip": "192.0.2.%d" % (i + 2), "name": "device-%d" % i,
                "names": ["device-%d" % i], "vendor": "Example Corp", "kind": ["phone", "tv", "computer", "smart", "other"][i % 5],
                "first_seen": "2026-11-01T10:00:00Z", "last_seen": "2026-11-10T10:00:00Z"} for i in range(60)]
    store = {"networks": [{"uuid": "11111111-2222-3333-4444-555555555555", "ssid": "Example Home", "first_scan": "2026-11-01T10:00:00Z",
                           "last_scan": "2026-11-10T10:00:00Z", "devices": devices}],
             "status": "scanned", "status_uuid": "11111111-2222-3333-4444-555555555555", "status_time": "2026-11-10T10:00:00Z"}
    for side in ("go", "rust"):
        for d in ("lan-" + side, "lanscan-" + side, "trust-" + side, "immunity-" + side, "home-" + side):
            os.makedirs(os.path.join(tmp, d))
        with open(os.path.join(tmp, "lan-" + side, "devices.json"), "w") as f:
            json.dump(store, f, indent=1)
    files = os.path.join(tmp, "files")
    os.makedirs(files)
    for i in range(300):
        with open(os.path.join(files, "download-%03d.bin" % i), "wb") as f:
            f.write(bytes(rng.getrandbits(8) for _ in range(2048)))
    return {"env": env, "ips": ips, "lists": lists, "files": files}


def cli_cases(tmp, go, rs, inp):
    env = inp["env"]

    def side(binary, s, args, extra=None):
        e = {"PATH": "/usr/bin:/bin", "HOME": os.path.join(tmp, "home-" + s), "LANG": "C.UTF-8", "TZ": "UTC",
             "HEIMDALL_TRUST_DIR": os.path.join(tmp, "trust-" + s), "HEIMDALL_IMMUNITY_DIR": os.path.join(tmp, "immunity-" + s)}
        e.update(extra or {})
        return {"argv": [binary] + [a.replace("{side}", s) for a in args], "env": e}

    cfg = os.path.join(env, "{side}", "config.json")
    specs = [
        ("version", ["version"]),
        ("scan (6,641 sessions, Limbo, a vault, 25 watched files)", ["scan", "--config", cfg]),
        ("origin (40 addresses, offline databases)", ["origin", "--config", cfg] + inp["ips"]),
        ("ipdb-check (two 1 MB databases)", ["ipdb-check"] + [os.path.join(env, "ipdb", n) for n in ("synthetic-country.mmdb", "synthetic-asn.mmdb")]),
        ("intel-check list (5,000 networks against the last copy)", ["intel-check", "list", os.path.join(inp["lists"], "new.txt"), os.path.join(inp["lists"], "last.txt")]),
        ("intel-check tracker (6,000 advisories)", ["intel-check", "tracker", os.path.join(env, "arch-security.json")]),
        ("kernel-check (9,000 kernel CVEs, this computer's kernels)", ["kernel-check", "--list", os.path.join(env, "linux-kernel.json")]),
        ("lan list (60 devices)", ["lan", "list", "--dir", os.path.join(tmp, "lan-{side}")]),
        ("lan scan (no network: the 5-minute timer's quick answer)", ["lan", "scan", "--dir", os.path.join(tmp, "lanscan-{side}")]),
        ("maintenance status", ["maintenance", "status", "--config", cfg]),
        ("grant status", ["grant", "status"]),
        ("contain status", ["contain", "status"]),
        ("remote list", ["remote", "list"]),
        ("trust status", ["trust", "status"]),
        ("immunity list", ["immunity", "list"]),
        ("scan-files (300 files, one ClamAV call)", ["scan-files", inp["files"]]),
        ("scan-files --state (300 files, unchanged since the last scan)", ["scan-files", "--state", os.path.join(tmp, "home-{side}", "scan-state.json"), inp["files"]]),
        ("wifi-health (no Wi-Fi route: the quick answer)", ["wifi-health", "--api", ""]),
    ]

    def clamav():  # ClamAV's stand-in finds every file clean
        files = sorted(os.path.join(inp["files"], f) for f in os.listdir(inp["files"]))
        answers({"clamscan --no-summary --": "".join("%s: OK\n" % f for f in files)})
    return [{"name": n, "group": "cli", "setup": clamav if a[0] == "scan-files" else None, "old": side(go, "go", a), "new": side(rs, "rust", a)}
            for n, a in specs]


def wifi_user_cases(tmp, py, rsd):
    """heimdall-wifi-check (as its unit runs it) and heimdall-wifi-notify (the user's session)."""
    def side(d, s, prog, args, extra=None):
        e = {"PATH": "/usr/bin:/bin", "HOME": os.path.join(tmp, "home-" + s), "LANG": "C.UTF-8", "TZ": "UTC",
             "XDG_STATE_HOME": os.path.join(tmp, "home-" + s, "state"), "HEIMDALL_WIFI_DIR": os.path.join(tmp, "wifi-" + s),
             "HEIMDALL_WIFI_PUBLIC": os.path.join(tmp, "wifi-" + s, "last.json")}
        e.update(extra or {})
        return {"argv": [os.path.join(d, prog)] + args, "env": e}

    def both(name, prog, args, setup=None):
        return {"name": name, "group": "wifi", "prog": prog, "setup": setup, "old": side(py, "go", prog, args), "new": side(rsd, "rust", prog, args)}

    def check_net():
        answers({"nmcli -t -f ACTIVE,SSID,BSSID,SECURITY dev wifi list --rescan no":
                 "yes:Example Cafe:02\\:00\\:00\\:00\\:10\\:01:WPA2\nno:Example Cafe 5G:02\\:00\\:00\\:00\\:10\\:02:WPA2\nno:Neighbour:02\\:00\\:00\\:00\\:10\\:03:WPA2 WPA3\n",
                 "nmcli -t -f CONNECTIVITY general": "full\n",
                 "ip -j route show default": '[{"dst":"default","gateway":"192.0.2.1","dev":"wlan0","protocol":"dhcp"}]\n',
                 "ip -j neigh show dev wlan0": '[{"dst":"192.0.2.1","lladdr":"02:00:00:00:10:fe","state":["REACHABLE"]}]\n',
                 "ip -j addr": '[{"ifname":"lo","addr_info":[{"local":"127.0.0.1"}]},{"ifname":"wlan0","addr_info":[{"local":"192.0.2.10"}]}]\n',
                 "systemctl is-active ufw": "active\n"})
        os.makedirs("/run/heimdall-wifi-guard", exist_ok=True)
        with open("/run/heimdall-wifi-guard/state.json", "w") as f:
            json.dump({"locked": True}, f)

    def notify_unsafe():
        os.makedirs("/run/heimdall-wifi", exist_ok=True)
        with open("/run/heimdall-wifi/last.json", "w") as f:
            json.dump({"time": "2026-11-11T10:00:00Z", "ssid": "Example Cafe", "verdict": "unsafe",
                       "reasons": ["another network with the same name but different security is nearby"]}, f)

    def notify_known():
        os.makedirs("/run/heimdall-wifi", exist_ok=True)
        with open("/run/heimdall-wifi/last.json", "w") as f:
            json.dump({"time": "2026-11-11T10:00:00Z", "ssid": "Example Home", "verdict": "safe", "reasons": []}, f)

    return [both("check (a whole check, online tests held by the guard)", "heimdall-wifi-check", ["--uuid", "aaaaaaaa-0000-0000-0000-000000000001"], check_net),
            both("notify (an unsafe network: one notification)", "heimdall-wifi-notify", [], notify_unsafe),
            both("notify (a safe network already shown: nothing to do)", "heimdall-wifi-notify", [], notify_known)]


def wifi_root_cases(tmp, py, rsd):
    """heimdall-wifi-guard as NetworkManager's dispatcher starts it (root)."""
    home, other, vpn = "aaaaaaaa-0000-0000-0000-000000000001", "bbbbbbbb-0000-0000-0000-000000000002", "cccccccc-0000-0000-0000-000000000003"

    def side(d, s, args):
        return {"argv": [os.path.join(d, "heimdall-wifi-guard")] + args, "env": {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC"}}

    def setup():
        with open("/etc/heimdall/wifi-trusted.json", "w") as f:
            json.dump({home: {"ssid": "Example Home", "routers": ["02:00:00:00:20:FE"]}}, f, indent=1)
        with open("/etc/heimdall/wifi-guard.json", "w") as f:
            json.dump({"vpn": {"uuid": vpn, "iface": "wg-heimdall", "endpoints": [{"ip": "203.0.113.5", "port": 51820}]}}, f, indent=1)
        answers({"nmcli -g 802-11-wireless.ssid connection show " + home: "Example Home\n",
                 "nmcli -g 802-11-wireless.ssid connection show " + other: "Example Cafe\n",
                 "nmcli -t -f DEVICE,TYPE,STATE,CONNECTION device": "wlan0:wifi:connected:Example Home\nlo:loopback:connected (externally):lo\n",
                 "nmcli -g GENERAL.CON-UUID device show wlan0": home + "\n",
                 "ip -j route show default dev wlan0": '[{"dst":"default","gateway":"192.0.2.1","dev":"wlan0"}]\n',
                 "ip -j neigh show 192.0.2.1 dev wlan0": '[{"dst":"192.0.2.1","lladdr":"02:00:00:00:20:fe","state":["REACHABLE"]}]\n',
                 "systemctl is-active avahi-daemon.service": "inactive\n"})

    specs = [("guard up (a trusted network: the router checked, nothing locked)", ["up", "wlan0", home]),
             ("guard pre-up (an untrusted network: the lockdown before any traffic)", ["pre-up", "wlan0", other]),
             ("guard up (an untrusted network: quiet, lockdown, VPN)", ["up", "wlan0", other]),
             ("guard down", ["down", "wlan0", other]),
             ("guard status", ["status"])]
    return [{"name": n, "group": "wifi", "prog": "heimdall-wifi-guard", "setup": setup, "old": side(py, "go", a), "new": side(rsd, "rust", a)}
            for n, a in specs]


# ---- report

def change(old, new, unit, digits=1):
    if old == 0:
        return "n/a"
    pct = (old - new) / old * 100
    word = {"ms": ("faster", "slower"), "MB": ("less", "more")}[unit]
    return "%s%.0f %%, %.*f %s %s" % ("\u2212" if pct > 0 else "+", abs(pct), digits, abs(old - new), unit, word[0] if pct > 0 else word[1])


def markdown(results):
    lines = []
    for r in results.get("cases", []):
        o, n = r["old"], r["new"]
        lines.append("| %s | %.2f ms (%.2f-%.2f) | %.2f ms (%.2f-%.2f) | %s | %.2f -> %.2f ms | %.1f -> %.1f MB | %s |" % (
            r["case"], o["wall_ms"], o["p10_ms"], o["p90_ms"], n["wall_ms"], n["p10_ms"], n["p90_ms"], change(o["wall_ms"], n["wall_ms"], "ms", 2),
            o["cpu_ms"], n["cpu_ms"], o["rss_kb"] / 1024, n["rss_kb"] / 1024, "yes" if r["same_output"] else "NO"))
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--runs", type=int, default=30)
    ap.add_argument("--only", default="daemon,engine,cli,wifi")
    ap.add_argument("--window", type=int, default=60, help="seconds the two running daemons are watched")
    ap.add_argument("--events", type=int, default=100000, help="synthetic events through each engine")
    ap.add_argument("--engine-runs", type=int, default=5)
    ap.add_argument("--go-commit", default=OLD_COMMIT, help="the commit whose Go source is built (default: the one measured, before the switch)")
    ap.add_argument("--py-commit", default=OLD_COMMIT, help="the commit whose Python Wi-Fi helpers are run")
    ap.add_argument("--rust-bin", default=RUST_BIN)
    ap.add_argument("--json", help="write every number here")
    a = ap.parse_args()
    only = set(a.only.split(","))
    os.nice(19 - os.nice(0))
    tmp = tempfile.mkdtemp(prefix="bench-port-")
    res = {"go_commit": git("rev-parse", a.go_commit).decode().strip(), "py_commit": git("rev-parse", a.py_commit).decode().strip(),
           "rust_commit": git("rev-parse", "HEAD").decode().strip(), "runs": a.runs, "cpus": os.cpu_count()}
    try:
        go, replay, py = build_old(tmp, a.go_commit, a.py_commit)
        rs = os.path.abspath(a.rust_bin)
        rsd = link_new(tmp, rs)
        launch, static = build_c(tmp, "bench-launch", LAUNCH_C)
        fake, _ = build_c(tmp, "bench-fake", FAKE_C)
        L = Launcher(launch, tmp)
        python3 = shutil.which("python3")
        res["sizes"] = {"go_bytes": os.path.getsize(go), "rust_bytes": os.path.getsize(rs),
                        "python_scripts_bytes": {n: os.path.getsize(os.path.join(py, n)) for n in HELPERS}}
        res["floor"] = bench_one(L, "/usr/bin/true (the launcher's floor)", {"argv": ["/usr/bin/true"], "env": {}}, a.runs)
        res["floor"]["static_launcher"] = static
        if "wifi" in only:
            res["python_start"] = bench_one(L, "python3 -c pass (the interpreter alone)", {"argv": [python3, "-c", "pass"], "env": {"PATH": "/usr/bin:/bin"}}, a.runs)
        if "daemon" in only:
            print("watching the two running daemons for %d s ..." % a.window, flush=True)
            res["daemon"] = daemon_live(a.window)
        inp = make_inputs(tmp)

        def user_part():
            out = {"cases": []}
            if "engine" in only:
                ev = os.path.join(tmp, "events.jsonl")
                with open(ev, "w") as f:
                    run([sys.executable, "-I", os.path.join(HERE, "gen-events.py"), str(a.events), "20261110"], stdout=f)
                cfg = os.path.join(tmp, "replay-config.json")
                with open(cfg, "w") as f:
                    json.dump({"maintenance_path": os.path.join(tmp, "none", "m.json"), "mesh_peers_path": os.path.join(tmp, "none", "p.json"),
                               "agent_baseline_state_path": "", "baseline_min_samples": 20}, f)
                specs = {"old": {"argv": [replay, "--config", cfg, "--approvals", os.path.join(tmp, "none")], "env": {}, "stdin": ev,
                                 "stdout": os.path.join(tmp, "replay-go.jsonl")},
                         "new": {"argv": [rs, "replay", "--config", cfg, "--approvals", os.path.join(tmp, "none")], "env": {}, "stdin": ev,
                                 "stdout": os.path.join(tmp, "replay-rs.jsonl")}}
                r = bench(L, dict(specs, name="engine: %d synthetic events" % a.events, group="engine"), a.engine_runs, tmp)
                strip = lambda p: [re.sub(r'"time":"[^"]*",?', "", l) for l in open(p)]
                r["alerts"] = [sum(1 for _ in open(specs[s]["stdout"])) for s in ("old", "new")]
                r["same_output"] = strip(specs["old"]["stdout"]) == strip(specs["new"]["stdout"])
                r["events"] = a.events
                out["engine"] = r
                print("engine done", flush=True)
            cases = (cli_cases(tmp, go, rs, inp) if "cli" in only else []) + (wifi_user_cases(tmp, py, rsd) if "wifi" in only else [])
            for c in cases:
                if c.get("setup"):
                    c["setup"]()
                out["cases"].append(bench(L, {k: v for k, v in c.items() if k != "setup"}, a.runs, tmp))
                print("  " + c["name"], flush=True)
            return out

        def root_part():
            out = {"cases": []}
            for c in wifi_root_cases(tmp, py, rsd):
                c["setup"]()
                out["cases"].append(bench(L, {k: v for k, v in c.items() if k != "setup"}, a.runs, tmp))
                print("  " + c["name"], flush=True)
            return out

        part = in_namespace(user_part, False, tmp, fake, os.path.join(tmp, "user.json"))
        res["engine"] = part.get("engine")
        res["cases"] = part["cases"]
        if "wifi" in only:
            res["cases"] += in_namespace(root_part, True, tmp, fake, os.path.join(tmp, "root.json"))["cases"]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(json.dumps({k: v for k, v in res.items() if k != "cases"}, indent=1))
    print("| case | old: median (p10-p90) | Rust: median (p10-p90) | change | CPU | peak RSS | same output |")
    print(markdown(res))
    if a.json:
        with open(a.json, "w") as f:
            json.dump(res, f, indent=1)


if __name__ == "__main__":
    main()
