"""Runs a command with stdin passed through and stdout to a file, then prints its CPU time and peak memory.

    python3 -I measure.py OUT CMD [ARGS...] < input

CPU: user + system seconds of the child (getrusage). Peak memory: the child's own VmHWM, read from /proc while it runs
(getrusage's ru_maxrss of a child counts the forked Python before the exec, about 12 MB, which hides a small daemon).
"""
import os, resource, subprocess, sys, time

out, cmd = sys.argv[1], sys.argv[2:]
start = time.monotonic()
with open(out, "wb") as f:
    p = subprocess.Popen(cmd, stdin=sys.stdin, stdout=f)
    target = p.pid
    hwm = 0
    while p.poll() is None:
        try:
            # follow through `nice`: the measured program is the newest descendant with the same pid after exec
            for line in open(f"/proc/{target}/status"):
                if line.startswith("VmHWM:"):
                    hwm = max(hwm, int(line.split()[1]))
        except (FileNotFoundError, ProcessLookupError, ValueError):
            pass
        time.sleep(0.02)
    rc = p.returncode
wall = time.monotonic() - start
ru = resource.getrusage(resource.RUSAGE_CHILDREN)
name = os.path.basename(next((c for c in cmd if "/" in c), cmd[0]))
print(f"{name}: exit {rc}, CPU {ru.ru_utime + ru.ru_stime:.2f} s (user {ru.ru_utime:.2f}), wall {wall:.2f} s, peak RSS {hwm / 1024:.1f} MB (VmHWM)")
sys.exit(rc)
