"""Runs a command with stdin passed through and stdout to a file, then prints its CPU time and peak memory (getrusage of the
child: user + system seconds, maximum resident set).

    python3 -I measure.py OUT CMD [ARGS...] < input
"""
import resource, subprocess, sys, time

out, cmd = sys.argv[1], sys.argv[2:]
start = time.monotonic()
with open(out, "wb") as f:
    rc = subprocess.call(cmd, stdin=sys.stdin, stdout=f)
wall = time.monotonic() - start
ru = resource.getrusage(resource.RUSAGE_CHILDREN)
import os
name = os.path.basename(next((c for c in cmd if "/" in c), cmd[0]))
print(f"{name}: exit {rc}, CPU {ru.ru_utime + ru.ru_stime:.2f} s (user {ru.ru_utime:.2f}), wall {wall:.2f} s, peak RSS {ru.ru_maxrss / 1024:.1f} MB")
sys.exit(rc)
