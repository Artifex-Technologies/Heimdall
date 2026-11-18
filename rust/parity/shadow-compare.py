"""Compares a week of the Go daemon's alerts with the shadow daemon's (docs/RUST_SHADOW.md).

    python3 -I shadow-compare.py GO_ALERTS RS_ALERTS [--since RFC3339] [--until RFC3339] [--audit-edge-hours 7]
                                 [--conn-state-not-copied]

Only alerts raised in the window and by detectors whose sources the Rust port has ported are compared (as multisets, time
dropped; alerts within a minute of either end of the window, or for the audits within --audit-edge-hours, may be on one side
only and are listed apart). Detectors that
learn from the host's own load are timing-dependent (each daemon samples /proc at its own moment) and are counted, not
compared. Exit 0: no difference in the compared detectors.

The connection log (new_connection alerts: connection-watch, and remote-access on a remote-access tool's connection) samples
/proc/net every 10 seconds in each daemon, at each daemon's own moment, so it has rules of its own (docs/RUST_SHADOW.md,
"Reading the connection log"):

1. Same destination, another socket: each daemon reports a (process, address, port) once, for the first socket it saw to it,
   which may be another socket of it held by another process of that name. Those alerts are compared without what belongs to
   the socket and its process: the local port, uid, pid (also in the texts), app, exe, script and agent.
2. One poll only: an info alert on one side for a destination the other daemon never reported (not before the window, not
   in it) is a connection short enough to fall between the other's polls. Expected only while the two sides miss about
   equally: per address family, scope and named/unnamed owner, the counts must not be lopsided (two-sided binomial test,
   p < 0.01, against the even split two daemons polling at random phases give). A lopsided group stays a difference.
3. With --conn-state-not-copied (the shadow week began without a copy of the Go daemon's learned destinations,
   connections-state.json, which step 3 of docs/RUST_SHADOW.md did not copy before 2026-11-18): an alert of any severity
   only in the shadow log, for a destination the Go log reported before the window began (so it was in Go's state and not
   in the shadow daemon's). Never applied without the flag: with the state copied, such an alert would be the shadow daemon
   failing to read the state.

A destination reported twice by the same daemon (by one detector, up to the window's end) is never expected: each daemon
remembers what it reported. Every other one-sided alert, and any one-sided alert above info but for rule 3, is a difference.
"""
import collections, json, math, re, sys
from datetime import datetime, timedelta

COMPARED = {"injection-phrase", "credential-shape", "invisible-unicode", "permission-escalation", "session-burst", "file-integrity",
            "maintenance-window", "agent-baseline", "limbo-guest", "limbo-network", "limbo-exchange", "tool-rules",
            "network-exposure", "connection-watch", "inbound", "lan-watch", "wifi-safety", "remote-access",
            "package-vulnerability", "kernel-vulnerability", "hardening", "incident"}
TIMING = {"resource-pressure", "baseline-drift"}
# the 6-hourly audits run at each daemon's own start and every package_audit_interval_hours after it, so one daemon may report
# a new finding up to that long before the other: near either end of the window their alerts count as edge alerts
AUDITS = {"package-vulnerability", "kernel-vulnerability", "hardening"}
SHOWN = 40  # difference lines printed per side

args = sys.argv[1:]


def opt_raw(name):
    if name in args:
        i = args.index(name)
        v = args[i + 1]
        del args[i:i + 2]
        return v
    return None


def flag(name):
    if name in args:
        args.remove(name)
        return True
    return False


def opt(name):
    v = opt_raw(name)
    return datetime.fromisoformat(v.replace("Z", "+00:00")) if v else None


since, until = opt("--since"), opt("--until")
audit_edge = timedelta(hours=float(opt_raw("--audit-edge-hours") or 7))
conn_state_not_copied = flag("--conn-state-not-copied")
go_path, rs_path = args


def when(a):
    return datetime.fromisoformat(a["time"][:26].rstrip("Z") + "+00:00") if a["time"].endswith("Z") else datetime.fromisoformat(a["time"])


def is_conn(a):
    return a["detector_id"] in ("connection-watch", "remote-access") and a.get("event_kind") == "new_connection"


def dest(a):
    f = a.get("fields", {})
    return f.get("process", ""), f.get("remote_addr", ""), f.get("remote_port", "")


PID = re.compile(r" \(pid \d+\) ")
OWNER = {"local_port", "uid", "pid", "app", "exe", "script", "agent"}  # the socket's and its process's, not the destination's


def comparable(a):
    """The alert as compared: time dropped; for the connection log also the socket (rule 1)."""
    a = dict(a)
    a.pop("time")
    if is_conn(a):
        a["fields"] = {k: v for k, v in a.get("fields", {}).items() if k not in OWNER}
        for k in ("event_text", "summary"):
            a[k] = PID.sub(" ", a.get(k, ""), count=1)
    return json.dumps(a, sort_keys=True, ensure_ascii=False)


def load(path):
    keep, edge, timing, other = collections.Counter(), collections.Counter(), collections.Counter(), collections.Counter()
    reported = collections.defaultdict(list)  # (detector, destination) -> every time this daemon reported it (the whole log)
    for line in open(path, encoding="utf-8"):
        if not line.strip():
            continue
        a = json.loads(line)
        t = when(a)
        if is_conn(a):
            reported[(a["detector_id"], dest(a))].append(t)
        if (since and t < since) or (until and t > until):
            continue
        d = a["detector_id"]
        if d in TIMING:
            timing[d] += 1
            continue
        if d not in COMPARED:
            # integration alerts about the session files are the sources' own; the rest (the responder) is not ported
            if d == "integration" and a.get("fields", {}).get("error_code", "").startswith("agent_session_"):
                pass
            else:
                other[d] += 1
                continue
        key = comparable(a)
        margin = audit_edge if d in AUDITS else timedelta(minutes=1)
        near = (since and t < since + margin) or (until and t > until - margin)
        (edge if near else keep)[(key, t)] += 1
    return keep, edge, timing, other, reported


def multiset(c):
    out = collections.Counter()
    for (key, _), n in c.items():
        out[key] += n
    return out


def binom_p(a, b):
    """Two-sided exact binomial test of a against an even split of a+b."""
    n, k = a + b, min(a, b)
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * tail)


g_all, ge, gt, go_other, g_rep = load(go_path)
r_all, re_, rt, rs_other, r_rep = load(rs_path)
g, r = multiset(g_all), multiset(r_all)
g_edge, r_edge = multiset(ge), multiset(re_)
print(f"compared: Go {sum(g.values())}, Rust {sum(r.values())}; timing-dependent (not compared): Go {dict(gt)}, Rust {dict(rt)}")
print(f"not ported, Go only: {dict(sorted(go_other.items()))}")


def explain_conn(key, side_rep, other_rep, is_shadow):
    """Which connection-log rule (2 or 3) makes this one-sided alert expected, or None."""
    a = json.loads(key)
    if not is_conn(a):
        return None
    d = (a["detector_id"], dest(a))
    if len([x for x in side_rep.get(d, []) if not until or x <= until]) > 1:
        return None  # reported twice by the same daemon
    others = other_rep.get(d, [])
    if a.get("severity") == "info" and all(until and x > until for x in others):
        return "one poll only"
    if conn_state_not_copied and is_shadow and since and others and all(x < since for x in others):
        return "learned by Go before the shadow"
    return None


def group(key):
    f = json.loads(key).get("fields", {})
    return ("IPv6" if ":" in f.get("remote_addr", "") else "IPv4", f.get("remote_scope", ""),
            "unnamed owner" if f.get("process") == "unknown" else "named owner")


diff = False
expected = {}
for name, d, other_edge, side_rep, other_rep, shadow in (
        ("only Go", g - r, r_edge, g_rep, r_rep, False), ("only Rust", r - g, g_edge, r_rep, g_rep, True)):
    # an alert at the window's edge on the other side is not a difference
    items = [x for x in sorted(d.elements()) if other_edge[x] == 0]
    why = {x: explain_conn(x, side_rep, other_rep, shadow) for x in set(items)}
    expected[name] = [x for x in items if why[x]]
    real = [x for x in items if not why[x]]
    expected[name + " why"] = collections.Counter(why[x] for x in expected[name])
    if real:
        diff = True
        per = collections.Counter(json.loads(x)["detector_id"] for x in real)
        print(f"{name}: {len(real)} alert(s), by detector {dict(sorted(per.items()))}" + (f" (first {SHOWN} shown)" if len(real) > SHOWN else ""))
    for x in real[:SHOWN]:
        print(name + ":", x[:500])



def one_poll(name, side_rep, other_rep, shadow):
    """Rule 2's alerts of one side by group (connection-watch only: a remote-access tool's connection is in both detectors)."""
    return collections.Counter(group(x) for x in expected[name] if json.loads(x)["detector_id"] == "connection-watch"
                               and explain_conn(x, side_rep, other_rep, shadow) == "one poll only")


# rule 2 holds only while the two daemons miss about equally
og, orr = one_poll("only Go", g_rep, r_rep, False), one_poll("only Rust", r_rep, g_rep, True)
for grp in sorted(set(og) | set(orr)):
    a, b = og[grp], orr[grp]
    p = binom_p(a, b)
    lopsided = p < 0.01
    print(f"connection log, one poll only, {' / '.join(grp)}: Go {a}, Rust {b} (p={p:.3f})" + (" LOPSIDED: a difference" if lopsided else ""))
    diff = diff or lopsided
for name in ("only Go", "only Rust"):
    if expected[name]:
        print(f"{name}, expected (connection log): {dict(sorted(expected[name + ' why'].items()))}")
print("NO DIFFERENCE in the compared detectors" if not diff else "DIFFERENCES above")
sys.exit(1 if diff else 0)
