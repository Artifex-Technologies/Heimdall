"""Compares a week of the Go daemon's alerts with the shadow daemon's (docs/RUST_SHADOW.md).

    python3 -I shadow-compare.py GO_ALERTS RS_ALERTS [--since RFC3339] [--until RFC3339]

Only alerts raised in the window and by detectors whose sources the Rust port has ported are compared (as multisets, time
dropped; alerts within a minute of either end of the window may be on one side only and are listed apart). Detectors that
learn from the host's own load are timing-dependent (each daemon samples /proc at its own moment) and are counted, not
compared. Exit 0: no difference in the compared detectors.
"""
import collections, json, sys
from datetime import datetime, timedelta

COMPARED = {"injection-phrase", "credential-shape", "invisible-unicode", "permission-escalation", "session-burst", "file-integrity",
            "maintenance-window", "agent-baseline", "limbo-guest", "limbo-network", "limbo-exchange", "tool-rules",
            "network-exposure", "connection-watch", "inbound", "lan-watch", "wifi-safety", "remote-access"}
TIMING = {"resource-pressure", "baseline-drift"}

args = sys.argv[1:]


def opt(name):
    if name in args:
        i = args.index(name)
        v = args[i + 1]
        del args[i:i + 2]
        return datetime.fromisoformat(v.replace("Z", "+00:00"))
    return None


since, until = opt("--since"), opt("--until")
go_path, rs_path = args


def when(a):
    return datetime.fromisoformat(a["time"][:26].rstrip("Z") + "+00:00") if a["time"].endswith("Z") else datetime.fromisoformat(a["time"])


def load(path):
    keep, edge, timing, other = collections.Counter(), collections.Counter(), collections.Counter(), collections.Counter()
    for line in open(path, encoding="utf-8"):
        if not line.strip():
            continue
        a = json.loads(line)
        t = when(a)
        if (since and t < since) or (until and t > until):
            continue
        d = a["detector_id"]
        if d in TIMING:
            timing[d] += 1
            continue
        if d not in COMPARED:
            # integration alerts about the session files are the sources' own; the rest (responder, correlator) is not ported
            if d == "integration" and a.get("fields", {}).get("error_code", "").startswith("agent_session_"):
                pass
            else:
                other[d] += 1
                continue
        a.pop("time")
        key = json.dumps(a, sort_keys=True, ensure_ascii=False)
        near = (since and t < since + timedelta(minutes=1)) or (until and t > until - timedelta(minutes=1))
        (edge if near else keep)[key] += 1
    return keep, edge, timing, other


g, ge, gt, go_other = load(go_path)
r, re_, rt, rs_other = load(rs_path)
print(f"compared: Go {sum(g.values())}, Rust {sum(r.values())}; timing-dependent (not compared): Go {dict(gt)}, Rust {dict(rt)}")
print(f"not ported, Go only: {dict(sorted(go_other.items()))}")
diff = False
for name, d in (("only Go", g - r), ("only Rust", r - g)):
    items = sorted(d.elements())
    if not items:
        continue
    # an alert at the window's edge on the other side is not a difference
    other_edge = re_ if name == "only Go" else ge
    real = [x for x in items if other_edge[x] == 0]
    for x in real[:40]:
        print(name + ":", x[:500])
    diff = diff or bool(real)
print("NO DIFFERENCE in the compared detectors" if not diff else "DIFFERENCES above")
sys.exit(1 if diff else 0)
