"""Compares two alert logs (one JSON object per line), as multisets, after normalising: the time each alert was raised is
dropped (the daemons notice an event at slightly different moments); everything else must be equal. A cleaned copy of the
phase-0 comparison, for any two logs.

    python3 -I compare-alerts.py A.jsonl B.jsonl [--ignore-detector ID]...

Exit 0: identical after normalising; 1: they differ (the differences are printed, at most 40 each way).
"""
import collections, json, sys

args = sys.argv[1:]
ignore = set()
while "--ignore-detector" in args:
    i = args.index("--ignore-detector")
    ignore.add(args[i + 1])
    del args[i:i + 2]
a_path, b_path = args


def load(path):
    out = collections.Counter()
    with open(path, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            a = json.loads(line)
            if a.get("detector_id") in ignore:
                continue
            a.pop("time", None)
            out[json.dumps(a, sort_keys=True, ensure_ascii=False)] += 1
    return out


a, b = load(a_path), load(b_path)
by = collections.Counter(json.loads(x)["detector_id"] for x in a.elements())
print(f"{a_path}: {sum(a.values())} alerts; {b_path}: {sum(b.values())} alerts")
print("by detector:", dict(sorted(by.items())))
if a == b:
    print("IDENTICAL after normalising (time dropped)")
    sys.exit(0)
for name, d in (("only in " + a_path, a - b), ("only in " + b_path, b - a)):
    items = sorted(d.elements())
    for x in items[:40]:
        print(name + ":", x[:600])
    if len(items) > 40:
        print(f"... and {len(items) - 40} more {name}")
sys.exit(1)
