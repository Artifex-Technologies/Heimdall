#!/bin/bash
# The Go heimdalld and heimdalld-rs side by side on the same synthetic load, then their alert logs compared. A cleaned copy
# of the phase-0 harness (it compared the old and the new Go daemon). Made-up data only; nothing outside OUT_DIR is written.
#
#   rust/parity/harness/side-by-side.sh MODE OUT_DIR [--network]
#     MODE steady: nothing happens; activity: the planted events of loadgen.py.
#     --network: the /proc/net watchers too, inside a network namespace of its own (run the script under `unshare -rn`;
#     made-up addresses only), with 40 MB of made-up IP databases.
#   AUDITS=1: the 6-hourly audits too (made-up tracker, pacman database and kernel list; see setup-env.py).
#   GO_BIN, RS_BIN: the two daemons (default: built from this checkout). WARM, WINDOW: seconds (45, 240).
# Measured over WINDOW after WARM: CPU (own + children), context switches of all threads, PSS, RSS.
set -u
mode=$1; out=$2; net=${3:-}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
env=$out/env
mkdir -p "$out"
if [ -n "$net" ]; then
	ip link set lo up
	ip link add d0 type dummy
	ip addr add 203.0.113.1/24 dev d0
	ip addr add 198.51.100.1/24 dev d0
	ip link set d0 up
fi
GO_BIN=${GO_BIN:-$out/heimdalld}
RS_BIN=${RS_BIN:-$root/rust/target/release/heimdalld-rs}
[ -x "$GO_BIN" ] || (cd "$root" && nice -n 15 go build -o "$GO_BIN" ./cmd/heimdalld)
[ -x "$RS_BIN" ] || "$root/rust/scripts/nicecargo.sh" build --release --offline --quiet
python3 -I "$here/setup-env.py" "$env" $net ${AUDITS:+--audits} >/dev/null
if [ -n "$net" ]; then # 40 MB of made-up IP databases, as in phase 0 (mapped, not read into the heap)
	mkdir -p "$env/ipdb"
	(cd "$here/genmmdb" && nice -n 15 go run . country "$env/ipdb/dbip-country-lite.mmdb" 20 && nice -n 15 go run . asn "$env/ipdb/dbip-asn-lite.mmdb" 20) >/dev/null
fi

start=$(date +%s)
python3 -I "$here/loadgen.py" "$mode" "$env" $((start + 3)) $net &
lg=$!
while [[ ! -e $env/loadgen.ready ]]; do sleep 0.1; done
sleep 1
nice -n 15 "$GO_BIN" run --config "$env/go/config.json" >"$env/go/stdout.log" 2>"$env/go/stderr.log" &
pg=$!
nice -n 15 "$RS_BIN" run --shadow --config "$env/rust/config.json" >"$env/rust/stdout.log" 2>"$env/rust/stderr.log" &
pr=$!

cpu() { awk '{print $14+$15, $16+$17}' /proc/$1/stat; }
ns() { cat /proc/$1/task/*/schedstat 2>/dev/null | awk '{s+=$1} END{print s}'; }
sw() { cat /proc/$1/task/*/status 2>/dev/null | awk '/^voluntary_ctxt_switches|^nonvoluntary_ctxt_switches/{s+=$2} END{print s}'; }
sleep "${WARM:-45}"
declare -A A0 B0 N0 W0
for p in $pg $pr; do read -r a b < <(cpu $p); A0[$p]=$a; B0[$p]=$b; N0[$p]=$(ns $p); W0[$p]=$(sw $p); done
sleep "${WINDOW:-240}"
hz=$(getconf CLK_TCK)
{
	echo "mode $mode${net:+ (network)}, window ${WINDOW:-240} s after ${WARM:-45} s warm-up, daemons at nice 15, $(nproc) CPUs"
	for x in "go $pg" "rust $pr"; do
		set -- $x
		read -r a b < <(cpu $2)
		n=$(ns $2); w=$(sw $2)
		awk -v name=$1 -v a=$((a - ${A0[$2]})) -v b=$((b - ${B0[$2]})) -v n=$((n - ${N0[$2]})) -v w=$((w - ${W0[$2]})) -v hz=$hz -v win=${WINDOW:-240} 'BEGIN {
      printf "%s: CPU %.3f %% of a core (threads %.1f ms; children %d ticks), %d context switches = %.2f/s\n", name, (a + b) / hz / win * 100, n / 1e6, b, w, w / win }'
		grep -E '^(Pss|Pss_Anon|Pss_File):' /proc/$2/smaps_rollup | awk -v name=$1 '{printf "%s %s %s kB  ", name, $1, $2} END{print ""}'
		echo "$1 since start: CPU $(awk "{print \$14+\$15}" /proc/$2/stat) ticks"
		grep -E '^(VmRSS|RssAnon|RssFile|VmHWM|Threads):' /proc/$2/status | tr -s ' \t' ' ' | tr '\n' ' ' | sed "s/^/$1 /"
		echo
	done
} >"$out/results.txt"
kill $pg $pr $lg 2>/dev/null
wait $pg $pr 2>/dev/null
cat "$out/results.txt"
python3 -I "$here/../compare-alerts.py" "$env/go/alerts.jsonl" "$env/rust/alerts.jsonl"
