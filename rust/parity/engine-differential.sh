#!/bin/sh
# The engine differential: the same synthetic events (gen-events.py) through the Go daemon's detectors and engine
# (rust/gotools/replay) and the Rust port's (heimdalld-rs replay), the alert logs compared with the time dropped, once
# without and once with a maintenance window open. Prints each side's CPU time and peak memory for the run.
#   rust/parity/engine-differential.sh [EVENTS] [SEED]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
events=${1:-200000}
seed=${2:-20261110}
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
"$root/rust/scripts/nicego.sh" build -o "$out/replay-go" ./rust/gotools/replay
"$root/rust/scripts/nicecargo.sh" build --release --offline --quiet
rs="$root/rust/target/release/heimdalld-rs"
python3 -I "$here/gen-events.py" "$events" "$seed" >"$out/events.jsonl"
echo "$(wc -l <"$out/events.jsonl") events, $(du -h "$out/events.jsonl" | cut -f1)"
for mode in closed open; do
	mkdir -p "$out/$mode"
	if [ $mode = open ]; then
		printf '{"reason":"updates","actor":"claude-agent","opened":"2098-12-31T23:00:00Z","until":"2099-01-01T00:00:00Z"}' >"$out/$mode/maintenance.json"
	fi
	printf '{"maintenance_path":"%s","mesh_peers_path":"%s","agent_baseline_state_path":"","baseline_min_samples":20}' \
		"$out/$mode/maintenance.json" "$out/$mode/no-peers.json" >"$out/$mode/config.json"
	python3 -I "$here/measure.py" "$out/$mode/go.jsonl" nice -n 15 "$out/replay-go" --config "$out/$mode/config.json" --approvals "$out/none" <"$out/events.jsonl"
	python3 -I "$here/measure.py" "$out/$mode/rust.jsonl" nice -n 15 "$rs" replay --config "$out/$mode/config.json" --approvals "$out/none" <"$out/events.jsonl"
	echo "maintenance window $mode:"
	python3 -I "$here/compare-alerts.py" "$out/$mode/go.jsonl" "$out/$mode/rust.jsonl"
done
