#!/bin/bash
# Both side-by-side runs, steady and activity, one after the other (about 11 minutes):
#   rust/parity/harness/run-both.sh OUT_DIR [--network]
# --network: the /proc/net watchers on in both, each run in a network namespace of its own (unshare -rn; made-up addresses).
set -u
here=$(cd "$(dirname "$0")" && pwd)
out=$1; net=${2:-}
rm -rf "$out/steady" "$out/activity"
mkdir -p "$out"
for mode in steady activity; do
	if [ -n "$net" ]; then
		unshare -rn bash "$here/side-by-side.sh" $mode "$out/$mode" --network >"$out/$mode.log" 2>&1
	else
		"$here/side-by-side.sh" $mode "$out/$mode" >"$out/$mode.log" 2>&1
	fi
done
cut -c1-300 "$out/steady.log" "$out/activity.log"
