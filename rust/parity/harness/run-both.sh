#!/bin/bash
# Both side-by-side runs, steady and activity, one after the other (about 11 minutes):
#   rust/parity/harness/run-both.sh OUT_DIR
set -u
here=$(cd "$(dirname "$0")" && pwd)
out=$1
rm -rf "$out/steady" "$out/activity"
mkdir -p "$out"
"$here/side-by-side.sh" steady "$out/steady" >"$out/steady.log" 2>&1
"$here/side-by-side.sh" activity "$out/activity" >"$out/activity.log" 2>&1
cut -c1-300 "$out/steady.log" "$out/activity.log"
