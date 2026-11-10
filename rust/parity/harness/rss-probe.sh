#!/bin/bash
# heimdalld-rs alone on a harness environment (setup-env.py), its resident memory sampled at a few moments:
#   rust/parity/harness/rss-probe.sh ENV_DIR [SECONDS...]
set -u
env=$1; shift
here=$(cd "$(dirname "$0")" && pwd)
bin=${RS_BIN:-$here/../../target/release/heimdalld-rs}
[ -n "${KEEP_STATE:-}" ] || rm -f "$env/rust/agent-sessions.json"  # KEEP_STATE=1: a restart, not a first start
"$bin" run --shadow --config "$env/rust/config.json" >/dev/null 2>&1 &
p=$!
prev=0
for t in "${@:-2 10 65}"; do
	sleep $((t - prev)); prev=$t
	echo "t=${t}s $(grep -E '^(VmRSS|RssAnon|VmHWM)' /proc/$p/status | tr -s ' \t' ' ' | tr '\n' ' ') $(grep -E '^Pss:' /proc/$p/smaps_rollup | tr -s ' ')"
done
kill $p
