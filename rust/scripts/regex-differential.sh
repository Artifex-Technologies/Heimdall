#!/bin/sh
# The full regex differential: the Go detectors' answers on the repository's own files plus 400 made-up hostile texts per
# pattern (about 60,000 texts), then the Rust detectors on the same bytes. Prints the counts; exits non-zero on a difference.
#   rust/scripts/regex-differential.sh [PER]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
HEIMDALL_REGEX_CORPUS="$out/corpus.jsonl" HEIMDALL_REGEX_PER="${1:-400}" HEIMDALL_REGEX_REPO=1 \
	"$here/nicego.sh" test ./internal/detect -run TestExportRegexCorpus -count=1 -v | grep -E 'texts|ok|FAIL'
cd "$root/rust"
HEIMDALL_REGEX_CORPUS="$out/corpus.jsonl" "$here/nicecargo.sh" test --release --offline --test regex_corpus -- --nocapture 2>&1 |
	grep -E 'texts|test result|differences|go |rust '
