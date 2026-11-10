#!/bin/sh
# go at nice 15 from the repository root (the Go side of the parity fixtures and the differential run).
cd "$(dirname "$0")/../.." || exit 2
exec nice -n 15 go "$@"
