#!/bin/sh
# The rogue-router watch against the kernel's real IPv6 table, inside a throwaway network namespace (unshare -rn: an
# unprivileged user namespace with its own network, nothing reaches the real one). Two "routers" on a veth pair announce
# themselves; the watcher must report only the second. Needs: go, iproute2, unprivileged user namespaces.
set -e
cd "$(dirname "$0")/../.."
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
go test -c -o "$out/netsource.test" ./internal/sources/netsource
HEIMDALL_NETNS_TEST=1 unshare -rn "$out/netsource.test" -test.run 'TestRogueRouterNetns' -test.v
