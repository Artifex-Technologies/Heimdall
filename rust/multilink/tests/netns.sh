#!/bin/sh
# The whole service in a made-up network, inside a user + network + mount namespace of its own (tests/netns.rs runs it as
# `unshare -rnm sh tests/netns.sh BIN HELPER DIR`): nothing here can reach the computer's real network, routes or sysctls.
#
#   this namespace ("the computer")  p1 10.1.0.2 / 2001:db8:1::2 --- isp1 --- net (the internet: 198.51.100.1, 2001:db8:100::1)
#                                    p2 10.2.0.2 / 2001:db8:2::2 --- isp2 ---/
#
# The main table has a default route per link, as NetworkManager makes them (p1 metric 100, p2 metric 200). isp1 is shaped
# to 40 Mbit/s towards the computer and isp2 to 10, when tc can (sch_tbf).
set -eu
BIN=$1 HELP=$2 W=$3
RUN=$W/run STATE=$W/state CFG=$W/multilink.json
mkdir -p "$RUN" "$STATE"
pass=0
ok() { pass=$((pass + 1)); echo "ok   $*"; }
fail() { echo "FAIL $*"; echo "--- service log"; cat "$W/service.log" 2>/dev/null; ip rule; ip route show table all | grep -v local; exit 1; }
st() { python3 "$HELP" get "$RUN/status.json" "$1"; }
# wait up to $1 seconds for the command in the rest to succeed
until_ok() { t=$1; shift; i=0; while [ $i -lt $((t * 10)) ]; do if "$@" >/dev/null 2>&1; then return 0; fi; sleep 0.1; i=$((i + 1)); done; return 1; }
is() { [ "$(st "$1")" = "$2" ]; }
spread_hops() { ip -j route show table 7700000 | python3 -c 'import json,sys; r=json.load(sys.stdin); print(len(r[0].get("nexthops",[1])) if r else 0)'; }
# isp1 loses its way to the internet (its link to us stays up, as when a provider has an outage), and gets it back
isp1_cut() { ip netns exec isp1 sh -c 'ip route del default; ip -6 route del default'; }
isp1_back() { ip netns exec isp1 sh -c 'ip route replace default via 10.91.0.2; ip -6 route replace default via 2001:db8:91::2'; }
weight() { ip -j route show table 7700000 | python3 -c "import json,sys; r=json.load(sys.stdin); print(next((h['weight'] for h in r[0].get('nexthops',[]) if h['dev']=='$1'),0) if r else 0)"; }
hops_are() { [ "$(spread_hops)" = "$1" ]; }
ours() { { ip rule; ip -6 rule; ip route show table all proto 199; ip -6 route show table all proto 199; } | grep -c ' 199' || true; }
none_of_ours() { [ "$(ours)" = 0 ]; }

# --- the made-up network
mount -t tmpfs none /run
mkdir -p /run/netns
ip link set lo up
for n in isp1 isp2 net; do ip netns add $n; ip netns exec $n ip link set lo up; done
ip link add p1 type veth peer name i1 netns isp1
ip link add p2 type veth peer name i2 netns isp2
ip netns exec isp1 ip link add u1 type veth peer name n1 netns net
ip netns exec isp2 ip link add u2 type veth peer name n2 netns net
ip link set p1 up; ip link set p2 up
ip addr add 10.1.0.2/24 dev p1; ip addr add 10.2.0.2/24 dev p2
ip addr add 2001:db8:1::2/64 dev p1 nodad; ip addr add 2001:db8:2::2/64 dev p2 nodad
for k in 1 2; do
  ip netns exec isp$k sh -e -c "
    ip link set i$k up; ip link set u$k up
    ip addr add 10.$k.0.1/24 dev i$k; ip addr add 10.9$k.0.1/30 dev u$k
    ip addr add 2001:db8:$k::1/64 dev i$k nodad; ip addr add 2001:db8:9$k::1/64 dev u$k nodad
    ip route add default via 10.9$k.0.2; ip -6 route add default via 2001:db8:9$k::2
    echo 1 > /proc/sys/net/ipv4/ip_forward; echo 1 > /proc/sys/net/ipv6/conf/all/forwarding"
  ip netns exec net sh -e -c "
    ip link set n$k up; ip addr add 10.9$k.0.2/30 dev n$k; ip addr add 2001:db8:9$k::2/64 dev n$k nodad
    ip route add 10.$k.0.0/24 via 10.9$k.0.1; ip -6 route add 2001:db8:$k::/64 via 2001:db8:9$k::1"
done
ip netns exec net ip addr add 198.51.100.1/32 dev lo
ip netns exec net ip addr add 2001:db8:100::1/128 dev lo
ip route add default via 10.1.0.1 dev p1 metric 100
ip route add default via 10.2.0.1 dev p2 metric 200
ip -6 route add default via 2001:db8:1::1 dev p1 metric 100
ip -6 route add default via 2001:db8:2::1 dev p2 metric 200
shaped=no
if ip netns exec isp1 tc qdisc add dev i1 root tbf rate 40mbit burst 64k latency 100ms 2>/dev/null &&
   ip netns exec isp2 tc qdisc add dev i2 root tbf rate 10mbit burst 32k latency 100ms 2>/dev/null; then shaped=yes; fi
ip netns exec net python3 "$HELP" serve 198.51.100.1 2001:db8:100::1 >"$W/server.log" 2>&1 &
until_ok 10 grep -q ready "$W/server.log" || fail "the test server did not start"
python3 "$HELP" peers 198.51.100.1 1 | grep -q '10.1.0.2' || fail "the made-up internet is not reachable"

main_before=$(ip route show table main; ip -6 route show table main)
rules_before=$(ip rule; ip -6 rule)
hash_before=$(cat /proc/sys/net/ipv4/fib_multipath_hash_policy)
echo 0 > /proc/sys/net/ipv4/fib_multipath_hash_policy
echo 0 > /proc/sys/net/ipv6/fib_multipath_hash_policy

cat >"$CFG" <<EOF
{"new_links": "use", "links": {}, "probe4": ["198.51.100.1:80"], "probe6": ["[2001:db8:100::1]:80"], "probe_every_ms": 500}
EOF
start() {
  "$BIN" run --config "$CFG" --run-dir "$RUN" --state-dir "$STATE" --no-nm >>"$W/service.log" 2>&1 &
  SVC=$!
}
start

# --- 1. both links found, checked and in the multipath route; the kernel settings set
until_ok 15 is state active || fail "1: not active: $(st state) $(st reason)"
until_ok 15 hops_are 2 || fail "1: the IPv4 multipath route has not got both links"
until_ok 10 sh -c '[ "$(ip -j -6 route show table 7700000 | grep -c nexthops)" = 1 ]' || fail "1: no IPv6 multipath route"
[ "$(cat /proc/sys/net/ipv4/fib_multipath_hash_policy)" = 1 ] || fail "1: hash policy not set"
ip rule | grep -q 'iif lo lookup 7700000 proto 199' || ip rule | grep -q 'fwmark 0 iif lo lookup 7700000' || fail "1: no spreading rule"
ok "1: both links checked and in the multipath route (IPv4 and IPv6), L4 hashing on"

# --- 2. new connections are spread, even to one server
p=$(python3 "$HELP" peers 198.51.100.1 60)
echo "     60 connections to one IPv4 server: $p"
echo "$p" | grep -q '"10.1.0.2"' && echo "$p" | grep -q '"10.2.0.2"' || fail "2: IPv4 connections not spread: $p"
echo "$p" | grep -q error && fail "2: connections failed: $p"
p6=$(python3 "$HELP" peers 2001:db8:100::1 60)
echo "     60 connections to one IPv6 server: $p6"
echo "$p6" | grep -q '2001:db8:1::2' && echo "$p6" | grep -q '2001:db8:2::2' || fail "2: IPv6 connections not spread: $p6"
ok "2: new connections spread over both links, IPv4 and IPv6, to the same server"

# --- 3. weights follow what each link carried (shaped 40 and 10 Mbit/s)
if [ $shaped = yes ]; then
  cpu0=$(awk '{print $14+$15+$16+$17}' /proc/$SVC/stat); t0=$(date +%s.%N)
  for round in 1 2 3; do python3 "$HELP" download 198.51.100.1 16 2500000 >"$W/dl$round.json"; done
  cpu1=$(awk '{print $14+$15+$16+$17}' /proc/$SVC/stat); t1=$(date +%s.%N)
  echo "     downloads: $(cat "$W/dl3.json")"
  echo "     service CPU while downloading: $(python3 -c "print(round(($cpu1-$cpu0)/$(getconf CLK_TCK)/($t1-$t0)*100,2))") % of one core over $(python3 -c "print(round($t1-$t0,1))") s"
  w1=$(weight p1) w2=$(weight p2)
  until_ok 10 sh -c "[ \$(ip -j route show table 7700000 | python3 -c \"import json,sys; h={x['dev']:x['weight'] for x in json.load(sys.stdin)[0]['nexthops']}; print(int(h['p1'] >= 2*h['p2']))\") = 1 ]" ||
    fail "3: weights did not follow the speeds: p1 $w1 p2 $w2 (peaks $(st p1.peak) $(st p2.peak))"
  echo "     weights now: p1 $(weight p1), p2 $(weight p2); learned peaks $(st p1.peak) and $(st p2.peak) bytes/s"
  ok "3: the faster link gets the bigger share"
else
  echo "skip 3: tc cannot shape here (no sch_tbf)"
fi

# --- 4. a link whose internet is gone drops out in seconds and comes back when it works
isp1_cut
t0=$(date +%s.%N)
until_ok 15 sh -c '[ "$(ip -j route show table 7700000 | grep -c nexthops)" = 0 ] && ip route show table 7700000 | grep -q "dev p2"' ||
  fail "4: p1 still in the route after its internet went"
echo "     p1 out after $(python3 -c "print(round($(date +%s.%N)-$t0,1))") s"
p=$(python3 "$HELP" peers 198.51.100.1 20)
[ "$p" = '{"10.2.0.2": 20}' ] || fail "4: new connections did not all take p2: $p"
isp1_back
until_ok 15 hops_are 2 || fail "4: p1 did not come back"
until_ok 15 sh -c '[ "$(ip -j -6 route show table 7700000 | grep -c nexthops)" = 1 ]' || fail "4: p1 did not come back for IPv6"
ok "4: failover: a dead link out in seconds, back when healthy"

# --- 5. backup only, a share limit, and a data cap
python3 - "$CFG" <<'EOF'
import json, sys
c = json.load(open(sys.argv[1])); c["links"] = {"p2": {"role": "backup"}}; json.dump(c, open(sys.argv[1] + ".new", "w"))
EOF
mv "$CFG.new" "$CFG"
until_ok 10 hops_are 1 || fail "5: a backup link is still in the route"
ip route show table 7700000 | grep -q 'dev p1' || fail "5: p1 not alone in the route"
isp1_cut
until_ok 15 sh -c 'ip route show table 7700000 | grep -q "dev p2"' || fail "5: the backup did not step in"
isp1_back
until_ok 15 sh -c 'ip route show table 7700000 | grep -q "dev p1"' || fail "5: p1 did not return"
ok "5a: backup only: used only while the other link has no internet"
python3 - "$CFG" <<'EOF'
import json, sys
c = json.load(open(sys.argv[1])); c["links"] = {"p1": {"role": "use", "share": 20}}; json.dump(c, open(sys.argv[1] + ".new", "w"))
EOF
mv "$CFG.new" "$CFG"
until_ok 10 sh -c '[ "$(ip -j route show table 7700000 | python3 -c "import json,sys; h={x[\"dev\"]:x[\"weight\"] for x in json.load(sys.stdin)[0][\"nexthops\"]}; print(h[\"p1\"])")" -le 21 ]' ||
  fail "5: the share limit is not kept: p1 $(weight p1)"
ok "5b: a share limit: p1 at most 20 % ($(weight p1) of 100)"
python3 - "$CFG" <<'EOF'
import json, sys
c = json.load(open(sys.argv[1])); c["links"] = {"p2": {"role": "use", "data_cap_mb": 1, "period": "day"}}; json.dump(c, open(sys.argv[1] + ".new", "w"))
EOF
mv "$CFG.new" "$CFG"
until_ok 10 hops_are 2 || fail "5: both links should be in before the cap"
python3 "$HELP" bound 10.2.0.2 198.51.100.1 3000000 >/dev/null
until_ok 10 is p2.over_cap true || fail "5: p2 not over its cap after 3 MB: used $(st p2.used_bytes)"
until_ok 10 hops_are 1 || fail "5: p2 still in the route past its cap"
ok "5c: a data cap: past 1 MB a day p2 is kept for backup ($(st p2.used_bytes) bytes counted)"
cat >"$CFG" <<EOF
{"new_links": "use", "links": {}, "probe4": ["198.51.100.1:80"], "probe6": ["[2001:db8:100::1]:80"], "probe_every_ms": 500}
EOF
rm -f "$STATE/usage.json"

# --- 6. a VPN pauses it: nothing of ours is left while it is on
until_ok 10 hops_are 2 || fail "6: not back to both links"
ip tuntap add mode tun name vpn0
ip link set vpn0 up
ip addr add 10.8.0.2/24 dev vpn0
ip route add 0.0.0.0/1 dev vpn0
ip route add 128.0.0.0/1 dev vpn0
until_ok 10 is state paused || fail "6: not paused with a VPN on"
until_ok 5 none_of_ours ||
  fail "6: rules or routes of ours left while paused"
echo "     $(st reason)"
ip link del vpn0
until_ok 10 is state active || fail "6: not active again after the VPN went"
ok "6: a VPN pauses it with a reason, and it resumes after"

# --- 7. stopping it restores exactly the routing from before
until_ok 10 hops_are 2 || fail "7: not back to both links"
kill -TERM $SVC; wait $SVC || true
[ "$(ip route show table main; ip -6 route show table main)" = "$main_before" ] || fail "7: the main table changed"
[ "$(ip rule; ip -6 rule)" = "$rules_before" ] || fail "7: rules left after stop: $(ip rule)"
[ "$(ip route show table all proto 199; ip -6 route show table all proto 199)" = "" ] || fail "7: routes left after stop"
[ "$(cat /proc/sys/net/ipv4/fib_multipath_hash_policy)" = 0 ] || fail "7: the hash policy was not put back"
[ ! -e "$RUN/status.json" ] || fail "7: status file left"
p=$(python3 "$HELP" peers 198.51.100.1 10)
[ "$p" = '{"10.1.0.2": 10}' ] || fail "7: after stop, connections do not take NetworkManager's default: $p"
ok "7: stop: rules, routes, sysctls and status as before; the main table never changed"

# --- 8. a crash (SIGKILL) leaves routing in place until restore (systemd's ExecStopPost), which cleans it
start
until_ok 15 hops_are 2 || fail "8: not active again"
kill -KILL $SVC; wait $SVC 2>/dev/null || true
[ "$(ip route show table all proto 199 | wc -l)" -gt 0 ] || fail "8: expected leftovers after SIGKILL"
"$BIN" restore --run-dir "$RUN" --state-dir "$STATE" --config "$CFG"
[ "$(ip rule; ip -6 rule)" = "$rules_before" ] || fail "8: restore left rules"
[ "$(ip route show table all proto 199; ip -6 route show table all proto 199)" = "" ] || fail "8: restore left routes"
[ "$(cat /proc/sys/net/ipv4/fib_multipath_hash_policy)" = 0 ] || fail "8: restore did not put the hash policy back"
ok "8: after a crash, restore puts everything back"

# --- 9. one link off: the feature waits and touches nothing
cat >"$CFG" <<EOF
{"new_links": "use", "links": {"p2": {"role": "off"}}, "probe4": ["198.51.100.1:80"], "probe_every_ms": 500}
EOF
start
until_ok 10 is state waiting || fail "9: not waiting with one link"
[ "$(ip rule; ip -6 rule)" = "$rules_before" ] || fail "9: rules added with one link"
kill -TERM $SVC; wait $SVC || true
ok "9: with one link left there is nothing to spread and nothing is changed"

echo "all $pass passed"
