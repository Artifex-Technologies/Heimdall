#!/usr/bin/env python3
"""A made-up device of a home network for the `lan scan` test (rust/heimdall/tests/cli_lan.rs), run inside a network
namespace of its own that is joined to the scanning one by a veth pair and a bridge: never on a real network.

  lan-responder.py LOG router IP   answers reverse lookups (PTR) on UDP 53
  lan-responder.py LOG tv IP       answers multicast DNS (services, a friendly name, a model)
  lan-responder.py LOG pc IP       answers NetBIOS node status on UDP 137

Every question received is logged (the role, from which address, the bytes; a DNS id is dropped, being random), one per
line, to LOG.
"""
import select
import socket
import struct
import sys

LOG = open(sys.argv[1], "a", buffering=1)
ROLE, IP = sys.argv[2], sys.argv[3]
GROUP = "224.0.0.251"


def name(n):
    out = b""
    for label in n.rstrip(".").split("."):
        b = label.encode()
        out += bytes([len(b)]) + b
    return out + b"\0"


def rr(n, typ, data, cls=1):
    return name(n) + struct.pack(">HHIH", typ, cls, 120, len(data)) + data


def qname(m, off):
    labels = []
    while m[off]:
        l = m[off]
        labels.append(m[off + 1:off + 1 + l].decode(errors="replace"))
        off += 1 + l
    return ".".join(labels), off + 1


def mdns_answer(round_two):
    recs = [
        rr("_services._dns-sd._udp.local", 12, name("_googlecast._tcp.local")),
        rr("_services._dns-sd._udp.local", 12, name("_madeup._tcp.local")),
        rr("_googlecast._tcp.local", 12, name("Chromecast-0123abcd._googlecast._tcp.local")),
        rr("_airplay._tcp.local", 12, name("Living Room._airplay._tcp.local")),
        rr("Chromecast-0123abcd._googlecast._tcp.local", 16, b"\x0cfn=Living TV\x0dmd=Chromecast\x05ca=12"),
        rr("Chromecast-0123abcd._googlecast._tcp.local", 33, struct.pack(">HHH", 0, 0, 8009) + name("living-tv.local")),
        rr("living-tv.local", 1, socket.inet_aton(IP), cls=0x8001),
    ]
    if round_two:
        recs.append(rr("_madeup._tcp.local", 12, name("Thing._madeup._tcp.local")))
    return struct.pack(">HHHHHH", 0, 0x8400, 0, len(recs), 0, 0) + b"".join(recs)


def nb_answer(q):
    names = [b"DESKTOP-ABC".ljust(15) + b"\x00", b"WORKGROUP".ljust(15) + b"\x00"]
    flags = [0x0400, 0x8400]
    body = bytes([len(names)]) + b"".join(n + struct.pack(">H", f) for n, f in zip(names, flags)) + b"\0" * 46
    return q[:2] + b"\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00" + q[12:12 + 34] + b"\x00\x21\x00\x01\x00\x00\x00\x00" + struct.pack(">H", len(body)) + body


def ptr_answer(q):
    n, off = qname(q, 12)
    host = {"1.2.0.192.in-addr.arpa": "router.lan.", "40.2.0.192.in-addr.arpa": "thermostat-7.lan.", "20.2.0.192.in-addr.arpa": "192-0-2-20.lan."}.get(n)
    if host is None:
        return q[:2] + b"\x81\x83" + q[4:6] + b"\0\0\0\0\0\0" + q[12:off + 4]
    return q[:2] + b"\x81\x80" + q[4:6] + b"\0\x01\0\0\0\0" + q[12:off + 4] + b"\xc0\x0c" + struct.pack(">HHIH", 12, 1, 60, len(name(host))) + name(host)


if ROLE == "tv":
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", 5353))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(GROUP) + socket.inet_aton(IP))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(IP))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
elif ROLE == "router":
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((IP, 53))
else:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((IP, 137))
print("ready", ROLE, file=LOG)
asked = 0
while True:
    ready, _, _ = select.select([s], [], [], 30)
    if not ready:
        break
    m, src = s.recvfrom(9000)
    if ROLE == "tv":
        if src[0] == IP:
            continue
        LOG.write("mdns %s %s\n" % (src[0], m.hex()))
        asked += 1
        s.sendto(mdns_answer(asked > 1), (GROUP, 5353))
    elif ROLE == "router":
        LOG.write("dns %s %s\n" % (src[0], m[2:].hex()))
        s.sendto(ptr_answer(m), src)
    else:
        LOG.write("netbios %s %s\n" % (src[0], m[2:].hex()))
        s.sendto(nb_answer(m), src)
