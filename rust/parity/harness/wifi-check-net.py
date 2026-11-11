#!/usr/bin/env python3
"""The made-up network heimdall-wifi-check is tested on (rust/heimdall/tests/cli_wifitools.rs), run inside a network
namespace of the test's own, never on a real network:

  wifi-check-net.py http CONFIG LOG ADDR PORT [CERT KEY]   web server: answers each request with the raw bytes CONFIG
                                                           gives for HOST+PATH (404 otherwise, "@hang": no answer); the
                                                           request heads are appended to LOG (both programs must send the
                                                           same); with CERT and KEY it speaks TLS
  wifi-check-net.py dns ADDR                               a DNS server that invents an answer (192.0.2.66) for every name
  wifi-check-net.py mcast SRC SECONDS                      another device announcing itself (multicast DNS and UPnP) from SRC
  wifi-check-net.py junk ADDR PORT                         answers every connection with a line of plain text (not TLS)
"""
import json
import socket
import ssl
import struct
import sys
import time


def http(config, log, addr, port, cert=None, key=None):
    with open(config) as f:
        answers = json.load(f)
    fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
    srv = socket.socket(fam, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((addr, int(port)))
    srv.listen(16)
    ctx = None
    if cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
    while True:
        c, _ = srv.accept()
        try:
            c.settimeout(5)
            if ctx:
                c = ctx.wrap_socket(c, server_side=True)
            head = b""
            while b"\r\n\r\n" not in head and len(head) < 65536:
                b = c.recv(4096)
                if not b:
                    break
                head += b
            with open(log, "ab") as f:
                f.write(head.split(b"\r\n\r\n")[0] + b"\n--\n")
            lines = head.decode("latin-1").split("\r\n")
            path = lines[0].split(" ")[1] if len(lines[0].split(" ")) > 1 else ""
            host = next((l.split(":", 1)[1].strip() for l in lines[1:] if l.lower().startswith("host:")), "")
            resp = answers.get(host + path, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            if resp == "@hang":
                time.sleep(20)
            else:
                c.sendall(resp.encode("latin-1"))
        except (OSError, ssl.SSLError, IndexError):
            pass
        finally:
            c.close()


def dns(addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((addr, 53))
    while True:
        q, src = s.recvfrom(512)
        if len(q) < 12:
            continue
        i = 12
        while i < len(q) and q[i]:
            i += q[i] + 1
        qtype = struct.unpack("!H", q[i + 1:i + 3])[0] if i + 3 <= len(q) else 0
        question = q[12:i + 5]
        an = b""
        if qtype == 1:
            an = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("192.0.2.66")
        head = q[:2] + b"\x81\x80" + struct.pack("!HHHH", 1, 1 if an else 0, 0, 0)
        s.sendto(head + question + an, src)


def mcast(src, seconds):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((src, 0))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(src))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    end = time.time() + float(seconds)
    while time.time() < end:
        s.sendto(b"\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00", ("224.0.0.251", 5353))
        s.sendto(b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\r\n", ("239.255.255.250", 1900))
        time.sleep(0.3)


def junk(addr, port):
    fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
    srv = socket.socket(fam, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((addr, int(port)))
    srv.listen(16)
    while True:
        c, _ = srv.accept()
        try:
            c.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        except OSError:
            pass
        c.close()


if __name__ == "__main__":
    mode, args = sys.argv[1], sys.argv[2:]
    {"http": http, "dns": dns, "mcast": mcast, "junk": junk}[mode](*args)
