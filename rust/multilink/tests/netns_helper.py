#!/usr/bin/env python3
"""The test network's servers and clients (tests/netns.sh); standard library only.

  serve ADDR...                  a server on port 80 of each address: "PEER" answers the client's address, "BYTES n" sends n bytes
  peers HOST N                   N connections to HOST, one after another: how many came from each of this computer's addresses
  download HOST CONNS BYTES      CONNS downloads at once of BYTES each: Mbit/s, and the bytes per source address
  bound SRC HOST BYTES           one download from source address SRC
  get FILE KEY                   a value from the status file: state, or LINK.FIELD
"""
import collections
import json
import socket
import socketserver
import sys
import threading
import time


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        line = self.rfile.readline().decode().strip()
        if line == "PEER":
            self.wfile.write((self.client_address[0] + "\n").encode())
        elif line.startswith("BYTES "):
            n = int(line.split()[1])
            chunk = b"x" * 65536
            while n > 0:
                k = min(n, len(chunk))
                self.wfile.write(chunk[:k])
                n -= k


class Server4(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Server6(Server4):
    address_family = socket.AF_INET6


def serve(addrs):
    for a in addrs:
        cls = Server6 if ":" in a else Server4
        s = cls((a, 80), Handler)
        threading.Thread(target=s.serve_forever, daemon=True).start()
    print("ready", flush=True)
    while True:
        time.sleep(3600)


def connect(host, src=None):
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(10)
    if src:
        s.bind((src, 0))
    s.connect((host, 80))
    return s


def peers(host, n):
    c = collections.Counter()
    for _ in range(n):
        try:
            s = connect(host)
            s.sendall(b"PEER\n")
            c[s.makefile().readline().strip()] += 1
            s.close()
        except OSError as e:
            c["error:" + type(e).__name__] += 1
    print(json.dumps(c))


def fetch(host, n, src, out):
    try:
        s = connect(host, src)
        local = s.getsockname()[0]
        s.sendall(b"BYTES %d\n" % n)
        got = 0
        while True:
            b = s.recv(262144)
            if not b:
                break
            got += len(b)
        out.append((local, got))
    except OSError:
        out.append(("error", 0))


def download(host, conns, n):
    out = []
    t0 = time.time()
    ts = [threading.Thread(target=fetch, args=(host, n, None, out)) for _ in range(conns)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    dt = time.time() - t0
    by = collections.Counter()
    for local, got in out:
        by[local] += got
    print(json.dumps({"mbit": round(sum(by.values()) * 8 / dt / 1e6, 1), "seconds": round(dt, 2), "by_source": by}))


def get(path, key):
    try:
        v = json.load(open(path))
    except (OSError, ValueError):
        print("")
        return
    if "." in key:
        link, field = key.split(".", 1)
        v = next((l for l in v["links"] if l["name"] == link), {}).get(field)
    else:
        v = v.get(key)
    print("" if v is None else json.dumps(v) if not isinstance(v, str) else v)


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[0] == "serve":
        serve(a[1:])
    elif a[0] == "peers":
        peers(a[1], int(a[2]))
    elif a[0] == "download":
        download(a[1], int(a[2]), int(a[3]))
    elif a[0] == "bound":
        out = []
        fetch(a[2], int(a[3]), a[1], out)
        print(json.dumps(out))
    elif a[0] == "get":
        get(a[1], a[2])
