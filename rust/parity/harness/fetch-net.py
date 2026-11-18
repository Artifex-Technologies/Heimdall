#!/usr/bin/env python3
"""The made-up internet heimdall-intel-update and heimdall-dns-blocklist are tested on (rust/heimdall/tests/cli_shtools.rs),
run inside a network namespace of the test's own, never on a real network:

  fetch-net.py CONFIG LOG CERTDIR ADDR=CERT...

HTTPS servers on port 443 of each ADDR, each with the certificate CERTDIR/CERT.crt (key CERT.key). A request is answered
with the raw bytes of the file CONFIG names for HOST+PATH ({"HOST/PATH": {"file": PATH, "close": "notify" or "abrupt"}};
404 otherwise), then the connection is closed with TLS's close_notify ("notify") or without it ("abrupt"). Each request's
head is appended to LOG (ADDR, then the head's lines but the User-Agent), so the test can compare what the shell script's
curl and the Rust port asked, and of whom.
"""
import json
import socket
import ssl
import sys
import threading

NOT_FOUND = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


def serve(config, log, lock, addr, ctx):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((addr, 443))
    srv.listen(16)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=answer, args=(config, log, lock, addr, ctx, c), daemon=True).start()


def answer(config, log, lock, addr, ctx, raw):
    c = raw
    try:
        raw.settimeout(10)
        c = ctx.wrap_socket(raw, server_side=True)
        head = b""
        while b"\r\n\r\n" not in head and len(head) < 65536:
            b = c.recv(4096)
            if not b:
                break
            head += b
        lines = head.split(b"\r\n\r\n")[0].decode("latin-1").split("\r\n")
        with lock, open(log, "a", encoding="latin-1") as f:
            f.write(addr + " " + " | ".join(l for l in lines if not l.lower().startswith("user-agent:")) + "\n")
        path = lines[0].split(" ")[1] if len(lines[0].split(" ")) > 1 else ""
        host = next((l.split(":", 1)[1].strip() for l in lines[1:] if l.lower().startswith("host:")), "")
        with open(config) as f:
            answers = json.load(f)
        a = answers.get(host + path)
        if a is None:
            c.sendall(NOT_FOUND)
            close = "notify"
        else:
            with open(a["file"], "rb") as f:
                c.sendall(f.read())
            close = a.get("close", "notify")
        if close == "notify":
            try:
                c = c.unwrap()
            except (OSError, ssl.SSLError, ValueError):
                pass
    except (OSError, ssl.SSLError, IndexError, ValueError):
        pass
    finally:
        try:
            c.close()
        except OSError:
            pass
        try:
            raw.close()
        except OSError:
            pass


def main():
    config, log, certdir = sys.argv[1:4]
    lock = threading.Lock()
    threads = []
    for spec in sys.argv[4:]:
        addr, cert = spec.split("=", 1)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(f"{certdir}/{cert}.crt", f"{certdir}/{cert}.key")
        t = threading.Thread(target=serve, args=(config, log, lock, addr, ctx), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
