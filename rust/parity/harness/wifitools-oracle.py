#!/usr/bin/env python3
"""The Python side of the Wi-Fi helpers' properties (rust/heimdall/tests/wifitools_python.rs): reads one question per line,
{"f": NAME, "a": [ARGS]} (bytes as {"hex": ...}), answers each with {"ok": RESULT} or {"err": EXCEPTION CLASS}, by calling
the shipped programs' own functions (packaging/arch/heimdall-wifi-check, packaging/net/heimdall-wifi-guard, imported as
modules; their tools replaced by the answer given) and Python's own json, re, ipaddress, http.client and urllib.parse.
Nothing is looked up or sent: getaddrinfo is replaced by a table."""
import http.client
import importlib.machinery
import importlib.util
import io
import ipaddress
import json
import os
import re
import socket
import string
import struct
import sys
from urllib.parse import quote, urljoin, urlparse, urlunparse

HERE = os.path.dirname(os.path.abspath(__file__))
PACKAGING = os.path.join(HERE, "..", "..", "..", "packaging")


def module(name, path):
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


check = module("check", os.path.join(PACKAGING, "arch", "heimdall-wifi-check"))
guard = module("guard", os.path.join(PACKAGING, "net", "heimdall-wifi-guard"))

# the only name the tests' WireGuard files may look up; everything else is not found
FAKE_DNS = {"vpn.example": ["2001:db8::7", "203.0.113.7"]}


def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    host.encode("idna")
    if host not in FAKE_DNS:
        raise socket.gaierror(-2, "Name or service not known")
    return [(0, 0, 0, "", (a, int(port))) for a in FAKE_DNS[host]]


socket.getaddrinfo = fake_getaddrinfo


class FakeSock:
    def __init__(self, data):
        self.data = data

    def makefile(self, mode, *a, **k):
        return io.BytesIO(self.data)


def http_view(data):
    r = http.client.HTTPResponse(FakeSock(data), method="GET")
    r.begin()
    loc = r.headers["location"] if "location" in r.headers else r.headers["uri"] if "uri" in r.headers else None
    if 200 <= r.status < 300:
        return [r.status, loc, r.read(4096).hex(), True]
    try:
        r.read()
        ok = True
    except Exception:
        ok = False
    return [r.status, loc, None, ok]


def redirect(base, newurl):
    """urllib's HTTPRedirectHandler.http_error_302, up to the URL it opens next."""
    urlparts = urlparse(newurl)
    if urlparts.scheme not in ("http", "https", "ftp", ""):
        raise ValueError("not allowed")
    if not urlparts.path and urlparts.netloc:
        urlparts = list(urlparts)
        urlparts[2] = "/"
    newurl = urlunparse(urlparts)
    newurl = quote(newurl, encoding="iso-8859-1", safe=string.punctuation)
    return urljoin(base, newurl).replace(" ", "%20")


def text(data):
    return data.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")


def with_run(out, f, *a):
    check.run = lambda argv, timeout=15: out
    return f(*a)


def as_number(t):
    m = re.search(r"\bAS\d+\b", t)
    return m.group(0) if m else None


def endpoint(line):
    m = re.match(r"\s*Endpoint\s*=\s*(\S+)", line, re.I)
    return m.group(1) if m else None


def ip_address(v):
    a = ipaddress.ip_address(v)
    return [a.version, str(a)]


def loopback(s):
    try:
        return ipaddress.ip_address(s).is_loopback
    except ValueError:
        return None


def json_view(s):
    v = json.loads(s)
    return [json.dumps(v), json.dumps(v, indent=1), json.dumps(v, indent=2), repr(v), str(v), bool(v)]


def lines(s):
    return [s.splitlines(), s.strip(), s.split(), "".join(c for c in s if c.isprintable())[:64]]


FUNCS = {
    "split_nmcli": check.split_nmcli,
    "wifi_networks": lambda out: with_run(out, check.wifi_networks),
    "security_class": check.security_class,
    "as_number": as_number,
    "listening_services": lambda out: with_run(out, check.listening_services),
    "origins": lambda out: {k: list(v) for k, v in with_run(out, check.origins, ["x"]).items()},
    "guard_split": lambda line: re.split(r"(?<!\\):", line),
    "endpoint": endpoint,
    "parse_wg": guard.parse_wg,
    "ruleset": guard.ruleset,
    "mac_is_real": guard.mac_is_real,
    "ip_address": ip_address,
    "is_private": lambda s: ipaddress.ip_address(s).is_private,
    "is_loopback": loopback,
    "json": json_view,
    "float_repr": lambda b: repr(struct.unpack("<d", b)[0]),
    "int": lambda s: str(int(s)),
    "text": text,
    "lines": lines,
    "redirect": redirect,
    "http": http_view,
}


def arg(a):
    return bytes.fromhex(a["hex"]) if isinstance(a, dict) and set(a) == {"hex"} else a


for line in sys.stdin:
    q = json.loads(line)
    try:
        out = {"ok": FUNCS[q["f"]](*[arg(a) for a in q["a"]])}
    except Exception as e:  # the class is what is compared
        out = {"err": type(e).__name__}
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()
