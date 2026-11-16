"""heimdall-wifi-check's readers of NetworkManager's answers and its idea of a trusted network, without running a check (the
whole program runs against its Rust port on made-up networks in rust/heimdall/tests/cli_wifitools.rs)."""
import importlib.machinery
import importlib.util
import json
import os
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "arch", "heimdall-wifi-check")


def load():
    loader = importlib.machinery.SourceFileLoader("check", SCRIPT)
    spec = importlib.util.spec_from_loader("check", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


class Check(unittest.TestCase):
    def setUp(self):
        self.m = load()

    def test_nmcli_fields_are_read_left_to_right(self):
        split = self.m.split_nmcli
        self.assertEqual(split(r"yes:Cafe:00\:00\:5E\:00\:53\:21:WPA2"), ["yes", "Cafe", "00:00:5E:00:53:21", "WPA2"])
        # a name ending in a backslash: nmcli writes "x\\" before the separator; it must not swallow the next field
        self.assertEqual(split(r"yes:x\\:00\:00:WPA2"), ["yes", "x\\", "00:00", "WPA2"])
        self.assertEqual(split(r"no:a\\\:b:c:d"), ["no", "a\\:b", "c", "d"])
        self.assertEqual(split("a\\b:c\\"), ["a\\b", "c\\"])

    def test_a_network_named_with_a_trailing_backslash_is_checked(self):
        nets = []
        self.m.run = lambda argv, timeout=15: "yes:Free\\\\:00\\:00\\:5E\\:00\\:53\\:31:--\n"
        nets = self.m.wifi_networks()
        self.assertEqual(nets, [{"active": True, "ssid": "Free\\", "bssid": "00:00:5E:00:53:31", "security": "--"}])

    def test_home_needs_the_remembered_router(self):
        level = self.m.level_of
        home = {"ssid": "Example-Home", "level": "home", "key_mgmt": "wpa-psk", "routers": ["00:00:5E:00:53:01"]}
        self.assertEqual(level(home, "Example-Home", "wpa-psk", "00:00:5E:00:53:01"), "home")
        self.assertEqual(level(home, "Example-Home", "wpa-psk", ""), "trusted")  # silent to ARP: not home, still known by its password
        self.assertEqual(level(home, "Example-Home", "wpa-psk", "00:00:5E:00:53:09"), "trusted")
        self.assertEqual(level(None, "Example-Home", "wpa-psk", "00:00:5E:00:53:01"), "untrusted")

    def test_legacy_entry_is_home(self):
        legacy = {"ssid": "Example-Home", "routers": ["00:00:5E:00:53:01"]}
        self.assertEqual(self.m.level_of(legacy, "Example-Home", "", "00:00:5E:00:53:01"), "home")  # as before the levels
        self.assertEqual(self.m.level_of(legacy, "Example-Home", "", "00:00:5E:00:53:09"), "untrusted")

    def test_trusted_survives_a_new_router_address(self):
        e = {"ssid": "Example-Phone", "level": "trusted", "key_mgmt": "sae", "routers": []}
        for mac in ("", "02:00:00:00:00:01", "0A:00:00:00:00:02"):
            self.assertEqual(self.m.level_of(e, "Example-Phone", "sae", mac), "trusted")
        self.m.gateway = lambda: ("192.0.2.1", "wlan0")
        me = {"ssid": "Example-Phone", "bssid": "02:00:00:00:00:AA"}

        def run(hotspot, macs):
            r, known = self.m.Report(), {}
            for mac in macs:
                self.m.neighbours = lambda dev, mac=mac: [{"dst": "192.0.2.1", "lladdr": mac}]
                self.m.check_gateway(r, me, known, hotspot)
            return r
        # trusted (as trusted, not home), and the new address one a hotspot makes up: expected
        r = run(lambda m: True, ("02:00:00:00:00:01", "0A:00:00:00:00:02"))
        self.assertEqual([c["status"] for c in r.checks], ["ok", "ok"])
        self.assertIn("recognized by its password", r.checks[1]["detail"])
        # anywhere else (untrusted, home or an entry from before the levels, or a factory address): still a warning
        r = run(lambda m: False, ("02:00:00:00:00:01", "06:00:00:00:00:03"))
        self.assertEqual(r.checks[1]["status"], "warn")
        self.assertIn("phone hotspots change it", r.checks[1]["detail"])

    def test_only_a_trusted_hotspot_may_change_its_router(self):
        self.m.TRUSTED = os.path.join(tempfile.mkdtemp(), "trusted.json")
        self.m.GUARD_STATE = os.path.join(tempfile.mkdtemp(), "state.json")
        seen = []
        self.m.check_gateway = lambda r, me, known, hotspot: seen.append(hotspot) or ("wlan0", "")
        entries = {"aaaa": {"ssid": "Example-Phone", "level": "trusted", "key_mgmt": "wpa-psk", "routers": []},
                   "bbbb": {"ssid": "Example-Phone", "level": "home", "key_mgmt": "wpa-psk", "routers": ["00:00:5E:00:53:01"]},
                   "cccc": {"ssid": "Example-Phone", "routers": ["00:00:5E:00:53:01"]}}
        with open(self.m.TRUSTED, "w") as f:
            json.dump(entries, f)
        self.m.check_radio = lambda r: {"ssid": "Example-Phone", "bssid": "02:00:00:00:00:AA", "security": "WPA2"}
        self.m.connectivity = lambda: "none"
        self.m.profile = lambda uuid: ("Example-Phone", "wpa-psk")
        self.m.check_neighbourhood = lambda *a: 0
        self.m.gateway = lambda: (None, None)
        self.m.print = lambda *a, **k: None
        self.m.STATE = tempfile.mkdtemp()
        self.m.PUBLIC = os.path.join(self.m.STATE, "last.json")
        for u in ("aaaa", "bbbb", "cccc", "dddd"):
            self.m.sys.argv = ["heimdall-wifi-check", "--uuid", u]
            self.m.main()
        hs = dict(zip(("t", "h", "l", "x"), seen))
        self.assertTrue(hs["t"]("06:00:00:00:00:02"), "a trusted hotspot's made-up address")
        self.assertFalse(hs["t"]("00:00:5E:00:53:09"), "a factory address on a trusted network: still a warning")
        for u in ("h", "l", "x"):
            self.assertFalse(hs[u]("06:00:00:00:00:02"), u)
        mode = os.stat(os.path.join(self.m.STATE, "results.jsonl")).st_mode & 0o777
        self.assertEqual(mode, 0o640)

    def test_an_owe_copy_is_an_evil_twin(self):
        self.m.run = lambda argv, timeout=15: "yes:Cafe:00\\:00\\:5E\\:00\\:53\\:21:WPA2\nno:Cafe:00\\:00\\:5E\\:00\\:53\\:22:OWE\n"
        r = self.m.Report()
        self.m.check_radio(r)
        self.assertEqual([c["status"] for c in r.checks], ["ok", "bad"])
        self.assertEqual(self.m.security_class("OWE"), "owe")

    def test_a_hotspot_whose_password_changed_gets_no_exception(self):
        self.m.TRUSTED = os.path.join(tempfile.mkdtemp(), "trusted.json")
        self.m.GUARD_STATE = os.path.join(tempfile.mkdtemp(), "state.json")
        with open(self.m.TRUSTED, "w") as f:
            json.dump({"aaaa": {"ssid": "Example-Phone", "level": "trusted", "key_mgmt": "wpa-psk", "routers": []}}, f)
        seen = []
        self.m.check_gateway = lambda r, me, known, hotspot: seen.append(hotspot) or ("wlan0", "")
        self.m.check_radio = lambda r: {"ssid": "Example-Phone", "bssid": "02:00:00:00:00:AA", "security": "WPA2"}
        self.m.connectivity = lambda: "none"
        self.m.profile = lambda uuid: ("Example-Phone", "wpa-psk")
        self.m.check_neighbourhood = lambda *a: 0
        self.m.gateway = lambda: (None, None)
        self.m.print = lambda *a, **k: None
        self.m.STATE = tempfile.mkdtemp()
        self.m.PUBLIC = os.path.join(self.m.STATE, "last.json")
        self.m.sys.argv = ["heimdall-wifi-check", "--uuid", "aaaa"]
        for level in ("trusted", "untrusted"):
            with open(self.m.GUARD_STATE, "w") as f:
                json.dump({"wifi": "aaaa", "level": level}, f)
            self.m.main()
        self.assertTrue(seen[0]("06:00:00:00:00:02"))
        self.assertFalse(seen[1]("06:00:00:00:00:02"), "the guard found its saved password changed")

    def test_a_check_out_of_time_writes_what_it_found(self):
        self.m.check_radio = lambda r: r.add("encryption", "ok", "x") or {"ssid": "Example-Phone", "bssid": "02:00:00:00:00:AA", "security": "WPA2"}

        def slow():
            raise self.m.OutOfTime()  # as the alarm does, at LIMIT seconds
        self.m.connectivity = slow
        self.m.print = lambda *a, **k: None
        self.m.STATE = tempfile.mkdtemp()
        self.m.PUBLIC = os.path.join(self.m.STATE, "last.json")
        self.m.sys.argv = ["heimdall-wifi-check"]
        self.assertEqual(self.m.main(), 0)
        with open(os.path.join(self.m.STATE, "results.jsonl")) as f:
            res = json.loads(f.readline())
        self.assertEqual((res["verdict"], res["connectivity"], [c["check"] for c in res["checks"]]), ("caution", "unknown", ["encryption", "finish"]))
        self.assertIn("could not finish within 240 seconds", res["checks"][1]["detail"])
        with open(self.m.PUBLIC) as f:
            self.assertIn("could not finish", json.load(f)["reasons"][0])
        for v, want in (("30", 30), ("", 240), ("x", 240), ("0", 240), ("999999", 240), ("٣", 240)):
            os.environ["HEIMDALL_WIFI_CHECK_LIMIT"] = v
            self.assertEqual(self.m.limit(), want, v)
        del os.environ["HEIMDALL_WIFI_CHECK_LIMIT"]

    def test_discoverable_is_covered_and_said(self):
        r, _, g = self.listen({"192.0.2.5"}, {"firewall": True, "not_announcing": False, "discoverable": True, "own_address": True})
        self.assertEqual(r.checks[0]["status"], "covered")
        self.assertIn("what it announces (you made it discoverable here)", r.checks[0]["detail"])
        self.assertIn("you made it discoverable here", self.m.exposure(r, {"ssid": "Example-Phone"}, g))

    def test_trusted_refuses_open_owe_wep(self):
        e = {"ssid": "Example-Phone", "level": "trusted", "key_mgmt": "wpa-psk", "routers": []}
        for key in ("", "owe", "none", "ieee8021x", "wpa-eap"):
            self.assertEqual(self.m.level_of(e, "Example-Phone", key, "02:00:00:00:00:01"), "untrusted", key)

    def test_trusted_name_with_weaker_lock_is_bad(self):
        trusted = {"phone-uuid": {"ssid": "Example-Phone", "level": "trusted", "key_mgmt": "sae", "routers": []}}
        me = {"ssid": "Example-Phone"}
        for uuid, key in (("other-uuid", ""), ("other-uuid", "owe"), ("other-uuid", "wpa-psk")):
            r = self.m.Report()
            self.m.check_trusted_name(r, me, uuid, key, trusted)
            self.assertEqual([c["status"] for c in r.checks], ["bad"], (uuid, key))
        r = self.m.Report()
        self.m.check_trusted_name(r, me, "phone-uuid", "wpa-psk", trusted)  # the trusted profile itself made weaker
        self.assertEqual([c["status"] for c in r.checks], ["warn"])
        for uuid, key in (("phone-uuid", "sae"), ("other-uuid", "sae")):
            r = self.m.Report()
            self.m.check_trusted_name(r, me, uuid, key, trusted)
            self.assertEqual(r.checks, [], (uuid, key))
        r = self.m.Report()
        self.m.check_trusted_name(r, {"ssid": "Elsewhere"}, "x", "", trusted)
        self.assertEqual(r.checks, [])

    def listen(self, heard, protections):
        self.m.listen_for_devices = lambda seconds=8: set(heard)
        self.m.neighbours = lambda dev: [{"dst": "192.0.2.1", "lladdr": "02:00:00:00:00:01"}, {"dst": "192.0.2.9", "lladdr": "02:00:00:00:00:01"},
                                         {"dst": "192.0.2.5", "lladdr": "0e:00:00:00:00:05"}]
        self.m.run = lambda argv, timeout=15: "active\n" if argv[:2] == ["systemctl", "is-active"] else ""
        r = self.m.Report()
        g = {"wifi": "phone-uuid", "protections": protections}
        found = self.m.check_neighbourhood(r, "wlan0", {"ssid": "Example-Phone"}, "trusted", g, "192.0.2.1", "02:00:00:00:00:01")
        return r, found, g

    def test_gateway_not_counted(self):
        on = {"firewall": True, "not_announcing": True, "own_address": True}
        # the hotspot itself, from its own address and from a second one: no other device
        r, found, _ = self.listen({"192.0.2.1", "192.0.2.9"}, on)
        self.assertEqual(r.checks[0]["status"], "ok")
        self.assertEqual(found, 0)
        r, found, _ = self.listen({"192.0.2.1", "192.0.2.5"}, on)
        self.assertEqual(found, 1, "only the number is kept, nobody's address")
        self.assertIn("1 other device(s) heard on this network (not counting the router or hotspot)", r.checks[0]["detail"])

    def test_covered_gives_protected(self):
        r, _, g = self.listen({"192.0.2.5"}, {"firewall": True, "not_announcing": True, "own_address": True, "vpn": False})
        self.assertEqual(r.checks[0]["status"], "covered")
        self.assertIn("it answers pings", r.checks[0]["detail"])
        self.assertEqual(r.verdict(), "protected")
        self.assertIn("DNS is not encrypted", self.m.exposure(r, {"ssid": "Example-Phone"}, g))
        r, _, _ = self.listen({"192.0.2.5"}, {"firewall": True, "not_announcing": True, "own_address": False})
        self.assertEqual(r.checks[0]["status"], "warn")
        self.assertIn("its own hardware address here", r.checks[0]["detail"])
        self.assertEqual(r.verdict(), "caution")
        r.add("dns", "bad", "x")
        self.assertEqual(r.verdict(), "unsafe")  # an attack is never covered
        # a service listening here that a ufw rule lets in: the firewall covers nothing it reaches
        r, _, _ = self.listen({"192.0.2.5"}, {"firewall": False, "allowed_in": ["tcp/22"], "not_announcing": True, "own_address": True})
        self.assertEqual(r.checks[0]["status"], "warn")
        self.assertIn("the firewall turning connections away (a rule lets in tcp/22)", r.checks[0]["detail"])
        r, _, _ = self.listen({"192.0.2.5"}, None)  # no state from the guard for this connection
        self.assertEqual(r.checks[0]["status"], "warn")

    def test_the_guard_is_waited_for(self):
        d = tempfile.mkdtemp()
        self.m.GUARD_STATE = os.path.join(d, "state.json")
        naps = []

        def nap(s):  # the guard's up finishes while the check waits
            naps.append(s)
            if len(naps) == 2:
                with open(self.m.GUARD_STATE, "w") as f:
                    json.dump({"wifi": "phone-uuid", "pending": None, "protections": {"firewall": True}}, f)
        self.m.time.sleep = nap
        with open(self.m.GUARD_STATE, "w") as f:
            json.dump({"wifi": "old-uuid", "pending": "phone-uuid", "pending_at": self.m.stamp(), "protections": {}}, f)
        self.assertEqual(self.m.guard_state("phone-uuid")["protections"], {"firewall": True})
        self.assertEqual(len(naps), 2)
        # a mark of long ago (an up that never came), another connection's, or none: no waiting
        for st in ({"pending": "phone-uuid", "pending_at": "2020-01-01T00:00:00Z", "wifi": "phone-uuid"}, {"pending": "x", "pending_at": self.m.stamp()},
                   {"pending_at": self.m.stamp()}, {"pending": "phone-uuid", "pending_at": 5}):
            naps.clear()
            with open(self.m.GUARD_STATE, "w") as f:
                json.dump(st, f)
            self.m.guard_state("phone-uuid")
            self.assertEqual(naps, [], st)
        self.assertEqual(self.m.guard_state(""), {})

    def dns(self, answers, origins, probe):
        self.m.socket.getaddrinfo = lambda name, port, *a: (_ for _ in ()).throw(self.m.socket.gaierror()) if name.startswith("heimdall-") else [
            (2, 1, 6, "", (ip, 443)) for ip in answers.get(name, [])]
        self.m.origins = lambda ips: origins
        asked = []
        self.m.tls_probe_at = lambda ip, host: asked.append((ip, host)) or probe
        r = self.m.Report()
        self.m.check_dns(r)
        return r.checks[1], asked

    def test_dns_off_as_with_genuine_cert_is_ok(self):
        # made-up answers in the shared address space (100.64.0.0/10: not private to Python, never contacted here)
        answers = {"www.google.com": ["100.64.0.10"], "github.com": ["100.64.0.20"], "www.wikipedia.org": ["100.64.0.30"], "www.cloudflare.com": ["100.64.0.40"]}
        origins = {"100.64.0.10": ("AS15169", "US, AS15169 Google"), "100.64.0.20": ("AS64500", "US, AS64500 Example Cloud"),
                   "100.64.0.30": ("AS14907", "x"), "100.64.0.40": ("AS13335", "x")}
        c, asked = self.dns(answers, origins, "ok")
        self.assertEqual(c["status"], "ok")
        self.assertIn("genuine certificate", c["detail"])
        self.assertEqual(asked, [("100.64.0.20", "github.com")])
        c, _ = self.dns(answers, origins, "cert")
        self.assertEqual(c["status"], "bad")
        self.assertIn("DNS spoofing", c["detail"])
        c, _ = self.dns(answers, origins, "none")
        self.assertEqual(c["status"], "warn")
        # a big cloud anyone can rent space in (GitHub's other network, Microsoft's) is no shortcut: the certificate decides
        origins["100.64.0.20"] = ("AS8075", "US, AS8075 Microsoft")
        c, asked = self.dns(answers, origins, "cert")
        self.assertEqual((c["status"], asked), ("bad", [("100.64.0.20", "github.com")]))
        c, _ = self.dns(answers, origins, "ok")
        self.assertEqual(c["status"], "ok")

    def test_dns_local_answers_must_show_the_certificate(self):
        answers = {"www.google.com": ["100.64.0.10"], "www.wikipedia.org": ["100.64.0.30"], "www.cloudflare.com": ["100.64.0.40"]}
        origins = {"100.64.0.10": ("AS15169", "x"), "100.64.0.30": ("AS14907", "x"), "100.64.0.40": ("AS13335", "x")}
        # a local, link-local or this computer's address: anything but the genuine certificate is spoofing
        for ip in ("192.168.0.20", "169.254.0.20", "10.0.0.20"):
            for probe in ("none", "cert"):
                c, asked = self.dns(dict(answers, **{"github.com": [ip]}), origins, probe)
                self.assertEqual((c["status"], asked), ("bad", [(ip, "github.com")]), (ip, probe))
            c, _ = self.dns(dict(answers, **{"github.com": [ip]}), origins, "ok")
            self.assertEqual(c["status"], "ok", ip)
        for ip in ("127.0.0.1", "0.0.0.0"):  # never asked: a connection there reaches this computer itself
            c, asked = self.dns(dict(answers, **{"github.com": [ip]}), origins, "ok")
            self.assertEqual((c["status"], asked), ("bad", []), ip)
            self.assertIn("this computer itself", c["detail"])

    def test_dns_every_answer_is_asked(self):
        answers = {"www.google.com": ["100.64.0.10"], "www.wikipedia.org": ["100.64.0.30"], "www.cloudflare.com": ["100.64.0.40"]}
        origins = {"100.64.0.10": ("AS15169", "x"), "100.64.0.30": ("AS14907", "x"), "100.64.0.40": ("AS13335", "x")}
        # one genuine address first, a fake one after it in the same network: each is asked
        gh = ["100.64.0.21", "100.64.0.22"]
        origins.update({ip: ("AS64500", "US, AS64500 Example Cloud") for ip in gh})
        self.m.socket.getaddrinfo = lambda name, port, *a: (_ for _ in ()).throw(self.m.socket.gaierror()) if name.startswith("heimdall-") else [
            (2, 1, 6, "", (ip, 443)) for ip in dict(answers, **{"github.com": gh}).get(name, [])]
        self.m.origins = lambda ips: origins
        asked = []
        self.m.tls_probe_at = lambda ip, host: asked.append(ip) or ("ok" if ip == "100.64.0.21" else "cert")
        r = self.m.Report()
        self.m.check_dns(r)
        self.assertEqual((r.checks[1]["status"], asked), ("bad", gh))
        # more answers than are asked: the rest could not be confirmed
        gh = ["100.64.0.%d" % i for i in range(21, 27)]
        origins.update({ip: ("AS64500", "x") for ip in gh})
        c, asked = self.dns(dict(answers, **{"github.com": gh}), origins, "ok")
        self.assertEqual(len(asked), self.m.PROBES)
        self.assertEqual(c["status"], "warn")
        self.assertIn("not asked (more than 4 such answers)", c["detail"])


if __name__ == "__main__":
    unittest.main()
