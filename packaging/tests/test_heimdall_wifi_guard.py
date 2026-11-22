"""heimdall-wifi-guard's decisions with NetworkManager, nft and systemctl replaced by a recorder: what happens on untrusted, trusted
and home networks, when the VPN connects, fails, or drops later, and what trust and untrust change. Nothing on the real system is
touched; every network is made up."""
import importlib.machinery
import importlib.util
import json
import os
import tempfile
import types
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "net", "heimdall-wifi-guard")


def load():
    loader = importlib.machinery.SourceFileLoader("guard", SCRIPT)
    spec = importlib.util.spec_from_loader("guard", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


class Guard(unittest.TestCase):
    def setUp(self):
        self.m = load()
        self.d = tempfile.mkdtemp()
        self.m.CONF = os.path.join(self.d, "guard.json")
        self.m.TRUSTED = os.path.join(self.d, "trusted.json")
        self.m.RUN = os.path.join(self.d, "run")
        self.m.KEYS = os.path.join(self.d, "keys.json")
        self.m.UFW_RULES = (os.path.join(self.d, "user.rules"), os.path.join(self.d, "user6.rules"))
        self.m.HEIMDALL_CONFIG = os.path.join(self.d, "config.json")
        self.psk = ""  # the profile's saved password, as root reads it
        self.ss = ""  # what listens here (ss -tulnH)
        self.routes = ""  # ip -j route show default dev wlan0
        self.calls, self.vpn_ok, self.table, self.quiet = [], True, False, False
        self.mac = "AA:BB:CC:00:00:01"
        self.cloned = ""
        self.ssid, self.key = "Cafe", "wpa-psk"
        self.wifi = ""  # nmcli device's answer: the connected Wi-Fi, if any
        self.avahi = "active"
        self.ctype, self.name, self.link = "", "Wired connection 1", ""  # a profile's type and name; ip -j link show dev
        m = self

        def sh(argv, timeout=30, check=False, input=None):
            m.calls.append(" ".join(argv))
            out, rc = "", 0
            if argv[:4] == ["nft", "list", "table", "inet"]:
                on = m.quiet if argv[4] == m.m.QUIET else m.table
                mark = m.m.QUIET_MARK_OPEN if on == "open" else m.m.QUIET_MARK
                rc, out = (0, "table inet x { comment \"%s\" counter packets 3 bytes 9 }" % mark) if on else (1, "")
            elif argv[:3] == ["nft", "delete", "table"]:
                if argv[4] == m.m.QUIET:
                    m.quiet = False
                else:
                    m.table = False
            elif argv[:2] == ["nft", "-f"]:
                m.quiet = "open" if "discoverable" in (input or "").split("\n")[3] else True
                m.calls.append("QUIET")
            elif argv[:3] == ["nmcli", "connection", "up"]:
                rc = 0 if m.vpn_ok else 4
            elif argv[:3] == ["nmcli", "-g", "802-11-wireless.ssid"]:
                out = m.ssid
            elif argv[:3] == ["nmcli", "-g", "802-11-wireless-security.key-mgmt"]:
                out = m.key + "\n"
            elif argv[:3] in (["nmcli", "-g", "802-11-wireless.cloned-mac-address"], ["nmcli", "-g", "802-3-ethernet.cloned-mac-address"]):
                out = m.cloned + "\n"
            elif argv[:3] == ["nmcli", "-g", "connection.type"]:
                out = m.ctype + "\n"
            elif argv[:3] == ["nmcli", "-g", "connection.id"]:
                out = m.name + "\n"
            elif argv[:4] == ["ip", "-j", "link", "show"]:
                out = m.link
            elif argv[:4] == ["nmcli", "-s", "-g", "802-11-wireless-security.psk"]:
                out = m.psk + "\n"
            elif argv[:2] == ["ss", "-tulnH"]:
                out = m.ss
            elif argv[:4] == ["ip", "-j", "route", "show"]:
                out = m.routes
            elif argv[:3] == ["nmcli", "-g", "GENERAL.CON-UUID"]:
                out = "phone-uuid\n"
            elif argv[:5] == ["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"]:
                out = m.wifi
            elif argv[:2] == ["systemctl", "is-active"]:
                out = m.avahi
            return types.SimpleNamespace(returncode=rc, stdout=out, stderr="")

        def lock(vpn):
            m.table = True
            m.calls.append("LOCK")
            m.m.set_state(locked=True)

        self.m.sh = sh
        self.m.print = lambda *a, **k: None  # what trust says is for the owner, not the test output
        self.m.root = lambda: None
        self.m.router_mac = lambda iface: m.mac
        self.real_lock = self.m.lock
        self.m.lock = lock
        self.m.is_wifi = lambda iface: iface == "wlan0"
        with open(self.m.CONF, "w") as f:
            json.dump({"vpn": {"uuid": "vpn-uuid", "iface": "wg-heimdall", "endpoints": [{"ip": "203.0.113.5", "port": 51820}]}}, f)

    def last_note(self):
        with open(os.path.join(self.m.RUN, "last.json")) as f:
            return json.load(f)


    def trusted(self, entries):
        with open(self.m.TRUSTED, "w") as f:
            json.dump(entries, f)

    def state(self):
        with open(os.path.join(self.m.RUN, "state.json")) as f:
            return json.load(f)

    def test_an_entry_from_before_the_levels_is_home_bound_to_its_router(self):
        level = self.m.level_of
        e = {"ssid": "Home", "routers": ["00:00:5E:00:53:01"]}
        self.assertEqual(level(e, "Home", "wpa-psk", "00:00:5E:00:53:01"), "home")
        self.assertEqual(level(e), "home")  # the profile alone: before the link is up, and for status
        # a router that did not answer, or another one: recognized by the password, so trusted (protections stay), not home
        self.assertEqual(level(e, "Home", "wpa-psk", ""), "trusted")
        self.assertEqual(level(e, "Home", "sae", "00:00:5E:00:53:09"), "trusted")
        # ... unless the profile has no password to recognize it by
        for key in ("", "owe", "none", "wpa-eap"):
            self.assertEqual(level(e, "Home", key, "00:00:5E:00:53:09"), "untrusted", key)
        self.assertEqual(level(e, "Home", "", "00:00:5E:00:53:01"), "home")  # as it always was
        for odd in (None, {}, [], "x", 5, {"level": "admin", "ssid": "Home"}):
            self.assertEqual(level(odd, "Home", "sae", "00:00:5E:00:53:01"), "untrusted", odd)

    def test_trusted_is_recognized_by_name_and_lock_not_by_router(self):
        level = self.m.level_of
        e = {"ssid": "Example-Phone", "level": "trusted", "key_mgmt": "wpa-psk", "routers": []}
        for mac in (None, "", "02:00:00:00:00:01", "06:00:00:00:00:02"):  # a phone hotspot's address changes on restart
            self.assertEqual(level(e, "Example-Phone", "wpa-psk", mac), "trusted", mac)
        self.assertEqual(level(e, "Example-Phone", "sae", "02:00:00:00:00:01"), "trusted")  # a stronger lock
        self.assertEqual(level(e, "Other", "wpa-psk", None), "untrusted")  # the profile was renamed
        for key in ("", "owe", "none", "ieee8021x", "wpa-eap"):
            self.assertEqual(level(e, "Example-Phone", key, None), "untrusted", key)
        e3 = dict(e, key_mgmt="sae")
        self.assertEqual(level(e3, "Example-Phone", "wpa-psk", None), "untrusted")  # WPA3 trusted, WPA2 now: a downgrade
        home = {"ssid": "Example-Home", "level": "home", "key_mgmt": "sae", "routers": ["02:00:00:00:00:01"]}
        self.assertEqual(level(home, "Example-Home", "sae", "02:00:00:00:00:01"), "home")
        self.assertEqual(level(home, "Example-Home", "sae", "02:00:00:00:00:09"), "trusted")  # router replaced: the device list pauses
        self.assertEqual(level(home, "Example-Home", "sae", ""), "trusted")

    def test_trust_keeps_every_protection(self):
        self.wifi = "wlan0:wifi:connected:Example-Phone\n"
        self.ssid, self.key = "Example-Phone", "sae"
        self.m.cmd_trust([])
        with open(self.m.TRUSTED) as f:
            e = json.load(f)["phone-uuid"]
        self.assertEqual((e["ssid"], e["level"], e["key_mgmt"], e["routers"]), ("Example-Phone", "trusted", "sae", []))
        joined = "\n".join(self.calls)
        self.assertNotIn("permanent", joined)
        self.assertNotIn("dhcp-send-hostname yes", joined)
        self.assertNotIn("systemctl start avahi", joined)
        self.assertNotIn("nft delete table inet", joined)  # neither the lockdown nor the quiet table is taken away

    def test_trust_refuses_networks_without_a_password(self):
        self.wifi = "wlan0:wifi:connected:Free\n"
        with open(self.m.TRUSTED, "w") as f:
            f.write("{}")
        for key in ("", "owe", "none", "ieee8021x", "wpa-eap"):
            self.key = key
            with self.assertRaises(SystemExit, msg=key):
                self.m.cmd_trust([])
            with open(self.m.TRUSTED) as f:
                self.assertEqual(json.load(f), {}, key)

    def test_trust_home_with_the_real_address_opens_up(self):
        self.wifi = "wlan0:wifi:connected:Example-Home\n"
        self.ssid, self.key, self.quiet = "Example-Home", "wpa-psk", True
        os.makedirs(self.m.RUN)
        with open(os.path.join(self.m.RUN, "state.json"), "w") as f:
            json.dump({"avahi_was_on": True}, f)
        self.m.cmd_trust(["--home", "--real-address"])
        with open(self.m.TRUSTED) as f:
            e = json.load(f)["phone-uuid"]
        self.assertEqual((e["level"], e["routers"]), ("home", [self.mac]))
        joined = "\n".join(self.calls)
        self.assertIn("802-11-wireless.cloned-mac-address permanent ipv4.dhcp-send-hostname yes", joined)
        self.assertIn("systemctl start avahi-daemon", joined)
        self.assertFalse(self.quiet, "the quiet table goes at home")

    def test_trust_home_without_the_real_address_stays_private(self):
        self.wifi = "wlan0:wifi:connected:Example-Home\n"
        self.m.cmd_trust(["--home"])
        self.assertNotIn("permanent", "\n".join(self.calls))
        with self.assertRaises(SystemExit):
            self.m.cmd_trust(["--real-address"])  # only with --home

    def test_trust_by_uuid_refuses_another_connection(self):
        self.wifi = "wlan0:wifi:connected:Example-Phone\n"
        with self.assertRaises(SystemExit):
            self.m.cmd_trust(["--uuid", "other-uuid"])
        self.assertFalse(os.path.exists(self.m.TRUSTED))
        self.m.cmd_trust(["--uuid", "phone-uuid"])
        self.assertTrue(os.path.exists(self.m.TRUSTED))

    def test_status_names_levels_and_what_is_in_force(self):
        self.trusted({"phone-uuid": {"ssid": "Example-Phone", "level": "trusted", "key_mgmt": "sae", "routers": []},
                      "home-uuid": {"ssid": "Example-Home", "routers": ["02:00:00:00:00:01"]}, "odd": [1]})
        self.wifi = "wlan0:wifi:connected:Example-Phone\n"
        self.ssid, self.key = "Example-Phone", "sae"
        os.makedirs(self.m.RUN)
        with open(os.path.join(self.m.RUN, "state.json"), "w") as f:
            json.dump({"wifi": "phone-uuid", "level": "trusted", "protections": {"firewall": True, "not_announcing": True, "own_address": True,
                                                                                 "no_name": True, "vpn": False}}, f)
        said = []
        self.m.print = lambda *a, **k: said.append(" ".join(str(x) for x in a))
        self.m.cmd_status()
        text = "\n".join(said)
        self.assertIn("  Example-Phone: trusted (WPA3-Personal)", text)
        self.assertIn("  Example-Home: home, router 02:00:00:00:00:01", text)
        self.assertIn("now on: Example-Phone, trusted (WPA3-Personal)", text)
        self.assertIn("the firewall drops connections in: yes", text)
        self.assertIn("the VPN: no", text)
        self.assertIn("DNS is not encrypted", text)

    def test_untrust_restores_a_private_profile(self):
        self.trusted({"home-uuid": {"ssid": "Example-Home", "level": "home", "routers": [self.mac]}, "x": 5})
        self.cloned = "permanent"
        self.m.cmd_untrust("Example-Home")
        with open(self.m.TRUSTED) as f:
            self.assertEqual(json.load(f), {"x": 5})
        modify = [c for c in self.calls if c.startswith("nmcli connection modify home-uuid")]
        self.assertTrue(modify and "dhcp-send-hostname no" in modify[0] and "cloned-mac-address stable" in modify[0], self.calls)

    def test_trusted_hotspot_is_quiet_but_keeps_its_protections(self):
        self.trusted({"phone-uuid": {"ssid": "Example-Phone", "level": "trusted", "key_mgmt": "wpa-psk", "routers": []}})
        self.ssid = "Example-Phone"
        os.remove(self.m.CONF)  # no VPN set up
        for mac in ("02:00:00:00:00:01", "06:00:00:00:00:02"):  # the hotspot restarted: a new router address
            self.calls.clear()
            self.mac = mac
            self.m.pre_up("wlan0", "phone-uuid")
            self.m.up("wlan0", "phone-uuid")
            self.assertFalse(os.path.exists(os.path.join(self.m.RUN, "last.json")), "no notice on a trusted network")
            self.assertTrue(self.quiet, "the quiet table is in place")
            self.assertTrue(any("ipv4.dhcp-send-hostname no" in c for c in self.calls), "still no name sent")
            self.assertTrue(any("systemctl stop avahi-daemon" in c for c in self.calls) or self.avahi != "active")
            st = self.state()
            self.assertEqual((st["level"], st["trusted"]), ("trusted", False))
            self.assertIn("protections", st)

    def test_trusted_network_keeps_the_vpn(self):
        self.trusted({"phone-uuid": {"ssid": "Cafe", "level": "trusted", "key_mgmt": "wpa-psk", "routers": []}})
        self.m.pre_up("wlan0", "phone-uuid")
        self.assertIn("LOCK", self.calls)
        self.m.up("wlan0", "phone-uuid")
        self.assertIn("nmcli connection up vpn-uuid", self.calls)
        self.assertFalse(os.path.exists(os.path.join(self.m.RUN, "last.json")), "no vpn-up notice on a trusted network")
        self.assertTrue(self.state()["protections"]["vpn"])
        # the VPN dropping later still drops the Wi-Fi: the kill switch is a protection
        self.calls.clear()
        self.m.down("wg-heimdall", "vpn-uuid")
        self.assertIn("nmcli device disconnect wlan0", self.calls)

    def test_trusted_name_without_its_lock_is_untrusted(self):
        self.trusted({"phone-uuid": {"ssid": "Cafe", "level": "trusted", "key_mgmt": "sae", "routers": []}})
        self.key = "wpa-psk"
        os.remove(self.m.CONF)
        self.m.up("wlan0", "phone-uuid")
        self.assertEqual(self.state()["level"], "untrusted")
        self.assertIn("not its lock (WPA2-Personal now)", self.last_note()["message"])

    def test_home_router_changed_is_trusted_with_a_note(self):
        self.trusted({"home-uuid": {"ssid": "Cafe", "level": "home", "key_mgmt": "wpa-psk", "routers": ["02:00:00:00:00:01"]}})
        self.mac = "02:00:00:00:00:09"
        self.m.up("wlan0", "home-uuid")
        self.assertEqual(self.state()["level"], "trusted")
        self.assertIn("device list is paused", self.last_note()["message"])
        self.assertTrue(self.quiet, "not home: quiet")

    def test_no_vpn_note_on_every_connection(self):
        # the owner's choice (2026-11-15): an untrusted network says so on every connection; a trusted one never
        os.remove(self.m.CONF)
        self.m.up("wlan0", "cafe-uuid")
        self.assertEqual(self.last_note()["event"], "no-vpn")
        os.remove(os.path.join(self.m.RUN, "last.json"))
        self.m.up("wlan0", "cafe-uuid")
        self.assertEqual(self.last_note()["event"], "no-vpn", "again on the next connection")

    def test_home_takes_the_quiet_table_away_and_down_leaves_it(self):
        self.trusted({"home-uuid": {"ssid": "Cafe", "routers": [self.mac]}})
        self.quiet = True
        self.m.up("wlan0", "home-uuid")
        self.assertFalse(self.quiet)
        self.m.pre_up("wlan0", "cafe-uuid")
        self.assertTrue(self.quiet, "loaded before an untrusted network carries traffic")
        self.m.up("wlan0", "cafe-uuid")
        self.calls.clear()
        self.wifi = "wlan1:wifi:connected:Other\n"  # another Wi-Fi still up: Avahi stays off
        self.m.down("wlan0", "cafe-uuid")
        self.assertTrue(self.quiet, "left in place for the next network")
        self.assertFalse(any("systemctl start avahi" in c for c in self.calls))
        self.wifi = ""
        self.m.up("wlan0", "cafe-uuid")
        self.calls.clear()
        self.m.down("wlan0", "cafe-uuid")  # no Wi-Fi any more: Avahi comes back (the table still mutes it on Wi-Fi)
        self.assertTrue(any("systemctl start avahi" in c for c in self.calls))
        self.assertTrue(self.quiet)

    def test_the_quiet_table_mutes_discovery_and_only_logs_what_comes_in(self):
        rs = self.m.quiet_ruleset()
        self.assertIn('oifname != "wl*" accept', rs)
        self.assertIn('iifname != "wl*" accept', rs)
        # NetBIOS, KDE Connect, SSDP, WS-Discovery, mDNS, LLMNR, Dropbox, Syncthing, Steam, Spotify Connect
        self.assertIn("udp dport { 137, 138, 1714-1764, 1900, 3702, 5353, 5355, 17500, 21027, 27036, 57621 } counter drop", rs)
        self.assertIn("tcp dport { 1714-1764, 5355 } counter drop", rs)
        self.assertIn('log prefix "heimdall-wifi-in: "', rs)
        # only what a device on the network itself starts: never a packet of a known flow, a stray one or one from the internet
        for rule in ("ct state != new accept", "tcp flags & (syn | ack) != syn accept", "fib daddr type != local accept",
                     "ip saddr != { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } accept", "ip6 saddr != { fc00::/7, fe80::/10 } accept"):
            self.assertIn(rule, rs)
        self.assertLess(rs.index("ct state != new accept"), rs.index("log prefix"))
        chain_in = rs.split("chain in {")[1].split("}\n  chain out")[0]
        self.assertNotIn("drop", chain_in, "incoming traffic stays with ufw")
        self.assertNotIn("reject", chain_in)
        self.assertTrue(rs.startswith("table inet heimdall_wifi_quiet {}\ndelete table inet heimdall_wifi_quiet\n"), "replaced in one go")

    def test_protections_are_checked_not_assumed(self):
        ufw = os.path.join(self.d, "ufw")
        conf = os.path.join(self.d, "ufw.conf")
        self.m.UFW_DEFAULT, self.m.UFW_CONF = ufw, conf
        with open(ufw, "w") as f:
            f.write('IPV6=yes\nDEFAULT_INPUT_POLICY="DROP"\n')
        with open(conf, "w") as f:
            f.write("ENABLED=yes\n")
        self.quiet, self.avahi = True, "active"  # systemctl is-active answers "active" for ufw and Avahi alike here
        p = self.m.protections("wlan0", "u", False)
        self.assertEqual((p["firewall"], p["allowed_in"], p["not_announcing"]), (True, [], True), "the quiet table mutes Avahi too")
        self.assertTrue(self.m.ufw_drops())
        # a ufw rule letting in a service that listens here: the firewall covers nothing it reaches
        self.ss = ("tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 128 127.0.0.1:631 0.0.0.0:*\nudp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*\n"
                   "tcp LISTEN 0 128 [::]:8000 [::]:*\nudp UNCONN 0 0 *:51820 *:*\n")
        with open(self.m.UFW_RULES[0], "w") as f:
            f.write("*filter\n### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n### tuple ### deny tcp 8000 0.0.0.0/0 any 0.0.0.0/0 in\n"
                    "### tuple ### allow udp 51820 0.0.0.0/0 any 0.0.0.0/0 out\n### tuple ### route:allow tcp 8000 0.0.0.0/0 any 0.0.0.0/0 in\n")
        with open(self.m.UFW_RULES[1], "w") as f:
            f.write("### tuple ### limit tcp 7990:8010 ::/0 any ::/0 in_wlan0\n### tuple ### allow any any ::/0 any ::/0 in_eth0\n")
        p = self.m.protections("wlan0", "u", False)
        self.assertEqual((p["firewall"], p["allowed_in"]), (False, ["tcp/22", "tcp/8000"]))
        self.assertEqual(self.m.listening_services(), ["tcp/22", "tcp/8000", "udp/51820"])
        for spec, port, want in (("22", "22", True), ("80,443", "443", True), ("6000:6007", "6007", True), ("6000:6007", "6008", False),
                                 ("any", "1", True), ("x", "1", False), ("22", "x", False), ("1:99999999", "5", False)):
            self.assertEqual(self.m.port_in(spec, port), want, (spec, port))
        with open(ufw, "w") as f:
            f.write('DEFAULT_INPUT_POLICY="ACCEPT"\n')
        self.assertFalse(self.m.ufw_drops())
        with open(ufw, "w") as f:
            f.write('DEFAULT_INPUT_POLICY="REJECT"\n')
        with open(conf, "w") as f:
            f.write("ENABLED=no\n")
        self.assertFalse(self.m.ufw_drops(), "installed but not enabled")
        self.assertFalse(self.m.own_address("wlan0"), "ip said nothing")
    def test_a_late_down_leaves_the_next_connection_alone(self):
        # NetworkManager does not wait for the down job: the next connection's pre-up (or up) can come first
        self.m.pre_up("wlan0", "cafe-uuid")
        self.m.up("wlan0", "cafe-uuid")
        self.m.pre_up("wlan0", "other-uuid")  # the next network is coming up: its lockdown is in place
        self.calls.clear()
        self.m.down("wlan0", "cafe-uuid")
        self.assertTrue(self.table, "the next connection's lockdown stays")
        self.assertNotIn("nmcli connection down vpn-uuid", self.calls)
        self.m.up("wlan0", "other-uuid")
        self.m.down("wlan0", "cafe-uuid")  # ... or after its up: its state stays
        self.assertEqual((self.state()["wifi"], self.state()["level"]), ("other-uuid", "untrusted"))
        self.assertTrue(self.state()["protections"])
        # the same network again (a reconnect): this interface is connected again by the time the old down runs
        self.wifi = "wlan0:wifi:connected:Cafe\n"
        self.m.down("wlan0", "other-uuid")
        self.assertEqual(self.state()["wifi"], "other-uuid")
        self.assertTrue(self.table)
        # a mark of a pre-up long ago (its up never came) does not hold anything up
        self.wifi = ""
        self.m.set_state(pending="other-uuid", pending_at="2020-01-01T00:00:00Z")
        self.m.down("wlan0", "other-uuid")
        self.assertIsNone(self.state()["wifi"])
        self.assertFalse(self.table, "a real down still unlocks")

    def test_trust_from_home_closes_up_now(self):
        self.trusted({"phone-uuid": {"ssid": "Example-Phone", "routers": [self.mac]}})  # home, from before the levels
        self.wifi = "wlan0:wifi:connected:Example-Phone\n"
        self.ssid, self.key, self.quiet, self.cloned = "Example-Phone", "wpa-psk", False, "permanent"
        self.m.set_state(wifi="phone-uuid", level="home", protections={"not_announcing": False})
        said = []
        self.m.print = lambda *a, **k: said.append(" ".join(str(x) for x in a))
        self.m.cmd_trust([])
        self.assertTrue(self.quiet, "the quiet table is loaded now, not at the next connection")
        self.assertTrue(any("systemctl stop avahi-daemon" in c for c in self.calls))
        self.assertTrue(any("cloned-mac-address stable" in c and "dhcp-send-hostname no" in c for c in self.calls))
        self.assertEqual(self.state()["level"], "trusted")
        self.assertTrue(self.state()["protections"]["not_announcing"])
        self.assertIn("Reconnect to it", "\n".join(said))

    def test_trust_refuses_unknown_options(self):
        self.wifi = "wlan0:wifi:connected:Example-Phone\n"
        for args in (["--hom"], ["--home", "-x"], ["home"]):
            with self.assertRaises(SystemExit, msg=args):
                self.m.cmd_trust(args)
        self.assertFalse(os.path.exists(self.m.TRUSTED), "nothing changed")
        self.m.cmd_trust(["--uuid", "phone-uuid", "--home"])
        self.assertTrue(os.path.exists(self.m.TRUSTED))

    def test_a_trusted_profile_with_another_password_is_untrusted(self):
        self.wifi = "wlan0:wifi:connected:Example-Phone\n"
        self.ssid, self.psk = "Example-Phone", "a long made-up password"
        os.remove(self.m.CONF)
        self.m.cmd_trust([])
        with open(self.m.KEYS) as f:
            pins = json.load(f)
        self.assertEqual(list(pins), ["phone-uuid"])
        self.assertNotIn(self.psk, json.dumps(pins), "only a fingerprint is kept")
        self.assertEqual(os.stat(self.m.KEYS).st_mode & 0o777, 0o600)
        self.m.up("wlan0", "phone-uuid")
        self.assertEqual(self.state()["level"], "trusted")
        self.psk = "another password"  # the saved profile edited to join somebody else's network of the same name
        self.m.up("wlan0", "phone-uuid")
        self.assertEqual(self.state()["level"], "untrusted")
        self.assertIn("its saved password changed since you trusted it", self.last_note()["message"])
        self.m.cmd_untrust("Example-Phone")
        with open(self.m.KEYS) as f:
            self.assertEqual(json.load(f), {})

    def test_a_renamed_trusted_profile_is_untrusted_and_says_so(self):
        self.trusted({"phone-uuid": {"ssid": "Example-Phone", "level": "trusted", "key_mgmt": "wpa-psk", "routers": []}})
        os.remove(self.m.CONF)
        self.ssid = "Example-Other"
        self.m.up("wlan0", "phone-uuid")
        self.assertEqual(self.state()["level"], "untrusted")
        self.assertIn("now names another network (Example-Other)", self.last_note()["message"])
        self.assertNotIn("lock", self.last_note()["message"])

    def test_home_router_changed_is_told_once_a_day(self):
        self.trusted({"home-uuid": {"ssid": "Example-Phone", "routers": ["02:00:00:00:00:01"]}})  # a hotspot trusted before the levels
        os.remove(self.m.CONF)
        self.mac = "06:00:00:00:00:02"
        self.m.up("wlan0", "home-uuid")
        self.assertIn("If it is a phone hotspot", self.last_note()["message"])
        os.remove(os.path.join(self.m.RUN, "last.json"))
        self.mac = "0A:00:00:00:00:03"
        self.m.up("wlan0", "home-uuid")
        self.assertFalse(os.path.exists(os.path.join(self.m.RUN, "last.json")), "said already today")

    def test_status_says_whether_inbound_devices_are_reported(self):
        said = []
        self.m.print = lambda *a, **k: said.append(" ".join(str(x) for x in a))
        self.avahi = "inactive"  # systemctl is-active's answer, for heimdalld too here
        self.m.cmd_status()
        self.assertIn("devices reaching this computer: not reported: heimdalld is not running", said)
        self.avahi = "active"
        self.assertIn("cannot read the kernel log", self.m.inbound_watch())
        fake = self.m.sh
        self.m.sh = lambda argv, **k: types.SimpleNamespace(returncode=0, stdout="limbo-heimdall systemd-journal\n", stderr="") if argv[:2] == ["systemctl", "show"] else fake(argv, **k)
        self.assertTrue(self.m.inbound_watch().startswith("reported"))
        with open(self.m.HEIMDALL_CONFIG, "w") as f:
            json.dump({"firewall": False}, f)
        self.assertIn("firewall watch is off", self.m.inbound_watch())

    def test_ufw_rules_with_comments_logging_and_applications_are_read(self):
        # as ufw writes them: a comment (hex) after the rule, logged actions, application rules, no direction, forwarded rules
        rules = self.m.ufw_rules_in(
            "### tuple ### allow tcp 8931 0.0.0.0/0 any 192.168.0.7 in comment=4865696d64616c6c206d657368\n"  # docs/MESH.md's own rule
            "### tuple ### allow_log tcp 2222 0.0.0.0/0 any 0.0.0.0/0 in\n"
            "### tuple ### limit_log-all tcp 2223 0.0.0.0/0 any 0.0.0.0/0 in_wlan0\n"
            "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 OpenSSH - in\n"
            "### tuple ### allow udp 9 0.0.0.0/0 any 0.0.0.0/0\n"
            "### tuple ### route:allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in\n"
            "### tuple ### deny_log tcp 81 0.0.0.0/0 any 0.0.0.0/0 in\n"
            "### tuple ### allow tcp 82 0.0.0.0/0 any 0.0.0.0/0 out comment=78\n"
            "### tuple ### allow tcp 83 0.0.0.0/0 any 0.0.0.0/0 in_eth0\n")
        self.assertEqual(rules, [("tcp", "8931"), ("tcp", "2222"), ("tcp", "2223"), ("tcp", "22"), ("udp", "9")])
        self.ss = "tcp LISTEN 0 128 0.0.0.0:8931 0.0.0.0:*\ntcp LISTEN 0 128 0.0.0.0:80 0.0.0.0:*\n"
        with open(self.m.UFW_RULES[0], "w") as f:
            f.write("### tuple ### allow tcp 8931 0.0.0.0/0 any 192.168.0.7 in comment=4865696d64616c6c206d657368\n")
        self.assertEqual(self.m.ufw_allowed(self.m.listening_services()), ["tcp/8931"], "the mesh port of docs/MESH.md is let in")

    def test_the_quiet_table_holds_discovery_only_on_the_local_network(self):
        rs = self.m.quiet_ruleset()
        out = rs.split("chain out {")[1]
        # discovery to an internet address passes (PPTP 1723, H.323 1719/1720 share the KDE Connect ports)
        self.assertLess(out.index("ip daddr != { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 } accept"),
                        out.index("counter drop"))
        self.assertIn("ip6 daddr != { fc00::/7, fe80::/10, ff00::/8 } accept", out)
        # the router: once per connection, a prefix of its own
        self.assertIn('ip saddr @router4 limit rate 30/minute log prefix "heimdall-wifi-in-router: " level info add @seen4 { ip saddr timeout 7d } accept', rs)
        opened = self.m.quiet_ruleset(True)
        self.assertNotIn("counter drop", opened, "a discoverable network: discovery is let out")
        self.assertIn('comment "heimdall quiet 4 discoverable"', opened)
        self.assertEqual(rs.split("chain in {")[1].split("chain out")[0], opened.split("chain in {")[1].split("chain out")[0], "the same inbound log")

    def test_the_router_is_told_once_per_connection(self):
        os.remove(self.m.CONF)
        self.routes = '[{"dst":"default","gateway":"192.168.0.1","dev":"wlan0"}]'
        self.m.up("wlan0", "cafe-uuid")
        # the last network's router and senders go first (the table stays from one network to the next)
        flush = [self.calls.index("nft flush set inet heimdall_wifi_quiet " + s) for s in ("router4", "seen4")]
        self.assertLess(max(flush), self.calls.index("nft add element inet heimdall_wifi_quiet router4 { 192.168.0.1 }"))
        self.calls.clear()
        self.routes = '[{"gateway":"fe80::1"}]'  # not an IPv4 address: the old router forgotten, no new one
        self.m.up("wlan0", "cafe-uuid")
        self.assertIn("nft flush set inet heimdall_wifi_quiet router4", self.calls)
        self.assertFalse(any("add element" in c for c in self.calls))
        # a fresh table from trust, or from discoverable on the network connected now, learns the router again
        self.routes = '[{"dst":"default","gateway":"192.168.0.1","dev":"wlan0"}]'
        self.wifi = "wlan0:wifi:connected:Cafe\n"
        for run in (lambda: self.m.cmd_trust([]), lambda: self.m.cmd_discoverable(["on"])):
            self.m.set_state(wifi="phone-uuid")
            self.calls.clear()
            run()
            self.assertIn("nft add element inet heimdall_wifi_quiet router4 { 192.168.0.1 }", self.calls)

    def test_discoverable_is_the_owners_choice_per_network(self):
        self.wifi = "wlan0:wifi:connected:Cafe\n"
        os.remove(self.m.CONF)
        said = []
        self.m.print = lambda *a, **k: said.append(" ".join(str(x) for x in a))
        self.m.pre_up("wlan0", "phone-uuid")
        self.m.up("wlan0", "phone-uuid")  # untrusted, quiet
        self.assertIs(self.quiet, True)
        self.m.cmd_discoverable([])
        self.assertEqual(said[-1], "Cafe: discoverable off")
        self.avahi = "inactive"
        self.m.set_state(avahi_was_on=True)
        self.calls.clear()
        self.m.cmd_discoverable(["on"])  # at once on the network connected now: discovery let out, Avahi back
        self.assertEqual(self.quiet, "open")
        self.assertIn("systemctl start avahi-daemon.socket avahi-daemon.service", self.calls)
        with open(self.m.TRUSTED) as f:
            self.assertEqual(json.load(f), {"phone-uuid": {"ssid": "Cafe", "level": "untrusted", "discoverable": True}})
        p = self.state()["protections"]
        self.assertEqual((p["discoverable"], p["not_announcing"]), (True, False), "said honestly")
        self.assertEqual(self.m.level_of({"ssid": "Cafe", "level": "untrusted", "discoverable": True}, "Cafe", "wpa-psk", "x"), "untrusted")
        self.m.up("wlan0", "phone-uuid")  # the next connection: still discoverable, still untrusted (the VPN, the notices)
        self.assertEqual((self.quiet, self.state()["level"]), ("open", "untrusted"))
        self.assertIn("there is no VPN", self.last_note()["message"])
        self.assertNotIn("not announcing", self.last_note()["message"])
        self.m.cmd_trust([])  # trusting keeps the choice
        with open(self.m.TRUSTED) as f:
            self.assertTrue(json.load(f)["phone-uuid"]["discoverable"])
        self.assertEqual(self.quiet, "open")
        self.m.cmd_untrust("Cafe")  # ... and so does untrusting
        with open(self.m.TRUSTED) as f:
            self.assertEqual(json.load(f), {"phone-uuid": {"ssid": "Cafe", "level": "untrusted", "discoverable": True}})
        self.avahi = "active"
        with self.assertRaises(SystemExit):  # only a UUID as NetworkManager writes it
            self.m.cmd_discoverable(["off", "--uuid", "phone-uuid"])
        self.m.cmd_discoverable(["off"])
        self.assertIs(self.quiet, True)
        self.assertTrue(any("systemctl stop avahi-daemon" in c for c in self.calls))
        with open(self.m.TRUSTED) as f:
            self.assertEqual(json.load(f), {}, "nothing left to remember")
        for args in (["maybe"], ["on", "off"], ["on", "--uuid"]):
            with self.assertRaises(SystemExit, msg=args):
                self.m.cmd_discoverable(args)
        self.calls.clear()
        self.m.cmd_discoverable(["--uuid", "0e3f5a1c-2222-4333-8444-955566667777"])
        self.assertIn("nmcli -g 802-11-wireless.ssid connection show uuid 0e3f5a1c-2222-4333-8444-955566667777", self.calls)
        self.ssid = ""  # not a saved Wi-Fi profile
        with self.assertRaises(SystemExit):
            self.m.cmd_discoverable(["on", "--uuid", "0e3f5a1c-2222-4333-8444-955566667777"])
        for odd in ("0E3F5A1C-2222-4333-8444-955566667777", "0e3f5a1c-2222-4333-8444-95556666777", "0e3f5a1c22224333844495556666777700", ""):
            with self.assertRaises(SystemExit, msg=odd):
                self.m.cmd_discoverable(["--uuid", odd])

    def test_untrust_takes_effect_at_once(self):
        self.trusted({"phone-uuid": {"ssid": "Example-Phone", "routers": [self.mac]}})  # home
        self.wifi = "wlan0:wifi:connected:Example-Phone\n"
        self.ssid = "Example-Phone"
        self.m.up("wlan0", "phone-uuid")
        self.assertFalse(self.quiet)
        said = []
        self.m.print = lambda *a, **k: said.append(" ".join(str(x) for x in a))
        self.m.cmd_untrust("Example-Phone")
        self.assertIs(self.quiet, True, "the quiet table now, not at the next connection")
        self.assertTrue(any("systemctl stop avahi-daemon" in c for c in self.calls))
        self.assertEqual((self.state()["level"], self.state()["trusted"]), ("untrusted", False))
        self.assertIn("Reconnect", "\n".join(said))

    def test_untrusted_network_locks_first_then_vpn(self):
        self.m.pre_up("wlan0", "cafe-uuid")
        self.assertIn("LOCK", self.calls)
        self.m.up("wlan0", "cafe-uuid")
        self.assertIn("nmcli connection up vpn-uuid", self.calls)
        self.assertNotIn("nmcli device disconnect wlan0", self.calls)
        self.assertEqual(self.last_note()["event"], "vpn-up")
        self.assertTrue(any("systemctl stop avahi-daemon" in c for c in self.calls), "it announces itself")
        self.assertTrue(any("ipv4.dhcp-send-hostname no" in c for c in self.calls))

    def test_vpn_failure_drops_the_wifi(self):
        self.vpn_ok = False
        self.m.pre_up("wlan0", "cafe-uuid")
        self.m.up("wlan0", "cafe-uuid")
        self.assertIn("nmcli device disconnect wlan0", self.calls)
        self.assertEqual(self.last_note()["event"], "dropped")

    def test_vpn_dropping_later_drops_the_wifi(self):
        self.m.pre_up("wlan0", "cafe-uuid")
        self.m.up("wlan0", "cafe-uuid")
        self.calls.clear()
        self.m.down("wg-heimdall", "vpn-uuid")
        self.assertIn("nmcli device disconnect wlan0", self.calls)
        self.assertEqual(self.last_note()["event"], "dropped")

    def test_home_network_is_left_alone_unless_its_router_differs(self):
        with open(self.m.TRUSTED, "w") as f:
            json.dump({"home-uuid": {"ssid": "Home", "routers": ["AA:BB:CC:00:00:01"]}}, f)
        self.m.pre_up("wlan0", "home-uuid")
        self.m.up("wlan0", "home-uuid")
        self.assertNotIn("LOCK", self.calls)
        self.assertNotIn("nmcli connection up vpn-uuid", self.calls)
        # the same profile, but a different router: not home any more (recognized by its password: trusted, the VPN stays on)
        self.calls.clear()
        self.mac = "DE:AD:BE:EF:00:09"
        self.m.up("wlan0", "home-uuid")
        self.assertIn("LOCK", self.calls)
        self.assertIn("nmcli connection up vpn-uuid", self.calls)
        self.key = ""  # ... and with no password to recognize it by: untrusted
        self.calls.clear()
        self.m.up("wlan0", "home-uuid")
        self.assertIn("nmcli connection up vpn-uuid", self.calls)
        self.assertEqual(self.state()["level"], "untrusted")

    def test_untrusted_network_gets_a_private_address_unless_one_was_chosen(self):
        modify = lambda: [c for c in self.calls if c.startswith("nmcli connection modify")]
        for real in ("", "permanent"):
            self.calls, self.cloned = [], real
            self.m.quiet("cafe-uuid", True)
            self.assertIn("802-11-wireless.cloned-mac-address stable", modify()[0], f"the real address ({real!r}) is replaced")
        for chosen in ("random", "stable", "02:1A:2B:3C:4D:5E"):
            self.calls, self.cloned = [], chosen
            self.m.quiet("cafe-uuid", True)
            self.assertNotIn("cloned-mac-address", modify()[0], f"a chosen address ({chosen}) is kept")
            self.assertIn("ipv4.dhcp-send-hostname no", modify()[0])

    def test_the_private_profile_has_dhcp_identifiers_and_ipv6_privacy(self):
        self.m.private_profile("cafe-uuid")
        modify = [c for c in self.calls if c.startswith("nmcli connection modify cafe-uuid")]
        self.assertEqual(len(modify), 2, self.calls)
        self.assertIn("ipv4.dhcp-client-id mac ipv6.dhcp-duid ll", modify[0])
        # the address NetworkManager makes up is locally administered; no mask may keep (or borrow) a maker's prefix
        self.assertTrue(modify[0].endswith("802-11-wireless.cloned-mac-address stable 802-11-wireless.generate-mac-address-mask "), modify[0])
        # IPv6 privacy in a call of its own: a profile NetworkManager refuses it for keeps the rest
        self.assertEqual(modify[1], "nmcli connection modify cafe-uuid ipv6.ip6-privacy 2 ipv6.addr-gen-mode stable-privacy")

    def wired(self):
        """On a wired network: eth0 up with the profile wired-uuid ("Wired connection 1"), no Wi-Fi."""
        self.ctype = "802-3-ethernet"
        self.wifi = "eth0:ethernet:connected:Wired connection 1\nwlan0:wifi:disconnected:--\n"
        os.remove(self.m.CONF)

    def test_an_untrusted_wired_network_gets_the_private_profile_and_nothing_else(self):
        self.wired()
        self.m.pre_up("eth0", "wired-uuid")
        self.m.up("eth0", "wired-uuid")
        modify = [c for c in self.calls if c.startswith("nmcli connection modify wired-uuid")]
        self.assertEqual(len(modify), 2, self.calls)
        self.assertIn("ipv4.dhcp-send-hostname no ipv6.dhcp-send-hostname no ipv4.dhcp-client-id mac ipv6.dhcp-duid ll", modify[0])
        self.assertIn("802-3-ethernet.cloned-mac-address stable 802-3-ethernet.generate-mac-address-mask ", modify[0])
        self.assertNotIn("802-11-wireless", "\n".join(self.calls))
        self.assertIn("ipv6.ip6-privacy 2", modify[1])
        # Wi-Fi's own measures are not wired's: no lockdown, no quiet table, no Avahi, no state, no VPN
        for absent in ("LOCK", "QUIET", "systemctl stop avahi-daemon.socket avahi-daemon.service", "nmcli connection up vpn-uuid"):
            self.assertNotIn(absent, self.calls)
        self.assertFalse(os.path.exists(os.path.join(self.m.RUN, "state.json")))
        n = self.last_note()
        self.assertEqual((n["event"], n["ssid"]), ("wired", "Wired connection 1"))
        self.assertIn("trust --home --real-address", n["message"])
        self.assertLessEqual(len(n["message"]), 300)  # what the notification shows
        # once a day, and not at all once the address is its own
        os.remove(os.path.join(self.m.RUN, "last.json"))
        self.m.up("eth0", "wired-uuid")
        self.assertFalse(os.path.exists(os.path.join(self.m.RUN, "last.json")))
        os.remove(os.path.join(self.m.RUN, "notes.json"))
        self.link = '[{"ifname": "eth0", "address": "02:00:00:00:00:07", "permaddr": "00:00:5e:00:53:07"}]'
        self.m.up("eth0", "wired-uuid")
        self.assertFalse(os.path.exists(os.path.join(self.m.RUN, "last.json")))
        # a chosen address is kept, and other kinds of connection (a VPN, a bridge) are not touched
        self.calls, self.cloned = [], "random"
        self.m.up("eth0", "wired-uuid")
        self.assertNotIn("cloned-mac-address", "\n".join(c for c in self.calls if "modify" in c))
        for kind in ("wireguard", "bridge", ""):
            self.calls, self.ctype = [], kind
            self.m.up("wg-heimdall", "vpn-uuid")
            self.assertFalse([c for c in self.calls if "modify" in c], kind)

    def test_a_home_wired_network_is_bound_to_its_router(self):
        self.wired()
        self.trusted({"wired-uuid": {"name": "Wired connection 1", "wired": True, "level": "home", "routers": [self.mac]}})
        self.m.up("eth0", "wired-uuid")
        self.assertFalse([c for c in self.calls if "modify" in c], "home is left as it is")
        self.mac = ""  # the router did not answer: left as it is
        self.m.up("eth0", "wired-uuid")
        self.assertFalse([c for c in self.calls if "modify" in c])
        # the same profile plugged in elsewhere: private again, and told it used the real address there
        self.mac = "00:00:5E:00:53:09"
        self.m.up("eth0", "wired-uuid")
        self.assertTrue(any("802-3-ethernet.cloned-mac-address stable" in c for c in self.calls), self.calls)
        self.assertIn("router is a different one", self.last_note()["message"])
        with open(self.m.TRUSTED) as f:
            self.assertEqual(json.load(f)["wired-uuid"]["level"], "home", "the entry stays: back home it is home again")
        # an entry that is not a wired one (a Wi-Fi entry, a hand-edited one) does not make a wired profile home
        for e in ({"ssid": "Home", "routers": [self.mac]}, {"name": "x", "wired": 1, "level": "home", "routers": [self.mac]}):
            self.trusted({"wired-uuid": e})
            self.calls = []
            self.m.up("eth0", "wired-uuid")
            self.assertTrue(any("802-3-ethernet.cloned-mac-address stable" in c for c in self.calls), e)

    def test_trust_on_a_wired_network(self):
        self.wired()
        with self.assertRaises(SystemExit) as e:
            self.m.cmd_trust([])  # nothing to stop the notices of
        self.assertIn("trust --home", str(e.exception))
        self.assertFalse(os.path.exists(self.m.TRUSTED))
        with self.assertRaises(SystemExit):
            self.m.cmd_trust(["--home", "--uuid", "other-uuid"])
        self.assertFalse(os.path.exists(self.m.TRUSTED))
        self.m.cmd_trust(["--home", "--uuid", "phone-uuid"])  # the fake's connected device answers phone-uuid
        with open(self.m.TRUSTED) as f:
            e = json.load(f)["phone-uuid"]
        self.assertEqual((e["name"], e["wired"], e["level"], e["routers"]), ("Wired connection 1", True, "home", [self.mac]))
        self.assertNotIn("ssid", e)
        self.assertNotIn("permanent", "\n".join(self.calls))
        self.m.cmd_trust(["--home", "--real-address"])
        self.assertIn("nmcli connection modify phone-uuid 802-3-ethernet.cloned-mac-address permanent ipv4.dhcp-send-hostname yes "
                      "ipv6.dhcp-send-hostname yes", self.calls)
        for absent in ("LOCK", "QUIET", "nft delete table"):  # Wi-Fi's measures are not touched
            self.assertFalse([c for c in self.calls if c.startswith(absent)], absent)
        self.m.mac, self.mac = None, ""
        self.m.router_mac = lambda iface: ""
        with self.assertRaises(SystemExit):
            self.m.cmd_trust(["--home"])
        # with Wi-Fi connected too, Wi-Fi comes first, as before; the wired one by its UUID
        self.wifi = "wlan0:wifi:connected:Cafe\neth0:ethernet:connected:Wired connection 1\n"
        with self.assertRaises(SystemExit):
            self.m.cmd_trust(["--home"])  # Wi-Fi's router did not answer either
        self.m.cmd_trust([])  # Cafe (wpa-psk): the Wi-Fi one is trusted
        with open(self.m.TRUSTED) as f:
            e = json.load(f)["phone-uuid"]
        self.assertEqual((e["ssid"], e["level"]), ("Cafe", "trusted"))

    def test_untrust_and_status_on_a_wired_network(self):
        self.wired()
        self.trusted({"wired-uuid": {"name": "Wired connection 1", "wired": True, "level": "home", "routers": [self.mac]},
                      "home-uuid": {"ssid": "Example-Home", "level": "home", "routers": [self.mac]}})
        said = []
        self.m.print = lambda *a, **k: said.append(" ".join(str(x) for x in a))
        self.m.cmd_status()
        text = "\n".join(said)
        self.assertIn("  Wired connection 1: home (wired), router " + self.mac, text)
        self.assertIn("wired now: Wired connection 1, untrusted; a hardware address of its own here: no", text)  # phone-uuid
        said.clear()
        self.cloned = "permanent"
        self.m.cmd_untrust("Wired connection 1")
        with open(self.m.TRUSTED) as f:
            self.assertEqual(list(json.load(f)), ["home-uuid"])
        modify = [c for c in self.calls if c.startswith("nmcli connection modify wired-uuid")]
        self.assertTrue(modify and "802-3-ethernet.cloned-mac-address stable" in modify[0], self.calls)
        self.assertIn("Wired connection 1 (wired): from the next connection on", "\n".join(said))

    def test_no_vpn_means_quiet_but_not_locked(self):
        os.remove(self.m.CONF)
        self.m.pre_up("wlan0", "cafe-uuid")
        self.m.up("wlan0", "cafe-uuid")
        self.assertNotIn("LOCK", self.calls)
        self.assertEqual(self.last_note()["event"], "no-vpn")

    def test_the_ruleset_allows_only_dhcp_and_the_vpn(self):
        rs = self.m.ruleset({"iface": "wg-heimdall", "endpoints": [{"ip": "203.0.113.5", "port": 51820}, {"ip": "2001:db8::5", "port": 51820}]})
        self.assertIn("policy drop;", rs)
        self.assertIn("ip daddr 203.0.113.5 udp dport 51820 accept", rs)
        self.assertIn("ip6 daddr 2001:db8::5 udp dport 51820 accept", rs)
        self.assertIn('oifname "wg-heimdall" accept', rs)
        self.assertNotIn("tcp", rs)

    def test_a_file_of_another_kind_counts_as_missing(self):
        # JSON that is not an object (a damaged or hand-edited file) is treated as a missing file, not a traceback
        for text in ("[]", "null", '"x"', "5"):
            with open(self.m.CONF, "w") as f:
                f.write(text)
            self.assertEqual(self.m.load(self.m.CONF, {}), {})
            self.m.pre_up("wlan0", "cafe-uuid")
        self.assertNotIn("LOCK", self.calls)

    def test_wireguard_files_are_read(self):
        eps = self.m.parse_wg("[Interface]\nPrivateKey = x\n[Peer]\nPublicKey = y\nEndpoint = 185.159.157.1:51820\n")
        self.assertEqual(eps, [{"ip": "185.159.157.1", "port": 51820}])


if __name__ == "__main__":
    unittest.main()
