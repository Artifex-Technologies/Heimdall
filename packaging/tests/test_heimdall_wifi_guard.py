"""heimdall-wifi-guard's decisions with NetworkManager, nft and systemctl replaced by a recorder: what happens on trusted and
untrusted networks, when the VPN connects, fails, or drops later. Nothing on the real system is touched."""
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
        self.calls, self.vpn_ok, self.table = [], True, False
        self.mac = "AA:BB:CC:00:00:01"
        self.cloned = ""
        m = self

        def sh(argv, timeout=30, check=False):
            m.calls.append(" ".join(argv))
            out, rc = "", 0
            if argv[:2] == ["nft", "list"]:
                rc = 0 if m.table else 1
            elif argv[:3] == ["nft", "delete", "table"]:
                m.table = False
            elif argv[:3] == ["nmcli", "connection", "up"]:
                rc = 0 if m.vpn_ok else 4
            elif argv[:3] == ["nmcli", "-g", "802-11-wireless.ssid"]:
                out = "Cafe"
            elif argv[:3] == ["nmcli", "-g", "802-11-wireless.cloned-mac-address"]:
                out = m.cloned + "\n"
            elif argv[:2] == ["systemctl", "is-active"]:
                out = "active"
            return types.SimpleNamespace(returncode=rc, stdout=out, stderr="")

        def lock(vpn):
            m.table = True
            m.calls.append("LOCK")
            m.m.set_state(locked=True)

        self.m.sh = sh
        self.m.router_mac = lambda iface: m.mac
        self.real_lock = self.m.lock
        self.m.lock = lock
        self.m.is_wifi = lambda iface: iface == "wlan0"
        with open(self.m.CONF, "w") as f:
            json.dump({"vpn": {"uuid": "vpn-uuid", "iface": "wg-heimdall", "endpoints": [{"ip": "203.0.113.5", "port": 51820}]}}, f)

    def last_note(self):
        with open(os.path.join(self.m.RUN, "last.json")) as f:
            return json.load(f)

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

    def test_trusted_network_is_left_alone_unless_its_router_differs(self):
        with open(self.m.TRUSTED, "w") as f:
            json.dump({"home-uuid": {"ssid": "Home", "routers": ["AA:BB:CC:00:00:01"]}}, f)
        self.m.pre_up("wlan0", "home-uuid")
        self.m.up("wlan0", "home-uuid")
        self.assertNotIn("LOCK", self.calls)
        self.assertNotIn("nmcli connection up vpn-uuid", self.calls)
        # the same profile, but a different router: a stranger with the home network's name
        self.calls.clear()
        self.mac = "DE:AD:BE:EF:00:09"
        self.m.up("wlan0", "home-uuid")
        self.assertIn("LOCK", self.calls)
        self.assertIn("nmcli connection up vpn-uuid", self.calls)

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

    def test_wireguard_files_are_read(self):
        eps = self.m.parse_wg("[Interface]\nPrivateKey = x\n[Peer]\nPublicKey = y\nEndpoint = 185.159.157.1:51820\n")
        self.assertEqual(eps, [{"ip": "185.159.157.1", "port": 51820}])


if __name__ == "__main__":
    unittest.main()
