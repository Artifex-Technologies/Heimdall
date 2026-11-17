"""91-heimdall-netid (the NetworkManager dispatcher the rogue-router watch reads) against a throwaway folder: one JSON line per
connection event with only address characters in the values, nothing for a VPN or bridge, and the file cut short when large."""
import json
import os
import subprocess
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "net", "dispatcher.d", "91-heimdall-netid")


class NetID(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.sys = os.path.join(self.tmp.name, "sys")
        self.run_dir = os.path.join(self.tmp.name, "run")
        os.makedirs(os.path.join(self.sys, "wlan0", "device"))

    def tearDown(self):
        self.tmp.cleanup()

    def call(self, iface, action, **env):
        e = {"PATH": os.environ["PATH"], "HEIMDALL_NETID_SYS": self.sys, "HEIMDALL_NETID_DIR": self.run_dir, **env}
        subprocess.run(["sh", SCRIPT, iface, action], env=e, check=True)
        try:
            with open(os.path.join(self.run_dir, "netid.jsonl")) as f:
                return [json.loads(l) for l in f]
        except FileNotFoundError:
            return []

    def test_a_lease_is_recorded_and_cleaned(self):
        got = self.call("wlan0", "dhcp4-change", CONNECTION_UUID='0000-ab"x', DHCP4_DHCP_SERVER_IDENTIFIER='192.0.2.1"};x',
                        DHCP4_ROUTERS="192.0.2.1", DHCP4_DOMAIN_NAME_SERVERS="192.0.2.53 192.0.2.54", IP6_NAMESERVERS="2001:db8::1")
        self.assertEqual(len(got), 1)
        l = got[0]
        self.assertEqual((l["action"], l["iface"], l["uuid"], l["dhcp4_server"], l["dns4"], l["dns6"]),
                         ("dhcp4-change", "wlan0", "0000-ab", "192.0.2.1", "192.0.2.53 192.0.2.54", "2001:db8::1"))
        self.assertEqual(os.stat(os.path.join(self.run_dir, "netid.jsonl")).st_mode & 0o777, 0o640)

    def test_other_actions_and_virtual_interfaces_are_skipped(self):
        self.assertEqual(self.call("wlan0", "pre-up"), [])
        self.assertEqual(self.call("wg0", "up"), [])

    def test_the_file_is_cut_short(self):
        os.makedirs(self.run_dir)
        with open(os.path.join(self.run_dir, "netid.jsonl"), "w") as f:
            f.write(('{"t":1,"action":"up","iface":"wlan0"}' + " " * 60 + "\n") * 1000)
        got = self.call("wlan0", "down")
        self.assertEqual(len(got), 201)
        self.assertEqual(got[-1]["action"], "down")


if __name__ == "__main__":
    unittest.main()
