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

    def test_trusted_needs_the_remembered_router(self):
        d = tempfile.mkdtemp()
        self.m.TRUSTED = os.path.join(d, "trusted.json")
        with open(self.m.TRUSTED, "w") as f:
            json.dump({"u1": {"ssid": "Home", "routers": ["00:00:5E:00:53:01"]}}, f)
        self.assertTrue(self.m.is_trusted("u1", "00:00:5E:00:53:01"))
        self.assertFalse(self.m.is_trusted("u1", ""))  # the router did not answer: not trusted, as in the guard
        self.assertFalse(self.m.is_trusted("u1", "00:00:5E:00:53:09"))
        self.assertFalse(self.m.is_trusted("u2", "00:00:5E:00:53:01"))
        self.assertFalse(self.m.is_trusted("", "00:00:5E:00:53:01"))


if __name__ == "__main__":
    unittest.main()
