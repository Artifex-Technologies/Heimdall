"""heimdall-dns-blocklist with lists from local files: only plain domain names become dnsmasq lines (a hostile list cannot add
directives), the allow list wins over the lists, and a list that is suddenly tiny (an error page) never replaces a good block file."""
import os
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "net", "heimdall-dns-blocklist")


class DNSBlocklist(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.src = os.path.join(self.d, "src")
        os.makedirs(self.src)
        with open(os.path.join(self.src, "hagezi-tif-mini.raw"), "w") as f:
            f.write("# Title: test\nevil.example\nPhish.Example\nok-under-evil.evil.example\nlocalhost\n"
                    "dhcp-script=/bin/sh\nconf-file=/etc/shadow\nbad domain\n-leading.example\nx.y.z.co\n")
        with open(os.path.join(self.src, "urlhaus-filter.raw"), "w") as f:
            f.write("# hosts\n0.0.0.0 malware.example\n0.0.0.0 1.2.3.4\n127.0.0.1 tracker.test\n")
        self.allow = os.path.join(self.d, "allow.txt")
        with open(self.allow, "w") as f:
            f.write("# mine\nok-under-evil.evil.example\nnot a domain;rm -rf /\n")

    def tearDown(self):
        shutil.rmtree(self.d)

    def run_it(self, *args, **env):
        e = dict(os.environ, HEIMDALL_DNS_DIR=os.path.join(self.d, "out"), HEIMDALL_DNS_ALLOW=self.allow,
                 HEIMDALL_DNS_TEST_SOURCES=self.src, HEIMDALL_DNS_MIN="3")
        e.update(env)
        return subprocess.run(["bash", SCRIPT] + list(args), capture_output=True, text=True, env=e)

    def test_only_domains_become_lines_and_the_allow_list_wins(self):
        r = self.run_it("update")
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(self.d, "out", "blocklist.conf")) as f:
            conf = f.read()
        lines = [l for l in conf.splitlines() if not l.startswith("#")]
        for l in lines:
            self.assertRegex(l, r"^(local=/[a-z0-9.-]+/|server=/[a-z0-9.-]+/#)$")
        self.assertIn("local=/evil.example/", lines)
        self.assertIn("local=/phish.example/", lines)
        self.assertIn("local=/malware.example/", lines)
        self.assertIn("local=/tracker.test/", lines)
        self.assertIn("local=/x.y.z.co/", lines)
        self.assertNotIn("dhcp-script", conf)
        self.assertNotIn("shadow", conf)
        self.assertNotIn("local=/localhost/", lines)
        self.assertNotIn("local=/1.2.3.4/", lines)
        # allowed: not blocked, and resolved normally even under a blocked parent
        self.assertNotIn("local=/ok-under-evil.evil.example/", lines)
        self.assertIn("server=/ok-under-evil.evil.example/#", lines)
        t = self.run_it("test", "a.evil.example")
        self.assertIn("is blocked (listed: evil.example)", t.stdout)
        self.assertIn("is not blocked", self.run_it("test", "example.org").stdout)

    def test_a_tiny_list_never_replaces_a_good_one(self):
        self.assertEqual(self.run_it("update").returncode, 0)
        conf = os.path.join(self.d, "out", "blocklist.conf")
        with open(conf) as f:
            good = f.read()
        for n in ("hagezi-tif-mini.raw", "urlhaus-filter.raw"):
            with open(os.path.join(self.src, n), "w") as f:
                f.write("<html>503 Service Unavailable</html>\n")
        r = self.run_it("update", HEIMDALL_DNS_MIN="5")
        self.assertNotEqual(r.returncode, 0)
        with open(conf) as f:
            self.assertEqual(f.read(), good)


if __name__ == "__main__":
    unittest.main()
