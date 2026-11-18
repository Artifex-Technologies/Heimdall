"""heimdall-intel-update's URLhaus ClamAV signatures in a fake root, with a stand-in curl (never the network): only signature
lines are kept, a broken or shrunken download never replaces the last good copy, the Auth-Key is never on a command line, the
switch turns it off, and root's install step puts only signature lines into ClamAV's folder (never through a link). With the
real clamscan installed, a file carrying a listed address is reported."""
import os
import shutil
import stat
import subprocess
import tempfile
import time
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "arch", "heimdall-intel-update")
KEY = "TestKey0123456789abcdef"

# the stand-in curl: the URLhaus export (key in the path, address read from -K -) comes from $FAKE_URLHAUS; every other
# address fails as a refused download would. Each call's arguments and address are logged for the tests to read.
FAKE_CURL = r"""#!/usr/bin/env python3
import os, sys
args = sys.argv[1:]
url, out = None, None
i = 0
while i < len(args):
    a = args[i]
    if a == "-o":
        out = args[i + 1]; i += 2; continue
    if a == "-K" and args[i + 1] == "-":
        for line in sys.stdin.read().splitlines():
            if line.startswith("url = "):
                url = line[len("url = "):].strip('"')
        i += 2; continue
    if a in ("--proto", "--max-time", "--max-filesize", "-H"):
        i += 2; continue
    if not a.startswith("-"):
        url = a
    i += 1
with open(os.environ["FAKE_CURL_LOG"], "a") as f:
    f.write(repr(sys.argv[1:]) + " URL " + str(url) + "\n")
want = "https://urlhaus-api.abuse.ch/v2/files/exports/%s/urlhaus_clamav.ndb" % os.environ["FAKE_KEY"]
src = os.environ.get("FAKE_URLHAUS", "")
if url == want and src and os.path.exists(src):
    with open(src, "rb") as s, open(out, "wb") as d:
        d.write(s.read())
    sys.exit(0)
sys.exit(22)
"""


def sig(i):
    return "URLhaus.Test-%d:0:*:%s" % (i, ("malware.example/%d/payload.exe" % i).encode().hex())


class IntelUpdateURLhaus(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.bin = os.path.join(self.d, "bin")
        os.makedirs(self.bin)
        self.write(os.path.join(self.bin, "curl"), FAKE_CURL, 0o755)
        self.write(os.path.join(self.bin, "clamscan-ok"), "#!/bin/sh\nexit 0\n", 0o755)
        self.write(os.path.join(self.bin, "clamscan-broken"), "#!/bin/sh\nexit 2\n", 0o755)
        self.intel = os.path.join(self.d, "intel")
        self.ipdb = os.path.join(self.d, "ipdb")
        os.makedirs(self.ipdb)
        self.write(os.path.join(self.ipdb, "dbip-country-lite.mmdb"), "fresh: no IP database download in these tests")
        self.clamav = os.path.join(self.d, "clamav")
        os.makedirs(self.clamav)
        self.config = os.path.join(self.d, "config.json")
        self.write(self.config, '{"agent_session_dir": "/x"}\n')
        self.key = os.path.join(self.d, "abusech-auth-key")
        self.write(self.key, KEY + "\n")
        self.export = os.path.join(self.d, "export.ndb")
        self.log = os.path.join(self.d, "curl.log")

    def tearDown(self):
        shutil.rmtree(self.d)

    @staticmethod
    def write(path, text, mode=None):
        with open(path, "w") as f:
            f.write(text)
        if mode is not None:
            os.chmod(path, mode)

    def env(self, **extra):
        e = dict(os.environ, PATH=self.bin + os.pathsep + os.environ["PATH"], HEIMDALL_INTEL_DIR=self.intel,
                 HEIMDALL_IPDB_DIR=self.ipdb, HEIMDALL_CLAMAV_DIR=self.clamav, HEIMDALL_CONFIG=self.config,
                 HEIMDALL_ABUSECH_KEY_FILE=self.key, HEIMDALL_URLHAUS_MIN="5", FAKE_CURL_LOG=self.log, FAKE_KEY=KEY,
                 FAKE_URLHAUS=self.export, HEIMDALL_CLAMSCAN=os.path.join(self.bin, "clamscan-ok"))
        e.update(extra)
        return e

    def update(self, **extra):
        return subprocess.run(["bash", SCRIPT], capture_output=True, text=True, env=self.env(**extra))

    def install(self, **extra):
        return subprocess.run(["bash", SCRIPT, "install-clamav"], capture_output=True, text=True, env=self.env(**extra))

    def kept(self):
        with open(os.path.join(self.intel, "urlhaus.ndb")) as f:
            return f.read().splitlines()

    def installed(self):
        with open(os.path.join(self.clamav, "heimdall-urlhaus.ndb")) as f:
            return f.read().splitlines()

    def good_export(self, n=20, extra=""):
        self.write(self.export, "".join(sig(i) + "\r\n" for i in range(n)) + extra)

    def test_signatures_are_kept_checked_and_installed(self):
        self.good_export(20, "# a comment\n\nShort:0:*:6162\nOdd:0:*:6d616c776172652e6578616d706c65;touch /tmp/x\n")
        r = self.update()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("URLhaus: 20 ClamAV signatures", r.stdout)
        self.assertEqual(self.kept(), [sig(i) for i in range(20)])
        # the key is in the address's path, never on a command line (the process list)
        with open(self.log) as f:
            calls = f.read().splitlines()
        urlhaus = [c for c in calls if "urlhaus_clamav.ndb" in c]
        self.assertEqual(len(urlhaus), 1)
        self.assertTrue(urlhaus[0].endswith("URL https://urlhaus-api.abuse.ch/v2/files/exports/%s/urlhaus_clamav.ndb" % KEY))
        for c in calls:
            self.assertNotIn(KEY, c.split(" URL ")[0])
        self.assertNotIn(KEY, r.stdout + r.stderr)
        # root's step: into ClamAV's folder, readable by everyone, owned like the folder
        r = self.install()
        self.assertEqual(r.returncode, 0, r.stderr)
        dst = os.path.join(self.clamav, "heimdall-urlhaus.ndb")
        self.assertEqual(self.installed(), [sig(i) for i in range(20)])
        st = os.stat(dst)
        self.assertEqual(stat.S_IMODE(st.st_mode), 0o644)
        self.assertEqual((st.st_uid, st.st_gid), (os.stat(self.clamav).st_uid, os.stat(self.clamav).st_gid))
        self.assertEqual([n for n in os.listdir(self.clamav) if n.startswith(".")], [])
        # unchanged: not written again
        before = st.st_mtime_ns
        time.sleep(0.02)
        self.assertEqual(self.install().returncode, 0)
        self.assertEqual(os.stat(dst).st_mtime_ns, before)

    def test_a_bad_download_never_replaces_the_last_good_copy(self):
        self.good_export(40)
        self.assertEqual(self.update().returncode, 0)
        good = self.kept()
        bad = {
            "error page": "<html><body>410 Gone</body></html>\n",
            "too few": "".join(sig(i) + "\n" for i in range(3)),
            "shrunk": "".join(sig(i) + "\n" for i in range(8)),
            "format changed": "".join(sig(i) + "\n" for i in range(30)) + "".join("URLhaus.New-%d:0:*:%s\n" % (i, "zz" * 20) for i in range(10)),
        }
        for why, text in bad.items():
            self.write(self.export, text)
            r = self.update()
            self.assertIn("refused", r.stderr, why)
            self.assertEqual(self.kept(), good, why)
        # ClamAV cannot load it
        self.good_export(40)
        r = self.update(HEIMDALL_CLAMSCAN=os.path.join(self.bin, "clamscan-broken"))
        self.assertIn("ClamAV could not load it", r.stderr)
        self.assertEqual(self.kept(), good)
        # nothing fetched at all
        os.remove(self.export)
        r = self.update()
        self.assertIn("not fetched; the last good copy stays", r.stderr)
        self.assertEqual(self.kept(), good)

    def test_without_a_key_or_switched_off_nothing_is_asked(self):
        self.good_export(20)
        os.remove(self.key)
        r = self.update()
        self.assertIn("need a free abuse.ch Auth-Key", r.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.intel, "urlhaus.ndb")))
        self.assertEqual(self.install().returncode, 0)
        self.assertFalse(os.path.exists(os.path.join(self.clamav, "heimdall-urlhaus.ndb")))
        # with the key: kept and installed; then switched off: not asked, and ClamAV's copy is removed
        self.write(self.key, KEY)
        self.assertEqual(self.update().returncode, 0)
        self.assertEqual(self.install().returncode, 0)
        self.assertTrue(os.path.exists(os.path.join(self.clamav, "heimdall-urlhaus.ndb")))
        self.write(self.config, '{"agent_session_dir": "/x", "urlhaus_clamav": false}\n')
        os.remove(self.log)
        self.update()
        with open(self.log) as f:
            self.assertNotIn("urlhaus_clamav.ndb", f.read())
        self.assertEqual(self.install().returncode, 0)
        self.assertFalse(os.path.exists(os.path.join(self.clamav, "heimdall-urlhaus.ndb")))
        # anything but false (or a damaged config) leaves it on
        for conf in ('{"urlhaus_clamav": true}', '{"urlhaus_clamav": "false"}', "{broken", "[1]"):
            self.write(self.config, conf)
            self.assertEqual(self.install().returncode, 0, conf)
            self.assertTrue(os.path.exists(os.path.join(self.clamav, "heimdall-urlhaus.ndb")), conf)

    def test_root_installs_only_signature_lines_and_never_through_a_link(self):
        os.makedirs(self.intel)
        src = os.path.join(self.intel, "urlhaus.ndb")
        secret = os.path.join(self.d, "secret")
        self.write(secret, "".join(sig(i) + "\n" for i in range(10)) + "root:$6$hash:19000:0:99999:7:::\n")
        os.symlink(secret, src)
        r = self.install()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not a plain file", r.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.clamav, "heimdall-urlhaus.ndb")))
        os.remove(src)
        shutil.copy(secret, src)
        self.assertEqual(self.install().returncode, 0)
        self.assertEqual(self.installed(), [sig(i) for i in range(10)])
        # too few signatures: ClamAV's copy stays
        self.write(src, sig(1) + "\n")
        self.assertNotEqual(self.install().returncode, 0)
        self.assertEqual(len(self.installed()), 10)
        # no ClamAV: nothing to do
        shutil.rmtree(self.clamav)
        self.assertEqual(self.install().returncode, 0)

    @unittest.skipUnless(shutil.which("clamscan"), "ClamAV is not installed")
    def test_clamav_reports_a_file_carrying_a_listed_address(self):
        self.good_export(20)
        r = self.update(HEIMDALL_CLAMSCAN="clamscan")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.install().returncode, 0)
        doc = os.path.join(self.d, "invoice.html")
        self.write(doc, '<a href="http://malware.example/7/payload.exe">your invoice</a>\n')
        clean = os.path.join(self.d, "clean.html")
        self.write(clean, '<a href="https://example.org/">nothing here</a>\n')
        out = subprocess.run(["clamscan", "--no-summary", "-d", os.path.join(self.clamav, "heimdall-urlhaus.ndb"), doc, clean],
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
        self.assertIn(doc + ": URLhaus.Test-7.UNOFFICIAL FOUND", out.stdout)
        self.assertIn(clean + ": OK", out.stdout)


if __name__ == "__main__":
    unittest.main()
