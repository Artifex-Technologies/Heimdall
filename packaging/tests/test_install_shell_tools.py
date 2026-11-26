"""packaging/install.sh into a temporary folder (nothing on this computer is touched): the programs that were shell scripts
(heimdall-intel-update, heimdall-dns-blocklist, heimdall-enable-defaults, the dispatcher 91-heimdall-netid) are links to
the Rust heimdalld, which picks the program by the name it is started as; the scripts are not installed; the units and the
pacman hook call the same paths; and the build stops when the heimdalld installed is not the Rust one (merged before stage 1
of the switch, docs/RUST_SWITCH.md)."""
import os
import shutil
import subprocess
import tempfile
import unittest

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
TOOLS = ("heimdall-intel-update", "heimdall-dns-blocklist", "heimdall-enable-defaults")

# stands in for the Rust heimdalld: started as heimdall-dns-blocklist without arguments it prints that program's usage on
# standard output (as the real one does); otherwise it says which name it was started as
RUST = """#!/bin/sh
n=$(basename "$0")
if [ "$n" = heimdall-dns-blocklist ] && [ $# -eq 0 ]; then
  echo "heimdall-dns-blocklist: block known malware, phishing, scam and botnet domains for every program on this computer."
  exit 2
fi
echo "rust $n $*"
"""
# a heimdalld that is not the Rust one (the Go heimdalld of before the switch): its usage on standard error whatever its name
GO = """#!/bin/sh
echo "heimdalld -- Heimdall agent-behavior monitor" >&2
exit 2
"""


def install(heimdalld):
    src = tempfile.mkdtemp()
    for d in ("packaging", "docs"):
        shutil.copytree(os.path.join(REPO, d), os.path.join(src, d), ignore=shutil.ignore_patterns("__pycache__"))
    for f in ("LICENSE", "README.md", "NOTICE-ATTACK"):
        shutil.copy(os.path.join(REPO, f), src)
    # the Rust build becomes /usr/bin/heimdalld
    rs = os.path.join(src, "rust", "target", "release", "heimdalld-rs")
    os.makedirs(os.path.dirname(rs))
    with open(rs, "w") as f:
        f.write(heimdalld)
    os.chmod(rs, 0o755)
    dest = tempfile.mkdtemp()
    r = subprocess.run(["sh", os.path.join(src, "packaging", "install.sh"), dest], cwd=src, capture_output=True, text=True)
    return dest, r


class ShellTools(unittest.TestCase):
    def test_the_programs_are_links_to_the_rust_heimdalld(self):
        d, r = install(RUST)
        self.assertEqual(r.returncode, 0, r.stderr)
        heimdalld = os.path.join(d, "usr/bin/heimdalld")
        for name in TOOLS:
            link = os.path.join(d, "usr/bin", name)
            self.assertTrue(os.path.islink(link), name)
            self.assertEqual(os.readlink(link), "heimdalld")
            self.assertEqual(os.path.realpath(link), os.path.realpath(heimdalld))
            # started through the link, the program sees the name (what picks the program)
            out = subprocess.run([link, "x"], capture_output=True, text=True).stdout
            self.assertEqual(out, "rust %s x\n" % name)
        netid = os.path.join(d, "usr/lib/NetworkManager/dispatcher.d/91-heimdall-netid")
        self.assertTrue(os.path.islink(netid))
        self.assertEqual(os.readlink(netid), "/usr/bin/heimdalld")

    def test_the_scripts_are_not_installed(self):
        d, _ = install(RUST)
        for root, _, files in os.walk(d):
            for f in files:
                p = os.path.join(root, f)
                if os.path.islink(p) or not os.path.isfile(p):
                    continue
                with open(p, "rb") as fh:
                    head = fh.read(64)
                self.assertFalse(head.startswith(b"#!/bin/bash") and f in TOOLS, p)
        for name in ("heimdall-intel-update", "heimdall-dns-blocklist", "heimdall-enable-defaults"):
            self.assertTrue(os.path.islink(os.path.join(d, "usr/bin", name)))

    def test_the_units_and_the_hook_call_the_same_paths(self):
        d, _ = install(RUST)
        for f, want in [
            ("usr/lib/systemd/system/heimdall-intel-update.service", "ExecStart=/usr/bin/heimdall-intel-update\n"),
            ("usr/lib/systemd/system/heimdall-dns-blocklist.service", "ExecStart=/usr/bin/heimdall-dns-blocklist update\n"),
            ("usr/lib/systemd/system/heimdall-dns-blocklist.service", "ExecStartPost=+/usr/bin/heimdall-dns-blocklist apply\n"),
            ("usr/share/libalpm/hooks/heimdall-install.hook", "Exec = /usr/bin/heimdall-enable-defaults\n"),
        ]:
            with open(os.path.join(d, f)) as fh:
                self.assertIn(want, fh.read(), f)

    def test_the_build_stops_without_the_rust_heimdalld(self):
        _, r = install(GO)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not the Rust heimdalld", r.stderr)


if __name__ == "__main__":
    unittest.main()
