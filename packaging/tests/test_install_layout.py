"""packaging/install.sh into a temporary folder (nothing on this computer is touched), the switched layout
(docs/RUST_SWITCH.md, stage 1): /usr/bin/heimdalld is the Rust binary, the Go one sits at /usr/lib/heimdall/heimdalld-go as
the rollback, and the Wi-Fi helpers are links to heimdalld, started under their own names, with their Python programs kept
as the fallback. Without a Rust build the package is not made at all."""
import filecmp
import os
import shutil
import subprocess
import tempfile
import unittest

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
HELPERS = {"heimdall-wifi-check": "arch", "heimdall-wifi-guard": "net", "heimdall-wifi-notify": "net"}
# what the fake Rust binary prints for the shell programs' build check in install.sh
USAGE = "heimdall-dns-blocklist: block known bad domains"


def install(with_rust):
    src = tempfile.mkdtemp()
    for d in ("packaging", "docs"):
        shutil.copytree(os.path.join(REPO, d), os.path.join(src, d), ignore=shutil.ignore_patterns("__pycache__"))
    for f in ("LICENSE", "README.md", "NOTICE-ATTACK"):
        shutil.copy(os.path.join(REPO, f), src)
    with open(os.path.join(src, "heimdalld-go"), "w") as f:
        f.write("#!/bin/sh\necho go\n")
    if with_rust:
        rs = os.path.join(src, "rust", "target", "release", "heimdalld-rs")
        os.makedirs(os.path.dirname(rs))
        with open(rs, "w") as f:
            f.write('#!/bin/sh\nn=$(basename "$0")\n'
                    '[ "$n" = heimdall-dns-blocklist ] && [ $# -eq 0 ] && { echo "%s"; exit 2; }\n'
                    'echo "rust $n"\n' % USAGE)
        os.chmod(rs, 0o755)
    dest = tempfile.mkdtemp()
    r = subprocess.run(["sh", os.path.join(src, "packaging", "install.sh"), dest], cwd=src, capture_output=True, text=True)
    return dest, r


class Layout(unittest.TestCase):
    def test_heimdalld_is_rust_and_go_is_the_rollback(self):
        d, r = install(True)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = subprocess.run([os.path.join(d, "usr/bin/heimdalld")], capture_output=True, text=True).stdout
        self.assertEqual(out, "rust heimdalld\n")
        go = os.path.join(d, "usr/lib/heimdall/heimdalld-go")
        self.assertTrue(os.access(go, os.X_OK))
        self.assertEqual(subprocess.run([go], capture_output=True, text=True).stdout, "go\n")
        # one Rust binary, not a second copy for the helpers
        self.assertFalse(os.path.exists(os.path.join(d, "usr/lib/heimdall/heimdalld-rs")))

    def test_the_helpers_are_links_to_heimdalld_and_python_stays(self):
        d, r = install(True)
        self.assertEqual(r.returncode, 0, r.stderr)
        for name, folder in HELPERS.items():
            link = os.path.join(d, "usr/bin", name)
            self.assertTrue(os.path.islink(link), name)
            self.assertEqual(os.readlink(link), "heimdalld")
            # started through the link, the program sees the helper's name (what picks the helper)
            out = subprocess.run([link], capture_output=True, text=True).stdout
            self.assertEqual(out, "rust %s\n" % name)
            fallback = os.path.join(d, "usr/lib/heimdall/python", name)
            self.assertTrue(filecmp.cmp(fallback, os.path.join(REPO, "packaging", folder, name), shallow=False))
            self.assertTrue(os.access(fallback, os.X_OK))

    def test_without_the_rust_build_no_package(self):
        _, r = install(False)
        self.assertNotEqual(r.returncode, 0)

    def test_the_units_and_dispatcher_scripts_call_the_same_paths(self):
        d, r = install(True)
        self.assertEqual(r.returncode, 0, r.stderr)
        for f, want in [
            ("usr/lib/systemd/system/heimdall.service", "ExecStart=/usr/bin/heimdalld run"),
            ("usr/lib/systemd/system/heimdall-wifi-check@.service", "ExecStart=/usr/bin/heimdall-wifi-check --uuid %i"),
            ("usr/lib/NetworkManager/dispatcher.d/50-heimdall-wifi-guard", "/usr/bin/heimdall-wifi-guard"),
            ("usr/lib/NetworkManager/dispatcher.d/pre-up.d/50-heimdall-wifi-guard", "/usr/bin/heimdall-wifi-guard pre-up"),
            ("usr/lib/systemd/user/heimdall-wifi-notify.service", "ExecStart=/usr/bin/heimdall-wifi-notify"),
        ]:
            with open(os.path.join(d, f)) as fh:
                self.assertIn(want, fh.read(), f)


if __name__ == "__main__":
    unittest.main()
