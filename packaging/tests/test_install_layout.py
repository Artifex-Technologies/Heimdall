"""packaging/install.sh into a temporary folder (nothing on this computer is touched): with the Rust heimdalld built, the
Wi-Fi helpers are links to it, started under their own names, and their Python programs stay as the fallback; without it
(a recipe that builds only Go), the Python programs are installed as before."""
import filecmp
import os
import shutil
import subprocess
import tempfile
import unittest

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
HELPERS = {"heimdall-wifi-check": "arch", "heimdall-wifi-guard": "net", "heimdall-wifi-notify": "net"}


def install(with_rust):
    src = tempfile.mkdtemp()
    for d in ("packaging", "docs"):
        shutil.copytree(os.path.join(REPO, d), os.path.join(src, d), ignore=shutil.ignore_patterns("__pycache__"))
    for f in ("LICENSE", "README.md"):
        shutil.copy(os.path.join(REPO, f), src)
    with open(os.path.join(src, "heimdalld"), "w") as f:
        f.write("#!/bin/sh\necho go\n")
    if with_rust:
        os.makedirs(os.path.join(src, "rust", "target", "release"))
        with open(os.path.join(src, "rust", "target", "release", "heimdalld-rs"), "w") as f:
            f.write('#!/bin/sh\necho "rust $(basename "$0")"\n')
        os.chmod(os.path.join(src, "rust", "target", "release", "heimdalld-rs"), 0o755)
    dest = tempfile.mkdtemp()
    r = subprocess.run(["sh", os.path.join(src, "packaging", "install.sh"), dest], cwd=src, capture_output=True, text=True)
    return dest, r


class Layout(unittest.TestCase):
    def test_with_rust_the_helpers_are_links_and_python_stays(self):
        d, r = install(True)
        self.assertEqual(r.returncode, 0, r.stderr)
        rs = os.path.join(d, "usr/lib/heimdall/heimdalld-rs")
        self.assertTrue(os.access(rs, os.X_OK))
        for name, folder in HELPERS.items():
            link = os.path.join(d, "usr/bin", name)
            self.assertTrue(os.path.islink(link), name)
            self.assertEqual(os.readlink(link), "../lib/heimdall/heimdalld-rs")
            self.assertEqual(os.path.realpath(link), os.path.realpath(rs))
            # started through the link, the program sees the helper's name (what picks the helper)
            out = subprocess.run([link], capture_output=True, text=True).stdout
            self.assertEqual(out, "rust %s\n" % name)
            fallback = os.path.join(d, "usr/lib/heimdall/python", name)
            self.assertTrue(filecmp.cmp(fallback, os.path.join(REPO, "packaging", folder, name), shallow=False))
            self.assertTrue(os.access(fallback, os.X_OK))
        # the daemon is not changed by this (the switch does that, docs/RUST_SWITCH.md)
        with open(os.path.join(d, "usr/bin/heimdalld")) as f:
            self.assertIn("echo go", f.read())

    def test_without_rust_the_python_programs_are_installed_as_before(self):
        d, r = install(False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("not built", r.stderr)
        self.assertFalse(os.path.exists(os.path.join(d, "usr/lib/heimdall/heimdalld-rs")))
        for name, folder in HELPERS.items():
            path = os.path.join(d, "usr/bin", name)
            self.assertFalse(os.path.islink(path))
            self.assertTrue(filecmp.cmp(path, os.path.join(REPO, "packaging", folder, name), shallow=False))
        self.assertFalse(os.path.exists(os.path.join(d, "usr/lib/heimdall/python")))

    def test_the_units_and_dispatcher_scripts_call_the_same_paths(self):
        d, _ = install(True)
        for f, want in [
            ("usr/lib/systemd/system/heimdall-wifi-check@.service", "ExecStart=/usr/bin/heimdall-wifi-check --uuid %i"),
            ("usr/lib/NetworkManager/dispatcher.d/50-heimdall-wifi-guard", "/usr/bin/heimdall-wifi-guard"),
            ("usr/lib/NetworkManager/dispatcher.d/pre-up.d/50-heimdall-wifi-guard", "/usr/bin/heimdall-wifi-guard pre-up"),
            ("usr/lib/systemd/user/heimdall-wifi-notify.service", "ExecStart=/usr/bin/heimdall-wifi-notify"),
        ]:
            with open(os.path.join(d, f)) as fh:
                self.assertIn(want, fh.read(), f)


if __name__ == "__main__":
    unittest.main()
