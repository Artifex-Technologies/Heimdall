"""heimdall-enable-defaults: an OS image with /etc/heimdall/defaults-off keeps Heimdall off; --force switches it on."""
import os
import pathlib
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "net" / "heimdall-enable-defaults"


class DefaultsOff(unittest.TestCase):
    def run_in(self, root, *args):
        # the script with its paths under `root`, and a systemctl that only records what it was asked
        text = SCRIPT.read_text().replace("/etc/heimdall/defaults-off", f"{root}/etc/heimdall/defaults-off")
        script = pathlib.Path(root, "enable.sh")
        script.write_text(text)
        bindir = pathlib.Path(root, "bin")
        bindir.mkdir(exist_ok=True)
        fake = bindir / "systemctl"
        fake.write_text(f'#!/bin/sh\necho "$@" >> {root}/calls\n')
        fake.chmod(0o755)
        env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}")
        out = subprocess.run(["sh", str(script), *args], capture_output=True, text=True, env=env)
        calls = pathlib.Path(root, "calls")
        return out, calls.read_text().splitlines() if calls.exists() else []

    def test_switched_on_without_the_file(self):
        with tempfile.TemporaryDirectory() as root:
            out, calls = self.run_in(root)
            self.assertEqual(out.returncode, 0)
            self.assertIn("enable heimdall.service", calls)

    def test_left_off_with_the_file_until_forced(self):
        with tempfile.TemporaryDirectory() as root:
            pathlib.Path(root, "etc/heimdall").mkdir(parents=True)
            pathlib.Path(root, "etc/heimdall/defaults-off").touch()
            out, calls = self.run_in(root)
            self.assertEqual((out.returncode, calls), (0, []))
            self.assertIn("nothing was switched on", out.stdout)
            out, calls = self.run_in(root, "--force")
            self.assertIn("enable heimdall.service", calls)


if __name__ == "__main__":
    unittest.main()
