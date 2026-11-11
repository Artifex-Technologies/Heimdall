"""heimdall-sarina-read.conf (tmpfiles.d) against a throw-away root: the heimdall user gets read access to Sarina's session
folder and to the session files made in it afterwards, enter-only access to /var/lib/sarina, never write; a missing folder
(Sarina not installed) is not an error. Runs as any user (the ACLs are set on files the test owns)."""
import os
import shutil
import subprocess
import tempfile
import unittest

CONF = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "arch", "heimdall-sarina-read.tmpfiles")
HAVE = shutil.which("systemd-tmpfiles") and shutil.which("getfacl")


def acl(path):
    out = subprocess.run(["getfacl", "-n", "-p", path], capture_output=True, text=True, check=True).stdout
    return [l.split("#")[0].strip() for l in out.splitlines() if l and not l.startswith("#")]


def effective(path):
    out = subprocess.run(["getfacl", "-n", "-p", path], capture_output=True, text=True, check=True).stdout
    for l in out.splitlines():
        if l.startswith("user:950:"):
            return l.split("#effective:")[1].strip() if "#effective:" in l else l.split(":")[2]
    return None


def tmpfiles_sets_named_acls():
    """Whether this systemd-tmpfiles, run as this user, sets an ACL for a user named in --root's passwd at all (the GitHub
    runner's does not), so that the tests below can say anything about our file."""
    if not HAVE:
        return False
    root = tempfile.mkdtemp()
    try:
        os.makedirs(os.path.join(root, "etc"))
        os.makedirs(os.path.join(root, "probe"))
        with open(os.path.join(root, "etc", "passwd"), "w") as f:
            f.write("heimdall:x:950:950::/var/lib/heimdall:/usr/bin/nologin\n")
        with open(os.path.join(root, "etc", "group"), "w") as f:
            f.write("heimdall:x:950:\n")
        conf = os.path.join(root, "probe.conf")
        with open(conf, "w") as f:
            f.write("a+ /probe - - - - u:heimdall:r-x\n")
        subprocess.run(["systemd-tmpfiles", "--root=" + root, "--create", conf], capture_output=True)
        return any(l.startswith("user:950:") for l in acl(os.path.join(root, "probe")))
    finally:
        shutil.rmtree(root)


@unittest.skipUnless(HAVE, "systemd-tmpfiles and getfacl are needed")
@unittest.skipUnless(tmpfiles_sets_named_acls(), "this systemd-tmpfiles sets no ACL when run unprivileged")
class SarinaRead(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.root, "etc"))
        with open(os.path.join(self.root, "etc", "passwd"), "w") as f:
            f.write("heimdall:x:950:950::/var/lib/heimdall:/usr/bin/nologin\n")
        with open(os.path.join(self.root, "etc", "group"), "w") as f:
            f.write("heimdall:x:950:\n")

    def tearDown(self):
        shutil.rmtree(self.root)

    def apply(self):
        return subprocess.run(["systemd-tmpfiles", "--root=" + self.root, "--create", CONF], capture_output=True, text=True)

    def test_read_only_access_for_heimdall(self):
        sessions = os.path.join(self.root, "var", "lib", "sarina", "sessions")
        os.makedirs(sessions)
        self.assertEqual(self.apply().returncode, 0)
        self.assertIn("user:950:--x", acl(os.path.dirname(sessions)))
        self.assertIn("user:950:r-x", acl(sessions))
        self.assertIn("default:user:950:r-x", acl(sessions))
        new = os.path.join(sessions, "s.json")
        fd = os.open(new, os.O_CREAT | os.O_WRONLY, 0o640)  # the mode Sarina's files have
        os.close(fd)
        self.assertEqual(effective(new), "r--", "a new session file must be readable, never writable, by heimdall")

    def test_missing_folder_is_not_an_error(self):
        r = self.apply()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.root, "var", "lib", "sarina")), "Heimdall must never create Sarina's folders")


if __name__ == "__main__":
    unittest.main()
