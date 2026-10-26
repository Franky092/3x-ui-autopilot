"""Команды acme.sh и загрузка с проверкой хэша."""
import hashlib
import io
import os
import tempfile
import unittest
from pathlib import Path

from autopilot import cert, core


class Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class CertTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old = os.environ.get("AUTOPILOT_ROOT")
        os.environ["AUTOPILOT_ROOT"] = self.tmp.name

    def tearDown(self):
        if self.old is None:
            os.environ.pop("AUTOPILOT_ROOT", None)
        else:
            os.environ["AUTOPILOT_ROOT"] = self.old
        self.tmp.cleanup()

    def test_issue_command_uses_shortlived_profile_and_ip(self):
        cmd = cert.issue_command("203.0.113.7")
        self.assertIn("shortlived", cmd)
        self.assertEqual(cmd[cmd.index("-d") + 1], "203.0.113.7")
        self.assertEqual(cmd[cmd.index("--days") + 1], "3")

    def test_hostile_ip_rejected(self):
        for bad in ("1.2.3.4; rm -rf /", "example.com", "::1", ""):
            with self.assertRaises(core.Error):
                cert.issue_command(bad)

    def test_install_command_has_reload_hook(self):
        cmd = cert.install_command("203.0.113.7")
        self.assertEqual(cmd[cmd.index("--reloadcmd") + 1], cert.RELOAD_COMMAND)
        self.assertTrue(cmd[cmd.index("--fullchain-file") + 1].endswith("etc/autopilot/certs/ip/fullchain.pem"))

    def test_fetch_checks_pinned_hash(self):
        def bad(url, timeout):
            return Resp(b"not acme.sh")
        with self.assertRaises(core.Error):
            cert.fetch_acme(opener=bad)
        self.assertFalse(core.path(cert.ACME_BIN).exists())

    def test_hook_is_a_real_subcommand(self):
        from autopilot.__main__ import build_parser

        args = build_parser().parse_args(cert.RELOAD_COMMAND.split()[1:])
        self.assertEqual((args.cmd, args.action), ("cert", "reload"))

    def test_pins(self):
        self.assertRegex(cert.ACME_COMMIT, r"^[0-9a-f]{40}$")
        self.assertRegex(cert.ACME_SHA256, r"^[0-9a-f]{64}$")

    def test_days_left_missing_file(self):
        self.assertIsNone(cert.days_left(Path(self.tmp.name) / "none.pem"))


if __name__ == "__main__":
    unittest.main()
