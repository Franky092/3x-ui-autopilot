"""Сертификат: повторное использование из копии и автоматическое продление по таймеру."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from autopilot import cert, core


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old = os.environ.get("AUTOPILOT_ROOT")
        os.environ["AUTOPILOT_ROOT"] = self.tmp.name
        self.src = Path(self.tmp.name) / "backup-certs"
        self.src.mkdir()
        (self.src / "fullchain.pem").write_text("CERT")
        (self.src / "privkey.pem").write_text("KEY")

    def tearDown(self):
        if self.old is None:
            os.environ.pop("AUTOPILOT_ROOT", None)
        else:
            os.environ["AUTOPILOT_ROOT"] = self.old
        self.tmp.cleanup()


class ReusableTest(Base):
    def fake(self, alive=0, match="Certificate does match IP address"):
        def run(cmd, **kw):
            if "-checkend" in cmd:
                return mock.Mock(returncode=alive, stdout="", stderr="")
            return mock.Mock(returncode=0, stdout=match, stderr="")
        return run

    def test_valid_certificate_for_this_ip_is_reusable(self):
        with mock.patch.object(core, "run", self.fake()):
            self.assertTrue(cert.reusable(self.src, "203.0.113.5"))

    def test_expiring_or_foreign_or_missing_is_not(self):
        with mock.patch.object(core, "run", self.fake(alive=1)):
            self.assertFalse(cert.reusable(self.src, "203.0.113.5"))
        with mock.patch.object(core, "run", self.fake(match="does NOT match certificate")):
            self.assertFalse(cert.reusable(self.src, "203.0.113.5"))
        (self.src / "privkey.pem").unlink()
        with mock.patch.object(core, "run", self.fake()):
            self.assertFalse(cert.reusable(self.src, "203.0.113.5"))
        self.assertFalse(cert.reusable(self.src / "none", "203.0.113.5"))

    def test_bad_ip_is_refused(self):
        with mock.patch.object(core, "run", self.fake()):
            self.assertFalse(cert.reusable(self.src, "not-an-ip; rm -rf /"))

    def test_reuse_copies_with_private_key_mode(self):
        cert.reuse(self.src)
        fullchain, key = cert.paths()
        self.assertEqual((fullchain.read_text(), key.read_text()), ("CERT", "KEY"))
        self.assertEqual(oct(key.stat().st_mode & 0o777), "0o600")


class EnsureTest(Base):
    def test_fresh_certificate_is_left_alone(self):
        with mock.patch.object(cert, "days_left", return_value=5), mock.patch.object(cert, "issue") as issue, \
                mock.patch.object(cert, "reload_services") as reload:
            self.assertFalse(cert.ensure("203.0.113.5"))
        issue.assert_not_called()
        reload.assert_not_called()

    def test_expiring_or_missing_certificate_is_issued_and_services_reloaded(self):
        for days in (2, 0, -1, None):
            with mock.patch.object(cert, "days_left", return_value=days), mock.patch.object(cert, "issue") as issue, \
                    mock.patch.object(cert, "reload_services") as reload:
                self.assertTrue(cert.ensure("203.0.113.5"), days)
            issue.assert_called_once_with("203.0.113.5")
            reload.assert_called_once()

    def test_timer_runs_our_command_not_bare_acme(self):
        self.assertIn("/usr/local/bin/autopilot cert auto", cert.SERVICE)
        self.assertNotIn("--cron", cert.SERVICE)

    def test_cert_auto_is_a_real_subcommand(self):
        from autopilot.__main__ import build_parser

        args = build_parser().parse_args(["cert", "auto"])
        self.assertEqual((args.cmd, args.action), ("cert", "auto"))


if __name__ == "__main__":
    unittest.main()
