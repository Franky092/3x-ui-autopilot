"""Сертификат: сбой хука перезагрузки не должен отменять успешный выпуск."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from autopilot import cert, core


class InstallFilesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old = os.environ.get("AUTOPILOT_ROOT")
        os.environ["AUTOPILOT_ROOT"] = self.tmp.name
        core.path(cert.CERT_DIR).mkdir(parents=True)

    def tearDown(self):
        if self.old is None:
            os.environ.pop("AUTOPILOT_ROOT", None)
        else:
            os.environ["AUTOPILOT_ROOT"] = self.old
        self.tmp.cleanup()

    def fake_run(self, rc, write=True):
        def run(cmd, **kw):
            if write:
                for p in cert.paths():
                    p.write_text("data")
            return mock.Mock(returncode=rc, stdout="", stderr="Reload error for: 203.0.113.5")
        return run

    def test_reload_hook_failure_is_not_fatal_when_files_are_installed(self):
        with mock.patch.object(core, "run", self.fake_run(1)):
            cert._install_files("203.0.113.5")  # не бросает
        self.assertEqual(oct(cert.paths()[1].stat().st_mode & 0o777), "0o600")

    def test_missing_files_are_fatal(self):
        with mock.patch.object(core, "run", self.fake_run(1, write=False)):
            with self.assertRaises(core.Error):
                cert._install_files("203.0.113.5")

    def test_empty_files_are_fatal(self):
        for p in cert.paths():
            p.write_text("")
        with mock.patch.object(core, "run", lambda *a, **k: mock.Mock(returncode=0, stdout="", stderr="")):
            with self.assertRaises(core.Error):
                cert._install_files("203.0.113.5")


class OrderTest(unittest.TestCase):
    def test_cli_is_installed_before_the_certificate_step(self):
        import inspect

        from autopilot import installer

        src = inspect.getsource(installer._install_locked)
        self.assertLess(src.index("install_cli()"), src.index("issue_certificate(plan)"))


if __name__ == "__main__":
    unittest.main()
