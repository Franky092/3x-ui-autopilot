"""Тесты SSH и fail2ban."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from autopilot import core, harden


class HardenTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.old_root = os.environ.get("AUTOPILOT_ROOT")
        os.environ["AUTOPILOT_ROOT"] = self.temp.name
        self.root = Path(self.temp.name)
        config = core.path("etc/ssh/sshd_config")
        config.parent.mkdir(parents=True)
        config.write_text("Include /etc/ssh/sshd_config.d/*.conf\n")

    def tearDown(self) -> None:
        if self.old_root is None:
            os.environ.pop("AUTOPILOT_ROOT", None)
        else:
            os.environ["AUTOPILOT_ROOT"] = self.old_root
        self.temp.cleanup()

    def add_key(self) -> None:
        directory = core.path("root/.ssh")
        directory.mkdir(parents=True)
        import base64
        import struct

        blob = struct.pack(">I", 11) + b"ssh-ed25519" + b"\x00" * 32
        (directory / "authorized_keys").write_text("ssh-ed25519 %s test\n" % base64.b64encode(blob).decode())

    def test_harden_refuses_without_key(self) -> None:
        with self.assertRaisesRegex(core.Error, "нет ни одного ключа"):
            harden.harden_ssh()

    def test_dry_run_writes_nothing(self) -> None:
        self.add_key()
        result = harden.harden_ssh(dry_run=True)
        self.assertIn("ничего не изменено", result)
        self.assertFalse(core.path(harden.DROPIN).exists())

    def test_dropin_removed_when_sshd_test_fails(self) -> None:
        self.add_key()
        def run(cmd, **kwargs):
            if cmd == ["sshd", "-t"]:
                return SimpleNamespace(returncode=1, stdout="", stderr="bad")
            return SimpleNamespace(returncode=0, stdout="passwordauthentication no\n", stderr="")
        with mock.patch.object(core, "run", side_effect=run):
            with self.assertRaises(core.Error):
                harden.harden_ssh()
        self.assertFalse(core.path(harden.DROPIN).exists())

    def test_fail2ban_jail_content(self) -> None:
        def run(cmd, **kwargs):
            if cmd[:2] == ["sshd", "-T"]:
                return SimpleNamespace(returncode=0, stdout="port 2222\n", stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        with mock.patch.object(harden.shutil, "which", return_value="/usr/bin/fail2ban-client"), \
             mock.patch.object(core, "run", side_effect=run), \
             mock.patch.object(core, "systemctl", return_value=SimpleNamespace(returncode=0)):
            harden.setup_fail2ban()
        content = core.path("etc/fail2ban/jail.d/zz-autopilot.local").read_text()
        for line in ("ignoreip = 127.0.0.1/8 ::1", "bantime.increment = true", "bantime.maxtime = 4w",
                     "port = 2222", "backend = systemd", "[recidive]", "logpath = /var/log/fail2ban.log"):
            self.assertIn(line, content)




class WaitJailTest(unittest.TestCase):
    def test_waits_until_jail_answers(self):
        from unittest import mock

        answers = iter([1, 1, 0])
        fake = lambda *a, **k: mock.Mock(returncode=next(answers))  # noqa: E731
        sleeps = []
        with mock.patch("autopilot.core.run", fake):
            self.assertTrue(harden.wait_jail("sshd", sleep=sleeps.append))
        self.assertEqual(len(sleeps), 2)

    def test_gives_up(self):
        from unittest import mock

        with mock.patch("autopilot.core.run", lambda *a, **k: mock.Mock(returncode=1)):
            self.assertFalse(harden.wait_jail("sshd", attempts=3, sleep=lambda s: None))


if __name__ == "__main__":
    unittest.main()
