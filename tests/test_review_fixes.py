"""Регрессии по замечаниям ревью: каждый сценарий из отчёта закреплён тестом."""
import base64
import json
import os
import stat
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from autopilot import backup, core, harden, installer, nginx, notify, ui


def real_key(kind="ssh-ed25519"):
    name = kind.encode()
    blob = struct.pack(">I", len(name)) + name + b"\x00" * 32
    return "%s %s user@host" % (kind, base64.b64encode(blob).decode())


class Base(unittest.TestCase):
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


class SshKeyTest(Base):
    def test_real_keys_accepted_with_options(self):
        self.assertTrue(harden.valid_key_line(real_key()))
        self.assertTrue(harden.valid_key_line('from="1.2.3.4",no-pty ' + real_key("ssh-rsa")))

    def test_broken_keys_rejected(self):
        for bad in ("ssh-ed25519 AAAA", "ssh-ed25519", "ssh-ed25519 !!!notbase64", "ssh-rsa " + real_key().split()[1], "", "# " + real_key()):
            self.assertFalse(harden.valid_key_line(bad), bad)

    def test_file_with_only_garbage_has_no_key(self):
        ssh = Path(self.tmp.name) / "ssh"
        ssh.mkdir()
        (ssh / "authorized_keys").write_text("ssh-ed25519 AAAA broken\n# comment\n")
        self.assertFalse(harden.ssh_has_key(ssh))
        (ssh / "authorized_keys").write_text("ssh-ed25519 AAAA broken\n" + real_key() + "\n")
        self.assertTrue(harden.ssh_has_key(ssh))


class BackupKeepTest(Base):
    def test_negative_or_huge_keep_falls_back(self):
        cfg = core.path(backup.CONFIG)
        for raw, expected in (('{"keep": -1}', 7), ('{"keep": 0}', 7), ('{"keep": 5000}', 7), ('{"keep": 3}', 3), ("garbage", 7), ("[]", 7)):
            core.write_file(cfg, raw)
            self.assertEqual(backup._read_keep(cfg), expected, raw)

    def test_rotate_never_deletes_everything(self):
        directory = Path(self.tmp.name) / "b"
        directory.mkdir()
        for i in range(3):
            (directory / ("backup-%d.tar.gz.enc" % i)).write_text("x")
        backup.rotate(directory, -1)
        self.assertEqual(len(list(directory.iterdir())), 1)

    def test_decrypt_output_is_private_from_the_start(self):
        target = Path(self.tmp.name) / "out.bin"
        with mock.patch("subprocess.Popen", side_effect=OSError("no openssl")):
            with self.assertRaises(core.Error):
                backup.decrypt_file(Path(self.tmp.name) / "in", target, "x")
        self.assertFalse(target.exists())  # не оставляем и пустой файл


class NginxPathsTest(Base):
    def lay(self, **kw):
        base = dict(sni_routes={"a.example.com": 1}, cert_file="/etc/autopilot/c.pem", key_file="/etc/autopilot/k.pem")
        base.update(kw)
        return nginx.Layout(**base)

    def test_injection_in_cert_path_rejected(self):
        for bad in ("/c.pem;\n  include /etc/passwd;", "/c.pem\nfoo", "/a b.pem", "relative.pem", "/a/../etc/x.pem", '/c"x.pem'):
            with self.assertRaises(core.Error, msg=bad):
                nginx.render(self.lay(cert_file=bad))
            with self.assertRaises(core.Error, msg=bad):
                nginx.render(self.lay(key_file=bad))

    def test_bad_sub_path_rejected(self):
        with self.assertRaises(core.Error):
            nginx.render(self.lay(sub_paths=["/x; return 200/"], sub_port=2096))
        with self.assertRaises(core.Error):
            nginx.render(self.lay(sub_paths=["/ok/"], sub_port=0))


class NotifyRecoveryTest(Base):
    def test_failed_recovery_is_retried(self):
        core.write_env(core.path(notify.ENV_FILE), {"NOTIFY_TOKEN": "123456789:" + "A" * 35, "NOTIFY_CHAT": "42"})
        core.write_file(core.path(notify.STATE_FILE), json.dumps({"disk": "Диск заполнен"}))
        with mock.patch.object(notify, "collect_alerts", return_value={}):
            self.assertEqual(notify.check(None, send=lambda text: False), [])
            self.assertIn("disk", json.loads(core.path(notify.STATE_FILE).read_text()))
            sent = notify.check(None, send=lambda text: True)
        self.assertEqual(len(sent), 1)
        self.assertEqual(json.loads(core.path(notify.STATE_FILE).read_text()), {})


class LockTest(Base):
    def test_second_holder_is_refused(self):
        with core.lock("install"):
            with self.assertRaises(core.Error):
                with core.lock("install"):
                    pass
        with core.lock("install"):  # после выхода блокировка свободна
            pass


class SecretPromptTest(unittest.TestCase):
    def test_no_tty_gives_clear_error(self):
        with mock.patch("sys.stdin.isatty", return_value=False):
            with self.assertRaises(core.Error):
                ui.ask_secret("Пароль")


class IdempotentInstallTest(unittest.TestCase):
    def test_existing_inbounds_are_not_duplicated(self):
        class Api:
            def __init__(self):
                self.added = []

            def inbounds(self):
                return [{"remark": "REALITY", "id": 1}, {"remark": "XHTTP", "id": 2}]

            def new_x25519(self):
                return {"privateKey": "p", "publicKey": "q"}

            def add_inbound(self, body):
                self.added.append(body["remark"])
                return {"remark": body["remark"], "id": 100 + len(self.added)}

        api = Api()
        plan = installer.Plan(host="203.0.113.5", arch="amd64", sni="a.example.com", xhttp_sni="b.example.com",
                              ssh_ports=[22], mtproto_sni="c.example.com")
        made = installer.create_inbounds(api, plan, "/c.pem", "/k.pem")
        self.assertEqual(len(made), 11)
        self.assertNotIn("REALITY", api.added)
        self.assertNotIn("XHTTP", api.added)
        self.assertEqual(len(api.added), 9)


if __name__ == "__main__":
    unittest.main()
