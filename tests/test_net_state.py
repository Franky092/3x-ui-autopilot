"""Изменённые порты сохраняются и учитываются при удалении."""
import json
import os
import tempfile
import unittest
from unittest import mock

from autopilot import core, installer, uninstaller


class StateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old = os.environ.get("AUTOPILOT_ROOT")
        os.environ["AUTOPILOT_ROOT"] = self.tmp.name
        core.write_file(core.path(core.CONF_DIR, "install.json"), json.dumps({"host": "1.2.3.4", "snis": {"reality": "a.example.com"}}), 0o600)

    def tearDown(self):
        if self.old is None:
            os.environ.pop("AUTOPILOT_ROOT", None)
        else:
            os.environ["AUTOPILOT_ROOT"] = self.old
        self.tmp.cleanup()

    def test_update_state_keeps_other_fields_and_mode(self):
        data = installer.update_state(ports={"tuic": 9444})
        self.assertEqual(data["host"], "1.2.3.4")
        self.assertEqual(json.loads(core.path(core.CONF_DIR, "install.json").read_text())["ports"], {"tuic": 9444})
        self.assertEqual(oct(core.path(core.CONF_DIR, "install.json").stat().st_mode & 0o777), "0o600")

    def test_update_state_without_install(self):
        core.path(core.CONF_DIR, "install.json").unlink()
        with self.assertRaises(core.Error):
            installer.update_state(x=1)

    def test_uninstall_closes_the_changed_port_not_the_old_one(self):
        installer.update_state(ports={"tuic": 9444, "shadowsocks": 9388})
        rules = uninstaller.ufw_rules()
        self.assertIn("9444/udp", rules)
        self.assertNotIn("8444/udp", rules)
        self.assertIn("9388/tcp", rules)
        self.assertIn("9388/udp", rules)
        self.assertIn("443/tcp", rules)    # nginx и 80/tcp не меняются
        self.assertIn("80/tcp", rules)
        self.assertIn("443/udp", rules)    # Hysteria2 на своём порту по умолчанию

    def test_remove_reads_ports_before_deleting_the_state(self):
        installer.update_state(ports={"tuic": 9444})
        calls = []
        with mock.patch.object(core, "unit_exists", return_value=False), mock.patch.object(core, "systemctl"), \
                mock.patch.object(core, "unit_active", return_value=False), mock.patch("shutil.which", return_value="/usr/sbin/ufw"), \
                mock.patch.object(core, "run", side_effect=lambda cmd, **k: calls.append(list(cmd))):
            uninstaller.remove()
        self.assertIn(["ufw", "--force", "delete", "allow", "9444/udp"], calls)
        self.assertNotIn(["ufw", "--force", "delete", "allow", "8444/udp"], calls)


if __name__ == "__main__":
    unittest.main()
