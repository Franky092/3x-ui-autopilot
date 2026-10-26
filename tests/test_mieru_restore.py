"""Mieru при восстановлении: состояние из копии возвращается, чужая mita не меняется."""
import json
import os
import sqlite3
import tempfile
import unittest
from unittest import mock

from autopilot import backup, core, mieru, restore


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

    def make_panel(self):
        db = core.path("etc/x-ui/x-ui.db")
        db.parent.mkdir(parents=True)
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE inbounds (id INTEGER)")
        conn.commit()
        conn.close()
        core.write_file(core.path("etc/autopilot/install.json"), json.dumps({"host": "1.2.3.4"}), 0o600)


class BackupCarriesMieruTest(Base):
    def test_backup_includes_and_bundle_exposes_the_mieru_state(self):
        self.make_panel()
        mieru.save_state({"enabled": True, "users": {"admin": "pw-admin"}, "own_port": False})
        with restore.open_backup(backup.create(), None, panel_version="v3.9.0") as bundle:
            self.assertEqual(bundle.mieru["users"], {"admin": "pw-admin"})
            self.assertTrue(bundle.mieru["enabled"])

    def test_backup_without_mieru_has_empty_state(self):
        self.make_panel()
        with restore.open_backup(backup.create(), None, panel_version="v3.9.0") as bundle:
            self.assertEqual(bundle.mieru, {})

    def test_broken_mieru_state_in_a_backup_is_ignored(self):
        self.make_panel()
        core.write_file(core.path(mieru.STATE), "not json", 0o600)
        with restore.open_backup(backup.create(), None, panel_version="v3.9.0") as bundle:
            self.assertEqual(bundle.mieru, {})


class RestoreStateTest(Base):
    def run_restore(self, *, installed, described, saved):
        added = []
        with mock.patch.object(mieru, "installed", return_value=installed), mock.patch.object(mieru, "install") as inst, \
                mock.patch.object(mieru, "describe", return_value=described), \
                mock.patch.object(mieru, "configure", return_value={"portBindings": [{"port": 32145, "protocol": "TCP"}]}), \
                mock.patch.object(mieru, "add_user", side_effect=lambda n, p=None: added.append((n, p))), \
                mock.patch.object(mieru, "open_firewall") as fw:
            mieru.restore_state("amd64", saved)
        return inst, fw, added

    def test_users_are_recreated_with_their_old_passwords(self):
        inst, fw, added = self.run_restore(installed=False, described={},
                                           saved={"enabled": True, "users": {"admin": "pa", "bob": "pb"}})
        inst.assert_called_once_with("amd64")
        self.assertEqual(sorted(added), [("admin", "pa"), ("bob", "pb")])
        fw.assert_called_once()
        state = mieru.load_state()
        self.assertTrue(state["enabled"] and state["own_port"])
        self.assertEqual(state["users"], {"admin": "pa", "bob": "pb"})

    def test_existing_mita_keeps_its_own_port_flag(self):
        self.run_restore(installed=True, described={"portBindings": [{"port": 1, "protocol": "TCP"}]},
                         saved={"enabled": True, "users": {"a": "p"}})
        self.assertFalse(mieru.load_state()["own_port"])   # чужой порт при отключении не закрываем

    def test_disabled_or_broken_state_does_nothing(self):
        with mock.patch.object(mieru, "install") as inst:
            for saved in ({"enabled": False, "users": {"a": "p"}}, {"enabled": True, "users": "oops"}, {}):
                mieru.restore_state("amd64", saved)
        inst.assert_not_called()
        self.assertFalse(mieru.enabled())


if __name__ == "__main__":
    unittest.main()
