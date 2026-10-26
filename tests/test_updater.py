"""Проверки обновления панели без сети и системных команд."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from autopilot import core, installer, updater


class API:
    def __init__(self, count):
        self.count = count

    def inbounds(self):
        return [{} for _ in range(self.count)]


class UpdaterTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.previous_root = os.environ.get("AUTOPILOT_ROOT")
        os.environ["AUTOPILOT_ROOT"] = self.tmp.name
        self.state = core.path("etc/autopilot/install.json")
        self.state.parent.mkdir(parents=True)
        self.state.write_text(json.dumps({"panel_version": "v3.8.0", "host": "203.0.113.5", "extra": 7}))
        self.panel = core.path(installer.XUI_DIR)
        (self.panel / "bin").mkdir(parents=True)
        (self.panel / "x-ui").write_text("old panel")
        (self.panel / "bin" / "xray-linux-amd64").write_text("old xray")
        self.database = core.path("etc/x-ui/x-ui.db")
        self.database.parent.mkdir(parents=True)
        self.database.write_text("database")

    def tearDown(self):
        if self.previous_root is None:
            os.environ.pop("AUTOPILOT_ROOT", None)
        else:
            os.environ["AUTOPILOT_ROOT"] = self.previous_root
        self.tmp.cleanup()

    def _mocks(self, api_factory=None):
        def unpack(_archive, dest):
            source = dest / "x-ui"
            (source / "bin").mkdir(parents=True)
            (source / "x-ui").write_text("new panel")
            (source / "bin" / "xray-linux-amd64").write_text("new xray")

        return (
            mock.patch.object(updater.backup, "create", return_value=Path("/backup.tar.gz")),
            mock.patch.object(installer, "download", side_effect=lambda _url, dest, _sha, **_kw: dest.write_bytes(b"archive")),
            mock.patch.object(installer, "safe_extract", side_effect=unpack),
            mock.patch.object(core, "systemctl"),
        )

    def test_same_version_does_nothing(self):
        data = json.loads(self.state.read_text())
        data["panel_version"] = installer.PANEL_VERSION
        self.state.write_text(json.dumps(data))
        with mock.patch.object(updater.backup, "create") as create, mock.patch.object(core, "systemctl") as ctl:
            result = updater.upgrade(lambda: self.fail("API не должен вызываться"), arch="amd64")
        self.assertFalse(result["rolled_back"])
        create.assert_not_called()
        ctl.assert_not_called()

    def test_success_replaces_panel_preserves_state_and_database(self):
        patches = self._mocks()
        with patches[0], patches[1], patches[2], patches[3]:
            result = updater.upgrade(lambda: API(2), arch="amd64", sleep=lambda _seconds: None)
        self.assertFalse(result["rolled_back"])
        self.assertEqual((self.panel / "x-ui").read_text(), "new panel")
        self.assertEqual((self.panel / "bin/xray-linux-amd64").stat().st_mode & 0o777, 0o755)
        self.assertEqual(json.loads(self.state.read_text()), {
            "panel_version": installer.PANEL_VERSION, "host": "203.0.113.5", "extra": 7,
        })
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.database.read_text(), "database")
        self.assertFalse(core.path(installer.XUI_DIR + ".old").exists())

    def test_download_failure_does_not_change_system(self):
        old = (self.panel / "x-ui").read_text()
        with mock.patch.object(updater.backup, "create", return_value=Path("/backup")), \
                mock.patch.object(installer, "download", side_effect=core.Error("SHA256 mismatch")), \
                mock.patch.object(core, "systemctl") as ctl:
            with self.assertRaises(core.Error):
                updater.upgrade(lambda: API(2), arch="amd64")
        self.assertEqual((self.panel / "x-ui").read_text(), old)
        self.assertFalse(core.path(installer.XUI_DIR + ".old").exists())
        ctl.assert_not_called()

    def test_unavailable_panel_rolls_back(self):
        patches = self._mocks()
        calls = [0]

        def api_factory():
            calls[0] += 1
            if calls[0] == 1:
                return API(2)
            raise core.Error("не отвечает")

        with patches[0], patches[1], patches[2], patches[3]:
            result = updater.upgrade(api_factory, arch="amd64", sleep=lambda _seconds: None)
        self.assertTrue(result["rolled_back"])
        self.assertIn("не отвечает", result["error"])
        self.assertEqual((self.panel / "x-ui").read_text(), "old panel")
        self.assertFalse(core.path(installer.XUI_DIR + ".old").exists())
        self.assertEqual(updater.installed_version(), "v3.8.0")

    def test_fewer_inbounds_rolls_back(self):
        patches = self._mocks()
        counts = iter((3, 2))
        with patches[0], patches[1], patches[2], patches[3]:
            result = updater.upgrade(lambda: API(next(counts)), arch="amd64")
        self.assertTrue(result["rolled_back"])
        self.assertIn("подключений стало меньше", result["error"])
        self.assertEqual((self.panel / "x-ui").read_text(), "old panel")

    def test_backup_failure_stops_before_download(self):
        with mock.patch.object(updater.backup, "create", side_effect=core.Error("backup failed")), \
                mock.patch.object(installer, "download") as download:
            with self.assertRaises(core.Error):
                updater.upgrade(lambda: API(1), arch="amd64")
        download.assert_not_called()
        self.assertEqual((self.panel / "x-ui").read_text(), "old panel")

    def test_existing_old_directory_is_handled(self):
        old_dir = core.path(installer.XUI_DIR + ".old")
        old_dir.mkdir()
        (old_dir / "stale").write_text("stale")
        patches = self._mocks()
        with patches[0], patches[1], patches[2], patches[3]:
            result = updater.upgrade(lambda: API(2), arch="amd64")
        self.assertFalse(result["rolled_back"])
        self.assertEqual((self.panel / "x-ui").read_text(), "new panel")
        self.assertFalse(old_dir.exists())

    def test_missing_installation_is_a_clear_error(self):
        self.state.unlink()
        self.assertFalse(updater.needs_update())
        with self.assertRaisesRegex(core.Error, "Установка не найдена"):
            updater.upgrade(lambda: API(0), arch="amd64")


if __name__ == "__main__":
    unittest.main()
