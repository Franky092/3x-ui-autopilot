"""Дополнительные проверки backup: пустой пароль, права каталога, предел размера."""
import io
import os
import stat
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from autopilot import backup, core


class LimitsTest(unittest.TestCase):
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

    def test_empty_passphrase_rejected(self):
        with self.assertRaises(core.Error):
            backup.create(passphrase="")

    def test_backup_dir_is_private(self):
        import sqlite3
        db = core.path("etc/x-ui/x-ui.db")
        db.parent.mkdir(parents=True)
        sqlite3.connect(str(db)).close()
        path = backup.create()
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)

    def test_oversized_archive_rejected(self):
        archive = Path(self.tmp.name) / "big.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            info = tarfile.TarInfo("etc/x-ui/x-ui.db")
            info.size = 100
            tar.addfile(info, io.BytesIO(b"x" * 100))
        out = Path(self.tmp.name) / "out"
        with mock.patch.object(backup, "MAX_EXPANDED", 10), self.assertRaises(core.Error):
            backup.safe_extract(archive, out)
        self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
