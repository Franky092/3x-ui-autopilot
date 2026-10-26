"""Тесты резервного копирования."""
from __future__ import annotations

import os
import shutil
import sqlite3
import stat
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from autopilot import backup, core


def subprocess_supports_pbkdf2() -> bool:
    if not shutil.which("openssl"):
        return False
    import subprocess
    result = subprocess.run(["openssl", "enc", "-help"], capture_output=True, text=True)
    return "pbkdf2" in result.stderr.lower() or "pbkdf2" in result.stdout.lower()


class BackupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.old_root = os.environ.get("AUTOPILOT_ROOT")
        os.environ["AUTOPILOT_ROOT"] = self.temp.name
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        if self.old_root is None:
            os.environ.pop("AUTOPILOT_ROOT", None)
        else:
            os.environ["AUTOPILOT_ROOT"] = self.old_root
        self.temp.cleanup()

    @unittest.skipUnless(shutil.which("openssl") and subprocess_supports_pbkdf2(), "openssl enc -pbkdf2 недоступен")
    def test_encrypt_decrypt_roundtrip_and_bad_password(self) -> None:
        source = self.root / "source"
        encrypted = self.root / "source.enc"
        output = self.root / "output"
        source.write_bytes(b"payload" * 100)
        backup.encrypt_file(source, encrypted, "секрет")
        self.assertEqual(stat.S_IMODE(encrypted.stat().st_mode), 0o600)
        backup.decrypt_file(encrypted, output, "секрет")
        self.assertEqual(output.read_bytes(), source.read_bytes())
        partial = self.root / "partial"
        with self.assertRaisesRegex(core.Error, "Не удалось расшифровать"):
            backup.decrypt_file(encrypted, partial, "неверно")
        self.assertFalse(partial.exists())

    def test_create_excludes_secrets_and_uses_private_permissions(self) -> None:
        db = core.path("etc/x-ui/x-ui.db")
        db.parent.mkdir(parents=True)
        conn = sqlite3.connect(db)
        conn.execute("create table t (value text)")
        conn.execute("insert into t values ('ok')")
        conn.commit()
        conn.close()
        config = core.path("etc/autopilot/install.json")
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text("{}")
        (config.parent / "notify.env").write_text("NOTIFY_TOKEN=secret")
        (config.parent / "backup.key").write_text("key")
        certs = config.parent / "certs"
        certs.mkdir()
        (certs / "cert.pem").write_text("cert")
        output = backup.create(out_dir=self.root / "backups")
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        with tarfile.open(output, "r:gz") as archive:
            names = archive.getnames()
            self.assertIn("etc/x-ui/x-ui.db", names)
            self.assertIn("backup.json", names)
            self.assertFalse(any(Path(name).name in backup.EXCLUDE_NAMES for name in names))
            for member in archive.getmembers():
                if member.isfile():
                    self.assertEqual(member.mode, 0o600)

    def test_rotation_keeps_newest(self) -> None:
        directory = self.root / "backups"
        directory.mkdir()
        files = []
        for index in range(4):
            item = directory / ("backup-%d.tar.gz.enc" % index)
            item.write_text("x")
            os.utime(item, (index + 1, index + 1))
            files.append(item)
        backup.rotate(directory, 2)
        self.assertEqual({p.name for p in directory.iterdir()}, {files[2].name, files[3].name})

    def test_snapshot_sqlite(self) -> None:
        source, target = self.root / "live.db", self.root / "snapshot.db"
        conn = sqlite3.connect(source)
        conn.execute("create table t (value text)")
        conn.execute("insert into t values ('running')")
        conn.commit()
        conn.close()
        backup.snapshot_sqlite(source, target)
        conn = sqlite3.connect(target)
        self.assertEqual(conn.execute("select value from t").fetchone()[0], "running")
        conn.close()
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_safe_extract_rejects_unsafe_members_before_writing(self) -> None:
        cases = [("../escape", tarfile.REGTYPE), ("/absolute", tarfile.REGTYPE),
                 ("unknown.txt", tarfile.REGTYPE), ("etc/x-ui/link", tarfile.SYMTYPE)]
        for name, kind in cases:
            with self.subTest(name=name):
                archive_path = self.root / "bad.tar.gz"
                with tarfile.open(archive_path, "w:gz") as archive:
                    info = tarfile.TarInfo(name)
                    if kind == tarfile.SYMTYPE:
                        info.type = tarfile.SYMTYPE
                        info.linkname = "target"
                        archive.addfile(info)
                    else:
                        info.size = 1
                        import io
                        archive.addfile(info, io.BytesIO(b"x"))
                destination = self.root / ("dest-" + str(len(list(self.root.glob("dest-*")))))
                with self.assertRaises(core.Error):
                    backup.safe_extract(archive_path, destination)
                self.assertFalse(destination.exists())
                self.assertFalse((self.root / "escape").exists())


if __name__ == "__main__":
    unittest.main()
