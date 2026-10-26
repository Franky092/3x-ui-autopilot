"""Восстановление: проверка копии, перепись IP, отказ на повреждённых данных."""
import json
import os
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path

from autopilot import backup, core, inbounds, protocols as P, restore

KEYS = {"privateKey": "p", "publicKey": "q"}


def has_pbkdf2():
    return subprocess.run(["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-pass", "pass:x"], input=b"x", capture_output=True).returncode == 0


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

    def make_server(self, version="v3.9.0"):
        db = core.path("etc/x-ui/x-ui.db")
        db.parent.mkdir(parents=True)
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE inbounds (id INTEGER PRIMARY KEY, remark TEXT)")
        conn.execute("INSERT INTO inbounds (remark) VALUES ('REALITY')")
        conn.commit()
        conn.close()
        core.write_file(core.path("etc/autopilot/install.json"),
                        json.dumps({"host": "198.51.100.7", "panel_version": version, "snis": {"reality": "a.example.com"}}), 0o600)


class OpenBackupTest(Base):
    def test_plain_backup_round_trip(self):
        self.make_server()
        archive = backup.create()
        with restore.open_backup(archive, None, panel_version="v3.9.0") as bundle:
            self.assertEqual(bundle.state["host"], "198.51.100.7")
            self.assertEqual(bundle.warnings, [])
            self.assertEqual(sqlite3.connect(str(bundle.db)).execute("SELECT remark FROM inbounds").fetchone()[0], "REALITY")
            tmp = bundle.db
        self.assertFalse(tmp.exists())  # временная распаковка убирается

    @unittest.skipUnless(has_pbkdf2(), "openssl без -pbkdf2")
    def test_encrypted_backup_needs_the_right_password(self):
        self.make_server()
        archive = backup.create(passphrase="correct horse")
        with restore.open_backup(archive, "correct horse", panel_version="v3.9.0") as bundle:
            self.assertTrue(bundle.db.is_file())
        with self.assertRaises(core.Error):
            restore.open_backup(archive, "wrong", panel_version="v3.9.0")

    def test_version_mismatch_is_a_warning(self):
        self.make_server(version="v3.0.0")
        with restore.open_backup(backup.create(), None, panel_version="v3.9.0") as bundle:
            self.assertEqual(len(bundle.warnings), 1)
            self.assertIn("v3.0.0", bundle.warnings[0])

    def test_missing_file(self):
        with self.assertRaises(core.Error):
            restore.open_backup(Path(self.tmp.name) / "none.tar.gz", None, panel_version="v3.9.0")

    def test_not_a_database(self):
        self.make_server()
        core.path("etc/x-ui/x-ui.db").write_bytes(b"this is not sqlite" * 50)
        # снимок через sqlite откажется сам; кладём файл в копию напрямую
        import tarfile
        archive = Path(self.tmp.name) / "bad.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(core.path("etc/x-ui/x-ui.db"), arcname="etc/x-ui/x-ui.db")
        with self.assertRaises(core.Error):
            restore.open_backup(archive, None, panel_version="v3.9.0")

    def test_backup_without_database(self):
        import tarfile
        archive = Path(self.tmp.name) / "empty.tar.gz"
        core.write_file(core.path("etc/autopilot/install.json"), "{}")
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(core.path("etc/autopilot/install.json"), arcname="etc/autopilot/install.json")
        with self.assertRaises(core.Error):
            restore.open_backup(archive, None, panel_version="v3.9.0")


class RehostTest(unittest.TestCase):
    class Api:
        def __init__(self, items):
            self.items = items
            self.updated = {}

        def inbounds(self):
            return self.items

        def update_inbound(self, inbound_id, body):
            self.updated[inbound_id] = body

    def items(self):
        reality = inbounds.reality_inbound(10443, "a.example.com", KEYS, "ab", host="198.51.100.7") | {"id": 1}
        mt = P.mtproto(10445, "c.example.com", "198.51.100.7") | {"id": 2}
        ss = P.shadowsocks(8388) | {"id": 3}
        other = inbounds.reality_inbound(10444, "b.example.com", KEYS, "cd", host="203.0.113.99") | {"id": 4}
        return [reality, mt, ss, other]

    def test_old_host_replaced_everywhere_it_appears(self):
        api = self.Api(self.items())
        self.assertEqual(restore.rehost(api, "198.51.100.7", "192.0.2.50"), 2)
        self.assertEqual(json.loads(api.updated[1]["streamSettings"])["externalProxy"][0]["dest"], "192.0.2.50")
        self.assertEqual(json.loads(api.updated[2]["settings"])["publicIpv4"], "192.0.2.50")
        self.assertNotIn(3, api.updated)   # Shadowsocks адрес не хранит
        self.assertNotIn(4, api.updated)   # чужой адрес не трогаем

    def test_amneziawg_dns_follows_the_new_host(self):
        awg = P.amneziawg(51821, "10.8.1.0", "198.51.100.7") | {"id": 9}
        public = P.amneziawg(51822, "10.8.2.0", "1.1.1.1", remark="AmneziaWG-3.1") | {"id": 10}
        api = self.Api([awg, public])
        self.assertEqual(restore.rehost(api, "198.51.100.7", "192.0.2.50"), 1)
        server = json.loads(api.updated[9]["settings"])["server"]
        self.assertEqual((server["primaryDns"], server["secondaryDns"]), ("192.0.2.50", "192.0.2.50"))
        self.assertNotIn(10, api.updated)  # публичный DNS не наш: не трогаем

    def test_same_host_is_a_no_op(self):
        api = self.Api(self.items())
        self.assertEqual(restore.rehost(api, "198.51.100.7", "198.51.100.7"), 0)
        self.assertEqual(restore.rehost(api, "", "192.0.2.50"), 0)
        self.assertEqual(api.updated, {})

    def test_update_body_has_only_known_fields(self):
        api = self.Api(self.items())
        restore.rehost(api, "198.51.100.7", "192.0.2.50")
        self.assertLessEqual(set(api.updated[1]), set(restore._INBOUND_FIELDS))
        self.assertNotIn("id", api.updated[1])


if __name__ == "__main__":
    unittest.main()
