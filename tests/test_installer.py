"""Чистые функции установщика: разбор вывода команд, проверка ОС и адресов, загрузка с проверкой хэша, безопасная распаковка."""
import gzip  # noqa: F401  (импорт заранее: гонка импортов в Python 3.9 с потоком из test_panel)
import hashlib
import io
import os
import tarfile
import tempfile
import unittest
from pathlib import Path

from autopilot import core, installer


class ParsersTest(unittest.TestCase):
    def test_os_release(self):
        text = 'NAME="Ubuntu"\nVERSION_ID="22.04"\nID=ubuntu\n'
        self.assertEqual(installer.parse_os_release(text), ("ubuntu", "22.04"))
        installer.check_os(text)

    def test_unsupported_os_rejected(self):
        with self.assertRaises(core.Error):
            installer.check_os('ID=fedora\nVERSION_ID="40"\n')

    def test_arch(self):
        self.assertEqual(installer.normalize_arch("x86_64"), "amd64")
        self.assertEqual(installer.normalize_arch("aarch64"), "arm64")
        with self.assertRaises(core.Error):
            installer.normalize_arch("riscv64")

    def test_ipv4_selection(self):
        out = ("2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\n"
               "3: eth1    inet 203.0.113.10/24 brd 203.0.113.255 scope global eth1\n")
        found = installer.parse_ipv4_addresses(out)
        self.assertEqual(found, ["10.0.0.5", "203.0.113.10"])
        # 203.0.113.0/24 – документационная сеть: не is_global, поэтому берём явно заданный адрес из найденных
        with self.assertRaises(core.Error):
            installer.pick_public_ipv4(found)
        self.assertEqual(installer.pick_public_ipv4(["8.8.8.8", "10.0.0.5"]), "8.8.8.8")
        with self.assertRaises(core.Error):
            installer.pick_public_ipv4(["8.8.8.8"], "1.1.1.1")  # адреса нет на интерфейсах
        with self.assertRaises(core.Error):
            installer.pick_public_ipv4(["8.8.8.8"], "not-an-ip")

    def test_listening_ports(self):
        out = "LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 4096 [::]:443 [::]:*\nLISTEN 0 4096 *:8443 *:*\n"
        self.assertEqual(installer.parse_listening_ports(out), {22, 443, 8443})

    def test_api_token(self):
        self.assertEqual(installer.parse_api_token("apiToken: abc123XYZ\n"), "abc123XYZ")
        with self.assertRaises(core.Error):
            installer.parse_api_token("nothing")

    def test_random_alnum(self):
        value = installer.random_alnum(18)
        self.assertEqual(len(value), 18)
        self.assertTrue(value.isalnum())


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class DownloadTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dest = Path(self.tmp.name) / "f"

    def tearDown(self):
        self.tmp.cleanup()

    def test_good_hash(self):
        data = b"hello" * 1000
        installer.download("https://x/f", self.dest, hashlib.sha256(data).hexdigest(), opener=lambda url, timeout: FakeResponse(data))
        self.assertEqual(self.dest.read_bytes(), data)

    def test_bad_hash_leaves_nothing(self):
        with self.assertRaises(core.Error):
            installer.download("https://x/f", self.dest, "0" * 64, opener=lambda url, timeout: FakeResponse(b"data"))
        self.assertFalse(self.dest.exists())

    def test_http_refused(self):
        with self.assertRaises(core.Error):
            installer.download("http://x/f", self.dest, "0" * 64)


class ExtractTest(unittest.TestCase):
    def make(self, name, kind="file"):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            info = tarfile.TarInfo(name)
            if kind == "file":
                payload = b"x"
                info.size = len(payload)
                tar.addfile(info, io.BytesIO(payload))
            else:
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                tar.addfile(info)
        path = Path(self.tmp.name) / "a.tar.gz"
        path.write_bytes(buf.getvalue())
        return path

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name) / "out"
        self.out.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def test_normal_file(self):
        installer.safe_extract(self.make("x-ui/x-ui"), self.out)
        self.assertTrue((self.out / "x-ui" / "x-ui").is_file())

    def test_dotdot_rejected(self):
        with self.assertRaises(core.Error):
            installer.safe_extract(self.make("../evil"), self.out)

    def test_absolute_rejected(self):
        with self.assertRaises(core.Error):
            installer.safe_extract(self.make("/etc/evil"), self.out)

    def test_symlink_rejected(self):
        with self.assertRaises(core.Error):
            installer.safe_extract(self.make("x-ui/link", kind="link"), self.out)
        self.assertEqual(list(self.out.iterdir()), [])


class PinsTest(unittest.TestCase):
    def test_pins_are_sha256(self):
        for arch in ("amd64", "arm64"):
            self.assertRegex(installer.PANEL_SHA256[arch], r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
