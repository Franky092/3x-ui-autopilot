"""Сборка релиза: детерминированность, согласованность версий и хэшей, безопасность установочного скрипта."""
import hashlib
import importlib.util
import io
import re
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("release", ROOT / "tools" / "release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


def make_tree(base: Path, ver="1.2.3", hash_value="0" * 64):
    (base / "autopilot" / "data").mkdir(parents=True)
    (base / "manuals").mkdir()
    (base / "autopilot" / "__init__.py").write_text('__version__ = "%s"\n' % ver)
    (base / "autopilot" / "data" / "router.sh").write_text("#!/bin/sh\n")
    (base / "autopilot" / "__pycache__").mkdir()
    (base / "autopilot" / "__pycache__" / "x.pyc").write_bytes(b"junk")
    (base / "manuals" / "operations.md").write_text("ops\n")
    for name in release.INCLUDE_FILES:
        (base / name).write_text(ver + "\n" if name == "VERSION" else "x\n")
    (base / "install.sh").write_text('RELEASE_VERSION="%s"\nTARBALL_SHA256="%s"\n' % (ver, hash_value))
    (base / "README.md").write_text(
        'curl -o install.sh https://raw.githubusercontent.com/o/r/v%s/install.sh\necho "%s  install.sh" | sha256sum -c -\n' % (ver, "0" * 64))


class ReleaseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        make_tree(self.base)

    def tearDown(self):
        self.tmp.cleanup()

    def test_tar_is_deterministic_and_clean(self):
        first = release.build_tar(self.base)
        (self.base / "autopilot" / "__pycache__" / "y.pyc").write_bytes(b"more junk")
        self.assertEqual(first, release.build_tar(self.base))
        names = tarfile.open(fileobj=io.BytesIO(first)).getnames()
        self.assertTrue(all(n.startswith("autopilot-1.2.3") for n in names))
        self.assertFalse(any("pycache" in n or n.endswith(".pyc") for n in names))
        self.assertNotIn("autopilot-1.2.3/install.sh", names)   # иначе хэш ссылался бы сам на себя
        self.assertNotIn("autopilot-1.2.3/README.md", names)

    def test_modes_and_owners_are_fixed(self):
        tar = tarfile.open(fileobj=io.BytesIO(release.build_tar(self.base)))
        by = {m.name: m for m in tar.getmembers()}
        self.assertEqual(by["autopilot-1.2.3/autopilot/data/router.sh"].mode, 0o755)
        self.assertEqual(by["autopilot-1.2.3/LICENSE"].mode, 0o644)
        for member in by.values():
            self.assertEqual((member.mtime, member.uid, member.gid, member.uname, member.gname), (0, 0, 0, "", ""))

    def test_content_change_changes_the_hash(self):
        before = release.tar_sha256(self.base)
        (self.base / "manuals" / "operations.md").write_text("changed\n")
        self.assertNotEqual(before, release.tar_sha256(self.base))

    def test_write_then_check_is_consistent_and_stable(self):
        release.write(self.base)
        self.assertEqual(release.problems(self.base), [])
        script = (self.base / "install.sh").read_text()
        self.assertIn(release.tar_sha256(self.base), script)
        readme = (self.base / "README.md").read_text()
        self.assertIn(hashlib.sha256(script.encode()).hexdigest() + "  install.sh", readme)
        release.write(self.base)                         # повторная запись ничего не меняет
        self.assertEqual(release.problems(self.base), [])
        archive = self.base / "dist" / "autopilot-1.2.3.tar.gz"
        import gzip
        self.assertEqual(hashlib.sha256(gzip.decompress(archive.read_bytes())).hexdigest(), release.tar_sha256(self.base))

    def test_stale_hashes_and_versions_are_reported(self):
        release.write(self.base)
        (self.base / "autopilot" / "__init__.py").write_text('__version__ = "9.9.9"\n')
        self.assertTrue(any("__init__" in p for p in release.problems(self.base)))
        fresh = self.base / "fresh"
        fresh.mkdir()
        make_tree(fresh)  # заново: хэши нулевые
        found = "\n".join(release.problems(fresh))
        self.assertIn("TARBALL_SHA256", found)
        self.assertIn("хэш install.sh", found)

    def test_changing_install_sh_invalidates_the_readme_hash(self):
        release.write(self.base)
        (self.base / "install.sh").write_text((self.base / "install.sh").read_text() + "# tampered\n")
        self.assertTrue(any("README" in p for p in release.problems(self.base)))


class RepositoryReleaseTest(unittest.TestCase):
    def test_the_real_repository_is_consistent(self):
        self.assertEqual(release.problems(ROOT), [])


class InstallScriptTest(unittest.TestCase):
    script = (ROOT / "install.sh").read_text()

    def test_syntax(self):
        self.assertEqual(subprocess.run(["sh", "-n", str(ROOT / "install.sh")], capture_output=True).returncode, 0)

    def test_refuses_an_unsealed_script(self):
        self.assertIn('die "Этот install.sh не из релиза', self.script)

    def test_checksum_is_verified_before_extraction(self):
        self.assertLess(self.script.index("sha256sum \"$TAR\""), self.script.index("tar -xf"))
        self.assertLess(self.script.index("недопустимые пути"), self.script.index("tar -xf"))
        self.assertIn('gzip -dc "$TGZ" > "$TAR" || die', self.script)      # лишние данные в gzip – ошибка
        self.assertNotIn("tar -xzf", self.script)                           # извлекаем только проверенный tar

    def test_download_is_https_only(self):
        self.assertIn("--proto '=https'", self.script)
        self.assertEqual(re.findall(r"http://", self.script), [])

    def test_os_release_cannot_clobber_our_variables(self):
        # `. /etc/os-release` задаёт VERSION, ID, NAME…: читаем его только в подвыборке, а своё имя берём иное
        self.assertIn("$(. /etc/os-release;", self.script)
        self.assertNotRegex(self.script, r"(?m)^\. /etc/os-release")
        self.assertNotRegex(self.script, r"(?m)^VERSION=")
        self.assertNotIn("$VERSION", self.script)

    def test_the_real_archive_passes_the_path_check_of_the_script(self):
        """Тот же awk, что в install.sh, на списке файлов настоящего архива (ловит ошибки префикса)."""
        names = tarfile.open(fileobj=io.BytesIO(release.build_tar(ROOT))).getnames()
        listing = "\n".join(n if not n.endswith("/") else n for n in names) + "\n"
        awk = re.search(r"awk -v prefix=\"autopilot-\$RELEASE_VERSION/\" '([^']+)'", self.script).group(1)
        done = subprocess.run(["awk", "-v", "prefix=autopilot-%s/" % release.version(ROOT), awk], input=listing.replace("autopilot-%s\n" % release.version(ROOT), "autopilot-%s/\n" % release.version(ROOT)), capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_runs_python_isolated_without_exec(self):
        self.assertIn("python3 -I -c", self.script)
        self.assertNotRegex(self.script, r"(?m)^exec ")  # иначе не сработает очистка временной папки


if __name__ == "__main__":
    unittest.main()
