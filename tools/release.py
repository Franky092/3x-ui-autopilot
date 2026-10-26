#!/usr/bin/env python3
"""Сборка релиза 3X-UI Autopilot и проверка его согласованности.

  python3 tools/release.py --write   собрать dist/autopilot-<версия>.tar.gz и обновить хэши в install.sh и README.md
  python3 tools/release.py --check   проверить, что версии и хэши согласованы (запускается в CI)

В архив не входят install.sh и README.md: в них записаны хэши, иначе они зависели бы друг от друга по кругу.
Хэш считается по НЕСЖАТОМУ tar: он не зависит от версии zlib на машине, где собирают.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import re
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INCLUDE_DIRS = ("autopilot", "manuals")
INCLUDE_FILES = ("LICENSE", "NOTICE.md", "PRIVACY.md", "SECURITY.md", "CHANGELOG.md", "VERSION", "index.html")
EXECUTABLE = ("autopilot/data/router.sh",)
ZERO = "0" * 64
_SHA = re.compile(r'^TARBALL_SHA256="([0-9a-f]{64})"$', re.M)
_VER = re.compile(r'^RELEASE_VERSION="([^"]+)"$', re.M)
_README_HASH = re.compile(r"[0-9a-f]{64}(?=  install\.sh)")
_README_TAG = re.compile(r"(releases/download/|/)v\d+\.\d+\.\d+(/install\.sh|/autopilot-)")


def version(root: Path = ROOT) -> str:
    return (root / "VERSION").read_text(encoding="utf-8").strip()


def package_version(root: Path = ROOT) -> str:
    match = re.search(r'__version__\s*=\s*"([^"]+)"', (root / "autopilot" / "__init__.py").read_text(encoding="utf-8"))
    return match.group(1) if match else ""


def release_files(root: Path = ROOT) -> list[str]:
    found: list[str] = []
    for name in INCLUDE_DIRS:
        for path in sorted((root / name).rglob("*")):
            rel = path.relative_to(root)
            if path.is_file() and "__pycache__" not in rel.parts and path.suffix != ".pyc" and path.name != ".DS_Store":
                found.append(rel.as_posix())
    found += [name for name in INCLUDE_FILES if (root / name).is_file()]
    return sorted(found)


def build_tar(root: Path = ROOT) -> bytes:
    """Детерминированный tar: порядок, время, владельцы и права фиксированы."""
    prefix = "autopilot-%s" % version(root)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as tar:
        directories: set[str] = {prefix}
        names = release_files(root)
        for rel in names:
            parts = rel.split("/")
            for i in range(1, len(parts)):
                directories.add(prefix + "/" + "/".join(parts[:i]))
        for directory in sorted(directories):
            info = tarfile.TarInfo(directory)
            info.type, info.mode, info.mtime = tarfile.DIRTYPE, 0o755, 0
            tar.addfile(info)
        for rel in names:
            data = (root / rel).read_bytes()
            info = tarfile.TarInfo(prefix + "/" + rel)
            info.size, info.mtime = len(data), 0
            info.mode = 0o755 if rel in EXECUTABLE else 0o644
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def tar_sha256(root: Path = ROOT) -> str:
    return hashlib.sha256(build_tar(root)).hexdigest()


def install_sha256(root: Path = ROOT) -> str:
    return hashlib.sha256((root / "install.sh").read_bytes()).hexdigest()


def problems(root: Path = ROOT) -> list[str]:
    found = []
    ver = version(root)
    if package_version(root) != ver:
        found.append("autopilot/__init__.py: версия %r, а в VERSION %r" % (package_version(root), ver))
    script = (root / "install.sh").read_text(encoding="utf-8")
    match = _VER.search(script)
    if not match or match.group(1) != ver:
        found.append("install.sh: RELEASE_VERSION не совпадает с VERSION (%s)" % ver)
    sha = _SHA.search(script)
    if not sha or sha.group(1) == ZERO:
        found.append("install.sh: не задан TARBALL_SHA256 (выполните tools/release.py --write)")
    elif sha.group(1) != tar_sha256(root):
        found.append("install.sh: TARBALL_SHA256 не совпадает с архивом (выполните tools/release.py --write)")
    readme = (root / "README.md").read_text(encoding="utf-8")
    hashes = _README_HASH.findall(readme)
    if not hashes:
        found.append("README.md: нет строки с хэшем install.sh")
    elif hashes[0] != install_sha256(root):
        found.append("README.md: хэш install.sh устарел (выполните tools/release.py --write)")
    if ("v%s/install.sh" % ver) not in readme:
        found.append("README.md: ссылка на install.sh указывает не на v%s" % ver)
    return found


def write(root: Path = ROOT) -> Path:
    ver = version(root)
    script_path = root / "install.sh"
    script = script_path.read_text(encoding="utf-8")
    script = _VER.sub('RELEASE_VERSION="%s"' % ver, script, count=1)
    script = _SHA.sub('TARBALL_SHA256="%s"' % tar_sha256(root), script, count=1)
    script_path.write_text(script, encoding="utf-8")
    readme_path = root / "README.md"
    readme = readme_path.read_text(encoding="utf-8")
    readme = _README_HASH.sub(install_sha256(root), readme)
    readme = re.sub(r"(releases/download/|raw\.githubusercontent\.com/[^/]+/[^/]+/)v\d+\.\d+\.\d+", lambda m: m.group(1) + "v" + ver, readme)
    readme_path.write_text(readme, encoding="utf-8")
    out = root / "dist" / ("autopilot-%s.tar.gz" % ver)
    out.parent.mkdir(exist_ok=True)
    out.write_bytes(gzip.compress(build_tar(root), mtime=0))
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--write", action="store_true")
    group.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    if args.write:
        out = write()
        print("Собрано: %s (sha256 tar: %s)" % (out, tar_sha256()))
    found = problems()
    for line in found:
        print("✗ " + line, file=sys.stderr)
    if found:
        return 1
    print("Релиз согласован: версия %s, хэши совпадают." % version())
    return 0


if __name__ == "__main__":
    sys.exit(main())
