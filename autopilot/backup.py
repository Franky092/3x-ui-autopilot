"""Резервные копии настроек и базы панели."""
from __future__ import annotations

import base64
import json
import os
import secrets
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from . import core

INCLUDE = ("etc/x-ui/x-ui.db", "etc/autopilot/install.json", "etc/autopilot/mieru.json", "etc/autopilot/certs")
EXCLUDE_NAMES = ("notify.env", "backup.key")
KEY_FILE = "etc/autopilot/backup.key"
CONFIG = "etc/autopilot/backup.json"
BACKUP_DIR = core.BACKUP_DIR
MAX_EXPANDED = 1024 * 1024 * 1024  # предел распакованного размера: защита от «архивной бомбы»


def snapshot_sqlite(src: Path, dst: Path) -> None:
    """Снимает согласованную копию SQLite без остановки панели."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    source = sqlite3.connect("file:%s?mode=ro" % src.resolve().as_posix(), uri=True)
    try:
        target = sqlite3.connect(str(dst))
        try:
            source.backup(target)
        finally:
            target.close()
    finally:
        source.close()
    os.chmod(dst, 0o600)


def _openssl(src: Path, dst: Path, passphrase: str, decrypt: bool) -> None:
    """Запускает openssl, передавая пароль только через pipe."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    # Файл создаём сами с 0600: openssl открывает уже существующий, не меняя прав (иначе до chmod он мог быть доступен всем).
    os.close(os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600))
    read_fd, write_fd = os.pipe()
    cmd = ["openssl", "enc"]
    if decrypt:
        cmd.append("-d")
    cmd += ["-aes-256-cbc", "-pbkdf2", "-iter", "600000"]
    if not decrypt:
        cmd.append("-salt")
    cmd += ["-in", str(src), "-out", str(dst), "-pass", "fd:%d" % read_fd]
    try:
        proc = subprocess.Popen(cmd, pass_fds=(read_fd,), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.close(read_fd)
        read_fd = -1
        with os.fdopen(write_fd, "wb") as secret_pipe:
            write_fd = -1
            secret_pipe.write(passphrase.encode("utf-8") + b"\n")
        code = proc.wait()
        if code:
            raise subprocess.CalledProcessError(code, cmd)
        os.chmod(dst, 0o600)
    except (OSError, subprocess.SubprocessError) as exc:
        try:
            dst.unlink()
        except FileNotFoundError:
            pass
        if decrypt:
            core.die("Не удалось расшифровать: неверный пароль или файл повреждён.")
        raise core.Error("Не удалось зашифровать резервную копию.") from exc
    finally:
        if read_fd >= 0:
            os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


def encrypt_file(src: Path, dst: Path, passphrase: str) -> None:
    """Шифрует файл с помощью OpenSSL."""
    _openssl(src, dst, passphrase, False)


def decrypt_file(src: Path, dst: Path, passphrase: str) -> None:
    """Расшифровывает файл; при ошибке удаляет частичный результат."""
    _openssl(src, dst, passphrase, True)


def create(*, passphrase: str | None = None, out_dir: Path | None = None, name_prefix: str = "backup") -> Path:
    """Создаёт tar.gz, при необходимости шифрует его."""
    if passphrase is not None and not passphrase:
        core.die("Пароль копии не может быть пустым.")
    directory = out_dir or core.path(BACKUP_DIR)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    final = directory / ("%s-%s.tar.gz%s" % (name_prefix, stamp, ".enc" if passphrase is not None else ""))
    with tempfile.TemporaryDirectory(prefix="autopilot-backup-") as tmp:
        temp_root = Path(tmp)
        db_copy = temp_root / "x-ui.db"
        snapshot_sqlite(core.path("etc/x-ui/x-ui.db"), db_copy)
        plain = temp_root / "backup.tar.gz"
        with tarfile.open(plain, "w:gz") as archive:
            for rel in INCLUDE:
                src = core.path(rel)
                if rel == "etc/x-ui/x-ui.db":
                    archive.add(db_copy, arcname=rel, recursive=False)
                elif src.is_dir():
                    def safe_info(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
                        if PurePosixPath(info.name).name in EXCLUDE_NAMES or not (info.isfile() or info.isdir()):
                            return None
                        info.mode = 0o700 if info.isdir() else 0o600
                        return info
                    archive.add(src, arcname=rel, recursive=True, filter=safe_info)
                elif src.is_file() and src.name not in EXCLUDE_NAMES:
                    archive.add(src, arcname=rel, recursive=False, filter=lambda info: (setattr(info, "mode", 0o600) or info))
            metadata = json.dumps({"version": 1, "date": datetime.now(timezone.utc).isoformat()}, ensure_ascii=False).encode()
            info = tarfile.TarInfo("backup.json")
            info.size = len(metadata)
            info.mode = 0o600
            import io
            archive.addfile(info, io.BytesIO(metadata))
        if passphrase is None:
            shutil.copyfile(plain, final)
            os.chmod(final, 0o600)
        else:
            encrypt_file(plain, final, passphrase)
    return final


def rotate(directory: Path, keep: int) -> None:
    """Оставляет keep самых новых зашифрованных копий."""
    keep = max(1, int(keep))  # никогда не удаляем всё, включая только что созданную копию
    candidates = sorted(directory.glob("backup-*.tar.gz.enc"), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in candidates[keep:]:
        old.unlink()


def _ensure_key() -> str:
    target = core.path(KEY_FILE)
    if not target.is_file() or target.stat().st_size == 0:
        core.write_file(target, base64.b64encode(secrets.token_bytes(33)) + b"\n", 0o600)
    return target.read_text(encoding="utf-8").strip()


def auto_enable(keep: int = 7) -> None:
    """Включает ежедневное шифрованное резервное копирование."""
    if not 1 <= keep <= 999:
        core.die("keep должен быть числом от 1 до 999.")
    _ensure_key()
    directory = core.path(BACKUP_DIR)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    core.write_file(core.path(CONFIG), json.dumps({"keep": keep}) + "\n", 0o600)
    units = core.path("etc/systemd/system")
    core.write_file(units / "autopilot-backup.service", "[Unit]\nDescription=3X-UI Autopilot backup\n\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/autopilot backup --auto\nTimeoutStartSec=300\n")
    core.write_file(units / "autopilot-backup.timer", "[Unit]\nDescription=3X-UI Autopilot daily backup\n\n[Timer]\nOnCalendar=*-*-* 04:30\nRandomizedDelaySec=15min\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n")
    core.systemctl("daemon-reload", check=True)
    core.systemctl("enable", "--now", "autopilot-backup.timer", check=True)


def auto_disable() -> None:
    """Отключает таймер автобэкапа, сохраняя ключ и копии."""
    core.systemctl("disable", "--now", "autopilot-backup.timer", check=False)
    for name in ("autopilot-backup.service", "autopilot-backup.timer"):
        try:
            (core.path("etc/systemd/system") / name).unlink()
        except FileNotFoundError:
            pass
    core.systemctl("daemon-reload", check=True)


def auto_run() -> Path:
    """Создаёт автобэкап и применяет лимит хранения."""
    config_path = core.path(CONFIG)
    keep = _read_keep(config_path)
    result = create(passphrase=auto_key())
    rotate(core.path(BACKUP_DIR), keep)
    return result


def _read_keep(config_path: Path) -> int:
    """Сколько копий хранить: из настроек, но только число 1..999; иначе безопасные 7."""
    try:
        keep = int(json.loads(config_path.read_text(encoding="utf-8")).get("keep", 7))
    except (OSError, ValueError, TypeError, AttributeError):
        return 7
    return keep if 1 <= keep <= 999 else 7


def auto_key() -> str:
    """Возвращает ключ автобэкапа."""
    target = core.path(KEY_FILE)
    if not target.is_file():
        core.die("Ключа ещё нет: autopilot backup auto on")
    return target.read_text(encoding="utf-8").strip()


def auto_status() -> str:
    """Показывает состояние таймера и последние копии."""
    if core.systemctl("is-enabled", "--quiet", "autopilot-backup.timer").returncode != 0:
        return "Автобэкап выключен. Включить: autopilot backup auto on [--keep 7]"
    try:
        keep = json.loads(core.path(CONFIG).read_text(encoding="utf-8")).get("keep", 7)
    except (OSError, ValueError):
        keep = 7
    backups = sorted(core.path(BACKUP_DIR).glob("backup-*.tar.gz.enc"), key=lambda p: p.stat().st_mtime, reverse=True)[:3]
    return "Автобэкап включён (хранится %s копий).\n%s" % (keep, "\n".join("  " + str(p) for p in backups))


def safe_extract(archive: Path, dest: Path, passphrase: str | None = None) -> None:
    """Проверяет весь архив до безопасного распаковывания."""
    temporary: tempfile.TemporaryDirectory[str] | None = None
    source = archive
    if archive.name.endswith(".enc"):
        if passphrase is None:
            core.die("Для расшифровки архива нужен пароль.")
        temporary = tempfile.TemporaryDirectory(prefix="autopilot-restore-")
        source = Path(temporary.name) / "restore.tar.gz"
        decrypt_file(archive, source, passphrase)
    allowed = set(INCLUDE) | {"backup.json"}
    try:
        with tarfile.open(source, "r:gz") as tar:
            members = tar.getmembers()
            if sum(m.size for m in members if m.isfile()) > MAX_EXPANDED:
                core.die("Резервная копия слишком большая после распаковки.")
            for member in members:
                name = member.name
                path = PurePosixPath(name)
                if path.is_absolute() or ".." in path.parts or "\\" in name or not name:
                    core.die("Небезопасный путь в резервной копии.")
                if not (member.isfile() or member.isdir()):
                    core.die("Ссылки и специальные файлы в резервной копии запрещены.")
                included = name in allowed or any(item.startswith(name.rstrip("/") + "/") for item in INCLUDE)
                included = included or any(item.endswith("/certs") and name.startswith(item + "/") for item in INCLUDE)
                if PurePosixPath(name).name in EXCLUDE_NAMES or not included:
                    core.die("Неизвестный файл в резервной копии: %s" % name)
            dest.mkdir(parents=True, exist_ok=True)
            for member in members:
                target = dest.joinpath(*PurePosixPath(member.name).parts)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    stream = tar.extractfile(member)
                    if stream is None:
                        core.die("Не удалось прочитать резервную копию.")
                    with stream, target.open("wb") as handle:
                        shutil.copyfileobj(stream, handle)
                    os.chmod(target, 0o600)
    except (tarfile.TarError, OSError) as exc:
        core.die("Не удалось прочитать резервную копию: %s" % exc)
    finally:
        if temporary is not None:
            temporary.cleanup()
