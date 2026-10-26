"""Общие помощники: вывод, запуск команд, пути, файлы настроек.

Все пути к системным файлам строятся через `path()`: в тестах корень подменяется переменной
AUTOPILOT_ROOT, так что ничего не трогает настоящую систему.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Mapping, Sequence

CONF_DIR = "etc/autopilot"
STATE_DIR = "var/lib/autopilot"
BACKUP_DIR = "var/backups/autopilot"


class Error(Exception):
    """Ожидаемая ошибка: показываем сообщение без трассировки и выходим с кодом 1. hint – подсказка «что делать»."""

    def __init__(self, message: str, hint: str | None = None) -> None:
        super().__init__(message)
        self.hint = hint


def path(*parts: str) -> Path:
    """Путь внутри корня системы. path('etc/autopilot/notify.env')."""
    root = Path(os.environ.get("AUTOPILOT_ROOT", "/"))
    return root.joinpath(*[p.lstrip("/") for p in parts])


# --- вывод ---------------------------------------------------------------------------------------

def _color(code: str) -> str:
    return code if sys.stdout.isatty() and not os.environ.get("NO_COLOR") else ""


def say(message: str) -> None:
    print("%s==>%s %s" % (_color("\033[32m"), _color("\033[0m"), message))


def warn(message: str) -> None:
    print("%s!%s  %s" % (_color("\033[33m"), _color("\033[0m"), message), file=sys.stderr)


def bold(text: str) -> str:
    return "%s%s%s" % (_color("\033[1m"), text, _color("\033[0m"))


def die(message: str, hint: str | None = None) -> None:
    raise Error(message, hint)


# --- команды -------------------------------------------------------------------------------------

def run(cmd: Sequence[str], *, check: bool = True, input: str | None = None, timeout: float | None = None,
        env: Mapping[str, str] | None = None, cwd: str | None = None) -> subprocess.CompletedProcess:
    """Запуск без оболочки. stdout и stderr возвращаются текстом. При check=True код != 0 даёт Error."""
    try:
        done = subprocess.run(list(cmd), input=input, capture_output=True, text=True, timeout=timeout, cwd=cwd,
                              env=None if env is None else dict(os.environ, **env))
    except FileNotFoundError:
        if check:
            die("Нет команды %s" % cmd[0])
        return subprocess.CompletedProcess(list(cmd), 127, "", "not found")
    except subprocess.TimeoutExpired:
        if check:
            die("Команда не ответила за %s с: %s" % (timeout, " ".join(cmd)))
        return subprocess.CompletedProcess(list(cmd), 124, "", "timeout")
    if check and done.returncode != 0:
        tail = (done.stderr or done.stdout).strip().splitlines()[-3:]
        die("Команда %s завершилась с кодом %d: %s" % (" ".join(cmd[:3]), done.returncode, " | ".join(tail)))
    return done


def systemctl(*args: str, check: bool = False) -> subprocess.CompletedProcess:
    return run(["systemctl", *args], check=check)


def unit_active(unit: str) -> bool:
    return systemctl("is-active", "--quiet", unit).returncode == 0


def unit_exists(unit: str) -> bool:
    return systemctl("cat", unit).returncode == 0


class lock:
    """Эксклюзивная блокировка на время операции: with core.lock("install"). Вторая попытка сразу получает понятную ошибку."""

    def __init__(self, name: str) -> None:
        self.target = path("run/autopilot-%s.lock" % name)
        self.handle = None

    def __enter__(self) -> "lock":
        import fcntl

        self.target.parent.mkdir(parents=True, exist_ok=True)
        self.handle = open(self.target, "a+")
        try:
            fcntl.flock(self.handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.handle.close()
            die("Эта операция уже выполняется в другом окне.", "Дождитесь её завершения.")
        return self

    def __exit__(self, *exc) -> bool:
        import fcntl

        if self.handle:
            fcntl.flock(self.handle, fcntl.LOCK_UN)
            self.handle.close()
        return False


# --- файлы ---------------------------------------------------------------------------------------

def write_file(target: Path, data: str | bytes, mode: int = 0o644) -> None:
    """Атомарная запись: сначала временный файл рядом, потом rename; права выставляются до записи данных."""
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(target.parent), prefix=".tmp-")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data.encode() if isinstance(data, str) else data)
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


_ENV_KEY = re.compile(r"^[A-Z][A-Z0-9_]*$")
_ENV_VALUE = re.compile(r"^[^\x00-\x1f\x7f'\"\\$`\n]*$")


def read_env(target: Path) -> dict[str, str]:
    """Читает файл KEY=VALUE (без оболочки: значения не исполняются). Нет файла – пустой словарь."""
    values: dict[str, str] = {}
    try:
        text = target.read_text(encoding="utf-8")
    except FileNotFoundError:
        return values
    for line in text.splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if _ENV_KEY.match(key):
            values[key] = value
    return values


def write_env(target: Path, values: Mapping[str, str], mode: int = 0o600) -> None:
    lines = []
    for key, value in values.items():
        if not _ENV_KEY.match(key) or not _ENV_VALUE.match(str(value)):
            die("Недопустимая настройка %s" % key)
        lines.append("%s=%s" % (key, value))
    write_file(target, "\n".join(lines) + "\n", mode)


# --- форматирование ------------------------------------------------------------------------------

def human_bytes(value: float) -> str:
    units = ["Б", "КБ", "МБ", "ГБ", "ТБ"]
    index = 0
    while value >= 1024 and index < len(units) - 1:
        value /= 1024
        index += 1
    return ("%d %s" if index == 0 else "%.1f %s") % (value, units[index])
