"""Защита SSH и настройка fail2ban."""
from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Callable

from . import core

DROPIN = "etc/ssh/sshd_config.d/00-autopilot.conf"
_KEY = re.compile(r"^(ssh-ed25519|ssh-rsa|ecdsa-sha2-|sk-)")


def valid_key_line(line: str) -> bool:
    """Строка authorized_keys с настоящим ключом: тип + base64, внутри которого тот же тип. Параметры перед типом допустимы."""
    import base64
    import binascii

    if line.lstrip().startswith("#"):
        return False
    parts = line.strip().split()
    for index, token in enumerate(parts):
        if not _KEY.match(token) or index + 1 >= len(parts):
            continue
        try:
            blob = base64.b64decode(parts[index + 1], validate=True)
        except (binascii.Error, ValueError):
            return False
        if len(blob) < 8:
            return False
        size = int.from_bytes(blob[:4], "big")
        return 0 < size <= len(blob) - 4 and blob[4:4 + size].decode("ascii", "replace") == token
    return False


def ssh_has_key(ssh_dir: Path | None = None) -> bool:
    """Проверяет наличие настоящего ключа root: битая строка не должна давать закрыть вход по паролю."""
    directory = ssh_dir or core.path("root/.ssh")
    for name in ("authorized_keys", "authorized_keys2"):
        try:
            lines = (directory / name).read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        if any(valid_key_line(line) for line in lines if line.strip() and not line.lstrip().startswith("#")):
            return True
    return False


def ssh_ports() -> list[int]:
    """Читает порты из эффективной конфигурации sshd."""
    result = core.run(["sshd", "-T"], check=False)
    if result.returncode:
        return [22]
    ports = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0] == "port":
            try:
                port = int(fields[1])
                if 1 <= port <= 65535:
                    ports.append(port)
            except ValueError:
                pass
    return ports or [22]


def password_auth_enabled() -> bool | None:
    """Возвращает состояние PasswordAuthentication."""
    result = core.run(["sshd", "-T"], check=False)
    if result.returncode:
        return None
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0] == "passwordauthentication":
            return fields[1].lower() == "yes"
    return None


def harden_ssh(*, dry_run: bool = False, confirm: Callable[[], bool] | None = None) -> str:
    """Выключает вход по паролю после проверки ключа и конфигурации."""
    if not ssh_has_key():
        core.die("В /root/.ssh/authorized_keys нет ни одного ключа. Сначала добавьте свой ключ.")
    config = core.path("etc/ssh/sshd_config")
    try:
        text = config.read_text(encoding="utf-8")
    except OSError:
        text = ""
    if not re.search(r"^\s*Include\s+/etc/ssh/sshd_config\.d/", text, re.MULTILINE):
        core.die("В sshd_config нет Include для sshd_config.d: настройка автоматически не применяется.")
    target = core.path(DROPIN)
    if dry_run:
        return "Проверка пройдена, ничего не изменено (--dry-run)."
    if confirm is not None and not confirm():
        return "Отменено."
    core.write_file(target, "# 3X-UI Autopilot: вход только по ключу. Откат: autopilot harden ssh --undo\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\nMaxAuthTries 3\n")
    valid = core.run(["sshd", "-t"], check=False).returncode == 0
    if not valid or password_auth_enabled() is not False:
        try:
            target.unlink()
        except FileNotFoundError:
            pass
        core.die("sshd не принял настройку или её перекрывает другой файл. Изменений нет.")
    reloaded = core.systemctl("reload", "ssh", check=False)
    if reloaded.returncode != 0:
        core.systemctl("reload", "sshd", check=True)
    return "Вход по паролю выключен. Текущие сессии не прерваны; новые — только по ключу."


def undo_ssh() -> None:
    """Удаляет drop-in Autopilot и перезагружает sshd."""
    target = core.path(DROPIN)
    try:
        target.unlink()
    except FileNotFoundError:
        pass
    if core.run(["sshd", "-t"], check=False).returncode != 0:
        core.die("sshd не принял конфигурацию.")
    if core.systemctl("reload", "ssh", check=False).returncode != 0:
        core.systemctl("reload", "sshd", check=True)


def setup_fail2ban(ssh_port: int | None = None) -> None:
    """Настраивает jail для SSH и повторных нарушителей."""
    if shutil.which("fail2ban-client") is None:
        core.die("fail2ban не установлен. Установите fail2ban перед настройкой.")
    port = str(ssh_port) if ssh_port else ",".join(str(x) for x in ssh_ports())
    content = ("[DEFAULT]\nignoreip = 127.0.0.1/8 ::1\nfindtime = 10m\nbantime = 1h\n"
               "bantime.increment = true\nbantime.factor = 4\nbantime.maxtime = 4w\n\n"
               "[sshd]\nenabled = true\nport = %s\nbackend = systemd\nmaxretry = 4\n\n"
               "[recidive]\nenabled = true\nlogpath = /var/log/fail2ban.log\nfindtime = 1d\nmaxretry = 3\nbantime = 1w\n") % port
    core.write_file(core.path("etc/fail2ban/jail.d/zz-autopilot.local"), content)
    core.systemctl("enable", "fail2ban", check=False)
    core.systemctl("restart", "fail2ban", check=False)
    if not wait_jail("sshd"):
        core.die("fail2ban не запустил jail sshd.", "Смотрите: journalctl -u fail2ban и fail2ban-client -t")


def wait_jail(name: str, *, attempts: int = 20, delay: float = 1.0, sleep=None) -> bool:
    """`systemctl restart` возвращается до готовности сервера fail2ban, поэтому ждём, пока jail ответит."""
    import time

    sleep = sleep or time.sleep
    for _ in range(attempts):
        if core.run(["fail2ban-client", "status", name], check=False).returncode == 0:
            return True
        sleep(delay)
    return False


def remove_fail2ban_config() -> None:
    """Удаляет конфигурацию jail Autopilot."""
    try:
        core.path("etc/fail2ban/jail.d/zz-autopilot.local").unlink()
    except FileNotFoundError:
        pass
