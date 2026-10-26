"""Полное удаление Autopilot с сервера: `autopilot uninstall`."""
from __future__ import annotations

import glob
import os
import shutil
from pathlib import Path

from . import core, dns, installer

SERVICES = ("x-ui", "autopilot-nginx", "autopilot-watch.timer", "autopilot-cert.timer", "autopilot-backup.timer",
            "autopilot-watch.service", "autopilot-cert.service", "autopilot-backup.service")
PATHS = ("etc/unbound/unbound.conf.d/autopilot.conf", "usr/local/x-ui", "etc/x-ui", "var/log/x-ui", "etc/autopilot", "var/lib/autopilot", "var/www/autopilot",
         "usr/local/lib/autopilot", "usr/local/lib/autopilot-acme", "var/lib/autopilot-acme", "usr/local/bin/autopilot",
         "etc/fail2ban/jail.d/zz-autopilot.local", "etc/systemd/system/x-ui.service", "var/log/autopilot-nginx-error.log",
         "root/autopilot.txt")
GLOBS = ("etc/systemd/system/autopilot-*.service", "etc/systemd/system/autopilot-*.timer")
KEPT = ("var/backups/autopilot", "etc/ssh/sshd_config.d/00-autopilot.conf")  # намеренно не трогаем


def targets() -> list[Path]:
    """Что будет удалено (только существующее)."""
    found = [core.path(p) for p in PATHS]
    for pattern in GLOBS:
        found += [Path(p) for p in glob.glob(str(core.path(pattern)))]
    return [p for p in found if p.exists() or p.is_symlink()]


def kept() -> list[Path]:
    return [core.path(p) for p in KEPT if core.path(p).exists()]


DEFAULT_PORTS = {"shadowsocks": 8388, "hysteria2": installer.HY2_PORT, "tuic": installer.TUIC_PORT,
                 "amneziawg": installer.AWG_PORT, "amneziawg-3.1": installer.AWG31_PORT}


def ufw_rules() -> list[str]:
    """Правила ufw, которые добавил установщик, с учётом портов, изменённых через `autopilot net port`
    (SSH не трогаем: без него потерялся бы доступ)."""
    import json

    try:
        custom = json.loads(core.path(core.CONF_DIR, "install.json").read_text(encoding="utf-8")).get("ports") or {}
    except (OSError, ValueError, AttributeError):
        custom = {}
    replace = {DEFAULT_PORTS[name]: int(port) for name, port in custom.items() if name in DEFAULT_PORTS and isinstance(port, int)}
    rules = []
    for port, proto in installer.UFW_RULES:
        # 443/tcp (nginx) и 80/tcp менять нельзя; заменяем только публичные порты подключений
        new = replace.get(port, port) if (port, proto) not in ((443, "tcp"), (80, "tcp")) else port
        rules.append("%d/%s" % (new, proto))
    return rules


def remove(*, dry_run: bool = False) -> list[str]:
    """Останавливает службы и удаляет файлы. Возвращает список выполненных (или показанных при dry_run) действий."""
    actions: list[str] = []
    rules = ufw_rules()  # до удаления файлов: порты берём из состояния установки
    if core.path(dns.CONF).exists():  # unbound ставили мы: останавливаем, пока конфиг ещё на месте
        actions.append("stop unbound")
        if not dry_run:
            core.systemctl("disable", "--now", "unbound")
    for unit in SERVICES:
        if core.unit_exists(unit):
            actions.append("stop " + unit)
            if not dry_run:
                core.systemctl("disable", "--now", unit)
    for target in targets():
        actions.append("remove " + str(target))
        if dry_run:
            continue
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(target, ignore_errors=True)
        else:
            try:
                os.unlink(target)
            except FileNotFoundError:
                pass
    if shutil.which("ufw"):
        for rule in rules:
            actions.append("ufw delete allow " + rule)
            if not dry_run:
                core.run(["ufw", "--force", "delete", "allow", rule], check=False)
    if not dry_run:
        core.systemctl("daemon-reload")
        if core.unit_active("fail2ban"):
            core.systemctl("reload", "fail2ban")
    return actions
