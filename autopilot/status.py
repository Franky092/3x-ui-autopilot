"""Проверки состояния сервера и статистика трафика."""
from __future__ import annotations

import datetime as dt
import json
import re
import shutil
from dataclasses import dataclass
from typing import Any

from . import core
from .panel import PanelAPI

_AWG = re.compile(r"-awg[0-9]+$")


@dataclass
class Check:
    """Один результат проверки сервера."""
    level: str
    group: str
    text: str


def _run(command: list[str]):
    """Запускает проверку; отсутствующая команда пропускается."""
    try:
        result = core.run(command, check=False)
        return result if result.returncode != 127 else None
    except (core.Error, OSError):
        return None


def _cert_file() -> Any | None:
    try:
        data = json.loads(core.path("etc/autopilot/install.json").read_text(encoding="utf-8"))
        value = data.get("cert_file") if isinstance(data, dict) else None
        target = core.path(str(value)) if value else None
        return target if target and target.is_file() else None
    except (OSError, ValueError):
        return None


def _cert_days(target: Any) -> int | None:
    result = _run(["openssl", "x509", "-noout", "-enddate", "-in", str(target)])
    if result is None or result.returncode:
        return None
    try:
        from email.utils import parsedate_to_datetime
        expiry = parsedate_to_datetime(result.stdout.strip().split("=", 1)[1])
        if not expiry.tzinfo:
            expiry = expiry.replace(tzinfo=dt.timezone.utc)
        now = dt.datetime.now(dt.timezone.utc)
        return int((expiry - now).total_seconds() // 86400)
    except (IndexError, TypeError, ValueError):
        return None


def collect(panel: PanelAPI | None = None, *, services: tuple[str, ...] = ("x-ui", "autopilot-nginx", "unbound", "fail2ban")) -> list[Check]:
    """Собирает доступные проверки служб и системы."""
    checks: list[Check] = []
    for service in services:
        try:
            exists = core.unit_exists(service)
        except Exception:
            exists = False
        if exists:
            active = core.unit_active(service)
            checks.append(Check("ok" if active else "bad", "Службы",
                                "%s работает" % service if active else "%s не работает" % service))
    if core.unit_exists("autopilot-watch.timer"):
        active = core.unit_active("autopilot-watch.timer")
        checks.append(Check("ok" if active else "warn", "Службы",
                            "autopilot-watch.timer по расписанию" if active else "autopilot-watch.timer выключен"))

    certificate = _cert_file()
    if certificate:
        days = _cert_days(certificate)
        if days is not None:
            if days < 1:
                checks.append(Check("bad", "Сертификат", "истекает меньше чем через сутки"))
            elif days < 2:
                checks.append(Check("warn", "Сертификат", "остался 1 дн."))
            else:
                checks.append(Check("ok", "Сертификат", "осталось %d дн." % days))

    try:
        usage = shutil.disk_usage(core.path("/"))
        percent = int(usage.used * 100 / usage.total)
        level = "bad" if percent >= 90 else "warn" if percent >= 80 else "ok"
        disk_text = "диск заполнен на %d%%" % percent if level != "ok" else "диск %d%%" % percent
        checks.append(Check(level, "Система", disk_text))
    except OSError:
        pass
    try:
        mem = core.path("/proc/meminfo").read_text(encoding="utf-8")
        values = {key: int(value) for key, value in re.findall(r"^(MemTotal|MemAvailable):\s+(\d+)", mem, re.M)}
        if values.get("MemTotal"):
            used = 100 - int(values.get("MemAvailable", 0) * 100 / values["MemTotal"])
            checks.append(Check("ok", "Система", "память %d%%" % used))
    except OSError:
        pass
    try:
        load = core.path("/proc/loadavg").read_text(encoding="utf-8").split()[:3]
        if len(load) == 3:
            checks.append(Check("ok", "Система", "нагрузка %s" % " ".join(load)))
    except OSError:
        pass
    reboot = core.path("var/run/reboot-required").exists()
    checks.append(Check("warn" if reboot else "ok", "Система",
                        "нужна перезагрузка (обновилось ядро или библиотеки)" if reboot else "перезагрузка не нужна"))

    ufw = _run(["ufw", "status"])
    if ufw is not None:
        active = "Status: active" in ufw.stdout
        checks.append(Check("ok" if active else "bad", "Защита", "ufw включён" if active else "ufw выключен"))
    try:
        fail2ban_active = core.unit_active("fail2ban")
    except Exception:
        fail2ban_active = False
    if fail2ban_active:
        result = _run(["fail2ban-client", "status", "sshd"])
        if result is not None and result.returncode == 0:
            match = re.search(r"Currently banned:\s*(\d+)", result.stdout)
            count = match.group(1) if match else "0"
            checks.append(Check("ok", "Защита", "fail2ban: сейчас в бане %s" % count))
    ssh = _run(["sshd", "-T"])
    if ssh is not None and ssh.returncode == 0:
        match = re.search(r"^passwordauthentication\s+(\S+)", ssh.stdout, re.M | re.I)
        if match:
            allowed = match.group(1).lower() == "yes"
            checks.append(Check("warn" if allowed else "ok", "Защита",
                                "SSH: вход по паролю разрешён (autopilot harden ssh)" if allowed
                                else "SSH: вход по паролю выключен"))

    if panel is not None:
        try:
            count = sum(1 for client in panel.clients() if not _AWG.search(str(client.get("email", ""))))
            checks.append(Check("ok", "Пользователи", "пользователей: %d" % count))
        except Exception:
            checks.append(Check("warn", "Пользователи", "панель не ответила на запрос"))
    return checks


def render(checks: list[Check]) -> str:
    """Форматирует проверки по группам и уровню."""
    marks = {"ok": ("✓", "\033[32m"), "warn": ("!", "\033[33m"), "bad": ("✗", "\033[31m")}
    lines: list[str] = []
    group = None
    for item in checks:
        if item.group != group:
            group = item.group
            lines.append(core.bold(group))
        mark, color = marks.get(item.level, ("✗", "\033[31m"))
        lines.append("  %s%s%s  %s" % (core._color(color), mark, core._color("\033[0m"), item.text))
    return "\n".join(lines)


def exit_code(checks: list[Check]) -> int:
    """Возвращает ненулевой код при критической проверке."""
    return 1 if any(item.level == "bad" for item in checks) else 0


def usage_by_user(panel: PanelAPI) -> list[dict[str, Any]]:
    """Суммирует трафик записей одного пользователя, включая AmneziaWG."""
    users: dict[str, dict[str, Any]] = {}
    for client in panel.clients():
        email = str(client.get("email", ""))
        if not email:
            continue
        user = _AWG.sub("", email)
        traffic = client.get("traffic") or {}
        used = int(traffic.get("up") or 0) + int(traffic.get("down") or 0)
        limit = int(client.get("totalGB") or 0)
        if user not in users:
            users[user] = {"user": user, "bytes": 0, "limit": limit}
        users[user]["bytes"] += used
        users[user]["limit"] = max(users[user]["limit"], limit)
    return sorted(users.values(), key=lambda item: item["bytes"], reverse=True)


def _today(value: dt.date | None) -> dt.date:
    return value or dt.date.today()


def _snapshot_path(day: dt.date) -> Any:
    return core.path("var/lib/autopilot/traffic-%s.json" % day.isoformat())


def snapshot(panel: PanelAPI, today: dt.date | None = None) -> None:
    """Записывает дневной снимок один раз и удаляет старые снимки."""
    day = _today(today)
    target = _snapshot_path(day)
    if not target.exists():
        values = {item["user"]: item["bytes"] for item in usage_by_user(panel)}
        core.write_file(target, json.dumps(values, ensure_ascii=False, sort_keys=True) + "\n", 0o600)
    cutoff = day - dt.timedelta(days=45)
    directory = core.path("var/lib/autopilot")
    try:
        candidates = directory.glob("traffic-*.json")
        for old in candidates:
            match = re.fullmatch(r"traffic-(\d{4}-\d{2}-\d{2})\.json", old.name)
            if match:
                try:
                    if dt.date.fromisoformat(match.group(1)) < cutoff:
                        old.unlink()
                except ValueError:
                    continue
    except OSError:
        pass


def stats_table(panel: PanelAPI, today: dt.date | None = None) -> str:
    """Показывает текущий трафик, изменения за сутки и неделю, лимит."""
    day = _today(today)
    users = usage_by_user(panel)
    lines = ["%-18s %-12s %-12s %-12s %s" % ("Пользователь", "Всего", "За сутки", "За 7 дней", "Лимит")]
    total = 0
    for item in users:
        user, amount, limit = item["user"], item["bytes"], item["limit"]
        total += amount
        deltas: list[str] = []
        for ago in (1, 7):
            try:
                previous = json.loads(_snapshot_path(day - dt.timedelta(days=ago)).read_text(encoding="utf-8"))
                delta = max(amount - int(previous.get(user, amount)), 0)
                deltas.append(core.human_bytes(delta))
            except (OSError, ValueError, TypeError):
                deltas.append("–")
        limit_text = core.human_bytes(limit) if limit > 0 else "без лимита"
        lines.append("%-18s %-12s %-12s %-12s %s" %
                     (user, core.human_bytes(amount), deltas[0], deltas[1], limit_text))
    lines.append("Итого: %s" % core.human_bytes(total))
    return "\n".join(lines)


def to_json(panel: PanelAPI) -> str:
    """Возвращает статистику по пользователям в компактном JSON."""
    return json.dumps(usage_by_user(panel), ensure_ascii=False, separators=(",", ":"))
