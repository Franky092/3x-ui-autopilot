"""Глубокие проверки сервера и безопасное исправление известных проблем."""
from __future__ import annotations

import re
import shutil
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from . import cert, core, dns, installer, nginx, subscription, sync, uninstaller


@dataclass
class Problem:
    """Один результат проверки."""

    id: str
    level: str  # ok | warn | bad
    text: str
    hint: str = ""
    fixable: bool = False


_SERVICES = ("x-ui", "autopilot-nginx", "unbound", "fail2ban")
_UDP_PROTOCOLS = {"hysteria", "hysteria2", "tuic", "amneziawg"}


def _listeners(output: str) -> dict[tuple[str, int], set[str]]:
    """Разбирает локальные адреса и протоколы из `ss -Hltun`."""
    found: dict[tuple[str, int], set[str]] = {}
    for line in output.splitlines():
        columns = line.split()
        if len(columns) < 5:
            continue
        proto, address = columns[0].lower(), columns[4]
        if proto not in ("tcp", "udp"):
            continue
        match = re.match(r"^(.*):(\d+)$", address)
        if not match:
            continue
        host = match.group(1).strip("[]")
        found.setdefault((proto, int(match.group(2))), set()).add(host)
    return found


def _is_listening(listeners: dict[tuple[str, int], set[str]], proto: str, port: int,
                  loopback: bool = False) -> bool:
    hosts = listeners.get((proto, port), set())
    return "127.0.0.1" in hosts if loopback else bool(hosts)


def _ufw_state(output: str) -> tuple[bool, set[tuple[int, str]]]:
    """Возвращает состояние ufw и разрешённые IPv4/IPv6 правила."""
    active = bool(re.search(r"^Status:\s+active\s*$", output, re.M | re.I))
    allowed: set[tuple[int, str]] = set()
    for line in output.splitlines():
        match = re.match(r"\s*(\d+)/(tcp|udp)(?:\s+\(v6\))?\s+ALLOW\b", line, re.I)
        if match:
            allowed.add((int(match.group(1)), match.group(2).lower()))
    return active, allowed


def _expected_ufw() -> list[tuple[int, str]]:
    """Правила ufw с учётом портов, изменённых через `autopilot net port` (берутся из состояния установки)."""
    rules = []
    for rule in uninstaller.ufw_rules():
        port, _, proto = rule.partition("/")
        rules.append((int(port), proto))
    return rules


def _panel_inbounds(api: Any) -> list[dict[str, Any]]:
    values = api.inbounds()
    return values if isinstance(values, list) else []


def run_checks(api=None, *, host: str | None = None) -> list[Problem]:
    """Проверяет службы, сеть, сертификат, DNS, подписку, ufw и диск."""
    problems: list[Problem] = []
    down: set[str] = set()
    for name in _SERVICES:
        try:
            exists = core.unit_exists(name)
            active = core.unit_active(name) if exists else False
        except core.Error:
            exists, active = False, False
        if exists and active:
            problems.append(Problem("svc:" + name, "ok", "%s работает" % name))
        elif exists:
            down.add(name)
            problems.append(Problem("svc:" + name, "bad", "%s не работает" % name,
                                    "Перезапустить службу.", True))
        else:
            problems.append(Problem("svc:" + name, "bad", "служба %s не найдена" % name))

    try:
        result = core.run(["nginx", "-t", "-c", str(core.path(nginx.CONF))], check=False)
        good_nginx = result.returncode == 0
    except core.Error:
        good_nginx = False
    problems.append(Problem("nginx-config", "ok" if good_nginx else "bad",
                            "конфигурация nginx работает" if good_nginx else "конфигурация nginx не прошла проверку",
                            "Построить конфигурацию заново по панели." if not good_nginx else "",
                            not good_nginx and api is not None))

    panel_ok = api is not None
    if panel_ok:
        try:
            inbounds = _panel_inbounds(api)
            settings = api.settings() or {}
            clients = api.clients() or []
        except Exception:
            panel_ok = False
            inbounds, settings, clients = [], {}, []
    else:
        inbounds, settings, clients = [], {}, []

    try:
        ss = core.run(["ss", "-Hltun"], check=False)
        listeners = _listeners(ss.stdout if ss.returncode == 0 else "")
    except core.Error:
        listeners = {}
    if panel_ok:
        expected: dict[tuple[int, str], bool] = {}
        for inbound in inbounds:
            if not inbound.get("enable", True):
                continue
            try:
                port = int(inbound.get("port") or 0)
            except (TypeError, ValueError):
                continue
            if not 1 <= port <= 65535:
                continue
            protocol = str(inbound.get("protocol", "")).lower()
            protos = ("tcp", "udp") if protocol in ("shadowsocks", "shadowsocks2022") else (
                ("udp",) if protocol in _UDP_PROTOCOLS else ("tcp",))
            loopback = inbound.get("listen") == "127.0.0.1"
            for proto in protos:
                key = (port, proto)
                expected[key] = expected.get(key, False) or loopback
        expected[(443, "tcp")] = False
        for port, proto in sorted(expected, key=lambda item: (item[0], item[1])):
            loopback = expected[(port, proto)]
            listening = _is_listening(listeners, proto, port, loopback)
            if port == 443 and proto == "tcp" and "autopilot-nginx" not in down:
                # The dedicated unit owns this socket; a listener is required as well.
                listening = listening and core.unit_active("autopilot-nginx")
            caused_by_down = "x-ui" in down if port != 443 or proto != "tcp" else "autopilot-nginx" in down
            text = "%d/%s слушает" % (port, proto) if listening else "%d/%s не слушает" % (port, proto)
            problems.append(Problem("port:%d/%s" % (port, proto), "ok" if listening else "bad", text,
                                    "Проверить службу, которая обслуживает порт." if not listening else "",
                                    not listening and caused_by_down))
    else:
        problems.append(Problem("panel", "warn", "панель не отвечает"))

    try:
        days = cert.days_left()
    except core.Error:
        days = None
    if days is None:
        problems.append(Problem("cert", "warn", "сертификат не найден"))
    elif days < 1:
        problems.append(Problem("cert", "bad", "сертификат истёк или истекает менее чем через сутки",
                                "Продлить сертификат.", True))
    elif days < 2:
        problems.append(Problem("cert", "warn", "сертификат истекает менее чем через двое суток",
                                "Продлить сертификат.", True))
    else:
        problems.append(Problem("cert", "ok", "сертификат действителен ещё %d дн." % days))

    try:
        rcode, answers = dns.query("127.0.0.1", dns.LOCAL_PORT, "ubuntu.com")
        dns_ok = rcode == 0 and answers > 0
    except (core.Error, OSError, ValueError):
        dns_ok = False
    problems.append(Problem("dns", "ok" if dns_ok else "bad",
                            "DNS local отвечает" if dns_ok else "DNS local не отвечает",
                            "Настроить unbound заново." if not dns_ok else "", not dns_ok and host is not None))

    if panel_ok:
        if not settings.get("subEnable"):
            problems.append(Problem("subscription", "ok", "подписка выключена"))
        else:
            client = next((c for c in clients if c.get("subId")), None)
            if client is None:
                problems.append(Problem("subscription", "ok", "нет пользователей с subId; проверка пропущена"))
            else:
                try:
                    port = int(settings.get("subPort") or 0)
                    path = str(settings.get("subPath") or "/sub/").strip("/")
                    url = "http://127.0.0.1:%d/%s/%s" % (port, path, client["subId"])
                    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                    with opener.open(url, timeout=5) as response:
                        good_sub = response.status == 200
                except (ValueError, OSError, urllib.error.URLError, core.Error):
                    good_sub = False
                problems.append(Problem("subscription", "ok" if good_sub else "bad",
                                        "подписка отвечает" if good_sub else "подписка не отвечает",
                                        "Проверить службу панели и настройки подписки." if not good_sub else ""))

    try:
        result = core.run(["ufw", "status"], check=False)
        active, allowed = _ufw_state(result.stdout if result.returncode == 0 else "")
    except core.Error:
        active, allowed = False, set()
    if not active:
        problems.append(Problem("ufw", "bad", "ufw выключен; включение оставлено владельцу"))
    else:
        missing = [rule for rule in _expected_ufw() if rule not in allowed]
        if missing:
            names = ", ".join("%d/%s" % rule for rule in missing)
            problems.append(Problem("ufw", "bad", "нет разрешений ufw: " + names,
                                    "Добавить только отсутствующие правила.", True))
        else:
            problems.append(Problem("ufw", "ok", "правила ufw разрешены"))

    try:
        usage = shutil.disk_usage(core.path("/"))
        percent = usage.used * 100 / usage.total
        level = "bad" if percent >= 90 else "warn" if percent >= 80 else "ok"
        text = "диск заполнен на %.0f%%" % percent
    except OSError:
        level, text = "warn", "не удалось проверить заполнение диска"
    problems.append(Problem("disk", level, text))
    return problems


def apply_fixes(problems: list[Problem], api, *, host: str) -> list[str]:
    """Выполняет только безопасные исправления, отмеченные как fixable."""
    done: list[str] = []
    for problem in problems:
        if not problem.fixable:
            continue
        try:
            if problem.id.startswith("svc:"):
                unit = problem.id.split(":", 1)[1]
                core.systemctl("restart", unit, check=True)
                description = "перезапущена служба %s" % unit
            elif problem.id == "nginx-config":
                if api is None:
                    raise core.Error("панель недоступна")
                fullchain, key = cert.paths()
                sync.apply(api, str(fullchain), str(key))
                description = "пересобрана конфигурация nginx"
            elif problem.id == "cert":
                cert.renew(host)
                cert.reload_services()
                description = "сертификат продлён и службы перезагружены"
            elif problem.id == "dns":
                dns.setup(host)
                description = "настроен локальный DNS"
            elif problem.id == "ufw":
                status = core.run(["ufw", "status"], check=False)
                active, allowed = _ufw_state(status.stdout if status.returncode == 0 else "")
                if not active:
                    raise core.Error("ufw выключен")
                added = []
                for port, proto in _expected_ufw():
                    if (port, proto) not in allowed:
                        core.run(["ufw", "allow", "%d/%s" % (port, proto)], check=True)
                        added.append("%d/%s" % (port, proto))
                description = "добавлены правила ufw: " + ", ".join(added)
            else:
                continue
            done.append(description)
        except core.Error as exc:
            done.append("не удалось: %s" % exc)
    return done


def summary(problems: list[Problem]) -> tuple[int, int, int]:
    """Считает результаты в порядке ok, warn, bad."""
    return tuple(sum(problem.level == level for problem in problems) for level in ("ok", "warn", "bad"))
