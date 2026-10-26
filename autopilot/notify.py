"""Telegram-уведомления о состоянии сервера и пользователей."""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import shutil
import socket
import urllib.error
import urllib.parse
import urllib.request
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Callable

from . import core
from .panel import PanelAPI

ENV_FILE = "etc/autopilot/notify.env"
STATE_FILE = "var/lib/autopilot/alerts.json"
_TOKEN = re.compile(r"^[0-9]{5,12}:[A-Za-z0-9_-]{30,50}$")
_CHAT = re.compile(r"^-?[0-9]{1,20}$")
_AWG = re.compile(r"-awg[0-9]+$")


def valid_token(value: str) -> bool:
    """Проверяет формат токена Telegram."""
    return bool(_TOKEN.fullmatch(value))


def valid_chat(value: str) -> bool:
    """Проверяет числовой ID чата Telegram."""
    return bool(_CHAT.fullmatch(value))


def is_configured() -> bool:
    """Проверяет наличие корректных настроек Telegram."""
    values = core.read_env(core.path(ENV_FILE))
    return valid_token(values.get("NOTIFY_TOKEN", "")) and valid_chat(values.get("NOTIFY_CHAT", ""))


def send_message(text: str, *, token: str | None = None, chat: str | None = None) -> bool:
    """Отправляет текст через HTTPS API Telegram."""
    if token is None or chat is None:
        values = core.read_env(core.path(ENV_FILE))
        token = token or values.get("NOTIFY_TOKEN", "")
        chat = chat or values.get("NOTIFY_CHAT", "")
    if not valid_token(token) or not valid_chat(chat):
        return False
    body = urllib.parse.urlencode({"chat_id": chat, "text": "[%s] %s" % (socket.gethostname(), text)}).encode()
    request = urllib.request.Request(
        "https://api.telegram.org/bot%s/sendMessage" % token,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status == 200
    except (urllib.error.URLError, OSError, ValueError):
        return False


def configure(token: str, chat: str, send: Callable[..., bool] = send_message) -> None:
    """Сохраняет настройки и проверяет их тестовым сообщением."""
    token, chat = token.strip(), chat.strip()
    if not valid_token(token):
        core.die("Неверный формат токена Telegram.")
    if not valid_chat(chat):
        core.die("ID чата должен быть числом.")
    target = core.path(ENV_FILE)
    core.write_env(target, {"NOTIFY_TOKEN": token, "NOTIFY_CHAT": chat}, 0o600)
    try:
        sent = send("✅ Уведомления 3X-UI Autopilot настроены.", token=token, chat=chat)
    except TypeError:
        sent = send("✅ Уведомления 3X-UI Autopilot настроены.")
    if not sent:
        target.unlink(missing_ok=True)
        core.die("Не удалось отправить тестовое сообщение Telegram.")


def disable() -> None:
    """Удаляет настройки и сохранённое состояние уведомлений."""
    core.path(ENV_FILE).unlink(missing_ok=True)
    core.path(STATE_FILE).unlink(missing_ok=True)


def status_text() -> str:
    """Возвращает короткий статус настроек Telegram."""
    return "Уведомления Telegram настроены." if is_configured() else "Уведомления Telegram не настроены."


def _certificate_path(cert_file: str | Path | None) -> Path | None:
    if cert_file:
        return core.path(str(cert_file))
    try:
        data = json.loads(core.path("etc/autopilot/install.json").read_text(encoding="utf-8"))
        value = data.get("cert_file") if isinstance(data, dict) else None
        return core.path(str(value)) if value else None
    except (OSError, ValueError):
        return None


def _cert_expiry(path: Path) -> dt.datetime | None:
    result = core.run(["openssl", "x509", "-noout", "-enddate", "-in", str(path)], check=False)
    if result.returncode:
        return None
    try:
        value = result.stdout.strip().split("=", 1)[1]
        expires = parsedate_to_datetime(value)
        return expires if expires.tzinfo else expires.replace(tzinfo=dt.timezone.utc)
    except (IndexError, TypeError, ValueError):
        return None


def _now_datetime(now: float | dt.datetime | None) -> dt.datetime:
    if isinstance(now, dt.datetime):
        return now.replace(tzinfo=now.tzinfo or dt.timezone.utc)
    return dt.datetime.fromtimestamp(now if now is not None else dt.datetime.now().timestamp(), dt.timezone.utc)


def collect_alerts(panel: PanelAPI | None, *, services: tuple[str, ...] = ("x-ui", "autopilot-nginx", "unbound", "fail2ban"),
                   cert_file: str | Path | None = None, now: float | dt.datetime | None = None) -> dict[str, str]:
    """Собирает текущие проблемы служб, сертификата, диска и клиентов."""
    alerts: dict[str, str] = {}
    for service in services:
        if core.unit_exists(service) and not core.unit_active(service):
            alerts["svc:" + service] = "Служба %s не работает" % service
    cert = _certificate_path(cert_file)
    if cert and cert.is_file():
        expiry = _cert_expiry(cert)
        if expiry:
            remaining = (expiry - _now_datetime(now)).total_seconds()
            if remaining < 2 * 86400:
                days = int(remaining // 86400)
                alerts["cert"] = ("Сертификат уже истёк. Проверьте продление: systemctl status autopilot-cert.service" if remaining <= 0
                                  else "Сертификат истекает через %s дн. Проверьте сертификат и продление." % days)
    try:
        used = shutil.disk_usage(core.path("/"))
        percent = int(used.used * 100 / used.total)
        if percent >= 90:
            alerts["disk"] = "Диск заполнен на %s%%" % percent
    except OSError:
        pass
    if core.path("var/run/reboot-required").exists():
        alerts["reboot"] = "Нужна перезагрузка сервера"
    if panel is not None:
        try:
            clients = panel.clients()
        except Exception:
            clients = []
        current_ms = int(_now_datetime(now).timestamp() * 1000)
        for client in clients:
            email = str(client.get("email", ""))
            if not email or _AWG.search(email):
                continue
            expiry = int(client.get("expiryTime") or 0)
            if expiry > 0 and expiry < current_ms:
                alerts["user:%s:expired" % email] = "У пользователя %s закончился срок доступа" % email
            limit = int(client.get("totalGB") or 0)
            traffic = client.get("traffic") or {}
            used = int(traffic.get("up") or 0) + int(traffic.get("down") or 0)
            if limit > 0 and used >= limit:
                alerts["user:%s:limit" % email] = "У пользователя %s исчерпан лимит трафика" % email
    return alerts


def check(panel: PanelAPI | None, send: Callable[..., bool] = send_message, **kw: Any) -> list[str]:
    """Отправляет новые уведомления и сообщает о восстановлении."""
    if not is_configured():
        return []
    current = collect_alerts(panel, **kw)
    target = core.path(STATE_FILE)
    try:
        old = json.loads(target.read_text(encoding="utf-8"))
        if not isinstance(old, dict):
            old = {}
    except (OSError, ValueError):
        old = {}
    keep: dict[str, str] = {}
    sent: list[str] = []
    for key, message in current.items():
        if key in old:
            keep[key] = message
        else:
            outgoing = "⚠️ " + message
            try:
                ok = send(outgoing)
            except Exception:
                ok = False
            if ok:
                keep[key] = message
                sent.append(outgoing)
    for key, message in old.items():
        if key not in current:
            outgoing = "✅ Снова в порядке: " + str(message)
            try:
                delivered = bool(send(outgoing))
            except Exception:
                delivered = False
            if delivered:
                sent.append(outgoing)
            else:
                keep[key] = str(message)  # не доставлено – оставляем в состоянии и повторим при следующей проверке
    core.write_file(target, json.dumps(keep, ensure_ascii=False, sort_keys=True) + "\n", 0o600)
    return sent
