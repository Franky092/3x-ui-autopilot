"""Подключения (inbound) и пользователи панели: VLESS+REALITY (TCP, Vision) и VLESS+XHTTP+REALITY."""
from __future__ import annotations

import json
import re
import secrets
import time
from typing import Any

from . import core

NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
SNIFFING = {"enabled": True, "destOverride": ["http", "tls", "quic"], "metadataOnly": False, "routeOnly": False}
GB = 1024 ** 3


def valid_name(name: str) -> str:
    if not NAME_RE.match(name) or not re.search(r"[^.]", name):
        core.die("Имя: латиница, цифры, _ . - (до 32 символов, не только точки).")
    return name


def short_id() -> str:
    return secrets.token_hex(8)


def _reality(sni: str, keys: dict[str, str], sid: str) -> dict[str, Any]:
    return {
        "show": False, "xver": 0, "target": "%s:443" % sni, "serverNames": [sni],
        "privateKey": keys["privateKey"], "minClientVer": "", "maxClientVer": "", "maxTimeDiff": 0,
        "shortIds": [sid],
        "settings": {"publicKey": keys["publicKey"], "fingerprint": "chrome", "serverName": "", "spiderX": "/"},
    }


def _external(host: str) -> list[dict[str, Any]]:
    """Подключение слушает loopback (его держит за собой nginx на 443); в ссылках клиентов – публичный адрес и порт 443."""
    return [{"forceTls": "same", "dest": host, "port": 443, "remark": ""}]


def _envelope(remark: str, port: int, settings: dict, stream: dict, listen: str = "") -> dict[str, Any]:
    return {
        "up": 0, "down": 0, "total": 0, "remark": remark, "enable": True, "expiryTime": 0, "listen": listen,
        "port": port, "protocol": "vless",
        "settings": json.dumps(settings, separators=(",", ":")),
        "streamSettings": json.dumps(stream, separators=(",", ":")),
        "sniffing": json.dumps(SNIFFING, separators=(",", ":")),
    }


def reality_inbound(port: int, sni: str, keys: dict[str, str], sid: str, host: str | None = None) -> dict[str, Any]:
    stream = {"network": "tcp", "security": "reality", "realitySettings": _reality(sni, keys, sid),
              "tcpSettings": {"acceptProxyProtocol": False, "header": {"type": "none"}}}
    if host:
        stream["externalProxy"] = _external(host)
    return _envelope("REALITY", port, {"clients": [], "decryption": "none", "fallbacks": []}, stream,
                     "127.0.0.1" if host else "")


def xhttp_inbound(port: int, sni: str, keys: dict[str, str], sid: str, path: str | None = None,
                  host: str | None = None) -> dict[str, Any]:
    path = path or "/" + secrets.token_hex(6)
    stream = {"network": "xhttp", "security": "reality", "realitySettings": _reality(sni, keys, sid),
              "xhttpSettings": {"path": path, "host": "", "mode": "auto"}}
    if host:
        stream["externalProxy"] = _external(host)
    return _envelope("XHTTP", port, {"clients": [], "decryption": "none", "fallbacks": []}, stream,
                     "127.0.0.1" if host else "")


def create_defaults(api, *, reality_port: int, xhttp_port: int, sni: str, xhttp_sni: str,
                    host: str | None = None) -> list[dict[str, Any]]:
    """Создаёт оба подключения (у каждого свои ключи REALITY). Возвращает ответы панели."""
    made = []
    made.append(api.add_inbound(reality_inbound(reality_port, sni, api.new_x25519(), short_id(), host)))
    made.append(api.add_inbound(xhttp_inbound(xhttp_port, xhttp_sni, api.new_x25519(), short_id(), host=host)))
    return made


def new_client(name: str, client_id: str, *, gb: int = 0, days: int = 0, devices: int = 0, now: float | None = None) -> dict[str, Any]:
    """Запись клиента 3X-UI. gb – лимит трафика в гигабайтах (0 без лимита), days – срок, devices – число IP."""
    valid_name(name)
    if not (0 <= gb <= 999999 and 0 <= days <= 99999 and 0 <= devices <= 9999):
        core.die("Лимиты вне допустимого диапазона.")
    expiry = 0 if days == 0 else int(((now if now is not None else time.time()) + days * 86400) * 1000)
    return {
        "email": name, "id": client_id, "flow": "xtls-rprx-vision", "enable": True, "subId": secrets.token_hex(8),
        "limitIp": devices, "totalGB": gb * GB, "expiryTime": expiry, "comment": "autopilot",
    }


MANAGED = ("REALITY", "XHTTP", "VLESS-WS", "VMess-WS", "Trojan-gRPC", "Shadowsocks", "Hysteria2", "TUIC", "MTProto",
           "AmneziaWG", "AmneziaWG-3.1")


def add_user(api, name: str, *, gb: int = 0, days: int = 0, devices: int = 0) -> dict[str, Any]:
    """Создаёт пользователя на всех подключениях Autopilot."""
    valid_name(name)
    if any(c.get("email") == name for c in api.clients()):
        core.die("Пользователь %s уже есть." % name)
    ids = [int(i["id"]) for i in api.inbounds() if i.get("remark") in MANAGED]
    if not ids:
        core.die("Подключения не найдены. Сначала выполните: autopilot install")
    client = new_client(name, api.new_uuid(), gb=gb, days=days, devices=devices)
    api.add_client(client, ids)
    return client
