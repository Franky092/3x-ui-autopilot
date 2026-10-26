"""Сетевые настройки после установки: сайты-прикрытия и публичные порты (`autopilot net`)."""
from __future__ import annotations

import json
from typing import Any

from . import core, installer, reality, restore

SITES = {"reality": "REALITY", "xhttp": "XHTTP", "mtproto": "MTProto"}  # имя -> remark подключения
# Публичные подключения (не за nginx), у которых можно менять порт: имя -> (remark, протоколы для ufw)
PORTS = {
    "shadowsocks": ("Shadowsocks", ("tcp", "udp")),
    "hysteria2": ("Hysteria2", ("udp",)),
    "tuic": ("TUIC", ("udp",)),
    "amneziawg": ("AmneziaWG", ("udp",)),
    "amneziawg-3.1": ("AmneziaWG-3.1", ("udp",)),
}


def _by_remark(api, remark: str) -> dict[str, Any]:
    for item in api.inbounds():
        if item.get("remark") == remark:
            return item
    core.die("Подключение %s не найдено." % remark, "Список: autopilot net")
    raise AssertionError


def _site_of(item: dict[str, Any]) -> str:
    if item.get("remark") == "MTProto":
        return str(restore._load(item.get("settings")).get("fakeTlsDomain", ""))
    names = (restore._load(item.get("streamSettings")).get("realitySettings") or {}).get("serverNames") or []
    return str(names[0]) if names else ""


def overview(api) -> list[dict[str, Any]]:
    """Сводка для показа: подключение, порт, где слушает, сайт-прикрытие."""
    rows = []
    for item in sorted(api.inbounds(), key=lambda i: int(i.get("id") or 0)):
        loopback = item.get("listen") == "127.0.0.1"
        rows.append({"remark": item.get("remark"), "port": int(item.get("port") or 0), "protocol": item.get("protocol"),
                     "public": "443 (nginx)" if loopback else str(item.get("port")), "site": _site_of(item) if loopback else "",
                     "enabled": bool(item.get("enable", True))})
    return rows


def _update(api, item: dict[str, Any], *, stream: dict | None = None, settings: dict | None = None, **fields: Any) -> None:
    body = {key: item[key] for key in restore._INBOUND_FIELDS if key in item}
    body["streamSettings"] = json.dumps(stream if stream is not None else restore._load(item.get("streamSettings")), separators=(",", ":"))
    body["settings"] = json.dumps(settings if settings is not None else restore._load(item.get("settings")), separators=(",", ":"))
    body.update(fields)
    api.update_inbound(int(item["id"]), body)


def set_site(api, which: str, host: str, *, check=reality.supports_tls13_h2) -> str:
    """Меняет сайт-прикрытие. Возвращает прежний сайт. nginx и сохранённое состояние после этого нужно пересобрать (sync.apply)."""
    if which not in SITES:
        core.die("Выберите: %s" % ", ".join(SITES))
    host = host.strip().lower()
    if not reality.valid_host(host):
        core.die("Нужно только имя сайта, например www.microsoft.com")
    others = {name: _site_of(_by_remark(api, remark)) for name, remark in SITES.items() if name != which}
    if host in others.values():
        core.die("Сайт %s уже используется другим подключением: для маршрутизации по SNI они должны различаться." % host)
    if not check(host):
        core.die("Сайт %s не отвечает по TLS 1.3 и HTTP/2, REALITY с ним работать не будет." % host, "Выберите другой сайт.")
    item = _by_remark(api, SITES[which])
    old = _site_of(item)
    if which == "mtproto":
        settings = restore._load(item.get("settings"))
        settings["fakeTlsDomain"] = host
        _update(api, item, settings=settings)
    else:
        stream = restore._load(item.get("streamSettings"))
        real = stream.setdefault("realitySettings", {})
        real["target"] = "%s:443" % host
        real["serverNames"] = [host]
        _update(api, item, stream=stream)
    return old


def used_ports(api) -> set[int]:
    taken = {int(i.get("port") or 0) for i in api.inbounds()}
    taken |= installer.parse_listening_ports(core.run(["ss", "-Hltun"], check=False).stdout)
    return taken


def set_port(api, name: str, port: int) -> int:
    """Меняет публичный порт подключения. Возвращает прежний. Правила ufw меняются здесь же."""
    if name not in PORTS:
        core.die("Порт можно менять у: %s" % ", ".join(PORTS))
    if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
        core.die("Порт: число от 1024 до 65535.")
    remark, protocols = PORTS[name]
    item = _by_remark(api, remark)
    old = int(item.get("port") or 0)
    if port == old:
        return old
    if port in used_ports(api):
        core.die("Порт %d уже занят." % port, "Выберите другой.")
    _update(api, item, port=port)
    for proto in protocols:
        core.run(["ufw", "allow", "%d/%s" % (port, proto)], check=False)
        core.run(["ufw", "--force", "delete", "allow", "%d/%s" % (old, proto)], check=False)
    return old
