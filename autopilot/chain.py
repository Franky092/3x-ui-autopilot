"""Каскад для Xray-подключений: сервер 2 («выход», основной) и сервер 1 («вход», резервный путь).

Сервер 2: `autopilot relay on` создаёт служебное REALITY-подключение Relay за nginx на 443 и печатает токен.
Сервер 1: `autopilot chain set ТОКЕН` копирует ключи и пользователей REALITY/XHTTP с сервера 2 (клиент с ссылкой
сервера 2 подключается и к серверу 1) и направляет их трафик на сервер 2 через исходящее подключение Xray.
Сервер 2 в подписку добавляет вторую запись «через сервер 1» (externalProxy), если указан адрес входа.

Шаблон Xray (исходящие подключения и маршруты) хранится в базе панели; правим его напрямую, как backup и restore.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import re
import socket
import sqlite3
import zlib
from pathlib import Path
from typing import Any

from . import core, inbounds, net, reality, restore

RELAY_REMARK = "Relay"
RELAY_PORT = 10446
RELAY_USER = "relay"
CHAINED = ("REALITY", "XHTTP")      # подключения, которые копируются на вход и идут через выход
TOKEN_PREFIX = "ap1:"
OUTBOUND_TAG = "autopilot-exit"
TEMPLATE_KEY = "xrayTemplateConfig"
DB = "etc/x-ui/x-ui.db"
GENERATED = "usr/local/x-ui/bin/config.json"
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_SUB_ID = re.compile(r"^[A-Za-z0-9]{1,64}$")


# --- токен ------------------------------------------------------------------------------------------

def encode_token(data: dict[str, Any]) -> str:
    raw = zlib.compress(json.dumps(data, separators=(",", ":"), sort_keys=True).encode(), 9)
    return TOKEN_PREFIX + base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_token(token: str) -> dict[str, Any]:
    token = "".join(token.split())
    if not token.startswith(TOKEN_PREFIX):
        core.die("Это не токен каскада.", "Токен начинается с %s и выдаётся командой: autopilot relay on" % TOKEN_PREFIX)
    body = token[len(TOKEN_PREFIX):]
    try:
        # лимит распаковки: токен – ввод пользователя, бомбой он быть не должен
        decoder = zlib.decompressobj()
        raw = decoder.decompress(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)), 1 << 20)
        data = json.loads(raw)
    except (ValueError, zlib.error):
        core.die("Токен повреждён: скопируйте его целиком.")
        raise
    validate(data)
    return data


def _ipv4(value: str, message: str) -> None:
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        core.die(message)


def _text(value: Any, pattern: re.Pattern | None = None, limit: int = 128) -> str:
    if not isinstance(value, str) or not value or len(value) > limit or (pattern and not pattern.match(value)):
        core.die("В токене неверное поле.", "Выпустите токен заново: autopilot relay on")
    return value


def validate(data: Any) -> None:
    """Токен приходит от человека: проверяем всё, что потом попадёт в конфиги."""
    if not isinstance(data, dict) or data.get("v") != 1:
        core.die("Токен неизвестной версии.", "Обновите Autopilot на обоих серверах.")
    ex = data.get("exit")
    if not isinstance(ex, dict):
        core.die("В токене нет данных выхода.")
    host = _text(ex.get("host"))
    _ipv4(host, "В токене неверный адрес выхода.")
    if not reality.valid_host(_text(ex.get("sni"))):
        core.die("В токене неверный сайт-прикрытие выхода.")
    _text(ex.get("pbk"), re.compile(r"^[A-Za-z0-9_-]{20,64}$"))
    _text(ex.get("sid"), re.compile(r"^[0-9a-f]{2,16}$"))
    _text(ex.get("uuid"), _UUID)
    mirror = data.get("inbounds")
    if not isinstance(mirror, dict) or not mirror or set(mirror) - set(CHAINED):
        core.die("В токене неверный набор подключений.")
    for item in mirror.values():
        if not isinstance(item, dict):
            core.die("В токене неверное подключение.")
        if not reality.valid_host(_text(item.get("sni"))):
            core.die("В токене неверный сайт-прикрытие.")
        for key in ("private", "public"):
            _text(item.get(key), re.compile(r"^[A-Za-z0-9_-]{20,64}$"))
        _text(item.get("sid"), re.compile(r"^[0-9a-f]{2,16}$"))
        if "path" in item:
            _text(item["path"], re.compile(r"^/[A-Za-z0-9_-]{1,64}$"))
    users = data.get("users")
    if not isinstance(users, list) or len(users) > 200:
        core.die("В токене неверный список пользователей.")
    for user in users:
        if not isinstance(user, dict):
            core.die("В токене неверный пользователь.")
        inbounds.valid_name(_text(user.get("email"), limit=32))
        _text(user.get("id"), _UUID)
        _text(user.get("subId"), _SUB_ID)


# --- шаблон Xray -------------------------------------------------------------------------------------

def _connect() -> sqlite3.Connection:
    target = core.path(DB)
    if not target.exists():
        core.die("База панели не найдена.", "Сначала выполните: autopilot install")
    conn = sqlite3.connect(str(target), timeout=15)
    conn.execute("PRAGMA busy_timeout = 15000")
    return conn


def _generated_template() -> dict[str, Any] | None:
    """Панель не пишет шаблон в базу, пока его не сохранят вручную. Тогда берём собранный ею config.json
    и убираем из него подключения пользователей (остаётся служебное api)."""
    try:
        config = json.loads(core.path(GENERATED).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(config, dict) or not isinstance(config.get("outbounds"), list):
        return None
    config["inbounds"] = [i for i in config.get("inbounds", []) if isinstance(i, dict) and i.get("tag") == "api"]
    return config


def read_template() -> dict[str, Any]:
    conn = _connect()
    try:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (TEMPLATE_KEY,)).fetchone()
    finally:
        conn.close()
    if row and row[0]:
        try:
            value = json.loads(row[0])
        except ValueError:
            value = None
        if isinstance(value, dict):
            return value
    template = _generated_template()
    if template is None:
        core.die("Не удалось получить настройки Xray из панели.",
                 "Откройте панель → Настройки Xray, нажмите «Сохранить» и повторите.")
    return template


def write_template(config: dict[str, Any]) -> None:
    text = json.dumps(config, indent=2, ensure_ascii=False)
    conn = _connect()
    try:
        with conn:
            updated = conn.execute("UPDATE settings SET value = ? WHERE key = ?", (text, TEMPLATE_KEY)).rowcount
            if not updated:
                conn.execute("INSERT INTO settings (key, value) VALUES (?, ?)", (TEMPLATE_KEY, text))
    finally:
        conn.close()


def outbound(exit_: dict[str, Any]) -> dict[str, Any]:
    return {
        "tag": OUTBOUND_TAG, "protocol": "vless",
        "settings": {"vnext": [{"address": exit_["host"], "port": 443,
                                "users": [{"id": exit_["uuid"], "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
        "streamSettings": {"network": "tcp", "security": "reality",
                           "realitySettings": {"serverName": exit_["sni"], "fingerprint": "chrome", "publicKey": exit_["pbk"],
                                               "shortId": exit_["sid"], "spiderX": "/"}},
    }


def with_chain(template: dict[str, Any], exit_: dict[str, Any], tags: list[str]) -> dict[str, Any]:
    """Копия шаблона с исходящим подключением на выход и правилом для указанных входящих тегов.
    Правило стоит последним: запреты шаблона (локальные адреса, торренты) остаются выше и действуют первыми."""
    config = json.loads(json.dumps(without_chain(template)))
    config["outbounds"] = [*config.get("outbounds", []), outbound(exit_)]
    routing = config.setdefault("routing", {})
    routing["rules"] = [*routing.get("rules", []), {"type": "field", "inboundTag": sorted(tags), "outboundTag": OUTBOUND_TAG}]
    return config


def without_chain(template: dict[str, Any]) -> dict[str, Any]:
    config = json.loads(json.dumps(template))
    config["outbounds"] = [o for o in config.get("outbounds", []) if o.get("tag") != OUTBOUND_TAG]
    routing = config.get("routing")
    if isinstance(routing, dict):
        routing["rules"] = [r for r in routing.get("rules", []) if r.get("outboundTag") != OUTBOUND_TAG]
    return config


def active_exit(template: dict[str, Any]) -> dict[str, Any] | None:
    for item in template.get("outbounds", []):
        if item.get("tag") == OUTBOUND_TAG:
            try:
                vnext = item["settings"]["vnext"][0]
                return {"host": vnext["address"], "port": vnext["port"], "sni": item["streamSettings"]["realitySettings"]["serverName"]}
            except (KeyError, IndexError, TypeError):
                return {}
    return None


def rule_tags(template: dict[str, Any]) -> list[str]:
    for rule in template.get("routing", {}).get("rules", []):
        if rule.get("outboundTag") == OUTBOUND_TAG:
            return sorted(rule.get("inboundTag", []))
    return []


def stale_rule(api, template: dict[str, Any]) -> bool:
    """Каскад включён, но правило смотрит не на те теги: пересозданное подключение ушло бы мимо выхода, напрямую."""
    return active_exit(template) is not None and rule_tags(template) != sorted(chain_tags(api.inbounds()))


def refresh(api, restart) -> bool:
    template = read_template()
    ex = active_exit(template)
    if ex is None:
        return False
    old = json.loads(json.dumps(template))
    outs = next(o for o in template["outbounds"] if o.get("tag") == OUTBOUND_TAG)
    vn = outs["settings"]["vnext"][0]
    exit_ = {"host": vn["address"], "uuid": vn["users"][0]["id"], "sni": ex["sni"],
             "pbk": outs["streamSettings"]["realitySettings"]["publicKey"], "sid": outs["streamSettings"]["realitySettings"]["shortId"]}
    write_template(with_chain(template, exit_, chain_tags(api.inbounds())))
    try:
        restart()
    except core.Error:
        write_template(old)
        raise
    return True


def chain_tags(inbound_list: list[dict[str, Any]]) -> list[str]:
    return [str(i["tag"]) for i in inbound_list if i.get("remark") in CHAINED and i.get("tag")]


# --- чтение подключений ------------------------------------------------------------------------------

def _by_remark(inbound_list: list[dict[str, Any]], remark: str) -> dict[str, Any] | None:
    return next((i for i in inbound_list if i.get("remark") == remark), None)


def _reality_of(item: dict[str, Any]) -> dict[str, Any]:
    return restore._load(item.get("streamSettings")).get("realitySettings") or {}


def users_of(api) -> list[dict[str, str]]:
    """Пользователи сервера с их UUID: из клиентов подключения REALITY, запасной путь – список клиентов панели."""
    found: dict[str, dict[str, str]] = {}
    reality_inbound = _by_remark(api.inbounds(), "REALITY")
    for c in restore._load(reality_inbound.get("settings")).get("clients", []) if reality_inbound else []:
        if isinstance(c, dict) and _UUID.match(str(c.get("id", ""))) and c.get("email") and c.get("subId"):
            found[str(c["email"])] = {"email": str(c["email"]), "id": str(c["id"]), "subId": str(c["subId"])}
    for c in api.clients():
        uuid = c.get("uuid") or c.get("id")
        email = c.get("email")
        if email and email not in found and _UUID.match(str(uuid or "")) and c.get("subId"):
            found[str(email)] = {"email": str(email), "id": str(uuid), "subId": str(c["subId"])}
    return [found[k] for k in sorted(found) if k != RELAY_USER]


# --- сервер 2: выход ---------------------------------------------------------------------------------

def relay_state(api) -> dict[str, Any] | None:
    item = _by_remark(api.inbounds(), RELAY_REMARK)
    if item is None:
        return None
    real = _reality_of(item)
    settings = restore._load(item.get("settings"))
    client = next((c for c in settings.get("clients", []) if c.get("email") == RELAY_USER), None)
    return {"item": item, "sni": (real.get("serverNames") or [""])[0], "private": real.get("privateKey", ""),
            "public": (real.get("settings") or {}).get("publicKey", ""), "sid": (real.get("shortIds") or [""])[0],
            "uuid": (client or {}).get("id", "")}


def relay_on(api, host: str, *, sni: str | None = None, check=reality.supports_tls13_h2) -> dict[str, Any]:
    """Создаёт служебное подключение Relay, если его нет. Возвращает его состояние. nginx нужно пересобрать (sync.apply)."""
    current = relay_state(api)
    if current is not None and current["uuid"]:
        return current
    taken = {net._site_of(i) for i in api.inbounds() if i.get("listen") == "127.0.0.1"}
    if sni:
        sni = sni.strip().lower()
        if not reality.valid_host(sni) or sni in taken or not check(sni):
            core.die("Сайт %s не подходит для Relay." % sni, "Нужен свободный сайт с TLS 1.3 и HTTP/2.")
    else:
        sni = reality.pick(exclude=tuple(taken), check=check)
        if sni is None:
            core.die("Не нашёл сайт-прикрытие для Relay.", "Укажите свой: autopilot relay on --sni САЙТ")
    if current is not None:
        api.del_inbound(int(current["item"]["id"]))
    keys = api.new_x25519()
    sid = inbounds.short_id()
    body = inbounds.reality_inbound(RELAY_PORT, sni, keys, sid, host)
    body["remark"] = RELAY_REMARK
    api.add_inbound(body)
    created = _by_remark(api.inbounds(), RELAY_REMARK)
    if created is None:
        core.die("Панель не создала подключение Relay.")
    client = inbounds.new_client(RELAY_USER, api.new_uuid())
    client["comment"] = "autopilot-relay"
    api.add_client(client, [int(created["id"])])
    return relay_state(api)  # type: ignore[return-value]


def relay_off(api) -> bool:
    current = relay_state(api)
    if current is None:
        return False
    api.del_client(RELAY_USER)
    api.del_inbound(int(current["item"]["id"]))
    return True


def check_host(host: str) -> None:
    _ipv4(host, "Каскад работает только на сервере с адресом IPv4 (в установке указан %s)." % host)


def make_token(api, host: str) -> str:
    state = relay_state(api)
    if state is None or not state["uuid"]:
        core.die("Выход не включён.", "Выполните: autopilot relay on")
    mirror = {}
    for remark in CHAINED:
        item = _by_remark(api.inbounds(), remark)
        if item is None:
            continue
        real = _reality_of(item)
        entry = {"sni": (real.get("serverNames") or [""])[0], "private": real.get("privateKey", ""),
                 "public": (real.get("settings") or {}).get("publicKey", ""), "sid": (real.get("shortIds") or [""])[0]}
        if remark == "XHTTP":
            entry["path"] = (restore._load(item.get("streamSettings")).get("xhttpSettings") or {}).get("path", "")
        mirror[remark] = entry
    if not mirror:
        core.die("Нет подключений REALITY и XHTTP.")
    data = {"v": 1, "exit": {"host": host, "sni": state["sni"], "pbk": state["public"], "sid": state["sid"], "uuid": state["uuid"]},
            "inbounds": mirror, "users": users_of(api)}
    validate(data)
    return encode_token(data)


def set_entry(api, entry_host: str | None, exit_host: str) -> list[str]:
    """Добавляет (или убирает, если entry_host пуст) вторую запись «через вход» в ссылки REALITY и XHTTP.
    Возвращает remark обновлённых подключений."""
    if entry_host:
        _ipv4(entry_host, "Нужен IPv4-адрес сервера-входа.")
        if entry_host == exit_host:
            core.die("Вход и выход должны быть разными серверами.")
    changed = []
    for item in api.inbounds():
        if item.get("remark") not in CHAINED:
            continue
        stream = restore._load(item.get("streamSettings"))
        proxies = [p for p in stream.get("externalProxy", []) if p.get("remark") != "via-entry"]
        if entry_host:
            proxies.append({"forceTls": "same", "dest": entry_host, "port": 443, "remark": "via-entry"})
        stream["externalProxy"] = proxies
        net._update(api, item, stream=stream)
        changed.append(str(item["remark"]))
    return changed


# --- сервер 1: вход ----------------------------------------------------------------------------------

def apply_mirror(api, data: dict[str, Any]) -> dict[str, list[str]]:
    """Подставляет в REALITY/XHTTP этого сервера ключи, сайты и пути с основного и приводит пользователей к списку из токена."""
    existing = api.inbounds()
    changes: dict[str, list[str]] = {"inbounds": [], "users_added": [], "users_replaced": [], "users_removed": []}
    for remark in data["inbounds"]:  # сначала проверяем всё: частично применённое зеркало хуже непримённого
        if _by_remark(existing, remark) is None:
            core.die("На этом сервере нет подключения %s." % remark, "Сначала установите сервер: autopilot install")
    for remark, spec in data["inbounds"].items():
        item = _by_remark(existing, remark)
        stream = restore._load(item.get("streamSettings"))
        real = stream.setdefault("realitySettings", {})
        real.update({"target": "%s:443" % spec["sni"], "serverNames": [spec["sni"]], "privateKey": spec["private"], "shortIds": [spec["sid"]]})
        real.setdefault("settings", {})["publicKey"] = spec["public"]
        if remark == "XHTTP" and spec.get("path"):
            stream.setdefault("xhttpSettings", {})["path"] = spec["path"]
        net._update(api, item, stream=stream)
        changes["inbounds"].append(remark)
    ids = [int(i["id"]) for i in api.inbounds() if i.get("remark") in inbounds.MANAGED]
    present = {c.get("email"): c for c in api.clients()}
    wanted = {u["email"] for u in data["users"]}
    for email in sorted(set(present) - wanted - {RELAY_USER}):  # зеркало: удалённый на выходе пользователь теряет доступ и здесь
        api.del_client(str(email))
        changes["users_removed"].append(str(email))
    for user in data["users"]:
        current = present.get(user["email"])
        if current is not None:
            if current.get("subId") == user["subId"] and str(current.get("uuid") or current.get("id")) in (user["id"], "None"):
                continue
            api.del_client(user["email"])
            changes["users_replaced"].append(user["email"])
        client = inbounds.new_client(user["email"], user["id"])
        client["subId"] = user["subId"]
        api.add_client(client, ids)
        if current is None:
            changes["users_added"].append(user["email"])
    return changes


def exit_reachable(host: str, port: int = 443, timeout: float = 5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def enable(api, data: dict[str, Any], restart) -> dict[str, list[str]]:
    """Полная настройка входа: зеркалирование, шаблон Xray, перезапуск. При сбое запуска шаблон возвращается."""
    old_template = read_template()
    changes = apply_mirror(api, data)
    write_template(with_chain(old_template, data["exit"], chain_tags(api.inbounds())))
    try:
        restart()
    except core.Error:
        write_template(old_template)
        try:
            restart()
        except core.Error:
            pass
        raise
    return changes


def disable(restart) -> bool:
    template = read_template()
    if active_exit(template) is None:
        return False
    write_template(without_chain(template))
    restart()
    return True
