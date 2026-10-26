"""Клиент API панели 3X-UI (3.x).

Маршруты и проверка токена описаны в исходниках панели (internal/web/controller): запросы идут на
<схема>://127.0.0.1:<порт>/<базовый-путь>/panel/api/..., токен передаётся заголовком `Authorization: Bearer`.
Ответ – конверт {"success": bool, "msg": str, "obj": ...}.
"""
from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Protocol

from . import core


class PanelAPI(Protocol):
    def clients(self) -> list[dict[str, Any]]:
        """Все клиенты панели. Поля: email, subId, enable, totalGB (байты, 0 = без лимита),
        expiryTime (мс с эпохи, 0 = бессрочно), traffic {up, down, lastOnline}."""

    def inbounds(self) -> list[dict[str, Any]]:
        """Все подключения: id, remark, protocol, port, enable, settings, streamSettings."""


_LINK_HOST = re.compile(r"^([a-z0-9+.-]+://[^@/?#]+@)[^:/?#\[\]]+(:\d+)")
_TG_SERVER = re.compile(r"^(tg://proxy\?.*?\bserver=)[^&#]+")
_TG_PORT = re.compile(r"\bport=\d+")


def with_host(link: str, host: str) -> str:
    """Панель строит ссылки с адресом из запроса (localhost); подставляем публичный адрес сервера."""
    if link.startswith("tg://proxy"):
        # MTProto стоит за nginx на 443: внутренний порт панели клиенту не нужен
        return _TG_PORT.sub("port=443", _TG_SERVER.sub(lambda m: m.group(1) + host, link, count=1), count=1)
    return _LINK_HOST.sub(lambda m: m.group(1) + host + m.group(2), link, count=1)


class PanelClient:
    """Работает только с панелью на этом же сервере (loopback)."""

    def __init__(self, port: int, base_path: str, token: str, *, scheme: str = "http", timeout: float = 20,
                 public_host: str | None = None) -> None:
        if not isinstance(port, int) or not 1 <= port <= 65535:
            core.die("Неверный порт панели")
        self.base = "%s://127.0.0.1:%d/%s/panel/api" % (scheme, port, base_path.strip("/"))
        self._token = token
        self._timeout = timeout
        self.public_host = public_host
        # Панель на loopback может отвечать самоподписанным сертификатом: имя и цепочку проверять не из чего.
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE

    @classmethod
    def from_install(cls) -> "PanelClient":
        """Параметры берём из etc/autopilot/install.json, который пишет установщик."""
        target = core.path(core.CONF_DIR, "install.json")
        try:
            data = json.loads(target.read_text(encoding="utf-8"))
            return cls(int(data["panel_port"]), str(data["panel_path"]), str(data["api_token"]),
                       scheme=str(data.get("panel_scheme", "http")), public_host=data.get("host"))
        except (OSError, KeyError, ValueError):
            core.die("Установка не найдена (нет %s). Сначала выполните: autopilot install" % target)
            raise  # недостижимо: die бросает Error

    # --- низкий уровень -------------------------------------------------------------------------

    def request(self, method: str, route: str, body: Any | None = None) -> Any:
        data = None
        headers = {"Authorization": "Bearer " + self._token, "Accept": "application/json"}
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request("%s/%s" % (self.base, route.lstrip("/")), data=data, headers=headers, method=method)
        handler = urllib.request.ProxyHandler({})  # локальный API никогда не идёт через прокси из окружения
        opener = urllib.request.build_opener(handler, urllib.request.HTTPSHandler(context=self._ctx))
        try:
            with opener.open(req, timeout=self._timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403, 404):
                core.die("Панель не приняла запрос (HTTP %d). Токен API устарел или путь панели изменился." % exc.code)
            core.die("Панель ответила HTTP %d" % exc.code)
            raise
        except (urllib.error.URLError, OSError) as exc:
            core.die("Панель не отвечает: %s" % getattr(exc, "reason", exc))
            raise
        try:
            envelope = json.loads(raw)
        except ValueError:
            core.die("Панель вернула не JSON")
            raise
        if not isinstance(envelope, dict) or envelope.get("success") is not True:
            msg = envelope.get("msg") if isinstance(envelope, dict) else None
            core.die("Панель вернула ошибку: %s" % (str(msg)[:300] or "без пояснения"))
        return envelope.get("obj")

    # --- чтение ---------------------------------------------------------------------------------

    def clients(self) -> list[dict[str, Any]]:
        obj = self.request("GET", "clients/list")
        # В 3.x ответ – список; на случай обёртки {"clients": [...]} принимаем и её.
        if isinstance(obj, dict):
            obj = obj.get("clients", [])
        return obj if isinstance(obj, list) else []

    def inbounds(self) -> list[dict[str, Any]]:
        obj = self.request("GET", "inbounds/list")
        return obj if isinstance(obj, list) else []

    def settings(self) -> dict[str, Any]:
        obj = self.request("POST", "setting/all", {})
        return obj if isinstance(obj, dict) else {}

    def update_settings(self, settings: dict[str, Any]) -> None:
        self.request("POST", "setting/update", settings)

    def status(self) -> dict[str, Any]:
        obj = self.request("GET", "server/status")
        return obj if isinstance(obj, dict) else {}

    def client_links(self, email: str) -> list[str]:
        obj = self.request("GET", "clients/links/" + urllib.parse.quote(email, safe=""))
        links = [str(x) for x in obj] if isinstance(obj, list) else []
        return [with_host(link, self.public_host) for link in links] if self.public_host else links

    def sub_links(self, sub_id: str) -> list[str]:
        obj = self.request("GET", "clients/subLinks/" + urllib.parse.quote(sub_id, safe=""))
        return [str(x) for x in obj] if isinstance(obj, list) else []

    def new_uuid(self) -> str:
        obj = self.request("GET", "server/getNewUUID")
        value = obj.get("uuid") if isinstance(obj, dict) else obj
        return str(value)

    def new_x25519(self) -> dict[str, str]:
        obj = self.request("GET", "server/getNewX25519Cert")
        if not isinstance(obj, dict) or "privateKey" not in obj or "publicKey" not in obj:
            core.die("Панель не создала ключи REALITY")
        return {"privateKey": str(obj["privateKey"]), "publicKey": str(obj["publicKey"])}

    # --- изменение ------------------------------------------------------------------------------

    def add_inbound(self, inbound: dict[str, Any]) -> dict[str, Any]:
        obj = self.request("POST", "inbounds/add", inbound)
        return obj if isinstance(obj, dict) else {}

    def update_inbound(self, inbound_id: int, inbound: dict[str, Any]) -> Any:
        return self.request("POST", "inbounds/update/%d" % inbound_id, inbound)

    def del_inbound(self, inbound_id: int) -> None:
        self.request("POST", "inbounds/del/%d" % inbound_id)

    def add_client(self, client: dict[str, Any], inbound_ids: list[int]) -> Any:
        return self.request("POST", "clients/add", {"client": client, "inboundIds": inbound_ids})

    # Поля, которые безопасно отправлять при обновлении. Запись из clients/list нельзя вернуть как есть: в ней числовой
    # id строки БД, а панель ждёт в id строку-UUID.
    UPDATABLE = ("email", "subId", "totalGB", "expiryTime", "limitIp", "enable", "comment")

    def set_client_fields(self, email: str, **changes: Any) -> Any:
        """Меняет у клиента только указанные поля (enable, totalGB, expiryTime, limitIp, comment), остальные сохраняются."""
        unknown = set(changes) - set(self.UPDATABLE)
        if unknown:
            core.die("Нельзя менять поля: %s" % ", ".join(sorted(unknown)))
        current = next((c for c in self.clients() if c.get("email") == email), None)
        if current is None:
            core.die("Нет пользователя %s." % email, "Список: autopilot user list")
        body = {key: current.get(key) for key in self.UPDATABLE if key in current}
        body.update(changes)
        return self.update_client(email, body)

    def update_client(self, email: str, client: dict[str, Any]) -> Any:
        return self.request("POST", "clients/update/" + urllib.parse.quote(email, safe=""), client)

    def del_client(self, email: str) -> None:
        self.request("POST", "clients/del/" + urllib.parse.quote(email, safe=""))
