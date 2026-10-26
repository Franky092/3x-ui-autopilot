"""Подписка: встроенный сервер панели (на loopback) за nginx. Одна ссылка работает во всех приложениях:
формат (base64, Clash, JSON, Happ) панель выбирает по User-Agent приложения."""
from __future__ import annotations

from typing import Any

from . import core


def _slashed(path: str) -> str:
    return "/" + path.strip("/") + "/"


def public_urls(settings: dict[str, Any], host: str, sub_id: str) -> dict[str, str]:
    """Адреса подписки пользователя. «auto» – основная ссылка, остальные нужны, чтобы открыть конкретный формат вручную."""
    base = "https://%s" % host
    return {
        "auto": base + _slashed(settings.get("subPath", "/sub/")) + sub_id,
        "json": base + _slashed(settings.get("subJsonPath", "/json/")) + sub_id,
        "clash": base + _slashed(settings.get("subClashPath", "/clash/")) + sub_id,
    }


def user_urls(api, host: str, name: str) -> dict[str, str]:
    """Адреса подписки конкретного пользователя (по его subId из панели)."""
    client = next((c for c in api.clients() if c.get("email") == name), None)
    if client is None or not client.get("subId"):
        core.die("Нет пользователя %s." % name, "Список: autopilot user list")
    return public_urls(api.settings(), host, str(client["subId"]))


def paths(settings: dict[str, Any]) -> list[str]:
    return [_slashed(settings[key]) for key in ("subPath", "subJsonPath", "subClashPath") if settings.get(key)]


def configure(api, host: str) -> dict[str, Any]:
    """Включает подписку на loopback, форматы Clash и JSON, автоопределение приложения и публичные адреса через nginx.
    Возвращает применённые настройки (панель нужно перезапустить, чтобы сервер подписки подхватил их)."""
    settings = api.settings()
    if not settings:
        core.die("Панель не отдала настройки.")
    for key in ("subPath", "subJsonPath", "subClashPath"):
        settings[key] = _slashed(settings.get(key) or core_default(key))
    settings.update({
        "subEnable": True, "subListen": "127.0.0.1", "subDomain": "", "subCertFile": "", "subKeyFile": "",
        "subJsonEnable": True, "subClashEnable": True,
        "subClashAutoDetect": True, "subJsonAutoDetect": True, "subHappAutoDetect": True,
        "subURI": "https://%s%s" % (host, settings["subPath"]),
        "subJsonURI": "https://%s%s" % (host, settings["subJsonPath"]),
        "subClashURI": "https://%s%s" % (host, settings["subClashPath"]),
        "subSupportUrl": "", "subProfileUrl": "", "tgBotEnable": False,
    })
    api.update_settings(settings)
    return settings


def core_default(key: str) -> str:
    import secrets

    return "/" + secrets.token_hex(8) + "/"
