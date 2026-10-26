"""Автоустановка клиента на OpenWrt: скрипт раздаёт ваш же сервер по HTTPS, роутер скачивает и запускает его."""
from __future__ import annotations

import json
import secrets
from pathlib import Path

from . import core, nginx

APPS = ("nikki", "openclash", "passwall2")
NEEDS = {"nikki": "clash", "openclash": "clash", "passwall2": "auto"}  # какая ссылка подписки нужна приложению
SCRIPT = Path(__file__).resolve().parent / "data" / "router.sh"


def _state_path() -> Path:
    return core.path(core.CONF_DIR, "install.json")


def _load_state() -> dict:
    try:
        data = json.loads(_state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        core.die("Установка не найдена.", "Сначала выполните: autopilot install")
        raise
    return data


def publish() -> str:
    """Кладёт router.sh в веб-каталог nginx под случайным путём (он же остаётся постоянным) и возвращает его адрес."""
    state = _load_state()
    host = state.get("host")
    if not host:
        core.die("В состоянии установки нет адреса сервера.")
    token = state.get("router_token")
    if not isinstance(token, str) or len(token) != 16:
        token = secrets.token_hex(8)
        state["router_token"] = token
        core.write_file(_state_path(), json.dumps(state, ensure_ascii=False, indent=2) + "\n", 0o600)
    core.write_file(core.path(nginx.WEBROOT, token, "router.sh"), SCRIPT.read_text(encoding="utf-8"), 0o644)
    return "https://%s/%s/router.sh" % (host, token)


def command(app: str, script_url: str, sub_urls: dict[str, str], lang: str = "ru") -> str:
    """Готовая команда для роутера (выполняется там по SSH)."""
    if app not in APPS:
        core.die("Неизвестное приложение %s. Доступно: %s" % (app, ", ".join(APPS)))
    link = sub_urls[NEEDS[app]]
    flag = " --lang en" if lang == "en" else ""
    return "wget -qO- %s | sh -s --%s %s '%s'" % (script_url, flag, app, link)
