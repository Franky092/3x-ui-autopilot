"""Управление отдельной службой Mieru (mita)."""
from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import quote

from . import core, installer

MITA_VERSION = "3.39.0"
MITA_URL = "https://github.com/enfein/mieru/releases/download/v{version}/mita_{version}_{arch}.deb"
MITA_SHA256 = {
    "amd64": "976ef76b319f9be89c8ede69664fc7ca2de8811caa8f7fe292faa3042391dcbd",
    "arm64": "91beb29fdddca013397c4f123f3c0e3f862b8202ed5a0d59e372bd2abd1b263f",
}
_USER_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
_MULTIPLEXING = {"MULTIPLEXING_OFF", "MULTIPLEXING_LOW", "MULTIPLEXING_MIDDLE", "MULTIPLEXING_HIGH"}


def installed() -> bool:
    """Проверяет наличие mita или её systemd-службы."""
    return shutil.which("mita") is not None or core.unit_exists("mita")


def install(arch: str) -> None:
    """Скачивает проверенный deb-пакет и включает службу mita."""
    if installed():
        return
    if arch not in MITA_SHA256:
        core.die("Для mita поддерживаются только архитектуры amd64 и arm64.")
    temp_dir = core.path("tmp")
    temp_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=str(temp_dir), prefix="mieru-") as directory:
        package = Path(directory) / "mita.deb"
        installer.download(MITA_URL.format(version=MITA_VERSION, arch=arch), package, MITA_SHA256[arch])
        core.run(["dpkg", "-i", str(package)])
    core.systemctl("enable", "--now", "mita", check=True)


def describe(*, strict: bool = True) -> dict[str, Any]:
    """Читает текущий конфиг mita как JSON. Для изменяющих операций strict=True: сбой чтения НЕ считается пустым конфигом,
    иначе `replace` затёрла бы чужих пользователей. strict=False допустим только там, где пустой конфиг безопасен."""
    result = core.run(["mita", "describe", "config"], check=strict)
    output = (result.stdout or "").strip()
    if not strict and result.returncode != 0:
        return {}
    if not output:
        return {}
    try:
        value = json.loads(output)
    except (json.JSONDecodeError, TypeError):
        core.die("mita describe config вернула некорректный JSON.")
    if not isinstance(value, dict):
        core.die("mita describe config должна вернуть JSON-объект.")
    return value


def server_config(port: int, users: dict[str, str], *, protocol: str = "TCP", mtu: int = 1400) -> dict[str, Any]:
    """Создаёт новый конфиг сервера после проверки параметров."""
    if isinstance(port, bool) or not isinstance(port, int) or not 1025 <= port <= 65535:
        core.die("Порт Mieru должен быть в диапазоне 1025..65535.")
    if protocol not in ("TCP", "UDP"):
        core.die("Протокол Mieru должен быть TCP или UDP.")
    if isinstance(mtu, bool) or not isinstance(mtu, int) or mtu < 1280:
        core.die("MTU Mieru должен быть не меньше 1280.")
    checked = []
    for name, password in users.items():
        _validate_user(name, password)
        checked.append({"name": name, "password": password})
    return {"portBindings": [{"port": port, "protocol": protocol}], "users": checked,
            "mtu": mtu, "loggingLevel": "INFO"}


def _validate_user(name: str, password: str) -> None:
    if not isinstance(name, str) or not _USER_NAME.fullmatch(name):
        core.die("Имя пользователя Mieru: 1–32 символа A-Z, a-z, 0-9, точка, дефис или подчёркивание.")
    if not isinstance(password, str) or not password or any(c.isspace() for c in password):
        core.die("Пароль Mieru не должен быть пустым или содержать пробелы и переводы строк.")


def supports_replace() -> bool:
    """Есть ли у этой версии mita `replace config` (с 3.39). В более старых `apply config` САМ заменяет весь конфиг,
    хотя в справке написано «merges»: проверено на mita 3.37.0 – патч из одного пользователя стёр порты и остальных."""
    result = core.run(["mita", "help"], check=False)
    return "replace config" in ((result.stdout or "") + (result.stderr or ""))


def write_full(config: dict[str, Any]) -> None:
    """Записывает ПОЛНЫЙ конфиг так, чтобы результат был одинаков на любой версии mita: replace там, где он есть,
    иначе apply (в старых версиях он и есть замена). Частичные патчи не применяем никогда."""
    config = dict(config)
    if config.get("mtu") == 0:  # describe печатает 0 для «не задано», а apply этого значения не принимает
        del config["mtu"]
    _apply_file(config, "replace" if supports_replace() else "apply")


def _apply_file(config: dict[str, Any], action: str) -> None:
    """Передаёт полный конфиг через приватный временный файл."""
    temp_dir = core.path("tmp")
    temp_dir.mkdir(parents=True, exist_ok=True)
    fd, filename = tempfile.mkstemp(prefix="mieru-", suffix=".json", dir=str(temp_dir))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(config, handle, ensure_ascii=False)
            handle.write("\n")
        core.run(["mita", action, "config", filename])
    finally:
        try:
            os.unlink(filename)
        except FileNotFoundError:
            pass


def configure(port: int | None = None, protocol: str = "TCP") -> dict[str, Any]:
    """Создаёт первоначальный конфиг, не трогая уже настроенную службу."""
    current = describe(strict=False)
    if current and current.get("portBindings"):
        return current
    chosen_port = installer.free_port(set()) if port is None else port
    config = server_config(chosen_port, {}, protocol=protocol)
    _apply_file(config, "apply")
    core.run(["mita", "start"])
    return config


def add_user(name: str, password: str | None = None) -> str:
    """Добавляет пользователя или обновляет его пароль, сохраняя остальные настройки."""
    actual_password = installer.random_alnum(24) if password is None else password
    _validate_user(name, actual_password)
    config = describe()
    users = config.setdefault("users", [])
    if not isinstance(users, list):
        core.die("В конфиге mita поле users должно быть списком.")
    existing = next((user for user in users if isinstance(user, dict) and user.get("name") == name), None)
    if existing is None:
        users.append({"name": name, "password": actual_password})
    else:
        existing["password"] = actual_password
        existing.pop("hashedPassword", None)  # иначе старый хэш мог бы победить новый пароль
    write_full(config)
    core.run(["mita", "reload"])
    if name not in list_users():
        core.die("mita не приняла пользователя %s." % name, "Проверьте: mita describe config. Копия конфига – в /root/mita-backup-*")
    return actual_password


def remove_user(name: str) -> bool:
    """Удаляет пользователя, не меняя прочие поля конфига."""
    config = describe()
    users = config.get("users", [])
    if not isinstance(users, list):
        core.die("В конфиге mita поле users должно быть списком.")
    remaining = [user for user in users if not isinstance(user, dict) or user.get("name") != name]
    if len(remaining) == len(users):
        return False
    config["users"] = remaining
    write_full(config)
    core.run(["mita", "reload"])
    return True


def list_users() -> list[str]:
    """Возвращает имена настроенных пользователей."""
    users = describe().get("users", [])
    if not isinstance(users, list):
        return []
    return [str(user["name"]) for user in users if isinstance(user, dict) and isinstance(user.get("name"), str)]


def ports(config: dict[str, Any] | None = None) -> list[tuple[int | str, str]]:
    """Возвращает порты и протоколы; диапазоны представлены строкой «начало-конец» для ufw."""
    bindings = (describe() if config is None else config).get("portBindings", [])
    result = []
    for binding in bindings:
        if not isinstance(binding, dict):
            continue
        protocol = str(binding.get("protocol", "TCP")).lower()
        if "port" in binding:
            result.append((binding["port"], protocol))
        elif "portRange" in binding:
            value = binding["portRange"]
            if isinstance(value, dict):
                value = "%s-%s" % (value.get("start"), value.get("end"))
            start, _, end = str(value).partition("-")
            # диапазон из одного порта («32145-32145») ufw и клиенты лучше принимают как обычный порт
            result.append((int(start) if start.isdigit() and start == end else str(value), protocol))
    return result


def _validate_host(host: str) -> None:
    import ipaddress

    try:
        ipaddress.ip_address(host)
        return
    except ValueError:
        pass
    if not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", host or ""):
        core.die("Недопустимый адрес сервера для Mieru.")


def client_profile(name: str, password: str, host: str, config: dict[str, Any], *, profile: str = "default",
                   mtu: int = 1400, multiplexing: str = "MULTIPLEXING_HIGH") -> dict[str, Any]:
    """Строит JSON-профиль клиента из серверного конфига."""
    _validate_user(name, password)
    _validate_host(host)
    if mtu < 1280:
        core.die("MTU Mieru должен быть не меньше 1280.")
    if multiplexing not in _MULTIPLEXING:
        core.die("Недопустимый уровень multiplexing.")
    bindings = config.get("portBindings", [])
    return {"profiles": [{"profileName": profile, "user": {"name": name, "password": password},
                          "servers": [{"ipAddress": host, "portBindings": bindings}], "mtu": mtu,
                          "multiplexing": {"level": multiplexing}}], "activeProfile": profile,
            "rpcPort": 8964, "socks5Port": 1080, "loggingLevel": "INFO"}


def client_link(name: str, password: str, host: str, config: dict[str, Any], *, profile: str = "default",
                mtu: int = 1400, multiplexing: str = "MULTIPLEXING_HIGH") -> str:
    """Строит ссылку импорта mierus:// для пользователя."""
    if not isinstance(name, str) or not name:
        core.die("Имя пользователя для ссылки Mieru не должно быть пустым.")
    _validate_host(host)
    if not isinstance(password, str) or not password or any(c.isspace() for c in password):
        core.die("Пароль Mieru не должен быть пустым или содержать пробелы и переводы строк.")
    if mtu < 1280 or multiplexing not in _MULTIPLEXING:
        core.die("Недопустимые параметры профиля Mieru.")
    bindings = ports(config)
    params = ["handshake-mode=HANDSHAKE_NO_WAIT", "mtu=%s" % mtu,
              "multiplexing=%s" % quote(multiplexing, safe="" )]
    for port, protocol in bindings:
        params.extend(("port=%s" % quote(str(port), safe="-"), "protocol=%s" % quote(protocol.upper(), safe="")))
    params.append("profile=%s" % quote(profile, safe=""))
    return "mierus://%s:%s@%s?%s" % (quote(name, safe=""), quote(password, safe=""), host, "&".join(params))


def _firewall(config: dict[str, Any], *, delete: bool) -> None:
    """Добавляет или удаляет правила UFW, если он установлен."""
    if shutil.which("ufw") is None:
        return
    for port, protocol in ports(config):
        operation = ["ufw", "--force", "delete", "allow"] if delete else ["ufw", "allow"]
        core.run([*operation, "%s/%s" % (str(port).replace("-", ":"), protocol)], check=False)  # ufw пишет диапазон «a:b»


def open_firewall(config: dict[str, Any]) -> None:
    """Открывает порты Mieru в UFW."""
    _firewall(config, delete=False)


def close_firewall(config: dict[str, Any]) -> None:
    """Удаляет правила портов Mieru из UFW."""
    _firewall(config, delete=True)


# --- состояние Autopilot: свои пароли храним сами (mita хранит их хэшами и может не отдать обратно) -----------------

STATE = "etc/autopilot/mieru.json"


def load_state() -> dict[str, Any]:
    try:
        data = json.loads(core.path(STATE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"enabled": False, "users": {}}
    if not isinstance(data, dict) or not isinstance(data.get("users"), dict):
        return {"enabled": False, "users": {}}
    return data


def save_state(state: dict[str, Any]) -> None:
    core.write_file(core.path(STATE), json.dumps(state, ensure_ascii=False, indent=2) + "\n", 0o600)


def enabled() -> bool:
    return bool(load_state().get("enabled"))


def enable(arch: str, names: list[str], *, port: int | None = None) -> dict[str, Any]:
    """Ставит и настраивает mita (если её нет), заводит пользователей names и открывает порты. Чужой конфиг не трогает."""
    already_configured = installed() and bool(describe(strict=False).get("portBindings"))
    install(arch)
    config = configure(port)
    state = load_state()
    state["enabled"] = True
    state.setdefault("own_port", not already_configured)  # порт наш, только если конфига до нас не было
    for name in names:
        if name not in state["users"]:
            state["users"][name] = add_user(name)
    save_state(state)
    open_firewall(config)
    return config


def restore_state(arch: str, saved: dict[str, Any]) -> None:
    """Возвращает Mieru после восстановления из копии: наши пользователи заводятся с прежними паролями. Если mita уже
    настроена (тот же сервер), её порты и чужие пользователи не меняются."""
    if not saved.get("enabled") or not isinstance(saved.get("users"), dict):
        return
    already_configured = installed() and bool(describe(strict=False).get("portBindings"))
    install(arch)
    config = configure(None)
    for name, password in saved["users"].items():
        add_user(name, password)
    save_state({"enabled": True, "users": dict(saved["users"]), "own_port": saved.get("own_port", not already_configured)})
    open_firewall(config)


def disable() -> None:
    """Убирает только наших пользователей. Саму службу mita и чужие настройки не трогаем."""
    state = load_state()
    for name in list(state.get("users", {})):
        remove_user(name)
    if state.get("own_port"):  # порты закрываем только если конфиг создали мы
        close_firewall(describe(strict=False))
    state["enabled"] = False
    state["users"] = {}
    save_state(state)


def user_added(name: str) -> str | None:
    """Хук `user add`: если Mieru включён – заводит пользователя и возвращает ссылку."""
    state = load_state()
    if not state.get("enabled"):
        return None
    if name not in state["users"]:
        state["users"][name] = add_user(name)
        save_state(state)
    return state["users"][name]


def user_removed(name: str) -> None:
    state = load_state()
    if state.get("enabled") and name in state["users"]:
        remove_user(name)
        del state["users"][name]
        save_state(state)


def link_for(name: str, host: str) -> str | None:
    """Ссылка mierus:// пользователя (None, если Mieru выключен или у пользователя нет учётки)."""
    state = load_state()
    password = state.get("users", {}).get(name) if state.get("enabled") else None
    if not password:
        return None
    return client_link(name, password, host, describe())
