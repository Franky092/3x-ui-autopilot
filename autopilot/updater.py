"""Обновление панели до версии, закреплённой в пакете Autopilot."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from . import backup, core, installer


def _state_path() -> Path:
    return core.path(core.CONF_DIR, "install.json")


def installed_version() -> str | None:
    """Читает установленную версию панели."""
    target = _state_path()
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    version = data.get("panel_version") if isinstance(data, dict) else None
    return str(version) if version is not None else None


def pinned_version() -> str:
    """Возвращает версию панели из пакета."""
    return installer.PANEL_VERSION


def needs_update() -> bool:
    """Проверяет, установлена ли панель и отличается ли её версия."""
    return _state_path().is_file() and installed_version() != pinned_version()


def plan() -> dict[str, Any]:
    """Возвращает краткий план обновления."""
    return {"from": installed_version(), "to": pinned_version(), "needs": needs_update()}


def _load_state() -> dict[str, Any]:
    target = _state_path()
    if not target.is_file():
        core.die("Установка не найдена. Сначала выполните: autopilot install")
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        core.die("Не удалось прочитать %s" % target)
        raise
    if not isinstance(data, dict):
        core.die("Файл установки %s повреждён." % target)
    return data


def upgrade(api_factory: Callable[[], Any], *, arch: str, backup_first: bool = True,
            opener: Callable | None = None, sleep: Callable[[float], None] = time.sleep) -> dict[str, Any]:
    """Обновляет панель; при неудаче возвращает прежние исполняемые файлы."""
    state = _load_state()
    old_version = state.get("panel_version")
    new_version = pinned_version()
    result: dict[str, Any] = {"from": old_version, "to": new_version, "backup": None, "rolled_back": False}
    if old_version == new_version:
        return result

    backup_path = None
    if backup_first:
        try:
            backup_path = backup.create()
        except Exception as exc:
            core.die("Не удалось создать резервную копию: %s" % exc)
    result["backup"] = str(backup_path) if backup_path is not None else None

    try:
        old_count = len(api_factory().inbounds())
    except Exception as exc:
        core.die("Не удалось проверить подключения панели до обновления: %s" % exc)

    root = core.path(installer.XUI_DIR)
    old_root = core.path(installer.XUI_DIR + ".old")
    tmp_parent = core.path("tmp")
    tmp_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="autopilot-update-", dir=str(tmp_parent)) as tmp_name:
        tmp = Path(tmp_name)
        archive = tmp / "x-ui.tar.gz"
        staging = tmp / "out"
        staging.mkdir()
        try:
            url = installer.PANEL_URL % (new_version, arch)
            installer.download(url, archive, installer.PANEL_SHA256[arch], opener=opener)
            installer.safe_extract(archive, staging)
        except KeyError:
            core.die("Неподдерживаемая архитектура панели: %s" % arch)
        source = staging / "x-ui"
        if not (source / "x-ui").is_file():
            core.die("В архиве нет исполняемого файла панели.")

        core.systemctl("stop", "x-ui", check=True)
        if old_root.exists() and root.exists():
            shutil.rmtree(old_root)
        if root.exists():
            os.replace(root, old_root)
        root.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, root)
        os.chmod(root / "x-ui", 0o755)
        xray = root / "bin" / ("xray-linux-" + arch)
        if xray.exists():
            os.chmod(xray, 0o755)

        last_error = "Панель не ответила за 30 секунд."
        healthy = False
        try:
            core.systemctl("start", "x-ui", check=True)
        except Exception as exc:
            last_error = str(exc) or "Не удалось запустить панель."
        else:
            for attempt in range(30):
                try:
                    count = len(api_factory().inbounds())
                    if count < old_count:
                        last_error = "После обновления подключений стало меньше (%d вместо %d)." % (
                            count, old_count)
                        break
                    healthy = True
                    break
                except Exception as exc:
                    last_error = str(exc) or "Панель не отвечает."
                    if attempt < 29:
                        sleep(1)

        if not healthy:
            core.systemctl("stop", "x-ui", check=False)
            if root.exists():
                shutil.rmtree(root)
            if old_root.exists():
                os.replace(old_root, root)
            core.systemctl("start", "x-ui", check=False)
            result["rolled_back"] = True
            result["error"] = last_error
            return result

        state["panel_version"] = new_version
        core.write_file(_state_path(), json.dumps(state, ensure_ascii=False, indent=2) + "\n", 0o600)
        if old_root.exists():
            shutil.rmtree(old_root)
    return result
