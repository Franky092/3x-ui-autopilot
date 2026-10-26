"""Восстановление сервера из резервной копии (в том числе на другой VPS с другим IP): `autopilot restore ФАЙЛ`."""
from __future__ import annotations

import json
import sqlite3
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import backup, core


@dataclass
class Bundle:
    """Распакованная и проверенная копия: база панели и прежнее состояние установки."""
    db: Path
    state: dict[str, Any]
    warnings: list[str] = field(default_factory=list)
    mieru: dict[str, Any] = field(default_factory=dict)  # состояние Mieru из копии (пароли наших пользователей)
    cert_dir: Path | None = None                          # сертификат из копии (если был)
    _tmp: tempfile.TemporaryDirectory | None = None

    def close(self) -> None:
        if self._tmp is not None:
            self._tmp.cleanup()
            self._tmp = None

    def __enter__(self) -> "Bundle":
        return self

    def __exit__(self, *exc) -> bool:
        self.close()
        return False


def open_backup(archive: Path, passphrase: str | None, *, panel_version: str) -> Bundle:
    """Расшифровывает (если нужно), проверяет архив целиком и проверяет, что внутри целая база панели."""
    if not archive.is_file():
        core.die("Нет файла %s." % archive, "Сначала скопируйте копию на этот сервер: scp файл root@СЕРВЕР:")
    tmp = tempfile.TemporaryDirectory(prefix="autopilot-restore-")
    try:
        backup.safe_extract(archive, Path(tmp.name), passphrase)
        db = Path(tmp.name) / "etc/x-ui/x-ui.db"
        state_file = Path(tmp.name) / "etc/autopilot/install.json"
        if not db.is_file():
            core.die("В копии нет базы панели.")
        try:
            conn = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
            try:
                if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    core.die("База панели в копии повреждена.")
                conn.execute("SELECT count(*) FROM inbounds").fetchone()
            finally:
                conn.close()
        except sqlite3.Error:
            core.die("Файл базы в копии не похож на базу панели.")
        try:
            state = json.loads(state_file.read_text(encoding="utf-8")) if state_file.is_file() else {}
        except ValueError:
            state = {}
        if not isinstance(state, dict):
            state = {}
        mieru_state: dict[str, Any] = {}
        mieru_file = Path(tmp.name) / "etc/autopilot/mieru.json"
        if mieru_file.is_file():
            try:
                loaded = json.loads(mieru_file.read_text(encoding="utf-8"))
                if isinstance(loaded, dict) and isinstance(loaded.get("users"), dict):
                    mieru_state = loaded
            except ValueError:
                pass
        cert_dir = Path(tmp.name) / "etc/autopilot/certs/ip"
        warnings = []
        old = state.get("panel_version")
        if old and old != panel_version:
            warnings.append("Копия сделана с панелью %s, а ставится %s: после восстановления проверьте подключения." % (old, panel_version))
        return Bundle(db=db, state=state, warnings=warnings, mieru=mieru_state,
                      cert_dir=cert_dir if (cert_dir / "fullchain.pem").is_file() else None, _tmp=tmp)
    except BaseException:
        tmp.cleanup()
        raise


_INBOUND_FIELDS = ("up", "down", "total", "remark", "enable", "expiryTime", "listen", "port", "protocol", "settings",
                   "streamSettings", "sniffing", "tag")


def _load(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    try:
        value = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def rehost(api, old_host: str, new_host: str) -> int:
    """Переписывает прежний IP на новый в подключениях (externalProxy для ссылок, publicIpv4 у MTProto).
    Возвращает число изменённых подключений."""
    if not old_host or old_host == new_host:
        return 0
    changed = 0
    for item in api.inbounds():
        stream, settings = _load(item.get("streamSettings")), _load(item.get("settings"))
        dirty = False
        for proxy in stream.get("externalProxy") or []:
            if proxy.get("dest") == old_host:
                proxy["dest"] = new_host
                dirty = True
        if item.get("protocol") == "mtproto" and settings.get("publicIpv4") == old_host:
            settings["publicIpv4"] = new_host
            dirty = True
        if item.get("protocol") == "amneziawg":  # DNS туннеля – это сам сервер
            server = settings.get("server") or {}
            for key in ("primaryDns", "secondaryDns"):
                if server.get(key) == old_host:
                    server[key] = new_host
                    dirty = True
        if not dirty:
            continue
        body = {key: item[key] for key in _INBOUND_FIELDS if key in item}
        body["streamSettings"] = json.dumps(stream, separators=(",", ":"))
        body["settings"] = json.dumps(settings, separators=(",", ":"))
        api.update_inbound(int(item["id"]), body)
        changed += 1
    return changed
