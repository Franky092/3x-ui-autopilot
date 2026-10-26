"""Конфигурация nginx строится по подключениям панели: источником правды остаётся сама панель."""
from __future__ import annotations

import json
from typing import Any

from . import core, nginx

SNI_REMARKS = ("REALITY", "XHTTP")


def _load(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    try:
        value = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def layout_from_inbounds(inbounds: list[dict[str, Any]], cert_file: str, key_file: str, *,
                         sub_paths: list[str] | None = None, sub_port: int = 0) -> nginx.Layout:
    layout = nginx.Layout(cert_file=cert_file, key_file=key_file, sub_paths=list(sub_paths or []), sub_port=sub_port)
    for item in inbounds:
        if item.get("listen") != "127.0.0.1" or not item.get("enable", True):
            continue
        remark, port = item.get("remark"), int(item.get("port") or 0)
        stream, settings = _load(item.get("streamSettings")), _load(item.get("settings"))
        sni = None
        if remark in SNI_REMARKS:
            names = (stream.get("realitySettings") or {}).get("serverNames") or []
            sni = names[0] if names else None
        elif remark == "MTProto":
            sni = settings.get("fakeTlsDomain")
        if sni:
            if sni in layout.sni_routes:
                core.die("Сайт %s выбран для двух подключений: SNI должны различаться." % sni)
            layout.sni_routes[sni] = port
        elif remark in ("VLESS-WS", "VMess-WS"):
            layout.routes.append(nginx.Route((stream.get("wsSettings") or {}).get("path", ""), port, "ws"))
        elif remark == "Trojan-gRPC":
            layout.routes.append(nginx.Route("/" + (stream.get("grpcSettings") or {}).get("serviceName", ""), port, "grpc"))
    return layout


def apply(api, cert_file: str, key_file: str) -> None:
    """Пересобирает конфиг nginx по текущим подключениям и подписке панели и перечитывает его."""
    from . import subscription

    settings = api.settings()
    sub_paths = subscription.paths(settings) if settings.get("subEnable") else []
    nginx.write(layout_from_inbounds(api.inbounds(), cert_file, key_file, sub_paths=sub_paths,
                                     sub_port=int(settings.get("subPort") or 0)))
    nginx.enable()
