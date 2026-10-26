"""Выбор сайта-прикрытия для REALITY: он должен отвечать по TLS 1.3 и HTTP/2."""
from __future__ import annotations

import re
import socket
import ssl

# Запасной список: крупные сайты, которые обычно поддерживают TLS 1.3 и h2. Лучше указать свой через --sni:
# чем ближе сайт к IP сервера (тот же хостер, та же подсеть), тем менее заметно несовпадение имени и адреса.
FALLBACK_SITES = ("www.microsoft.com", "www.cloudflare.com", "www.apple.com", "dl.google.com", "www.amazon.com")

HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$")


def valid_host(name: str) -> bool:
    return bool(HOST_RE.match(name)) and len(name) <= 253


def supports_tls13_h2(host: str, *, timeout: float = 8) -> bool:
    """Сайт принимает TLS 1.3 и согласует ALPN h2. Любая сетевая ошибка – False."""
    if not valid_host(host):
        return False
    try:
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3  # ValueError, если OpenSSL у Python без TLS 1.3
        ctx.set_alpn_protocols(["h2"])
        with socket.create_connection((host, 443), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                return tls.version() == "TLSv1.3" and tls.selected_alpn_protocol() == "h2"
    except (OSError, ssl.SSLError, ValueError):
        return False


def pick(candidates=FALLBACK_SITES, *, exclude=(), check=supports_tls13_h2) -> str | None:
    """Первый подходящий сайт из списка, не входящий в exclude. None, если никто не подошёл."""
    for host in candidates:
        if host in exclude:
            continue
        if check(host):
            return host
    return None
