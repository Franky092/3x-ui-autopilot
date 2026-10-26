"""Свой экземпляр nginx для 443: stream-маршрутизация по SNI и HTTPS-сервер (заглушка, WS, gRPC, подписка).

Системный nginx не трогаем: у нас отдельный конфиг (etc/autopilot/nginx/nginx.conf) и юнит autopilot-nginx.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from . import core

CONF = "etc/autopilot/nginx/nginx.conf"
WEBROOT = "var/www/autopilot"
HTTPS_PORT = 10453  # внутренний TLS-сервер, куда уходит всё, что не опознано по SNI
SNI_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")
PATH_RE = re.compile(r"^/[A-Za-z0-9._~/-]*$")
FILE_RE = re.compile(r"^/[A-Za-z0-9._/-]+$")  # пути к сертификату и ключу: без пробелов, «;», кавычек и переводов строки


@dataclass
class Route:
    """Один путь HTTPS-сервера: WebSocket или gRPC на loopback-порт."""
    path: str
    port: int
    kind: str  # "ws" | "grpc" | "http"


@dataclass
class Layout:
    sni_routes: dict[str, int] = field(default_factory=dict)  # SNI -> loopback-порт
    routes: list[Route] = field(default_factory=list)
    cert_file: str = ""
    key_file: str = ""
    sub_paths: list[str] = field(default_factory=list)  # пути подписки (основной, JSON, Clash)
    sub_port: int = 0                                    # loopback-порт сервера подписки панели


def _check(layout: Layout) -> None:
    for sni, port in layout.sni_routes.items():
        if not SNI_RE.match(sni) or not 1 <= port <= 65535:
            core.die("Недопустимый маршрут SNI: %r" % sni)
    for route in layout.routes:
        if not PATH_RE.match(route.path) or route.kind not in ("ws", "grpc", "http") or not 1 <= route.port <= 65535:
            core.die("Недопустимый маршрут: %r" % (route,))
    if not layout.cert_file or not layout.key_file:
        core.die("Для HTTPS-сервера нужны сертификат и ключ.")
    for value in (layout.cert_file, layout.key_file):
        if not FILE_RE.match(value) or ".." in value.split("/"):
            core.die("Недопустимый путь к сертификату: %r" % value)
    for value in layout.sub_paths:
        if not re.match(r"^/[A-Za-z0-9._~-]+/$", value):
            core.die("Недопустимый путь подписки: %r" % value)
    if layout.sub_paths and not 1 <= layout.sub_port <= 65535:
        core.die("Нужен порт сервера подписки.")


def render(layout: Layout) -> str:
    _check(layout)
    mapping = "\n".join("        %s 127.0.0.1:%d;" % (sni, port) for sni, port in sorted(layout.sni_routes.items()))
    locations = []
    for route in layout.routes:
        if route.kind == "ws":
            locations.append("""        location %s {
            proxy_pass http://127.0.0.1:%d;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_read_timeout 3600s;
            proxy_send_timeout 3600s;
        }""" % (route.path, route.port))
        elif route.kind == "grpc":
            locations.append("""        location %s {
            grpc_pass grpc://127.0.0.1:%d;
            grpc_read_timeout 3600s;
            grpc_send_timeout 3600s;
            client_max_body_size 0;
        }""" % (route.path, route.port))
        else:
            locations.append("""        location %s {
            proxy_pass http://127.0.0.1:%d;
            proxy_set_header Host $http_host;
        }""" % (route.path, route.port))
    for sub in layout.sub_paths:
        locations.append("""        location %s {
            proxy_pass http://127.0.0.1:%d;
            proxy_set_header Host $http_host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header User-Agent $http_user_agent;
            proxy_set_header X-Forwarded-Proto https;
        }""" % (sub, layout.sub_port))
    return """# Создано автоматически (3X-UI Autopilot). Ручные правки будут перезаписаны.
worker_processes auto;
worker_rlimit_nofile 8192;
pid /run/autopilot-nginx.pid;
error_log /var/log/autopilot-nginx-error.log warn;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 4096;
}

stream {
    map $ssl_preread_server_name $autopilot_backend {
%(mapping)s
        default 127.0.0.1:%(https_port)d;
    }
    server {
        listen 443;
        listen [::]:443;
        ssl_preread on;
        proxy_pass $autopilot_backend;
        proxy_connect_timeout 10s;
    }
}

http {
    access_log off;
    server_tokens off;
    include /etc/nginx/mime.types;
    server {
        listen 127.0.0.1:%(https_port)d ssl http2;
        ssl_certificate %(cert)s;
        ssl_certificate_key %(key)s;
        ssl_protocols TLSv1.2 TLSv1.3;
        root /%(webroot)s;
        index index.html;
%(locations)s
        location / {
            try_files $uri $uri/ =404;
        }
    }
}
""" % {"mapping": mapping, "https_port": HTTPS_PORT, "cert": layout.cert_file, "key": layout.key_file,
       "webroot": WEBROOT, "locations": "\n".join(locations)}


STUB_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Welcome</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:15vh auto;padding:0 1rem;color:#333}</style></head>
<body><h1>Welcome</h1><p>This site is under construction. Please check back later.</p></body></html>
"""

UNIT = """[Unit]
Description=3X-UI Autopilot: nginx (443 по SNI, заглушка, WS, gRPC, подписка)
After=network.target

[Service]
Type=forking
PIDFile=/run/autopilot-nginx.pid
ExecStartPre=/usr/sbin/nginx -t -c /etc/autopilot/nginx/nginx.conf
ExecStart=/usr/sbin/nginx -c /etc/autopilot/nginx/nginx.conf
ExecReload=/usr/sbin/nginx -c /etc/autopilot/nginx/nginx.conf -s reload
ExecStop=/usr/sbin/nginx -c /etc/autopilot/nginx/nginx.conf -s quit
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
"""


def write(layout: Layout) -> Path:
    """Пишет конфиг и заглушку; проверяет `nginx -t`, при ошибке возвращает прежний конфиг."""
    target = core.path(CONF)
    previous = target.read_text(encoding="utf-8") if target.exists() else None
    core.write_file(target, render(layout), 0o644)
    core.write_file(core.path(WEBROOT, "index.html"), STUB_HTML, 0o644)
    check = core.run(["nginx", "-t", "-c", str(target)], check=False)
    if check.returncode != 0:
        if previous is None:
            target.unlink(missing_ok=True)
        else:
            core.write_file(target, previous, 0o644)
        core.die("nginx не принял конфигурацию: %s" % (check.stderr.strip().splitlines() or ["?"])[-1])
    return target


def enable() -> None:
    """Выключает системный nginx (порт 443 нужен нам) и включает свой."""
    core.write_file(core.path("etc/systemd/system/autopilot-nginx.service"), UNIT, 0o644)
    core.systemctl("disable", "--now", "nginx")
    core.systemctl("daemon-reload")
    core.systemctl("enable", "autopilot-nginx", check=True)
    core.systemctl("restart", "autopilot-nginx", check=True)


def reload() -> None:
    core.systemctl("reload", "autopilot-nginx", check=True)
