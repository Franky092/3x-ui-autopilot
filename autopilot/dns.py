"""Собственный рекурсивный DNS (unbound) без внешних серверов-пересылщиков.

Нужен AmneziaWG: клиенты запрашивают имена у сервера, а не у 1.1.1.1. Слушает 127.0.0.1:5353 и публичный IP сервера :53;
запросы принимает только от самого сервера (так обращается туннель панели), остальным отвечает отказом, а порт 53 в ufw закрыт.
Системный DNS самого сервера (systemd-resolved) мы НЕ трогаем.
"""
from __future__ import annotations

import ipaddress
import secrets
import socket
import struct
import time
from pathlib import Path

from . import core

CONF = "etc/unbound/unbound.conf.d/autopilot.conf"
LOCAL_PORT = 5353


def config_text(host: str) -> str:
    try:
        address = str(ipaddress.IPv4Address(host))
    except ValueError:
        core.die("Для DNS нужен IPv4-адрес сервера.")
        raise
    return """# Создано автоматически (3X-UI Autopilot). Ручные правки будут перезаписаны.
server:
    interface: 127.0.0.1@%(port)d
    interface: %(host)s@53
    access-control: 127.0.0.0/8 allow
    access-control: %(host)s/32 allow
    access-control: 0.0.0.0/0 refuse
    access-control: ::/0 refuse
    do-ip6: no
    qname-minimisation: yes
    hide-identity: yes
    hide-version: yes
    minimal-responses: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    prefetch: yes
    cache-min-ttl: 60
    log-queries: no
    log-replies: no
    verbosity: 0
""" % {"port": LOCAL_PORT, "host": address}


# --- минимальный DNS-клиент для проверки (без dig) -------------------------------------------------

def build_query(name: str, qid: int | None = None) -> bytes:
    qid = secrets.randbelow(65536) if qid is None else qid
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # рекурсия желательна
    question = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.strip(".").split(".")) + b"\x00"
    return header + question + struct.pack(">HH", 1, 1)  # тип A, класс IN


def parse_reply(data: bytes) -> tuple[int, int, int]:
    """(id, rcode, число ответов). Бросает ValueError на мусоре."""
    if len(data) < 12:
        raise ValueError("short reply")
    qid, flags, _, answers = struct.unpack(">HHHH", data[:8])
    if not flags & 0x8000:
        raise ValueError("not a reply")
    return qid, flags & 0xF, answers


def query(server: str, port: int, name: str = "example.com", *, timeout: float = 3.0) -> tuple[int, int]:
    """Отправляет запрос A по UDP. Возвращает (rcode, число ответов); OSError при отсутствии ответа."""
    packet = build_query(name)
    qid = struct.unpack(">H", packet[:2])[0]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, port))
        data, _ = sock.recvfrom(4096)
    got_id, rcode, answers = parse_reply(data)
    if got_id != qid:
        raise ValueError("id mismatch")
    return rcode, answers


def wait_ready(*, attempts: int = 20, delay: float = 1.0, sleep=time.sleep, ask=query) -> bool:
    """Ждёт, пока unbound реально разрешит имя (первый запрос рекурсора идёт долго)."""
    for _ in range(attempts):
        try:
            rcode, answers = ask("127.0.0.1", LOCAL_PORT, "ubuntu.com")
            if rcode == 0 and answers > 0:
                return True
        except (OSError, ValueError):
            pass
        sleep(delay)
    return False


def setup(host: str) -> None:
    """Пишет конфиг, проверяет его `unbound-checkconf`, включает службу и дожидается настоящего ответа."""
    target = core.path(CONF)
    previous = target.read_text(encoding="utf-8") if target.exists() else None
    core.write_file(target, config_text(host), 0o644)
    check = core.run(["unbound-checkconf"], check=False)
    if check.returncode != 0:
        _rollback(target, previous)
        core.die("unbound не принял конфигурацию: %s" % (check.stderr.strip().splitlines() or ["?"])[-1])
    core.systemctl("enable", "unbound")
    core.systemctl("restart", "unbound", check=True)
    if not wait_ready():
        core.systemctl("stop", "unbound")
        _rollback(target, previous)
        core.die("Собственный DNS не отвечает.", "Смотрите: journalctl -u unbound")


def _rollback(target: Path, previous: str | None) -> None:
    if previous is None:
        target.unlink(missing_ok=True)
    else:
        core.write_file(target, previous, 0o644)


def remove() -> None:
    if core.path(CONF).exists():
        core.systemctl("disable", "--now", "unbound")
        core.path(CONF).unlink(missing_ok=True)
