"""Сборщики остальных подключений панели 3X-UI: WS, VMess, Trojan-gRPC, SS2022, Hysteria2, TUIC, MTProto, AmneziaWG.

Форматы полей settings/streamSettings взяты из схем самой панели (frontend/src/schemas/protocols) и проверены
на живой панели 3.9.0. Подключения за nginx слушают loopback, а адрес и TLS в ссылках им задаёт externalProxy.
"""
from __future__ import annotations

import base64
import json
import secrets
from typing import Any

SNIFFING = {"enabled": True, "destOverride": ["http", "tls", "quic"], "metadataOnly": False, "routeOnly": False}


def _body(remark: str, port: int, protocol: str, settings: dict, stream: dict, *, listen: str = "") -> dict[str, Any]:
    return {
        "up": 0, "down": 0, "total": 0, "remark": remark, "enable": True, "expiryTime": 0, "listen": listen,
        "port": port, "protocol": protocol,
        "settings": json.dumps(settings, separators=(",", ":")),
        "streamSettings": json.dumps(stream, separators=(",", ":")),
        "sniffing": json.dumps(SNIFFING, separators=(",", ":")),
    }


def _external(host: str, port: int = 443) -> list[dict[str, Any]]:
    """Ссылки клиентов получают публичный адрес и TLS, хотя сам inbound слушает loopback без TLS (TLS держит nginx)."""
    return [{"forceTls": "tls", "dest": host, "port": port, "remark": ""}]


def vless_ws(port: int, path: str, host: str) -> dict[str, Any]:
    stream = {"network": "ws", "security": "none", "wsSettings": {"path": path, "headers": {}, "acceptProxyProtocol": False},
              "externalProxy": _external(host)}
    return _body("VLESS-WS", port, "vless", {"clients": [], "decryption": "none", "fallbacks": []}, stream, listen="127.0.0.1")


def vmess_ws(port: int, path: str, host: str) -> dict[str, Any]:
    stream = {"network": "ws", "security": "none", "wsSettings": {"path": path, "headers": {}},
              "externalProxy": _external(host)}
    return _body("VMess-WS", port, "vmess", {"clients": []}, stream, listen="127.0.0.1")


def trojan_grpc(port: int, service: str, host: str) -> dict[str, Any]:
    stream = {"network": "grpc", "security": "none", "grpcSettings": {"serviceName": service, "multiMode": False},
              "externalProxy": _external(host)}
    return _body("Trojan-gRPC", port, "trojan", {"clients": [], "fallbacks": []}, stream, listen="127.0.0.1")


def ss2022_key() -> str:
    return base64.b64encode(secrets.token_bytes(16)).decode()


def shadowsocks(port: int) -> dict[str, Any]:
    settings = {"method": "2022-blake3-aes-128-gcm", "password": ss2022_key(), "network": "tcp,udp", "clients": [], "ivCheck": False}
    return _body("Shadowsocks", port, "shadowsocks", settings, {"network": "tcp", "security": "none"})


def hysteria2(port: int, cert_file: str, key_file: str, *, masquerade_url: str | None = None) -> dict[str, Any]:
    masquerade = {"type": "proxy", "url": masquerade_url, "rewriteHost": True} if masquerade_url else {"type": ""}
    stream = {
        "network": "hysteria", "security": "tls",
        "tlsSettings": {"serverName": "", "alpn": ["h3"], "minVersion": "1.3", "maxVersion": "1.3",
                        "certificates": [{"certificateFile": cert_file, "keyFile": key_file, "ocspStapling": 3600}]},
        "hysteriaSettings": {"version": 2, "auth": "", "udpIdleTimeout": 60, "masquerade": masquerade},
    }
    return _body("Hysteria2", port, "hysteria", {"version": 2, "clients": []}, stream)


def tuic(port: int, cert_file: str, key_file: str) -> dict[str, Any]:
    settings = {
        "certificate": cert_file, "private_key": key_file, "congestion_control": "bbr", "alpn": ["h3", "spdy/3.1"],
        "udp_relay_mode": "native", "zero_rtt_handshake": False, "log_level": "warn", "max_idle_time": 15,
        "authentication_timeout": 3, "max_udp_relay_packet_size": 1500, "sni": "", "clients": [],
    }
    return _body("TUIC", port, "tuic", settings, {"network": "tcp", "security": "none"})


def mtproto(port: int, fake_tls_domain: str, host: str) -> dict[str, Any]:
    settings = {"fakeTlsDomain": fake_tls_domain, "clients": [], "publicIpv4": host}
    return _body("MTProto", port, "mtproto", settings, {"network": "tcp", "security": "none"}, listen="127.0.0.1")


def awg_obfuscation(v31: bool = False, rng: "secrets.SystemRandom | None" = None) -> dict[str, Any]:
    """Случайные параметры обфускации AmneziaWG: с нулями это обычный WireGuard, который легко узнать."""
    rng = rng or secrets.SystemRandom()
    jmin = rng.randint(40, 80)
    s1 = rng.randint(15, 150)
    s2 = rng.randint(15, 150)
    while s2 == s1 + 56:  # требование протокола: S1 + 56 != S2
        s2 = rng.randint(15, 150)
    params: dict[str, Any] = {"jc": rng.randint(4, 8), "jmin": jmin, "jmax": jmin + rng.randint(20, 100), "s1": s1, "s2": s2}
    if v31:
        params.update({"s3": rng.randint(8, 24), "s4": rng.randint(4, 24), "h1": "1", "h2": "2", "h3": "3", "h4": "4", "i1": "<r 69>"})
    else:
        heads = rng.sample(range(5, 2 ** 31), 4)
        params.update({"h1": str(heads[0]), "h2": str(heads[1]), "h3": str(heads[2]), "h4": str(heads[3])})
    return params


def amneziawg(port: int, subnet_ip: str, dns: str, *, remark: str = "AmneziaWG", v31: bool = False) -> dict[str, Any]:
    server: dict[str, Any] = {"subnetIp": subnet_ip, "subnetCidr": 24, "primaryDns": dns, "secondaryDns": dns, "mtu": 1420}
    server.update(awg_obfuscation(v31))
    return _body(remark, port, "amneziawg", {"server": server, "clients": []}, {"network": "tcp", "security": "none"})
