"""Установка 3X-UI и первичная настройка сервера одной командой: `autopilot install`."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import platform
import re
import secrets
import shutil
import string
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from . import __version__, core

PANEL_VERSION = "v3.9.0"
PANEL_URL = "https://github.com/MHSanaei/3x-ui/releases/download/%s/x-ui-linux-%s.tar.gz"
# SHA256 официальных сборок панели (совпадают с файлами .sha256 рядом с релизом на GitHub).
PANEL_SHA256 = {
    "amd64": "d7cbe0bf6358ee0d2117c24fd2efb483502e411d38e2ea59bd0bf5e7a3e39390",
    "arm64": "9a2e43c976a2e71618a30d8f38b52476b25ed363c6989599e2f625cc52f51a81",
}
SUPPORTED_OS = {("ubuntu", "22.04"), ("ubuntu", "24.04"), ("debian", "12"), ("debian", "13")}
MAX_DOWNLOAD = 256 * 1024 * 1024
APT_PACKAGES = ("ufw", "fail2ban", "openssl", "ca-certificates", "qrencode", "nginx", "libnginx-mod-stream", "socat", "unbound")
XUI_DIR = "usr/local/x-ui"
PUBLIC_TCP = (443, 80)            # 443 – nginx по SNI, 80 – только для продления сертификата
PORTS = {"reality": 10443, "xhttp": 10444, "mtproto": 10445, "vless_ws": 11001, "vmess_ws": 11002, "trojan": 11003}
SS_PORT, HY2_PORT, TUIC_PORT, AWG_PORT, AWG31_PORT = 8388, 443, 8444, 51821, 51822
# UFW: (порт, протокол)
UFW_RULES = [(443, "tcp"), (80, "tcp"), (443, "udp"), (SS_PORT, "tcp"), (SS_PORT, "udp"), (TUIC_PORT, "udp"),
             (AWG_PORT, "udp"), (AWG31_PORT, "udp")]


# --- чистые функции (покрыты тестами) ---------------------------------------------------------------

def random_alnum(length: int) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def parse_os_release(text: str) -> tuple[str, str]:
    values = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
    return values.get("ID", ""), values.get("VERSION_ID", "")


def check_os(text: str) -> None:
    ident = parse_os_release(text)
    if ident not in SUPPORTED_OS:
        core.die("Поддерживаются Ubuntu 22.04/24.04 и Debian 12/13, а здесь %s %s." % (ident[0] or "?", ident[1] or "?"))


def normalize_arch(machine: str) -> str:
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine)
    if arch is None:
        core.die("Нужен процессор amd64 или arm64, а здесь %s." % machine)
    return arch  # type: ignore[return-value]


def parse_ipv4_addresses(ip_output: str) -> list[str]:
    """Адреса из `ip -4 -o addr show scope global` (строки вида «2: eth0 inet 1.2.3.4/24 …»)."""
    found = []
    for line in ip_output.splitlines():
        parts = line.split()
        if "inet" in parts:
            candidate = parts[parts.index("inet") + 1].split("/")[0]
            try:
                found.append(str(ipaddress.IPv4Address(candidate)))
            except ValueError:
                continue
    return found


def pick_public_ipv4(addresses: Iterable[str], wanted: str | None = None) -> str:
    public = [a for a in addresses if ipaddress.IPv4Address(a).is_global]
    if wanted:
        try:
            ipaddress.IPv4Address(wanted)
        except ValueError:
            core.die("--host: нужен IPv4-адрес, например 203.0.113.10")
        if wanted not in public:
            core.die("Адрес %s не найден на интерфейсах сервера. NAT не поддерживается." % wanted)
        return wanted
    if not public:
        core.die("На сервере нет публичного IPv4 (NAT не поддерживается). Укажите адрес через --host.")
    return public[0]


def parse_listening_ports(ss_output: str) -> set[int]:
    ports = set()
    for line in ss_output.splitlines():
        for token in line.split():
            match = re.search(r":(\d{1,5})$", token)
            if match and ("." in token or "[" in token or token.startswith("*") or token.startswith(":")):
                ports.add(int(match.group(1)))
                break
    return ports


def parse_api_token(output: str) -> str:
    match = re.search(r"apiToken:\s*(\S+)", output)
    if not match:
        core.die("Панель не выдала токен API (вывод `x-ui setting -getApiToken` неожиданный).")
    return match.group(1)  # type: ignore[union-attr]


def safe_extract(archive: Path, dest: Path) -> None:
    """Распаковка tar.gz только с файлами и каталогами, без ссылок, «..» и абсолютных путей."""
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        for member in members:
            name = member.name
            parts = Path(name).parts
            if name.startswith("/") or ".." in parts or "\\" in name:
                core.die("Небезопасный путь в архиве: %r" % name)
            if not (member.isfile() or member.isdir()):
                core.die("В архиве запрещены ссылки и особые файлы: %r" % name)
        tar.extractall(dest, members=members)


def download(url: str, dest: Path, sha256: str, *, opener: Callable | None = None) -> None:
    """HTTPS-загрузка с лимитом размера и обязательной проверкой SHA256. Не оставляет файл при несовпадении."""
    if urllib.parse.urlsplit(url).scheme != "https":
        core.die("Скачивать можно только по HTTPS")
    opener = opener or urllib.request.urlopen
    digest = hashlib.sha256()
    total = 0
    try:
        with opener(url, timeout=60) as response, open(dest, "wb") as out:
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > MAX_DOWNLOAD:
                    core.die("Файл слишком большой")
                digest.update(block)
                out.write(block)
    except OSError as exc:
        dest.unlink(missing_ok=True)
        core.die("Не удалось скачать %s: %s" % (url, exc))
    if digest.hexdigest() != sha256:
        dest.unlink(missing_ok=True)
        core.die("SHA256 файла не совпал. Установка остановлена.")


# --- план и шаги ------------------------------------------------------------------------------------

@dataclass
class Plan:
    host: str
    arch: str
    sni: str
    xhttp_sni: str
    ssh_ports: list[int]
    mtproto_sni: str = ""
    panel_port: int = 0
    panel_path: str = ""
    username: str = ""
    password: str = ""
    api_token: str = ""
    no_ufw: bool = False
    extra: dict = field(default_factory=dict)


def preflight(host: str | None) -> tuple[str, str, list[int]]:
    """Проверки до любых изменений. Возвращает (ip, arch, ssh-порты)."""
    if os.geteuid() != 0 and "AUTOPILOT_ROOT" not in os.environ:
        core.die("Запустите от root: sudo -i, затем команду ещё раз.")
    check_os(core.path("etc/os-release").read_text(encoding="utf-8"))
    arch = normalize_arch(platform.machine())
    if not core.path("run/systemd/system").exists() and "AUTOPILOT_ROOT" not in os.environ:
        core.die("Нужен systemd.")
    if core.path(core.CONF_DIR, "install.json").exists():
        core.die("Autopilot уже установлен (есть %s). Для управления: autopilot" % core.path(core.CONF_DIR, "install.json"))
    addresses = parse_ipv4_addresses(core.run(["ip", "-4", "-o", "addr", "show", "scope", "global"]).stdout)
    ip = pick_public_ipv4(addresses, host)
    busy = parse_listening_ports(core.run(["ss", "-Hltn"]).stdout)
    for port in PUBLIC_TCP:
        if port in busy:
            core.die("Порт %d/TCP уже занят другой программой." % port,
                     "Освободите его (ss -ltnp 'sport = :%d') и запустите установку снова." % port)
    from . import harden  # отложенный импорт: модуль может отсутствовать в урезанных сборках

    return ip, arch, harden.ssh_ports()


def apt_install(packages: Iterable[str]) -> None:
    env = {"DEBIAN_FRONTEND": "noninteractive"}
    core.run(["apt-get", "-o", "DPkg::Lock::Timeout=900", "update", "-qq"], env=env)
    core.run(["apt-get", "-o", "DPkg::Lock::Timeout=900", "install", "-y", "-qq", *packages], env=env)


def free_port(avoid: set[int]) -> int:
    busy = parse_listening_ports(core.run(["ss", "-Hltn"]).stdout) | avoid
    for _ in range(100):
        port = 20000 + secrets.randbelow(40000)
        if port not in busy:
            return port
    core.die("Не нашёл свободный порт для панели.")
    return 0


def install_panel(plan: Plan, restore_db: Path | None = None) -> None:
    """Скачивает закреплённую сборку панели, проверяет SHA256, ставит её и настраивает на loopback.
    restore_db – база из резервной копии: кладётся до первого запуска, так что пользователи и ключи сохраняются."""
    root = core.path(XUI_DIR)
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / "x-ui.tar.gz"
        download(PANEL_URL % (PANEL_VERSION, plan.arch), archive, PANEL_SHA256[plan.arch])
        staging = Path(tmp) / "out"
        staging.mkdir()
        safe_extract(archive, staging)
        source = staging / "x-ui"
        if not (source / "x-ui").is_file():
            core.die("В архиве нет исполняемого файла панели.")
        if root.exists():
            shutil.rmtree(root)
        root.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, root)
    os.chmod(root / "x-ui", 0o755)
    xray = root / "bin" / ("xray-linux-" + plan.arch)
    if xray.exists():
        os.chmod(xray, 0o755)
    unit = (root / "x-ui.service.debian").read_text(encoding="utf-8")
    core.write_file(core.path("etc/systemd/system/x-ui.service"), unit)
    core.path("etc/x-ui").mkdir(parents=True, exist_ok=True)
    os.chmod(core.path("etc/x-ui"), 0o700)
    core.path("var/log/x-ui").mkdir(parents=True, exist_ok=True)
    if restore_db is not None:
        for stale in ("x-ui.db", "x-ui.db-wal", "x-ui.db-shm"):
            core.path("etc/x-ui", stale).unlink(missing_ok=True)
        shutil.copyfile(restore_db, core.path("etc/x-ui/x-ui.db"))
        os.chmod(core.path("etc/x-ui/x-ui.db"), 0o600)

    cli = str(root / "x-ui")
    # Известное ограничение: x-ui принимает пароль только аргументом, поэтому на доли секунды он виден в списке процессов.
    # На свежем одноарендном VPS посторонних пользователей нет, а панель слушает только loopback и открывается через SSH-туннель.
    core.run([cli, "setting", "-username", plan.username, "-password", plan.password, "-port", str(plan.panel_port),
              "-webBasePath", plan.panel_path, "-listenIP", "127.0.0.1"], cwd=str(root))
    plan.api_token = parse_api_token(core.run([cli, "setting", "-getApiToken"], cwd=str(root)).stdout)
    core.systemctl("daemon-reload")
    core.systemctl("enable", "--now", "x-ui", check=True)


def wait_panel(api, *, attempts: int = 30, delay: float = 1.0) -> None:
    last = ""
    for _ in range(attempts):
        try:
            api.inbounds()
            return
        except core.Error as exc:
            last = str(exc)
            time.sleep(delay)
    core.die("Панель не запустилась: %s. Подробности: journalctl -u x-ui" % last)


def setup_ufw(plan: Plan) -> None:
    if plan.no_ufw:
        return
    for port in plan.ssh_ports:  # SSH открываем первым, чтобы не потерять доступ
        core.run(["ufw", "allow", "%d/tcp" % port])
    for port, proto in UFW_RULES:
        core.run(["ufw", "allow", "%d/%s" % (port, proto)])
    core.run(["ufw", "--force", "enable"])


def install_cli() -> None:
    """Кладёт сам пакет на сервер и создаёт команду autopilot."""
    source = Path(__file__).resolve().parent
    target = core.path("usr/local/lib/autopilot/autopilot")
    if target.exists():
        shutil.rmtree(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    # python3 -I игнорирует PYTHONPATH, поэтому путь к пакету добавляем в самой точке входа.
    core.write_file(core.path("usr/local/bin/autopilot"),
                    "#!/usr/bin/python3 -I\nimport sys\nsys.path.insert(0, '/usr/local/lib/autopilot')\n"
                    "from autopilot.__main__ import main\nsys.exit(main())\n", 0o755)


def write_state(plan: Plan, inbounds: list[dict]) -> None:
    data = {
        "version": __version__, "host": plan.host, "arch": plan.arch, "panel_version": PANEL_VERSION,
        "panel_port": plan.panel_port, "panel_path": plan.panel_path, "panel_scheme": "http",
        "api_token": plan.api_token, "ssh_ports": plan.ssh_ports,
        "snis": {"reality": plan.sni, "xhttp": plan.xhttp_sni, "mtproto": plan.mtproto_sni},
        "cert_file": "/" + __import__("autopilot.cert", fromlist=["x"]).CERT_DIR + "/fullchain.pem",
        "cert_kind": plan.extra.get("cert_kind", "unknown"),
        "inbounds": inbounds, "installed_at": int(time.time()),
    }
    core.write_file(core.path(core.CONF_DIR, "install.json"), json.dumps(data, ensure_ascii=False, indent=2) + "\n", 0o600)


def update_state(**changes) -> dict:
    """Дописывает поля в etc/autopilot/install.json, остальное сохраняя (запись атомарная, права 0600)."""
    target = core.path(core.CONF_DIR, "install.json")
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        core.die("Установка не найдена.", "Сначала выполните: autopilot install")
        raise
    data.update(changes)
    core.write_file(target, json.dumps(data, ensure_ascii=False, indent=2) + "\n", 0o600)
    return data


def tunnel_hint(plan: Plan) -> str:
    return "ssh -L %d:127.0.0.1:%d root@%s" % (plan.panel_port, plan.panel_port, plan.host)


def choose_sni(wanted: str | None, *, exclude: tuple[str, ...] = ()) -> str:
    from . import reality

    if wanted:
        if not reality.valid_host(wanted):
            core.die("--sni: нужно только имя сайта, например www.microsoft.com")
        if not reality.supports_tls13_h2(wanted):
            core.die("Сайт %s не отвечает по TLS 1.3 и HTTP/2, REALITY с ним работать не будет." % wanted,
                     "Выберите другой сайт или не указывайте --sni, подберу сам.")
        return wanted
    found = reality.pick(exclude=exclude)
    if not found:
        core.die("Не нашёл подходящий сайт для REALITY.", "Укажите свой: --sni example.com")
    return found  # type: ignore[return-value]


def credentials_text(plan: Plan, links: list[str], sub_url: str = "", user: str = "admin") -> str:
    from . import subscription

    page = ["Страница с инструкцией (ссылка подставлена):", subscription.page_url(sub_url), ""] if sub_url else []
    lines = [
        "3X-UI Autopilot %s: данные для входа (файл виден только root)" % __version__, "",
        "Панель (через SSH-туннель): http://127.0.0.1:%d/%s/" % (plan.panel_port, plan.panel_path),
        "Туннель: " + tunnel_hint(plan),
        "Логин: " + plan.username, "Пароль: " + plan.password, "",
        "Подписка пользователя %s (одна ссылка для всех приложений):" % user, sub_url, "", *page,
        "Отдельные подключения пользователя %s:" % user, *links,
    ]
    return "\n".join(lines) + "\n"


def create_inbounds(api, plan: Plan, cert_file: str, key_file: str) -> list[dict]:
    """Все подключения Autopilot. За nginx (loopback): REALITY, XHTTP, MTProto, WS, VMess, Trojan-gRPC; напрямую: SS2022,
    Hysteria2 (UDP 443), TUIC, AmneziaWG."""
    from . import inbounds as ib
    from . import protocols as P

    host = plan.host
    token = lambda: secrets.token_hex(6)  # noqa: E731
    existing = {i.get("remark"): i for i in api.inbounds()}  # повторный запуск после сбоя не создаёт дубли
    made: list[dict] = []

    def add(remark: str, build) -> None:
        made.append(existing[remark] if remark in existing else api.add_inbound(build()))

    add("REALITY", lambda: ib.reality_inbound(PORTS["reality"], plan.sni, api.new_x25519(), ib.short_id(), host))
    add("XHTTP", lambda: ib.xhttp_inbound(PORTS["xhttp"], plan.xhttp_sni, api.new_x25519(), ib.short_id(), host=host))
    add("MTProto", lambda: P.mtproto(PORTS["mtproto"], plan.mtproto_sni, host))
    add("VLESS-WS", lambda: P.vless_ws(PORTS["vless_ws"], "/" + token(), host))
    add("VMess-WS", lambda: P.vmess_ws(PORTS["vmess_ws"], "/" + token(), host))
    add("Trojan-gRPC", lambda: P.trojan_grpc(PORTS["trojan"], token(), host))
    add("Shadowsocks", lambda: P.shadowsocks(SS_PORT))
    add("Hysteria2", lambda: P.hysteria2(HY2_PORT, cert_file, key_file))
    add("TUIC", lambda: P.tuic(TUIC_PORT, cert_file, key_file))
    add("AmneziaWG", lambda: P.amneziawg(AWG_PORT, "10.8.1.0", plan.extra.get("awg_dns", AWG_FALLBACK_DNS), remark="AmneziaWG"))
    add("AmneziaWG-3.1", lambda: P.amneziawg(AWG31_PORT, "10.8.2.0", plan.extra.get("awg_dns", AWG_FALLBACK_DNS), remark="AmneziaWG-3.1", v31=True))
    return made


AWG_FALLBACK_DNS = "1.1.1.1"  # только если собственный DNS поднять не удалось


def issue_certificate(plan: Plan) -> None:
    """Let's Encrypt на IP; если не вышло – самоподписанный, чтобы остальное всё равно заработало."""
    from . import cert, ui

    try:
        cert.issue(plan.host)
        plan.extra["cert_kind"] = "letsencrypt"
    except core.Error as exc:
        cert.self_signed(plan.host)
        plan.extra["cert_kind"] = "self-signed"
        plan.extra["cert_error"] = str(exc)
        ui.warn("Let's Encrypt не выдал сертификат (%s). Поставил самоподписанный." % str(exc)[:110])
    finally:
        cert.enable_renewal()  # таймер нужен в любом случае: после `autopilot cert renew` продление пойдёт само


def install(*, host: str | None = None, sni: str | None = None, xhttp_sni: str | None = None,
            mtproto_sni: str | None = None, no_ufw: bool = False, restore=None) -> None:
    """Полная установка. Любую ошибку до запуска панели можно просто повторить после исправления причины."""
    from . import cert, harden, inbounds, nginx, reality, sync, ui, units
    from .i18n import t
    from .panel import PanelClient

    total = 10
    ui.banner()
    ui.out()
    ui.out("  " + ui.bold(t("install.title")))
    ui.out()
    with core.lock("install"):
        _install_locked(host, sni, xhttp_sni, mtproto_sni, no_ufw, total, restore)


def _install_locked(host, sni, xhttp_sni, mtproto_sni, no_ufw, total, restore=None) -> None:
    from . import cert, dns, harden, inbounds, nginx, reality, subscription, sync, ui, units
    from . import restore as restore_mod
    from .i18n import t
    from .panel import PanelClient

    with ui.Step(t("install.check"), 1, total):
        ip, arch, ssh_ports = preflight(host)
    ident = parse_os_release(core.path("etc/os-release").read_text(encoding="utf-8"))
    ui.hint(t("install.found", host=ip, os="%s %s" % ident, arch=arch))
    with ui.Step(t("install.sni"), 2, total):
        if restore is not None:  # сайты-прикрытия уже зашиты в подключения из копии
            snis = restore.state.get("snis") or {}
            first, second, third = snis.get("reality", ""), snis.get("xhttp", ""), snis.get("mtproto", "")
        else:
            first = choose_sni(sni)
            second = choose_sni(xhttp_sni, exclude=(first,)) if xhttp_sni else (reality.pick(exclude=(first,)) or first)
            third = choose_sni(mtproto_sni, exclude=(first, second)) if mtproto_sni else (reality.pick(exclude=(first, second)) or "")
            if not third or len({first, second, third}) < 3:
                core.die("Нужны три разных сайта-прикрытия: REALITY, XHTTP и MTProto.", "Укажите их сами: --sni, --xhttp-sni, --mtproto-sni")
    ui.hint(t("install.sni.picked", sni=", ".join((first, second, third))))
    plan = Plan(host=ip, arch=arch, sni=first, xhttp_sni=second, mtproto_sni=third, ssh_ports=ssh_ports, no_ufw=no_ufw)
    plan.panel_port = free_port(set(PORTS.values()) | {443, 80, SS_PORT, TUIC_PORT})
    plan.panel_path = random_alnum(18)
    plan.username, plan.password = random_alnum(10), random_alnum(16)

    with ui.Step(t("install.packages"), 3, total):
        apt_install(APT_PACKAGES)
        core.systemctl("disable", "--now", "nginx")  # системный nginx не нужен: у нас свой
    with ui.Step(t("install.panel", version=PANEL_VERSION), 4, total):
        install_panel(plan, restore.db if restore is not None else None)
        api = PanelClient(plan.panel_port, plan.panel_path, plan.api_token, public_host=plan.host)
        wait_panel(api)
        install_cli()  # раньше сертификата: acme.sh вызывает `autopilot cert reload` сразу после выпуска
    with ui.Step(t("install.firewall"), 5, total):
        setup_ufw(plan)  # порт 80 нужен уже для выпуска сертификата
        harden.setup_fail2ban(plan.ssh_ports[0] if plan.ssh_ports else None)
    with ui.Step(t("install.cert"), 6, total):
        if restore is not None and restore.cert_dir is not None and cert.reusable(restore.cert_dir, plan.host):
            # Сертификат из копии ещё действует и выпущен на этот IP: берём его, а не просим новый (у Let's Encrypt есть лимиты).
            cert.reuse(restore.cert_dir)
            cert.enable_renewal()
            plan.extra["cert_kind"] = "restored"
        else:
            issue_certificate(plan)
    fullchain, key = cert.paths()
    with ui.Step(t("install.dns"), 7, total):
        try:
            dns.setup(plan.host)
            plan.extra["awg_dns"] = plan.host
        except core.Error as exc:  # без своего DNS остальное всё равно работает: AmneziaWG временно получит публичный
            ui.warn(t("install.dns.fail", reason=str(exc)[:100]))
    with ui.Step(t("install.restore.inbounds" if restore is not None else "install.inbounds"), 8, total):
        if restore is not None:
            restore_mod.rehost(api, str(restore.state.get("host") or ""), plan.host)
            made = api.inbounds()
        else:
            made = create_inbounds(api, plan, str(fullchain), str(key))
    with ui.Step(t("install.web"), 9, total):
        subscription.configure(api, plan.host)
        core.systemctl("restart", "x-ui", check=True)  # сервер подписки читает настройки при старте
        wait_panel(api)
        sync.apply(api, str(fullchain), str(key))
    with ui.Step(t("install.user"), 10, total):
        if restore is None:
            if any(c.get("email") == "admin" for c in api.clients()):
                api.del_client("admin")  # остаток прошлой попытки: пересоздаём, чтобы он был на всех подключениях
            inbounds.add_user(api, "admin")
        if restore is not None and restore.mieru:
            try:
                from . import mieru

                mieru.restore_state(plan.arch, restore.mieru)
            except core.Error as exc:  # Mieru – дополнение: сбой не отменяет восстановление всего остального
                ui.warn(t("mieru.restore.fail", reason=str(exc)[:100]))
        write_state(plan, [{"id": m.get("id"), "remark": m.get("remark"), "port": m.get("port")} for m in made])
        units.install_watch_timer()

    emails = sorted(str(c.get("email")) for c in api.clients() if c.get("email"))
    first_user = "admin" if "admin" in emails else (emails[0] if emails else "")
    links = api.client_links(first_user) if first_user else []
    sub_url = subscription.user_urls(api, plan.host, first_user)["auto"] if first_user else ""
    core.write_file(core.path("root/autopilot.txt"), credentials_text(plan, links, sub_url, first_user), 0o600)
    ui.out()
    ui.box(t("install.done"), [
        t("install.creds", file="/root/autopilot.txt"), "",
        t("install.tunnel"), "  " + ui.bold(tunnel_hint(plan)),
        "  http://127.0.0.1:%d/%s/" % (plan.panel_port, plan.panel_path),
    ], kind="ok")
    if plan.extra.get("cert_kind") == "self-signed":
        ui.warn(t("install.selfsigned"))
    ui.out()
    ui.out("  " + ui.bold(t("install.sub")))
    ui.out("  " + ui.accent(sub_url))
    ui.out()
    ui.out("  " + t("install.scan"))
    if not ui.qr(sub_url):
        ui.hint(sub_url)
    if sub_url:
        ui.out()
        ui.out("  " + ui.bold(t("install.page")))
        ui.out("  " + ui.accent(subscription.page_url(sub_url)))
    ui.out()
    ui.out("  " + ui.bold(t("what.next")))
    ui.out("    " + t("install.next1", cmd=ui.accent("autopilot")))
    ui.out("    " + t("install.next2", cmd=ui.accent("autopilot user add имя")))
    ui.out("    " + t("install.next3", cmd=ui.accent("autopilot status")))
    ui.out()
