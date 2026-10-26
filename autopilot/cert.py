"""Сертификат Let's Encrypt на IP-адрес сервера (короткоживущий профиль) через acme.sh с закреплённой версией."""
from __future__ import annotations

import ipaddress
import urllib.request
from pathlib import Path

from . import core, installer

ACME_COMMIT = "807da6498377ee5e0cf43a78091f46f12dc59a89"
ACME_SHA256 = "c7d68b021cfd6380ea83a82962abde5b484779fee0b97d38681dfa1396bbc8d7"
ACME_URL = "https://raw.githubusercontent.com/acmesh-official/acme.sh/%s/acme.sh" % ACME_COMMIT
ACME_BIN = "usr/local/lib/autopilot-acme/acme.sh"
ACME_HOME = "var/lib/autopilot-acme"
CERT_DIR = "etc/autopilot/certs/ip"
RELOAD_COMMAND = "/usr/local/bin/autopilot cert reload"

TIMER = """[Unit]
Description=3X-UI Autopilot: продление сертификата (раз в 12 часов, срок жизни сертификата на IP около 6 суток)

[Timer]
OnBootSec=10min
OnUnitActiveSec=12h
RandomizedDelaySec=20min
Persistent=true

[Install]
WantedBy=timers.target
"""

SERVICE = """[Unit]
Description=3X-UI Autopilot: продление сертификата
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Environment=ACME_PACKAGED=1
ExecStart=/usr/local/bin/autopilot cert auto
UMask=0077
"""


def paths() -> tuple[Path, Path]:
    return core.path(CERT_DIR, "fullchain.pem"), core.path(CERT_DIR, "privkey.pem")


def issue_command(ip: str) -> list[str]:
    """Команда выпуска. Адрес проверяется как IPv4: он попадает в аргументы acme.sh."""
    try:
        address = ipaddress.IPv4Address(ip)
    except ValueError:
        core.die("Сертификат выпускается только на IPv4-адрес.")
        raise
    return ["/bin/sh", str(core.path(ACME_BIN)), "--home", str(core.path(ACME_HOME)), "--issue",
            "--server", "letsencrypt", "--certificate-profile", "shortlived", "--days", "3",
            "--standalone", "--listen-v4", "--httpport", "80", "--keylength", "ec-256", "-d", str(address)]


def install_command(ip: str) -> list[str]:
    fullchain, key = paths()
    return ["/bin/sh", str(core.path(ACME_BIN)), "--home", str(core.path(ACME_HOME)), "--install-cert", "--ecc", "-d", ip,
            "--key-file", str(key), "--fullchain-file", str(fullchain), "--reloadcmd", RELOAD_COMMAND]


def fetch_acme(*, opener=None) -> None:
    target = core.path(ACME_BIN)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(".download")
    installer.download(ACME_URL, tmp, ACME_SHA256, opener=opener)
    tmp.chmod(0o755)
    tmp.replace(target)
    home = core.path(ACME_HOME)
    home.mkdir(parents=True, exist_ok=True)
    core.write_file(home / "account.conf", "AUTO_UPGRADE='0'\nNOTIFY_LEVEL='0'\n", 0o600)


def issue(ip: str) -> None:
    """Выпуск и установка. Код 2 у acme.sh значит «сертификат ещё свежий, пропускаю» (повторный запуск) – это не ошибка."""
    fetch_acme()
    core.path(CERT_DIR).mkdir(parents=True, exist_ok=True)
    done = core.run(issue_command(ip), check=False, env={"ACME_PACKAGED": "1"})
    if done.returncode not in (0, 2):
        tail = (done.stderr or done.stdout).strip().splitlines()[-2:]
        core.die("Не удалось получить сертификат (нужен свободный входящий 80/TCP): %s" % " | ".join(tail))
    _install_files(ip)


RENEW_BEFORE_DAYS = 3


def ensure(ip: str) -> bool:
    """Для таймера: если сертификата нет или он живёт меньше RENEW_BEFORE_DAYS суток – выпустить новый и перечитать службы.
    Работает и после восстановления из копии, когда у acme.sh нет записи о сертификате. True – что-то сделано."""
    days = days_left()
    if days is not None and days >= RENEW_BEFORE_DAYS:
        return False
    issue(ip)
    reload_services()
    return True


def reusable(cert_dir: Path, ip: str) -> bool:
    """Сертификат из резервной копии годится, если он на этот IP и проживёт ещё хотя бы RENEW_BEFORE_DAYS суток."""
    fullchain, key = cert_dir / "fullchain.pem", cert_dir / "privkey.pem"
    if not fullchain.is_file() or not key.is_file() or fullchain.stat().st_size == 0 or key.stat().st_size == 0:
        return False
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    alive = core.run(["openssl", "x509", "-in", str(fullchain), "-noout", "-checkend", str(RENEW_BEFORE_DAYS * 86400)], check=False)
    match = core.run(["openssl", "x509", "-in", str(fullchain), "-noout", "-checkip", ip], check=False)
    return alive.returncode == 0 and "does match" in (match.stdout or "")


def reuse(cert_dir: Path) -> None:
    """Кладёт сертификат из копии на место (права ключа 0600)."""
    fullchain, key = paths()
    fullchain.parent.mkdir(parents=True, exist_ok=True)
    core.write_file(fullchain, (cert_dir / "fullchain.pem").read_bytes(), 0o644)
    core.write_file(key, (cert_dir / "privkey.pem").read_bytes(), 0o600)


def _install_files(ip: str) -> None:
    """Копирует выпущенный сертификат на место. Сбой хука перезагрузки (команды ещё может не быть) не считается провалом,
    если сами файлы установлены: службы подхватят их при следующей перезагрузке."""
    done = core.run(install_command(ip), check=False, env={"ACME_PACKAGED": "1"})
    fullchain, key = paths()
    if not fullchain.is_file() or not key.is_file() or fullchain.stat().st_size == 0 or key.stat().st_size == 0:
        tail = (done.stderr or done.stdout).strip().splitlines()[-2:]
        core.die("Сертификат не установился: %s" % " | ".join(tail))
    key.chmod(0o600)


def enable_renewal() -> None:
    base = core.path("etc/systemd/system")
    core.write_file(base / "autopilot-cert.service", SERVICE)
    core.write_file(base / "autopilot-cert.timer", TIMER)
    core.systemctl("daemon-reload")
    core.systemctl("enable", "--now", "autopilot-cert.timer")


def days_left(cert_file: Path | None = None) -> int | None:
    """Сколько полных суток осталось у сертификата (None, если файла нет или он нечитаем)."""
    import datetime
    import re

    cert_file = cert_file or paths()[0]
    if not cert_file.is_file():
        return None
    out = core.run(["openssl", "x509", "-noout", "-enddate", "-in", str(cert_file)], check=False).stdout
    match = re.search(r"notAfter=(.+)", out)
    if not match:
        return None
    try:
        end = datetime.datetime.strptime(match.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return None
    return int((end - datetime.datetime.utcnow()).total_seconds() // 86400)


def self_signed(ip: str, days: int = 3650) -> None:
    """Запасной сертификат на IP, если Let's Encrypt недоступен (закрыт порт 80 и т. п.). Клиентам Hysteria2 и TUIC придётся
    разрешить небезопасное соединение или закрепить сертификат."""
    try:
        address = str(ipaddress.IPv4Address(ip))
    except ValueError:
        core.die("Сертификат выпускается только на IPv4-адрес.")
        raise
    fullchain, key = paths()
    fullchain.parent.mkdir(parents=True, exist_ok=True)
    core.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
              "-days", str(days), "-subj", "/CN=" + address, "-addext", "subjectAltName=IP:" + address,
              "-keyout", str(key), "-out", str(fullchain)])
    key.chmod(0o600)


def reload_services() -> None:
    """После продления: nginx перечитывает сертификат на лету, а Hysteria2 и TUIC читают его только при старте панели."""
    if core.unit_exists("autopilot-nginx"):
        core.systemctl("reload", "autopilot-nginx", check=True)
    core.systemctl("restart", "x-ui", check=True)


def renew(ip: str) -> None:
    """Принудительный выпуск заново (например, после того как открыли порт 80)."""
    fetch_acme()
    core.path(CERT_DIR).mkdir(parents=True, exist_ok=True)
    done = core.run(issue_command(ip) + ["--force"], check=False, env={"ACME_PACKAGED": "1"})
    if done.returncode != 0:
        tail = (done.stderr or done.stdout).strip().splitlines()[-2:]
        core.die("Не удалось получить сертификат (нужен свободный входящий 80/TCP): %s" % " | ".join(tail),
                 "Проверьте, что порт 80/TCP открыт у хостера и в ufw, и повторите: autopilot cert renew")
    _install_files(ip)
