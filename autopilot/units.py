"""systemd-юниты Autopilot: периодическая проверка (уведомления и снимки трафика)."""
from __future__ import annotations

from . import core

WATCH_SERVICE = """[Unit]
Description=3X-UI Autopilot: проверка состояния, снимок трафика, уведомления
After=x-ui.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/autopilot watch
TimeoutStartSec=120
"""

WATCH_TIMER = """[Unit]
Description=3X-UI Autopilot: проверка раз в 10 минут

[Timer]
OnBootSec=3min
OnUnitActiveSec=10min
AccuracySec=30s

[Install]
WantedBy=timers.target
"""


def install_watch_timer() -> None:
    base = core.path("etc/systemd/system")
    core.write_file(base / "autopilot-watch.service", WATCH_SERVICE)
    core.write_file(base / "autopilot-watch.timer", WATCH_TIMER)
    core.systemctl("daemon-reload")
    core.systemctl("enable", "--now", "autopilot-watch.timer")
