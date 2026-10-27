"""Точка входа: autopilot [команда]. Без команды в терминале открывается меню."""
from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Sequence

from . import __version__, core, i18n, ui
from .i18n import t


def _api():
    from .panel import PanelClient

    return PanelClient.from_install()


def _api_or_none():
    try:
        return _api()
    except core.Error:
        return None


# --- экраны ---------------------------------------------------------------------------------------

def user_rows(clients: list[dict]) -> list[list[str]]:
    now = time.time() * 1000
    rows = []
    for c in sorted(clients, key=lambda x: str(x.get("email"))):
        traffic = c.get("traffic") or {}
        used = int(traffic.get("up", 0)) + int(traffic.get("down", 0))
        total = int(c.get("totalGB") or 0)
        usage = core.human_bytes(used) + (" / " + core.human_bytes(total) if total else "")
        exp = int(c.get("expiryTime") or 0)
        till = t("forever") if not exp else datetime.fromtimestamp(exp / 1000).strftime("%d.%m.%Y")
        if not c.get("enable", True):
            state = ui.dim(t("state.off"))
        elif exp and exp < now:
            state = ui.warn_c(t("state.expired"))
        elif total and used >= total:
            state = ui.warn_c(t("state.limit"))
        else:
            state = ui.good(t("state.active"))
        rows.append([str(c.get("email")), usage, till, state])
    return rows


def show_users(api) -> None:
    ui.table([t("col.user"), t("col.traffic"), t("col.until"), t("col.state")], user_rows(api.clients()))


def show_links(api, name: str) -> None:
    from . import subscription

    host = _api_host()
    if host:
        urls = subscription.user_urls(api, host, name)
        ui.out()
        ui.out("  " + ui.bold(t("install.sub")))
        ui.out("  " + ui.accent(urls["auto"]))
        ui.out()
        if ui.qr(urls["auto"]):
            ui.hint(t("install.scan"))
        ui.out()
        ui.out("  " + ui.bold(t("install.page")))
        ui.out("  " + ui.accent(subscription.page_url(urls["auto"])))
        ui.out()
        ui.out("  " + ui.bold(t("links.router")))
        ui.out("  Nikki, OpenClash: " + urls["clash"])
        ui.out("  PassWall 2: " + urls["auto"])
    links = api.client_links(name)
    try:
        from . import mieru

        mieru_link = mieru.link_for(name, host) if host else None
    except core.Error:
        mieru_link = None
    if mieru_link:
        links.append(mieru_link)
    if links:
        ui.out()
        ui.out("  " + ui.bold(t("links.single")))
        for link in links:
            ui.out("  " + link)


def _mieru_user_added(name: str) -> None:
    try:
        from . import mieru

        mieru.user_added(name)
    except core.Error as exc:  # Mieru – дополнение: сбой не должен мешать создать пользователя
        ui.warn(t("mieru.user.fail", reason=str(exc)[:100]))


def _mieru_user_removed(name: str) -> None:
    try:
        from . import mieru

        mieru.user_removed(name)
    except core.Error as exc:
        ui.warn(t("mieru.user.fail", reason=str(exc)[:100]))


def show_status() -> int:
    from . import status

    checks = status.collect(_api_or_none())
    group = None
    for item in checks:
        if item.group != group:
            group = item.group
            ui.out()
            ui.out("  " + ui.bold(group))
        {"ok": ui.ok, "warn": ui.warn, "bad": ui.fail}.get(item.level, ui.fail)(item.text)
    ui.out()
    return status.exit_code(checks)


def show_stats(as_json: bool = False) -> None:
    from . import status

    api = _api()
    if as_json:
        print(status.to_json(api))
        return
    ui.out()
    for line in status.stats_table(api).splitlines():
        ui.out("  " + line)
    ui.out()


# --- команды --------------------------------------------------------------------------------------

def cmd_install(args: argparse.Namespace) -> None:
    from . import installer

    installer.install(host=args.host, sni=args.sni, xhttp_sni=args.xhttp_sni, mtproto_sni=args.mtproto_sni, no_ufw=args.no_ufw)


def cmd_user(args: argparse.Namespace) -> None:
    from . import inbounds

    api = _api()
    if args.action == "add":
        client = inbounds.add_user(api, args.name, gb=args.gb, days=args.days, devices=args.devices)
        _mieru_user_added(client["email"])
        ui.ok(t("users.created", name=client["email"]))
        show_links(api, client["email"])
    elif args.action == "list":
        ui.out()
        show_users(api)
        ui.out()
    elif args.action == "link":
        show_links(api, inbounds.valid_name(args.name))
    elif args.action == "del":
        inbounds.valid_name(args.name)
        api.del_client(args.name)
        _mieru_user_removed(args.name)
        ui.ok(args.name)
    elif args.action in ("on", "off"):
        api.set_client_fields(args.name, enable=args.action == "on")
        ui.ok(args.name)


def cmd_notify(args: argparse.Namespace) -> None:
    from . import notify, units

    if args.action == "setup":
        ui.out("  " + t("notify.intro"))
        token = ui.ask_secret(t("notify.token"))
        chat = ui.ask(t("notify.chat"))
        notify.configure(token, chat)
        units.install_watch_timer()
        ui.ok(t("notify.on"))
    elif args.action == "test":
        if not notify.send_message("Autopilot: проверка связи / connection test"):
            core.die(t("notify.fail"))
        ui.ok(t("notify.sent"))
    elif args.action == "off":
        notify.disable()
        ui.ok(t("notify.off"))
    else:
        ui.info(notify.status_text())


def cmd_backup(args: argparse.Namespace) -> None:
    from . import backup

    if args.action == "auto":
        if args.mode == "on":
            backup.auto_enable(args.keep)
            ui.ok(t("backup.auto.on", keep=args.keep))
            ui.warn(t("backup.key.warn"))
        elif args.mode == "off":
            backup.auto_disable()
            ui.ok(t("backup.auto.off"))
        elif args.mode == "key":
            print(backup.auto_key())
        else:
            ui.info(backup.auto_status())
    elif args.action == "decrypt":
        if not args.file:
            core.die("autopilot backup decrypt файл.enc")
        out = Path(args.file[:-4] if args.file.endswith(".enc") else args.file + ".dec")
        backup.decrypt_file(Path(args.file), out, ui.ask_secret(t("backup.pass")))
        ui.ok(str(out))
    elif args.auto:
        backup.auto_run()
    else:
        passphrase = None
        if args.encrypt:
            passphrase = ui.ask_secret(t("backup.pass.new"))
            if len(passphrase) < 8 or passphrase != ui.ask_secret(t("backup.pass.again")):
                core.die(t("backup.pass.bad"))
        path = backup.create(passphrase=passphrase)
        ui.ok(t("backup.created", path=path))
        ui.hint(t("backup.scp", host=(_api_host() or "SERVER"), path=path))


def _api_host() -> str | None:
    try:
        import json

        return json.loads(core.path(core.CONF_DIR, "install.json").read_text(encoding="utf-8")).get("host")
    except (OSError, ValueError):
        return None


def cmd_harden(args: argparse.Namespace) -> None:
    from . import harden

    if args.undo:
        harden.undo_ssh()
        ui.ok(t("ssh.undone"))
        return
    confirm = None
    if not args.yes and not args.dry_run:
        def confirm() -> bool:  # noqa: E306
            ui.warn(t("ssh.confirm.warn"))
            return ui.confirm(t("ssh.confirm"), False)
    ui.ok(harden.harden_ssh(dry_run=args.dry_run, confirm=confirm))


def cmd_router(args: argparse.Namespace) -> None:
    from . import inbounds, router, subscription

    app = args.app
    if app is None:
        app = ui.menu(t("router.pick"), [("nikki", "Nikki", t("router.d.nikki")), ("openclash", "OpenClash", t("router.d.openclash")),
                                         ("passwall2", "PassWall 2", t("router.d.passwall2"))], back=t("back"))
        if app is None:
            return
    api = _api()
    host = _api_host() or core.die("Установка не найдена.")
    urls = subscription.user_urls(api, host, inbounds.valid_name(args.user))
    cmd = router.command(app, router.publish(), urls, i18n.language())
    ui.out()
    ui.out("  " + t("router.run"))
    ui.out()
    ui.out("  " + ui.bold(ui.accent(cmd)))
    ui.out()
    ui.hint(t("router.note"))
    if app == "passwall2":
        ui.warn(t("router.pw2"))


def cmd_check(args: argparse.Namespace) -> int:
    from . import checks

    api = _api_or_none()
    host = _api_host()
    problems = checks.run_checks(api, host=host)
    marks = {"ok": ui.ok, "warn": ui.warn, "bad": ui.fail}
    ui.out()
    for p in problems:
        marks.get(p.level, ui.fail)(p.text + ("  " + ui.dim("(" + t("check.fixable") + ")") if p.fixable and p.level != "ok" else ""))
    fixable = [p for p in problems if p.fixable and p.level != "ok"]
    if args.fix and fixable and host:
        ui.out()
        for line in checks.apply_fixes(fixable, api, host=host):
            ui.info(line)
        problems = checks.run_checks(api, host=host)
        ui.out()
        ui.out("  " + ui.bold(t("check.after")))
        for p in problems:
            if p.level != "ok":
                marks.get(p.level, ui.fail)(p.text)
    ok, warn_n, bad = checks.summary(problems)
    ui.out()
    ui.out("  " + t("check.summary", ok=ok, warn=warn_n, bad=bad))
    if fixable and not args.fix:
        ui.hint(t("check.fixhint"))
    ui.out()
    return 1 if bad else 0


def cmd_update(args: argparse.Namespace) -> None:
    from . import installer, updater

    info = updater.plan()
    if info["from"] is None:
        core.die("Установка не найдена.", "Сначала выполните: autopilot install")
    if not info["needs"]:
        ui.ok(t("update.current", version=info["to"]))
        return
    ui.info(t("update.plan", old=info["from"], new=info["to"]))
    if args.check:
        return
    if not args.yes and not ui.confirm(t("update.confirm"), False):
        ui.out("  " + t("cancel"))
        return
    arch = installer.normalize_arch(__import__("platform").machine())
    with ui.Step(t("update.running")):
        result = updater.upgrade(_api, arch=arch, backup_first=not args.no_backup)
    if result.get("rolled_back"):
        core.die(t("update.rolled_back", reason=result.get("error", "?")), t("update.rolled_back.hint", path=result.get("backup") or "-"))
    ui.ok(t("update.done", version=result["to"]))
    if result.get("backup"):
        ui.hint(t("update.backup", path=result["backup"]))


def cmd_net(args: argparse.Namespace) -> None:
    from . import cert, installer, net, sync

    api = _api()
    if args.action == "site":
        if not args.name or not args.value:
            core.die("autopilot net site reality|xhttp|mtproto сайт")
        with ui.Step(t("net.changing")):
            old = net.set_site(api, args.name, args.value)
            fullchain, key = cert.paths()
            sync.apply(api, str(fullchain), str(key))
            state = _state()
            snis = dict(state.get("snis") or {})
            snis[args.name] = args.value.strip().lower()
            installer.update_state(snis=snis)
        ui.ok(t("net.site.done", old=old, new=args.value))
        ui.hint(t("net.links.hint"))
    elif args.action == "port":
        if not args.name or not args.value or not str(args.value).isdigit():
            core.die("autopilot net port shadowsocks|hysteria2|tuic|amneziawg|amneziawg-3.1 порт")
        with ui.Step(t("net.changing")):
            old = net.set_port(api, args.name, int(args.value))
            ports = dict(_state().get("ports") or {})
            ports[args.name] = int(args.value)
            installer.update_state(ports=ports)
        ui.ok(t("net.port.done", old=old, new=args.value))
        ui.hint(t("net.links.hint"))
    else:
        ui.out()
        ui.table([t("net.col.name"), t("net.col.public"), t("net.col.site")],
                 [[str(r["remark"]), r["public"], r["site"] or "–"] for r in net.overview(api)])
        ui.out()


def _state() -> dict:
    import json

    try:
        return json.loads(core.path(core.CONF_DIR, "install.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def cmd_mieru(args: argparse.Namespace) -> None:
    from . import installer, mieru

    if args.action == "enable":
        api = _api()
        names = sorted({str(c.get("email")) for c in api.clients() if c.get("email")})
        arch = installer.normalize_arch(__import__("platform").machine())
        with ui.Step(t("mieru.enabling")):
            config = mieru.enable(arch, names, port=args.port)
        ui.ok(t("mieru.on", ports=", ".join("%s/%s" % p for p in mieru.ports(config))))
        ui.hint(t("mieru.note"))
    elif args.action == "disable":
        mieru.disable()
        ui.ok(t("mieru.off"))
    else:
        if not mieru.enabled():
            ui.info(t("mieru.status.off"))
            return
        state = mieru.load_state()
        ui.info(t("mieru.status.on", users=len(state.get("users", {})), ports=", ".join("%s/%s" % p for p in mieru.ports())))


def cmd_restore(args: argparse.Namespace) -> None:
    from . import installer, restore

    path = Path(args.file)
    passphrase = ui.ask_secret(t("backup.pass")) if path.name.endswith(".enc") else None
    with restore.open_backup(path, passphrase, panel_version=installer.PANEL_VERSION) as bundle:
        for note in bundle.warnings:
            ui.warn(note)
        installer.install(host=args.host, no_ufw=args.no_ufw, restore=bundle)


def cmd_uninstall(args: argparse.Namespace) -> None:
    from datetime import datetime

    from . import backup, uninstaller

    items = uninstaller.targets()
    if not items:
        ui.info(t("uninstall.nothing"))
        return
    ui.out()
    ui.box(t("uninstall.title"), [t("uninstall.what"), "", *["  " + str(p) for p in items[:12]],
                                  *(["  …"] if len(items) > 12 else []), "", t("uninstall.keeps")], kind="warn")
    if args.dry_run:
        for action in uninstaller.remove(dry_run=True):
            ui.hint(action)
        return
    if not args.yes and not ui.confirm(t("uninstall.confirm"), False):
        ui.out("  " + t("cancel"))
        return
    if not args.no_backup and core.path("etc/x-ui/x-ui.db").exists():
        out = Path(core.path("root")) / ("autopilot-backup-%s.tar.gz" % datetime.now().strftime("%Y%m%d-%H%M%S"))
        backup.create(out_dir=out.parent, name_prefix=out.name[:-len(".tar.gz")])
        ui.ok(t("uninstall.backup", dir=out.parent))
    uninstaller.remove()
    ui.ok(t("uninstall.done"))
    for path in uninstaller.kept():
        ui.hint(t("uninstall.kept", path=path))


def cmd_cert(args: argparse.Namespace) -> None:
    from . import cert

    if args.action == "reload":
        cert.reload_services()
    elif args.action == "auto":
        host = _api_host()
        if host and cert.ensure(host):
            ui.ok(t("cert.done"))
    elif args.action == "renew":
        host = _api_host() or core.die("Установка не найдена.")
        with ui.Step(t("cert.renewing")):
            cert.renew(host)
            cert.enable_renewal()
            cert.reload_services()
        ui.ok(t("cert.done"))
    else:
        days = cert.days_left()
        ui.info(t("cert.none") if days is None else t("cert.days", days=days))


def cmd_watch(args: argparse.Namespace) -> None:
    from . import notify, status

    api = _api_or_none()
    if api is not None:
        status.snapshot(api)
        notify.check(api)


def cmd_lang(args: argparse.Namespace) -> None:
    if args.code not in i18n.CATALOGS:
        core.die(t("err.lang"))
    i18n.save_language(args.code)
    ui.ok(t("lang.set"))


# --- меню -----------------------------------------------------------------------------------------

def menu_main() -> None:
    while True:
        ui.out()
        choice = ui.menu(t("menu.title", version=__version__), [
            ("users", t("menu.users"), t("menu.users.d")),
            ("status", t("menu.status"), t("menu.status.d")),
            ("stats", t("menu.stats"), t("menu.stats.d")),
            ("notify", t("menu.notify"), t("menu.notify.d")),
            ("backup", t("menu.backup"), t("menu.backup.d")),
            ("router", t("menu.router"), t("menu.router.d")),
            ("ssh", t("menu.ssh"), t("menu.ssh.d")),
            ("lang", t("menu.lang"), t("menu.lang.d")),
        ], back=t("exit"))
        if choice is None:
            return
        try:
            {"users": menu_users, "status": show_status, "stats": show_stats, "notify": menu_notify,
             "backup": menu_backup, "router": lambda: cmd_router(argparse.Namespace(app=None, user="admin")),
             "ssh": menu_ssh, "lang": menu_lang}[choice]()
        except core.Error as exc:
            ui.error(str(exc), exc.hint)
        if choice in ("status", "stats"):
            ui.ask("Enter", "")


def menu_users() -> None:
    from . import inbounds

    api = _api()
    while True:
        ui.out()
        action = ui.menu(t("users.title"), [
            ("add", t("users.add"), ""), ("list", t("users.list"), ""), ("links", t("users.links"), ""),
            ("off", t("users.off"), ""), ("on", t("users.on"), ""), ("del", t("users.del"), ""),
        ], back=t("back"))
        if action is None:
            return
        try:
            if action == "add":
                name = ui.ask(t("users.name"))
                gb = int(ui.ask(t("users.gb"), "0") or 0)
                days = int(ui.ask(t("users.days"), "0") or 0)
                client = inbounds.add_user(api, name, gb=gb, days=days)
                ui.ok(t("users.created", name=client["email"]))
                show_links(api, client["email"])
            elif action == "list":
                ui.out()
                show_users(api)
            else:
                name = _pick_user(api)
                if name is None:
                    continue
                if action == "links":
                    show_links(api, name)
                elif action == "del":
                    if ui.confirm("%s %s?" % (t("users.del"), name), False):
                        api.del_client(name)
                        ui.ok(name)
                else:
                    api.set_client_fields(name, enable=action == "on")
                    ui.ok(name)
        except ValueError:
            ui.error("0–999999", None)
        except core.Error as exc:
            ui.error(str(exc), exc.hint)
        ui.ask("Enter", "")


def _pick_user(api) -> str | None:
    names = sorted(str(c.get("email")) for c in api.clients())
    return ui.menu(t("users.pick"), [(n, n, "") for n in names], back=t("back")) if names else None


def menu_notify() -> None:
    choice = ui.menu(t("menu.notify"), [("setup", t("notify.setup"), ""), ("test", t("notify.test"), ""),
                                         ("off", t("notify.disable"), ""), ("status", t("notify.status"), "")], back=t("back"))
    if choice:
        cmd_notify(argparse.Namespace(action=choice))
        ui.ask("Enter", "")


def menu_backup() -> None:
    choice = ui.menu(t("menu.backup"), [("now", t("backup.now"), ""), ("enc", t("backup.enc"), ""),
                                         ("auto_on", t("backup.auto_on"), ""), ("auto_off", t("backup.auto_off"), ""),
                                         ("auto_key", t("backup.auto_key"), "")], back=t("back"))
    ns = argparse.Namespace(action=None, mode="status", file=None, encrypt=False, auto=False, keep=7)
    if choice == "enc":
        ns.encrypt = True
    elif choice and choice.startswith("auto_"):
        ns.action, ns.mode = "auto", choice[5:]
    elif choice != "now":
        return
    cmd_backup(ns)
    ui.ask("Enter", "")


def menu_ssh() -> None:
    choice = ui.menu(t("menu.ssh"), [("on", t("ssh.on"), ""), ("off", t("ssh.off"), "")], back=t("back"))
    if choice:
        cmd_harden(argparse.Namespace(undo=choice == "off", yes=False, dry_run=False))
        ui.ask("Enter", "")


def menu_lang() -> None:
    choice = ui.menu(t("menu.lang"), [("ru", "Русский", ""), ("en", "English", "")], back=t("back"))
    if choice:
        i18n.save_language(choice)
        ui.ok(t("lang.set"))


# --- разбор аргументов -----------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="autopilot", description="3X-UI Autopilot %s" % __version__)
    p.add_argument("--version", action="version", version="3X-UI Autopilot " + __version__)
    p.add_argument("--lang", choices=sorted(i18n.CATALOGS), help="language / язык")
    sub = p.add_subparsers(dest="cmd")

    i = sub.add_parser("install", help="install the server / установить сервер")
    i.add_argument("--host", help="public IPv4 of this server")
    i.add_argument("--sni", help="cover site for REALITY (TLS 1.3 + HTTP/2)")
    i.add_argument("--xhttp-sni", help="cover site for XHTTP")
    i.add_argument("--mtproto-sni", help="cover site (fake TLS) for MTProto")
    i.add_argument("--no-ufw", action="store_true")
    i.set_defaults(func=cmd_install)

    u = sub.add_parser("user", help="users / пользователи")
    us = u.add_subparsers(dest="action", required=True)
    add = us.add_parser("add")
    add.add_argument("name")
    add.add_argument("--gb", type=int, default=0)
    add.add_argument("--days", type=int, default=0)
    add.add_argument("--devices", type=int, default=0)
    us.add_parser("list")
    for name in ("link", "del", "on", "off"):
        us.add_parser(name).add_argument("name")
    u.set_defaults(func=cmd_user)

    sub.add_parser("status", help="server health / состояние").set_defaults(func=lambda a: show_status())
    st = sub.add_parser("stats", help="traffic / трафик")
    st.add_argument("--json", action="store_true")
    st.set_defaults(func=lambda a: show_stats(a.json))

    n = sub.add_parser("notify", help="Telegram notifications / уведомления")
    n.add_argument("action", choices=["setup", "test", "off", "status"], nargs="?", default="status")
    n.set_defaults(func=cmd_notify)

    b = sub.add_parser("backup", help="backups / резервные копии")
    b.add_argument("action", nargs="?", choices=["auto", "decrypt"])
    b.add_argument("mode", nargs="?", choices=["on", "off", "key", "status"], default="status")
    b.add_argument("file", nargs="?")
    b.add_argument("--encrypt", action="store_true")
    b.add_argument("--auto", action="store_true", help=argparse.SUPPRESS)
    b.add_argument("--keep", type=int, default=7)
    b.set_defaults(func=cmd_backup)

    h = sub.add_parser("harden", help="SSH protection / защита SSH")
    h.add_argument("what", choices=["ssh"])
    h.add_argument("--dry-run", action="store_true")
    h.add_argument("--undo", action="store_true")
    h.add_argument("--yes", "-y", action="store_true")
    h.set_defaults(func=cmd_harden)

    ck = sub.add_parser("check", help="deep server check / глубокая проверка сервера")
    ck.add_argument("--fix", action="store_true", help="repair what is safe to repair")
    ck.set_defaults(func=cmd_check)

    up = sub.add_parser("update", help="update the panel to the pinned version / обновить панель")
    up.add_argument("--check", action="store_true", help="only show what would change")
    up.add_argument("--yes", "-y", action="store_true")
    up.add_argument("--no-backup", action="store_true")
    up.set_defaults(func=cmd_update)

    nt = sub.add_parser("net", help="ports and cover sites / порты и сайты-прикрытия")
    nt.add_argument("action", choices=["show", "site", "port"], nargs="?", default="show")
    nt.add_argument("name", nargs="?")
    nt.add_argument("value", nargs="?")
    nt.set_defaults(func=cmd_net)

    mi = sub.add_parser("mieru", help="Mieru service / служба Mieru")
    mi.add_argument("action", choices=["enable", "disable", "status"], nargs="?", default="status")
    mi.add_argument("--port", type=int, help="port for a new mita config (1025-65535)")
    mi.set_defaults(func=cmd_mieru)

    rs = sub.add_parser("restore", help="restore from a backup / восстановить из копии (на чистом сервере)")
    rs.add_argument("file")
    rs.add_argument("--host", help="public IPv4 of this server")
    rs.add_argument("--no-ufw", action="store_true")
    rs.set_defaults(func=cmd_restore)

    un = sub.add_parser("uninstall", help="remove everything / полностью удалить")
    un.add_argument("--yes", "-y", action="store_true")
    un.add_argument("--no-backup", action="store_true")
    un.add_argument("--dry-run", action="store_true")
    un.set_defaults(func=cmd_uninstall)

    r = sub.add_parser("router", help="OpenWrt router install / автоустановка на роутер")
    r.add_argument("app", nargs="?", choices=["nikki", "openclash", "passwall2"])
    r.add_argument("--user", default="admin", help="whose subscription to use (default admin)")
    r.set_defaults(func=cmd_router)

    c = sub.add_parser("cert", help="certificate / сертификат")
    c.add_argument("action", choices=["status", "renew", "reload", "auto"], nargs="?", default="status")
    c.set_defaults(func=cmd_cert)

    lg = sub.add_parser("lang", help="language / язык")
    lg.add_argument("code")
    lg.set_defaults(func=cmd_lang)

    sub.add_parser("watch", help=argparse.SUPPRESS).set_defaults(func=cmd_watch)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.lang:
        i18n.set_language(args.lang)
    try:
        if args.cmd is None:
            if ui.interactive():
                ui.banner()
                menu_main()
                return 0
            parser.print_help()
            return 0
        result = args.func(args)
    except core.Error as exc:
        ui.error(str(exc), exc.hint)
        return 1
    except KeyboardInterrupt:
        ui.out("\n" + t("cancel"))
        return 130
    except BrokenPipeError:  # вывод передали в head/less и закрыли: это не ошибка
        try:
            sys.stdout = open("/dev/null", "w")
        except OSError:
            pass
        return 0
    return result if isinstance(result, int) else 0


if __name__ == "__main__":
    sys.exit(main())
