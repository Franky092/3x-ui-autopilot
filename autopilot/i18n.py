"""Переводы интерфейса (русский и английский). Язык: AUTOPILOT_LANG, затем язык системы, по умолчанию русский.

Тексты интерфейса берутся по ключу: t("install.step.panel"). Нет перевода на английский – показывается русский,
нет ключа – показывается сам ключ (так пропуск виден сразу, а не прячется).
"""
from __future__ import annotations

import os

RU: dict[str, str] = {
    "app.tagline": "VPN-сервер за пару минут",
    "yes": "да", "no": "нет", "back": "Назад", "exit": "Выход", "cancel": "Отменено.",
    "hint.menu": "↑↓ выбор · Enter открыть · цифра – быстрый переход · q выход",
    "what.next": "Что дальше",
    "error": "Ошибка", "todo": "Что делать",

    "install.title": "Установка сервера",
    "install.check": "Проверяю сервер",
    "install.sni": "Подбираю сайт-прикрытие для REALITY",
    "install.packages": "Ставлю пакеты",
    "install.panel": "Ставлю панель 3X-UI %(version)s",
    "install.inbounds": "Создаю подключения",
    "install.user": "Создаю первого пользователя",
    "install.firewall": "Настраиваю защиту (ufw, fail2ban)",
    "install.cert": "Получаю сертификат на IP",
    "install.dns": "Настраиваю собственный DNS",
    "install.dns.fail": "Собственный DNS не поднялся (%(reason)s). AmneziaWG пока использует публичный DNS 1.1.1.1; повторите позже: autopilot status",
    "install.restore.inbounds": "Восстанавливаю подключения и пользователей",
    "install.web": "Настраиваю nginx на 443",
    "install.selfsigned": "Сертификат самоподписанный: Hysteria2 и TUIC потребуют отключить проверку сертификата в клиенте. Откройте порт 80 и выполните: autopilot cert renew",
    "install.cli": "Устанавливаю команду autopilot",
    "install.done": "Готово! Сервер установлен",
    "install.found": "Сервер: %(host)s · %(os)s · %(arch)s",
    "install.sni.picked": "Сайт-прикрытие: %(sni)s",
    "install.root": "Запустите от root: sudo -i, затем команду ещё раз.",
    "install.creds": "Данные для входа и ссылки сохранены в %(file)s (виден только root)",
    "install.tunnel": "Панель закрыта от интернета. Чтобы открыть её, на своём компьютере выполните:",
    "install.scan": "Отсканируйте QR-код в приложении (Happ, Hiddify, v2rayN, Streisand…) или вставьте ссылку:",
    "install.qr.long": "Ссылки слишком длинные для QR в терминале: показать их можно командой autopilot user link admin",
    "install.sub": "Ваша ссылка-подписка (одна на все приложения):",
    "install.page": "Страница с инструкцией для вашего устройства (ссылка уже подставлена):",
    "links.single": "Отдельные подключения (если приложение не умеет подписки):",
    "links.router": "Для роутера (OpenWrt):",
    "install.next1": "Управление сервером: введите %(cmd)s",
    "install.next2": "Добавить пользователя: %(cmd)s",
    "install.next3": "Состояние сервера: %(cmd)s",

    "menu.title": "3X-UI Autopilot %(version)s",
    "menu.users": "Пользователи", "menu.users.d": "добавить, ссылки, лимиты, отключить",
    "menu.status": "Состояние сервера", "menu.status.d": "службы, сертификат, диск, защита",
    "menu.stats": "Трафик", "menu.stats.d": "кто сколько использовал",
    "menu.notify": "Уведомления", "menu.notify.d": "сообщения в Telegram о проблемах",
    "menu.backup": "Резервные копии", "menu.backup.d": "сделать копию, расписание, шифрование",
    "menu.ssh": "Защита SSH", "menu.ssh.d": "вход только по ключу",
    "menu.lang": "Язык / Language", "menu.lang.d": "русский · English",

    "users.title": "Пользователи",
    "users.add": "Добавить пользователя", "users.list": "Список", "users.links": "Показать ссылки и QR",
    "users.off": "Выключить", "users.on": "Включить", "users.del": "Удалить",
    "users.name": "Имя (латиница, цифры, _ . -)", "users.gb": "Лимит трафика, ГБ (0 – без лимита)",
    "users.days": "Срок, дней (0 – бессрочно)", "users.created": "Пользователь %(name)s создан.",
    "users.pick": "Выберите пользователя",
    "col.user": "Пользователь", "col.traffic": "Трафик", "col.until": "До", "col.state": "Статус",
    "state.active": "активен", "state.off": "выключен", "state.expired": "истёк", "state.limit": "лимит",
    "forever": "бессрочно",

    "ask.confirm": "Продолжить?", "ask.yn": "[д/Н]",
    "err.lang": "Неизвестный язык. Доступно: ru, en.",
    "mieru.restore.fail": "Mieru не восстановлен (%(reason)s). Повторите: autopilot mieru enable",
    "check.fixable": "можно исправить", "check.after": "После исправления:", "check.summary": "Итого: в порядке %(ok)s, предупреждений %(warn)s, проблем %(bad)s.",
    "check.fixhint": "Безопасно исправить найденное: autopilot check --fix",
    "update.current": "Панель уже последней закреплённой версии (%(version)s).", "update.plan": "Панель 3X-UI: %(old)s → %(new)s.",
    "update.confirm": "Обновить? (сначала будет сделана резервная копия)", "update.running": "Обновляю панель",
    "update.rolled_back": "Обновление не удалось, прежняя версия возвращена: %(reason)s", "update.rolled_back.hint": "Копия перед обновлением: %(path)s",
    "update.done": "Панель обновлена до %(version)s.", "update.backup": "Копия перед обновлением: %(path)s",
    "net.changing": "Применяю изменения", "net.site.done": "Сайт-прикрытие: %(old)s → %(new)s.", "net.port.done": "Порт: %(old)s → %(new)s (правила ufw обновлены).",
    "net.links.hint": "Ссылки пользователей обновились сами; клиентам нужно обновить подписку.",
    "net.col.name": "Подключение", "net.col.public": "Порт снаружи", "net.col.site": "Сайт-прикрытие",
    "mieru.enabling": "Настраиваю Mieru", "mieru.on": "Mieru включён, порты: %(ports)s. Ссылки появятся в «autopilot user link имя».",
    "mieru.note": "Mieru – отдельная служба (mita), не часть панели. Если mita у вас уже была настроена, её порты и пользователи не тронуты.",
    "mieru.off": "Наши пользователи Mieru удалены. Служба mita и чужие настройки остались.",
    "mieru.status.off": "Mieru выключен. Включить: autopilot mieru enable", "mieru.status.on": "Mieru включён: пользователей %(users)s, порты %(ports)s.",
    "mieru.user.fail": "Mieru: пользователь не заведён (%(reason)s). Остальное создано.",
    "uninstall.nothing": "Autopilot не установлен: удалять нечего.", "uninstall.title": "Удаление Autopilot",
    "uninstall.what": "Будут остановлены службы и удалены файлы:", "uninstall.keeps": "Останутся: пакеты (nginx, fail2ban, ufw), ваш SSH, копии в /var/backups/autopilot.",
    "uninstall.confirm": "Удалить?", "uninstall.backup": "Перед удалением сделана копия в %(dir)s (ключи внутри, храните как пароль).",
    "uninstall.done": "Autopilot удалён.", "uninstall.kept": "Оставил: %(path)s",
    "menu.router": "Роутер (OpenWrt)", "menu.router.d": "автоустановка Nikki, OpenClash, PassWall 2",
    "router.pick": "Что ставим на роутер?", "router.run": "Выполните на роутере (по SSH: ssh root@192.168.1.1):",
    "router.note": "Скрипт сам определит opkg/apk, поставит приложение и пропишет подписку. Службу он НЕ запускает: трафик пойдёт через VPN только после «Запуск» в LuCI.",
    "router.pw2": "PassWall 2: автоустановка только для OpenWrt 25.12+ (apk); на opkg скрипт подскажет ручную установку.",
    "router.d.nikki": "Mihomo, OpenWrt 24.10+", "router.d.openclash": "Clash/Mihomo, самый популярный", "router.d.passwall2": "Xray/sing-box, 25.12+ (apk)",
    "cert.renewing": "Получаю сертификат заново", "cert.done": "Сертификат обновлён.", "cert.none": "Сертификат не найден.",
    "cert.days": "Сертификат действует ещё %(days)s дн.",
    "notify.intro": "Создайте бота у @BotFather и напишите ему любое сообщение. Сервер будет обращаться к api.telegram.org.",
    "notify.token": "Токен бота (ввод скрыт)", "notify.chat": "ID вашего чата (число, узнать у @userinfobot)",
    "notify.on": "Уведомления включены, проверка идёт раз в 10 минут.", "notify.off": "Уведомления выключены, токен удалён с сервера.",
    "notify.sent": "Сообщение отправлено.", "notify.fail": "Не удалось отправить сообщение.",
    "notify.setup": "Настроить", "notify.test": "Отправить проверочное сообщение", "notify.disable": "Выключить", "notify.status": "Состояние",
    "backup.now": "Сделать копию сейчас", "backup.enc": "Сделать копию с шифрованием", "backup.auto_on": "Включить автокопии",
    "backup.auto_off": "Выключить автокопии", "backup.auto_key": "Показать ключ автокопий",
    "backup.auto.on": "Автобэкап включён: каждый день около 04:30, хранится %(keep)s копий, все зашифрованы.",
    "backup.auto.off": "Автобэкап выключен. Уже сделанные копии и ключ остались на месте.",
    "backup.key.warn": "Сохраните ключ отдельно от копий (autopilot backup auto key): без него копии не открыть.",
    "backup.pass": "Пароль копии", "backup.pass.new": "Пароль для копии (не потеряйте: без него не восстановить)",
    "backup.pass.again": "Ещё раз", "backup.pass.bad": "Пароли не совпали или короче 8 символов.",
    "backup.created": "Резервная копия: %(path)s", "backup.scp": "Скачать к себе: scp root@%(host)s:%(path)s .",
    "ssh.on": "Выключить вход по паролю (только ключ)", "ssh.off": "Вернуть вход по паролю",
    "ssh.undone": "Ограничения SSH сняты.", "ssh.confirm.warn": "Не закрывайте это окно: откройте второе и убедитесь, что вход по ключу там работает.",
    "ssh.confirm": "Применить?",
    "lang.set": "Язык: русский",
}

EN: dict[str, str] = {
    "app.tagline": "your VPN server in minutes",
    "yes": "yes", "no": "no", "back": "Back", "exit": "Exit", "cancel": "Cancelled.",
    "hint.menu": "↑↓ choose · Enter open · number – jump · q quit",
    "what.next": "What's next",
    "error": "Error", "todo": "What to do",

    "install.title": "Server installation",
    "install.check": "Checking the server",
    "install.sni": "Choosing a cover site for REALITY",
    "install.packages": "Installing packages",
    "install.panel": "Installing the 3X-UI %(version)s panel",
    "install.inbounds": "Creating connections",
    "install.user": "Creating the first user",
    "install.firewall": "Setting up protection (ufw, fail2ban)",
    "install.cert": "Getting a certificate for the IP",
    "install.dns": "Setting up own DNS",
    "install.dns.fail": "Own DNS did not start (%(reason)s). AmneziaWG uses public DNS 1.1.1.1 for now; check later: autopilot status",
    "install.restore.inbounds": "Restoring connections and users",
    "install.web": "Setting up nginx on 443",
    "install.selfsigned": "The certificate is self-signed: Hysteria2 and TUIC clients must disable certificate verification. Open port 80 and run: autopilot cert renew",
    "install.cli": "Installing the autopilot command",
    "install.done": "Done! The server is installed",
    "install.found": "Server: %(host)s · %(os)s · %(arch)s",
    "install.sni.picked": "Cover site: %(sni)s",
    "install.root": "Run as root: sudo -i, then run the command again.",
    "install.creds": "Login details and links are saved to %(file)s (root only)",
    "install.tunnel": "The panel is closed to the internet. To open it, run on your computer:",
    "install.scan": "Scan the QR code in your app (Happ, Hiddify, v2rayN, Streisand…) or paste the link:",
    "install.qr.long": "The links are too long for a terminal QR: show them with autopilot user link admin",
    "install.sub": "Your subscription link (one for all apps):",
    "install.page": "A page with instructions for your device (the link is already filled in):",
    "links.single": "Individual connections (if your app has no subscription support):",
    "links.router": "For a router (OpenWrt):",
    "install.next1": "Manage the server: type %(cmd)s",
    "install.next2": "Add a user: %(cmd)s",
    "install.next3": "Server health: %(cmd)s",

    "menu.title": "3X-UI Autopilot %(version)s",
    "menu.users": "Users", "menu.users.d": "add, links, limits, disable",
    "menu.status": "Server health", "menu.status.d": "services, certificate, disk, protection",
    "menu.stats": "Traffic", "menu.stats.d": "who used how much",
    "menu.notify": "Notifications", "menu.notify.d": "Telegram messages about problems",
    "menu.backup": "Backups", "menu.backup.d": "make a copy, schedule, encryption",
    "menu.ssh": "SSH protection", "menu.ssh.d": "key-only login",
    "menu.lang": "Язык / Language", "menu.lang.d": "русский · English",

    "users.title": "Users",
    "users.add": "Add a user", "users.list": "List", "users.links": "Show links and QR",
    "users.off": "Disable", "users.on": "Enable", "users.del": "Delete",
    "users.name": "Name (letters, digits, _ . -)", "users.gb": "Traffic limit, GB (0 – unlimited)",
    "users.days": "Duration, days (0 – forever)", "users.created": "User %(name)s created.",
    "users.pick": "Choose a user",
    "col.user": "User", "col.traffic": "Traffic", "col.until": "Until", "col.state": "Status",
    "state.active": "active", "state.off": "disabled", "state.expired": "expired", "state.limit": "limit",
    "forever": "forever",

    "ask.confirm": "Continue?", "ask.yn": "[y/N]",
    "err.lang": "Unknown language. Available: ru, en.",
    "mieru.restore.fail": "Mieru was not restored (%(reason)s). Retry: autopilot mieru enable",
    "check.fixable": "can be fixed", "check.after": "After the fixes:", "check.summary": "Total: %(ok)s ok, %(warn)s warnings, %(bad)s problems.",
    "check.fixhint": "Safely fix what was found: autopilot check --fix",
    "update.current": "The panel is already at the pinned version (%(version)s).", "update.plan": "3X-UI panel: %(old)s → %(new)s.",
    "update.confirm": "Update? (a backup is made first)", "update.running": "Updating the panel",
    "update.rolled_back": "The update failed, the previous version was restored: %(reason)s", "update.rolled_back.hint": "Backup made before the update: %(path)s",
    "update.done": "The panel was updated to %(version)s.", "update.backup": "Backup made before the update: %(path)s",
    "net.changing": "Applying changes", "net.site.done": "Cover site: %(old)s → %(new)s.", "net.port.done": "Port: %(old)s → %(new)s (ufw rules updated).",
    "net.links.hint": "User links updated by themselves; clients need to refresh the subscription.",
    "net.col.name": "Connection", "net.col.public": "Public port", "net.col.site": "Cover site",
    "mieru.enabling": "Setting up Mieru", "mieru.on": "Mieru is on, ports: %(ports)s. Links appear in “autopilot user link name”.",
    "mieru.note": "Mieru is a separate service (mita), not part of the panel. If mita was already configured, its ports and users are untouched.",
    "mieru.off": "Our Mieru users were removed. The mita service and other settings were left alone.",
    "mieru.status.off": "Mieru is off. Turn it on: autopilot mieru enable", "mieru.status.on": "Mieru is on: %(users)s users, ports %(ports)s.",
    "mieru.user.fail": "Mieru: the user was not created (%(reason)s). Everything else was.",
    "uninstall.nothing": "Autopilot is not installed: nothing to remove.", "uninstall.title": "Removing Autopilot",
    "uninstall.what": "Services will be stopped and these files removed:", "uninstall.keeps": "Kept: packages (nginx, fail2ban, ufw), your SSH, copies in /var/backups/autopilot.",
    "uninstall.confirm": "Remove?", "uninstall.backup": "A copy was made in %(dir)s before removal (it contains keys: treat it like a password).",
    "uninstall.done": "Autopilot removed.", "uninstall.kept": "Kept: %(path)s",
    "menu.router": "Router (OpenWrt)", "menu.router.d": "automatic Nikki, OpenClash, PassWall 2 install",
    "router.pick": "What to install on the router?", "router.run": "Run on the router (over SSH: ssh root@192.168.1.1):",
    "router.note": "The script detects opkg/apk, installs the app and sets the subscription. It does NOT start the service: traffic goes through the VPN only after you press Start in LuCI.",
    "router.pw2": "PassWall 2: automatic install only for OpenWrt 25.12+ (apk); on opkg the script explains the manual install.",
    "router.d.nikki": "Mihomo, OpenWrt 24.10+", "router.d.openclash": "Clash/Mihomo, the most popular", "router.d.passwall2": "Xray/sing-box, 25.12+ (apk)",
    "cert.renewing": "Getting the certificate again", "cert.done": "Certificate renewed.", "cert.none": "Certificate not found.",
    "cert.days": "The certificate is valid for %(days)s more days.",
    "notify.intro": "Create a bot with @BotFather and send it any message. The server will contact api.telegram.org.",
    "notify.token": "Bot token (input hidden)", "notify.chat": "Your chat ID (a number, ask @userinfobot)",
    "notify.on": "Notifications are on, checks run every 10 minutes.", "notify.off": "Notifications are off, the token is removed from the server.",
    "notify.sent": "Message sent.", "notify.fail": "Could not send the message.",
    "notify.setup": "Set up", "notify.test": "Send a test message", "notify.disable": "Turn off", "notify.status": "Status",
    "backup.now": "Make a copy now", "backup.enc": "Make an encrypted copy", "backup.auto_on": "Turn on automatic copies",
    "backup.auto_off": "Turn off automatic copies", "backup.auto_key": "Show the automatic-copy key",
    "backup.auto.on": "Automatic backup is on: daily around 04:30, %(keep)s copies kept, all encrypted.",
    "backup.auto.off": "Automatic backup is off. Existing copies and the key were left in place.",
    "backup.key.warn": "Store the key separately from the copies (autopilot backup auto key): without it they cannot be opened.",
    "backup.pass": "Backup password", "backup.pass.new": "Password for the copy (do not lose it: no recovery without it)",
    "backup.pass.again": "Again", "backup.pass.bad": "Passwords differ or are shorter than 8 characters.",
    "backup.created": "Backup: %(path)s", "backup.scp": "Download it: scp root@%(host)s:%(path)s .",
    "ssh.on": "Disable password login (key only)", "ssh.off": "Restore password login",
    "ssh.undone": "SSH restrictions removed.", "ssh.confirm.warn": "Do not close this window: open a second one and make sure key login works there.",
    "ssh.confirm": "Apply?",
    "lang.set": "Language: English",
}

CATALOGS = {"ru": RU, "en": EN}
_current: str | None = None


LANG_FILE = "etc/autopilot/lang"


def saved() -> str | None:
    try:
        from . import core

        code = core.path(LANG_FILE).read_text(encoding="utf-8").strip().lower()[:2]
    except OSError:
        return None
    return code if code in CATALOGS else None


def save_language(code: str) -> None:
    from . import core

    if code not in CATALOGS:
        raise ValueError(code)
    core.write_file(core.path(LANG_FILE), code + "\n", 0o644)
    set_language(code)


def detect() -> str:
    forced = os.environ.get("AUTOPILOT_LANG", "").lower()[:2]
    if forced in CATALOGS:
        return forced
    if saved():
        return saved()  # type: ignore[return-value]
    for var in ("LC_ALL", "LC_MESSAGES", "LANG"):
        value = os.environ.get(var, "").lower()
        if value.startswith("ru"):
            return "ru"
        if value.startswith("en"):
            return "en"
    return "ru"


def set_language(code: str) -> None:
    global _current
    if code not in CATALOGS:
        raise ValueError(code)
    _current = code


def language() -> str:
    return _current or detect()


def t(key: str, **values: object) -> str:
    text = CATALOGS[language()].get(key) or RU.get(key) or key
    return text % values if values else text
