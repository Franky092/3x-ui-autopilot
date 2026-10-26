#!/bin/sh
# 3X-UI Autopilot: автоматическая установка клиента на OpenWrt (Nikki, OpenClash, PassWall 2).
# Automatic client install for OpenWrt.
#
#   sh router.sh [--dry-run] [--lang en] nikki|openclash|passwall2 [ССЫЛКА-ПОДПИСКИ]
#
# Для Nikki и OpenClash нужна Clash-ссылка подписки, для PassWall 2 – основная. Службу скрипт НЕ запускает:
# весь трафик сети пойдёт через VPN только после вашего нажатия «Запуск» в LuCI.
set -eu

DRY=0
LANG_UI=${AUTOPILOT_LANG:-ru}
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1; shift ;;
    --lang) LANG_UI=${2:-ru}; shift 2 ;;
    *) break ;;
  esac
done
APP=${1:-}
URL=${2:-}

# t "по-русски" "in English"
t() { if [ "$LANG_UI" = en ]; then printf '%s' "$2"; else printf '%s' "$1"; fi; }
say() { printf '==> %s\n' "$(t "$1" "$2")"; }
warn() { printf '!   %s\n' "$(t "$1" "$2")"; }
die() { printf 'x   %s\n' "$(t "$1" "$2")" >&2; exit 1; }

# Выполнить команду; при --dry-run только показать.
run() {
  if [ "$DRY" = 1 ]; then printf '+ %s\n' "$*"; else "$@"; fi
}

case "$APP" in
  nikki|openclash|passwall2) ;;
  *) die "Использование: sh router.sh [--dry-run] nikki|openclash|passwall2 [ссылка]" "Usage: sh router.sh [--dry-run] nikki|openclash|passwall2 [link]" ;;
esac

# Ссылка попадает в uci и в имя файла: допускаем только безопасные символы и https.
if [ -n "$URL" ]; then
  case "$URL" in
    https://*) ;;
    *) die "Ссылка подписки должна начинаться с https://" "The subscription link must start with https://" ;;
  esac
  case "$URL" in
    *[!A-Za-z0-9._~:/?#@%\&=+,-]*) die "В ссылке недопустимые символы." "The link contains unsupported characters." ;;
  esac
fi

[ "$(id -u)" = 0 ] || die "Запустите от root." "Run as root."
[ -f /etc/openwrt_release ] || die "Это не OpenWrt." "This is not OpenWrt."
. /etc/openwrt_release
RELEASE=${DISTRIB_RELEASE:-unknown}
ARCH=${DISTRIB_ARCH:-unknown}
if command -v apk >/dev/null 2>&1; then PM=apk
elif command -v opkg >/dev/null 2>&1; then PM=opkg
else die "Не найден ни opkg, ни apk." "Neither opkg nor apk found."; fi
say "OpenWrt $RELEASE, $ARCH, $PM" "OpenWrt $RELEASE, $ARCH, $PM"

# Место: ядру нужно несколько десятков МБ.
FREE_KB=$(df -k /overlay 2>/dev/null | awk 'NR==2 {print $4}')
[ -n "$FREE_KB" ] || FREE_KB=$(df -k / | awk 'NR==2 {print $4}')
if [ "${FREE_KB:-0}" -lt 40000 ] 2>/dev/null; then
  die "Мало места на роутере: свободно $((FREE_KB / 1024)) МБ, нужно не меньше 40 МБ." "Not enough free space: $((FREE_KB / 1024)) MB, need at least 40 MB."
fi
wget -q -O /dev/null https://github.com 2>/dev/null || die "Нет доступа к github.com с роутера." "Cannot reach github.com from the router."

pm_update() { if [ "$PM" = apk ]; then run apk update; else run opkg update; fi; }
pm_install() { if [ "$PM" = apk ]; then run apk add "$@"; else run opkg install "$@"; fi; }
pm_has() { if [ "$PM" = apk ]; then apk info -e "$1" >/dev/null 2>&1; else opkg list-installed 2>/dev/null | grep "^$1 " >/dev/null; fi; }

# Последний релиз из GitHub: печатает URL файла нужного типа (ipk для opkg, apk для apk).
latest_asset() { # репозиторий шаблон-имени
  ext=ipk; [ "$PM" = apk ] && ext=apk
  json=/tmp/autopilot-release.json
  wget -q -O "$json" "https://api.github.com/repos/$1/releases/latest" || return 1
  jsonfilter -i "$json" -e '@.assets[*].browser_download_url' | grep -m1 "/$2.*\\.$ext\$"
}

install_release_package() { # репозиторий префикс-файла
  asset=$(latest_asset "$1" "$2") || die "Не удалось узнать последнюю версию $1." "Could not find the latest release of $1."
  [ -n "$asset" ] || die "В релизе $1 нет файла для $PM." "No $PM file in the latest release of $1."
  say "Скачиваю $asset" "Downloading $asset"
  file=/tmp/autopilot-$(basename "$asset")
  run wget -q -O "$file" "$asset"
  if [ "$PM" = apk ]; then run apk add -q --force-overwrite --clean-protected --allow-untrusted "$file"; else run opkg install "$file"; fi
}

fetch_profile() { # куда
  [ -n "$URL" ] || die "Для $APP нужна ссылка подписки (Clash)." "$APP needs a subscription (Clash) link."
  run mkdir -p "$(dirname "$1")"
  run wget -q -U clash.meta -O "$1" "$URL"
}

install_nikki() {
  [ -x /sbin/fw4 ] || die "Nikki работает только с firewall4 (OpenWrt 24.10+)." "Nikki needs firewall4 (OpenWrt 24.10+)."
  say "Подключаю репозиторий Nikki" "Adding the Nikki repository"
  if [ "$DRY" = 1 ]; then echo '+ wget -O - https://github.com/nikkinikki-org/OpenWrt-nikki/raw/refs/heads/main/feed.sh | ash'
  else wget -qO- https://github.com/nikkinikki-org/OpenWrt-nikki/raw/refs/heads/main/feed.sh | ash; fi
  pm_update
  say "Ставлю Nikki" "Installing Nikki"
  pm_install nikki luci-app-nikki
  if [ -n "$URL" ]; then
    say "Прописываю подписку" "Setting the subscription"
    run uci set nikki.subscription.name='Autopilot'
    run uci set nikki.subscription.url="$URL"
    run uci set nikki.subscription.user_agent='clash.meta'
    run uci set nikki.subscription.prefer='remote'
    run uci set nikki.config.profile='subscription:subscription'
    run uci commit nikki
  fi
}

install_openclash() {
  say "Ставлю зависимости OpenClash" "Installing OpenClash dependencies"
  pm_update
  # dnsmasq-full заменяет обычный dnsmasq: делаем это только если он ещё не стоит
  if ! pm_has dnsmasq-full; then
    if [ "$PM" = apk ]; then run apk del dnsmasq; else run opkg remove dnsmasq; fi
    pm_install dnsmasq-full
  fi
  pm_install bash curl ca-bundle ip-full ruby ruby-yaml kmod-tun kmod-inet-diag kmod-nft-tproxy unzip luci-compat luci luci-base
  say "Ставлю OpenClash" "Installing OpenClash"
  install_release_package vernesong/OpenClash luci-app-openclash
  if [ -n "$URL" ]; then
    say "Скачиваю профиль подписки" "Downloading the subscription profile"
    fetch_profile /etc/openclash/config/autopilot.yaml
    run uci set openclash.config.config_path='/etc/openclash/config/autopilot.yaml'
    run uci commit openclash
  fi
}

install_passwall2() {
  if [ "$PM" != apk ]; then
    warn "Автоустановка PassWall 2 для opkg пока не поддерживается: репозиторий пакетов подписан ключом, который нужно взять из документации." \
         "Automatic PassWall 2 install for opkg is not supported yet: its package repository needs a signing key from the documentation."
    warn "Поставьте вручную: https://github.com/Openwrt-Passwall/openwrt-passwall2 – или выберите Nikki / OpenClash." \
         "Install it manually: https://github.com/Openwrt-Passwall/openwrt-passwall2 – or choose Nikki / OpenClash."
    exit 2
  fi
  say "Подключаю репозиторий PassWall (apk)" "Adding the PassWall repository (apk)"
  release=${RELEASE%.*}
  run wget -q -O /etc/apk/keys/passwall.pub https://sourceforge.net/projects/openwrt-passwall-build/files/apk.pub
  base=https://sourceforge.net/projects/openwrt-passwall-build/files/releases/packages-$release/$ARCH
  if [ "$DRY" = 1 ]; then echo "+ add repositories: $base/{passwall_packages,passwall_luci,passwall2}/packages.adb"
  else
    for feed in passwall_packages passwall_luci passwall2; do
      line="$base/$feed/packages.adb"
      grep -qxF "$line" /etc/apk/repositories.d/customfeeds.list 2>/dev/null || echo "$line" >> /etc/apk/repositories.d/customfeeds.list
    done
  fi
  run apk update
  pm_install tcping geoview luci-app-passwall2
  run /etc/init.d/rpcd restart
  if [ -n "$URL" ]; then
    warn "Подписку добавьте в LuCI: Службы → PassWall 2 → Подписка узлов → ссылка: $URL" \
         "Add the subscription in LuCI: Services → PassWall 2 → Node Subscribe → link: $URL"
  fi
}

"install_$APP"

printf '\n'
say "Готово." "Done."
case "$APP" in
  nikki) say "Откройте LuCI → Службы → Nikki: проверьте подписку и нажмите «Запуск»." "Open LuCI → Services → Nikki: check the subscription and press Start." ;;
  openclash) say "Откройте LuCI → Службы → OpenClash: выберите конфиг autopilot.yaml и нажмите «Запуск» (при первом запуске ядро скачается само)." "Open LuCI → Services → OpenClash: pick autopilot.yaml and press Start (the core downloads on first start)." ;;
  passwall2) say "Откройте LuCI → Службы → PassWall 2, добавьте подписку, выберите узел и включите." "Open LuCI → Services → PassWall 2, add the subscription, choose a node and enable." ;;
esac
