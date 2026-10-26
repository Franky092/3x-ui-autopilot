#!/bin/sh
# 3X-UI Autopilot: установка одной командой.
#   sh install.sh [параметры install]      – установить сервер (например: --host 203.0.113.10 --sni www.microsoft.com)
#   sh install.sh restore ФАЙЛ-КОПИИ       – восстановить сервер из резервной копии
# Скрипт скачивает релиз, сверяет его контрольную сумму и запускает установщик. Сам он ничего не ставит в систему,
# кроме python3 (если его нет) и curl.
set -eu

RELEASE_VERSION="0.4.0"
REPOSITORY="Franky092/3x-ui-autopilot"
# SHA-256 несжатого tar-архива релиза: пересчитывается командой `python3 tools/release.py --write`.
TARBALL_SHA256="e4d063eb57eca0c6c427b869f8937f8afd32890bca2292eb24ca695578543237"
URL="https://github.com/$REPOSITORY/releases/download/v$RELEASE_VERSION/autopilot-$RELEASE_VERSION.tar.gz"

die() { printf 'x   %s\n' "$*" >&2; exit 1; }
say() { printf '==> %s\n' "$*"; }

[ "$(id -u)" = 0 ] || die "Запустите от root: sudo -i, затем команду ещё раз. / Run as root."
[ -r /etc/os-release ] || die "Не удалось определить систему."
# В подвыборке: os-release сам задаёт переменную VERSION и затёр бы нашу.
OS=$(. /etc/os-release; printf '%s:%s' "${ID:-?}" "${VERSION_ID:-?}")
case "$OS" in
  ubuntu:22.04 | ubuntu:24.04 | debian:12 | debian:13) ;;
  *) die "Поддерживаются Ubuntu 22.04/24.04 и Debian 12/13, а здесь $OS." ;;
esac

need_apt=""
command -v python3 >/dev/null 2>&1 || need_apt="$need_apt python3"
command -v curl >/dev/null 2>&1 || need_apt="$need_apt curl ca-certificates"
command -v sha256sum >/dev/null 2>&1 || die "Нет sha256sum."
if [ -n "$need_apt" ]; then
  say "Ставлю:$need_apt"
  # shellcheck disable=SC2086
  DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=900 update -qq >/dev/null
  # shellcheck disable=SC2086
  DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=900 install -y -qq $need_apt >/dev/null
fi
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || die "Нужен Python 3.10 или новее."

# Запуск из клона репозитория (для разработки): берём исходники рядом со скриптом, ничего не скачиваем.
HERE=""
if [ -f "$0" ]; then HERE=$(cd "$(dirname "$0")" && pwd); fi
if [ -n "$HERE" ] && [ -f "$HERE/autopilot/__main__.py" ] && [ -z "${AUTOPILOT_TARBALL:-}" ]; then
  SRC="$HERE"
else
  WORK=$(mktemp -d)
  trap 'rm -rf "$WORK"' EXIT INT TERM
  TGZ="$WORK/autopilot.tar.gz"
  if [ -n "${AUTOPILOT_TARBALL:-}" ]; then
    [ -f "$AUTOPILOT_TARBALL" ] || die "Нет файла $AUTOPILOT_TARBALL."
    cp "$AUTOPILOT_TARBALL" "$TGZ"
  else
    say "Скачиваю Autopilot $RELEASE_VERSION"
    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 15 --max-time 180 -o "$TGZ" "$URL" \
      || die "Не удалось скачать $URL. Проверьте доступ к GitHub."
  fi
  [ "$TARBALL_SHA256" != "0000000000000000000000000000000000000000000000000000000000000000" ] \
    || die "Этот install.sh не из релиза (контрольная сумма не задана)."
  # Распаковываем один раз: хэшируем и извлекаем ровно те же байты, а лишние данные в конце gzip считаем ошибкой.
  TAR="$WORK/autopilot.tar"
  gzip -dc "$TGZ" > "$TAR" || die "Архив повреждён."
  GOT=$(sha256sum "$TAR" | cut -d' ' -f1)
  [ "$GOT" = "$TARBALL_SHA256" ] || die "Контрольная сумма архива не совпала. Установка остановлена."
  # Только пути внутри autopilot-<версия>/: ни абсолютных, ни «..», ничего снаружи.
  tar -tf "$TAR" | awk -v prefix="autopilot-$RELEASE_VERSION/" 'index($0, prefix) != 1 || $0 ~ /(^|\/)\.\.(\/|$)/ { bad = 1 } END { exit bad }' \
    || die "В архиве недопустимые пути."
  tar -xf "$TAR" -C "$WORK"
  SRC="$WORK/autopilot-$RELEASE_VERSION"
  [ -f "$SRC/autopilot/__main__.py" ] || die "В архиве нет установщика."
fi

# Без команды или с флагами – установка; иначе команда передаётся как есть (restore ФАЙЛ и т. п.).
if [ "$#" -eq 0 ]; then set -- install; else
  case "$1" in -*) set -- install "$@" ;; esac
fi

# python3 -I игнорирует переменные окружения и текущий каталог, поэтому путь к пакету добавляем сами.
# Без exec: после завершения должна сработать очистка временной папки.
python3 -I -c 'import sys; sys.path.insert(0, sys.argv[1]); from autopilot.__main__ import main; sys.exit(main(sys.argv[2:]))' "$SRC" "$@"
