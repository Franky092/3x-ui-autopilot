"""Оформление в терминале: цвета, рамки, шаги с индикатором, таблицы, меню со стрелками, QR.

Только стандартная библиотека. Без терминала (лог, pipe, NO_COLOR) всё выводится простым текстом без escape-кодов.
"""
from __future__ import annotations

import os
import re
import shutil
import sys
import threading
import time
from typing import Iterable, Sequence

from . import __version__, core
from .i18n import t

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


# --- возможности терминала -----------------------------------------------------------------------

def is_tty() -> bool:
    return sys.stdout.isatty()


def use_color() -> bool:
    return is_tty() and not os.environ.get("NO_COLOR") and os.environ.get("TERM", "") != "dumb"


def use_utf8() -> bool:
    enc = (getattr(sys.stdout, "encoding", "") or "").lower().replace("-", "")
    return enc == "utf8"


def interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def width() -> int:
    return max(40, min(shutil.get_terminal_size((80, 24)).columns, 100))


def style(text: str, *codes: str) -> str:
    return "\x1b[%sm%s\x1b[0m" % (";".join(codes), text) if use_color() and codes else text


def bold(text: str) -> str: return style(text, "1")
def dim(text: str) -> str: return style(text, "90")
def accent(text: str) -> str: return style(text, "36")
def good(text: str) -> str: return style(text, "32")
def warn_c(text: str) -> str: return style(text, "33")
def bad(text: str) -> str: return style(text, "31")


def visible_len(text: str) -> int:
    return len(_ANSI.sub("", text))


def pad(text: str, size: int) -> str:
    return text + " " * max(0, size - visible_len(text))


def sym(name: str) -> str:
    utf = {"ok": "✓", "bad": "✗", "warn": "!", "info": "•", "arrow": "→", "dot": "·", "bar": "│", "tl": "╭", "tr": "╮",
           "bl": "╰", "br": "╯", "h": "─", "cursor": "❯"}
    ascii_ = {"ok": "+", "bad": "x", "warn": "!", "info": "*", "arrow": "->", "dot": "-", "bar": "|", "tl": "+", "tr": "+",
              "bl": "+", "br": "+", "h": "-", "cursor": ">"}
    return (utf if use_utf8() else ascii_)[name]


def out(text: str = "") -> None:
    print(text, file=sys.stdout, flush=True)


# --- сообщения ---------------------------------------------------------------------------------

def ok(text: str) -> None: out("  %s %s" % (good(sym("ok")), text))
def info(text: str) -> None: out("  %s %s" % (accent(sym("info")), text))
def warn(text: str) -> None: out("  %s %s" % (warn_c(sym("warn")), text))
def fail(text: str) -> None: out("  %s %s" % (bad(sym("bad")), text))
def hint(text: str) -> None: out("    %s" % dim(text))


def error(message: str, todo: str | None = None) -> None:
    out()
    out("  %s %s" % (bad(bold(sym("bad") + " " + t("error"))), message))
    if todo:
        out("    %s %s" % (warn_c(bold(t("todo") + ":")), todo))
    out()


def banner() -> None:
    title = "◆ 3X-UI Autopilot  %s" % __version__ if use_utf8() else "3X-UI Autopilot  %s" % __version__
    box(None, [bold(accent(title)), dim(t("app.tagline"))], kind="accent")


# --- рамки и таблицы -----------------------------------------------------------------------------

def box(title: str | None, lines: Iterable[str], *, kind: str = "info") -> None:
    paint = {"info": accent, "ok": good, "warn": warn_c, "bad": bad, "accent": accent}.get(kind, accent)
    import textwrap

    limit = width() - 6
    lines = list(lines)
    wrapped: list[str] = []
    for line in lines:  # длинные строки без стилей переносим по словам, чтобы рамка не ломалась
        if visible_len(line) > limit and visible_len(line) == len(line):
            indent = " " * (len(line) - len(line.lstrip()))
            wrapped += textwrap.wrap(line, limit, subsequent_indent=indent) or [""]
        else:
            wrapped.append(line)
    lines = wrapped
    inner = max([visible_len(x) for x in lines] + [visible_len(title or "") + 2, 24])
    inner = min(inner, limit)
    top = sym("tl") + sym("h") * (inner + 2) + sym("tr")
    if title:
        label = " %s " % title
        top = sym("tl") + sym("h") + label + sym("h") * max(0, inner + 1 - visible_len(label)) + sym("tr")
    out("  " + paint(top))
    for line in lines:
        out("  %s %s %s" % (paint(sym("bar")), pad(line, inner), paint(sym("bar"))))
    out("  " + paint(sym("bl") + sym("h") * (inner + 2) + sym("br")))


def table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> None:
    widths = [max([visible_len(h)] + [visible_len(str(r[i])) for r in rows]) for i, h in enumerate(headers)]
    out("  " + "  ".join(bold(pad(h, widths[i])) for i, h in enumerate(headers)))
    out("  " + dim("  ".join(sym("h") * w for w in widths)))
    for row in rows:
        out("  " + "  ".join(pad(str(c), widths[i]) for i, c in enumerate(row)))


# --- шаги с индикатором -------------------------------------------------------------------------

class Step:
    """with ui.Step("Ставлю пакеты", 2, 6): ... – индикатор, затем ✓ с временем или ✗."""

    FRAMES_UTF = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    FRAMES_ASCII = "|/-\\"

    def __init__(self, text: str, index: int | None = None, total: int | None = None) -> None:
        self.text = text
        self.prefix = dim("[%d/%d] " % (index, total)) if index and total else ""
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._start = 0.0

    def _spin(self) -> None:
        frames = self.FRAMES_UTF if use_utf8() else self.FRAMES_ASCII
        i = 0
        while not self._stop.wait(0.1):
            sys.stdout.write("\r\x1b[2K  %s %s%s %s" % (accent(frames[i % len(frames)]), self.prefix, self.text,
                                                        dim("%ds" % (time.monotonic() - self._start))))
            sys.stdout.flush()
            i += 1

    def __enter__(self) -> "Step":
        self._start = time.monotonic()
        if use_color() and interactive():
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
        else:
            out("  %s %s%s…" % (sym("arrow"), self.prefix, self.text))
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self._stop.set()
        if self._thread:
            self._thread.join()
            sys.stdout.write("\r\x1b[2K")
        took = time.monotonic() - self._start
        mark = good(sym("ok")) if exc_type is None else bad(sym("bad"))
        if self._thread or exc_type is not None:
            out("  %s %s%s %s" % (mark, self.prefix, self.text, dim("%.1fs" % took) if took >= 1 else ""))
        return False

    def note(self, text: str) -> None:
        if not self._thread:
            hint(text)


# --- ввод ----------------------------------------------------------------------------------------

def ask(prompt: str, default: str | None = None) -> str:
    suffix = " [%s]" % default if default else ""
    try:
        value = input("  %s %s%s: " % (accent("?"), prompt, dim(suffix))).strip()
    except EOFError:
        value = ""
    return value or (default or "")


def ask_secret(prompt: str) -> str:
    import getpass

    if not sys.stdin.isatty():
        core.die("Для ввода секрета нужен интерактивный терминал.", "Запустите команду в терминале (например, по SSH).")
    return getpass.getpass("  %s %s: " % (accent("?"), prompt)).strip()


def confirm(prompt: str, default: bool = False) -> bool:
    answer = ask("%s %s" % (prompt, t("ask.yn") if not default else "[Y/n]")).lower()
    if not answer:
        return default
    return answer in ("y", "yes", "д", "да", "1")


# --- меню ----------------------------------------------------------------------------------------

def _read_key() -> str:
    import os as _os

    data = _os.read(sys.stdin.fileno(), 8)
    if data in (b"\x1b[A", b"\x1bOA"): return "up"
    if data in (b"\x1b[B", b"\x1bOB"): return "down"
    if data in (b"\r", b"\n"): return "enter"
    if data in (b"\x03", b"\x04"): return "quit"
    if data == b"\x1b": return "quit"
    try:
        return data.decode()
    except UnicodeDecodeError:
        return ""


def menu(title: str, items: Sequence[tuple[str, str, str]], *, back: str | None = None) -> str | None:
    """items: (ключ, название, пояснение). Возвращает ключ выбранного пункта или None при выходе.
    В терминале – стрелки, Enter, цифры, q; без терминала – нумерованный список и ввод номера."""
    entries = list(items) + ([("__back", back, "")] if back else [])
    if not interactive():
        return _menu_plain(title, entries)
    try:
        import termios
        import tty
    except ImportError:  # нет termios (не Linux/macOS)
        return _menu_plain(title, entries)
    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd)
    index = 0
    drawn = 0
    label_w = max(visible_len(e[1]) for e in entries)

    def draw() -> None:
        nonlocal drawn
        if drawn:
            sys.stdout.write("\x1b[%dA\x1b[J" % drawn)
        lines = ["  " + bold(title), ""]
        for n, (_, label, desc) in enumerate(entries):
            active = n == index
            num = dim("%d" % (n + 1 if n + 1 < 10 else 0)) if n < 9 else " "
            pointer = accent(sym("cursor")) if active else " "
            text = bold(pad(label, label_w)) if active else pad(label, label_w)
            lines.append("  %s %s %s  %s" % (pointer, num, text, dim(desc) if desc else ""))
        lines += ["", "  " + dim(t("hint.menu"))]
        sys.stdout.write("\n".join(lines) + "\n")
        sys.stdout.flush()
        drawn = len(lines)

    try:
        tty.setcbreak(fd)
        sys.stdout.write("\x1b[?25l")
        draw()
        while True:
            key = _read_key()
            if key == "up": index = (index - 1) % len(entries)
            elif key == "down": index = (index + 1) % len(entries)
            elif key == "enter": break
            elif key in ("q", "quit"): index = -1; break
            elif key.isdigit() and 1 <= int(key) <= min(9, len(entries)): index = int(key) - 1; break
            draw()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)
        sys.stdout.write("\x1b[?25h")
        sys.stdout.flush()
    if index < 0:
        return None
    chosen = entries[index][0]
    return None if chosen == "__back" else chosen


def _menu_plain(title: str, entries: Sequence[tuple[str, str, str]]) -> str | None:
    out(title)
    for n, (_, label, desc) in enumerate(entries, 1):
        out("  %d) %s%s" % (n, label, " – " + desc if desc else ""))
    try:
        raw = input("> ").strip().lower()
    except EOFError:
        return None
    if raw in ("", "q"):
        return None
    if raw.isdigit() and 1 <= int(raw) <= len(entries):
        chosen = entries[int(raw) - 1][0]
        return None if chosen == "__back" else chosen
    return None


# --- QR --------------------------------------------------------------------------------------------

def qr(text: str, *, max_lines: int = 34) -> bool:
    """QR-код блоками прямо в терминале (нужен пакет qrencode). False, если его нет или код не помещается по высоте."""
    if shutil.which("qrencode") is None:
        return False
    done = core.run(["qrencode", "-t", "UTF8", "-l", "L", "-m", "1", "-o", "-"], input=text, check=False)
    if done.returncode != 0 or not done.stdout:
        return False
    lines = done.stdout.rstrip("\n").splitlines()
    if len(lines) > max_lines:
        return False
    for line in lines:
        out("    " + line)
    return True
