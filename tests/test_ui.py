"""Оформление: без терминала – чистый текст; рамки ровные; меню в простом режиме; переводы полны."""
import contextlib
import io
import os
import unittest
from unittest import mock

from autopilot import core, i18n, ui


def capture(fn, *args, **kw):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        result = fn(*args, **kw)
    return result, buf.getvalue()


class PlainOutputTest(unittest.TestCase):
    def setUp(self):
        i18n.set_language("ru")

    def test_no_escape_codes_without_tty(self):
        _, text = capture(ui.ok, "готово")
        self.assertNotIn("\x1b", text)
        self.assertIn("готово", text)

    def test_box_lines_have_equal_visible_width(self):
        _, text = capture(ui.box, "Заголовок", ["раз", "двадцать пять символов тут.."], kind="ok")
        widths = {ui.visible_len(line) for line in text.rstrip("\n").splitlines()}
        self.assertEqual(len(widths), 1, text)

    def test_long_lines_are_wrapped_inside_the_box(self):
        with mock.patch("shutil.get_terminal_size", return_value=os.terminal_size((60, 24))):
            _, text = capture(ui.box, "T", ["слово " * 30], kind="info")
        widths = {ui.visible_len(line) for line in text.rstrip("\n").splitlines()}
        self.assertEqual(len(widths), 1, text)
        self.assertLessEqual(max(widths), 60)

    def test_table_aligns_columns(self):
        _, text = capture(ui.table, ["Имя", "Трафик"], [["anna", "1.0 ГБ"], ["bob-long-name", "2 КБ"]])
        lines = text.splitlines()
        self.assertEqual(lines[2].index("1.0"), lines[3].index("2 КБ"))

    def test_step_plain_prints_progress_line(self):
        def run():
            with ui.Step("Ставлю пакеты", 2, 6):
                pass
        _, text = capture(run)
        self.assertIn("Ставлю пакеты", text)
        self.assertIn("[2/6]", text)

    def test_step_failure_is_reported_and_reraised(self):
        def run():
            with ui.Step("Шаг"):
                raise core.Error("плохо")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), self.assertRaises(core.Error):
            run()
        self.assertIn("Шаг", buf.getvalue())

    def test_error_shows_hint(self):
        _, text = capture(ui.error, "Порт занят", "освободите 443")
        self.assertIn("Порт занят", text)
        self.assertIn("освободите 443", text)

    def test_no_color_env_disables_styles(self):
        with mock.patch.dict(os.environ, {"NO_COLOR": "1"}):
            self.assertEqual(ui.bold("x"), "x")


class MenuTest(unittest.TestCase):
    ITEMS = [("users", "Пользователи", "добавить"), ("status", "Состояние", "службы")]

    def test_plain_menu_by_number(self):
        with mock.patch("builtins.input", return_value="2"):
            result, text = capture(ui.menu, "Меню", self.ITEMS)
        self.assertEqual(result, "status")
        self.assertIn("1) Пользователи", text)

    def test_plain_menu_quit_and_garbage(self):
        for raw in ("q", "", "99", "abc"):
            with mock.patch("builtins.input", return_value=raw):
                result, _ = capture(ui.menu, "Меню", self.ITEMS)
            self.assertIsNone(result, raw)

    def test_back_item(self):
        with mock.patch("builtins.input", return_value="3"):
            result, _ = capture(ui.menu, "Меню", self.ITEMS, back="Назад")
        self.assertIsNone(result)

    def test_eof_means_quit(self):
        with mock.patch("builtins.input", side_effect=EOFError):
            result, _ = capture(ui.menu, "Меню", self.ITEMS)
        self.assertIsNone(result)


class AskTest(unittest.TestCase):
    def test_default_value(self):
        with mock.patch("builtins.input", return_value=""):
            self.assertEqual(ui.ask("Имя", "admin"), "admin")

    def test_confirm_variants(self):
        for raw, default, expected in (("y", False, True), ("да", False, True), ("", False, False), ("", True, True), ("n", True, False)):
            with mock.patch("builtins.input", return_value=raw):
                self.assertEqual(ui.confirm("Точно?", default), expected, raw)


class I18nTest(unittest.TestCase):
    def test_catalogs_have_same_keys(self):
        self.assertEqual(set(i18n.RU), set(i18n.EN))

    def test_format_placeholders_match(self):
        import re
        for key in i18n.RU:
            self.assertEqual(sorted(re.findall(r"%\((\w+)\)", i18n.RU[key])), sorted(re.findall(r"%\((\w+)\)", i18n.EN[key])), key)

    def test_missing_key_is_visible(self):
        self.assertEqual(i18n.t("no.such.key"), "no.such.key")

    def test_language_switch(self):
        i18n.set_language("en")
        self.assertEqual(i18n.t("yes"), "yes")
        i18n.set_language("ru")
        self.assertEqual(i18n.t("yes"), "да")


class QrTest(unittest.TestCase):
    def test_no_qrencode_returns_false(self):
        with mock.patch("shutil.which", return_value=None):
            self.assertFalse(ui.qr("hello"))


if __name__ == "__main__":
    unittest.main()
