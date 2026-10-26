"""Оболочечные скрипты работают под `set -e`/pipefail. Конвейер «команда | grep -q» тогда падает по SIGPIPE, как только grep
нашёл совпадение и вышел раньше команды, и проверка даёт ложное «нет». Такие места пишем через присвоение $(…).
python3 -m unittest tests.test_shell_lint"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = [ROOT / "install.sh", ROOT / "autopilot" / "data" / "router.sh"]
BAD = re.compile(r"\|\s*grep\s+(-[A-Za-z]*q[A-Za-z]*|--quiet|--silent)\b")


class ShellLint(unittest.TestCase):
    def test_no_pipe_into_grep_quiet(self):
        found = []
        for path in FILES:
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if line.lstrip().startswith("#"):
                    continue
                if BAD.search(line):
                    found.append("%s:%d: %s" % (path.relative_to(ROOT), n, line.strip()[:110]))
        self.assertEqual(found, [], "Используйте присвоение $(…) вместо конвейера в grep -q:\n" + "\n".join(found))

    def test_scripts_are_posix_sh(self):
        for path in FILES:
            self.assertTrue(path.read_text(encoding="utf-8").startswith("#!/bin/sh"), path.name)
            text = path.read_text(encoding="utf-8")
            self.assertNotRegex(text, r"\[\[|\bfunction\s+\w+\s*\(|<<<|\$\{[A-Za-z_]+//", path.name)


if __name__ == "__main__":
    unittest.main()
