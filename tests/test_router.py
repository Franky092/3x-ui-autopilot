"""Автоустановка на OpenWrt: публикация скрипта и команда для роутера."""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from autopilot import core, router

URLS = {"auto": "https://203.0.113.5/main/id1", "clash": "https://203.0.113.5/clash/id1", "json": "https://203.0.113.5/json/id1"}


class RouterTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old = os.environ.get("AUTOPILOT_ROOT")
        os.environ["AUTOPILOT_ROOT"] = self.tmp.name
        core.write_file(core.path(core.CONF_DIR, "install.json"), json.dumps({"host": "203.0.113.5"}), 0o600)

    def tearDown(self):
        if self.old is None:
            os.environ.pop("AUTOPILOT_ROOT", None)
        else:
            os.environ["AUTOPILOT_ROOT"] = self.old
        self.tmp.cleanup()

    def test_publish_is_stable_and_private(self):
        first = router.publish()
        second = router.publish()
        self.assertEqual(first, second)
        self.assertRegex(first, r"^https://203\.0\.113\.5/[0-9a-f]{16}/router\.sh$")
        token = first.split("/")[3]
        published = core.path("var/www/autopilot", token, "router.sh")
        self.assertEqual(published.read_text(), router.SCRIPT.read_text())
        self.assertEqual(json.loads(core.path(core.CONF_DIR, "install.json").read_text())["router_token"], token)

    def test_command_uses_the_right_link(self):
        url = "https://203.0.113.5/abc/router.sh"
        self.assertEqual(router.command("nikki", url, URLS), "wget -qO- %s | sh -s -- nikki '%s'" % (url, URLS["clash"]))
        self.assertTrue(router.command("openclash", url, URLS).endswith("'%s'" % URLS["clash"]))
        self.assertTrue(router.command("passwall2", url, URLS).endswith("'%s'" % URLS["auto"]))
        self.assertIn("--lang en", router.command("nikki", url, URLS, "en"))

    def test_unknown_app_rejected(self):
        with self.assertRaises(core.Error):
            router.command("x; rm -rf /", "https://h/p", URLS)

    def test_without_install_it_explains(self):
        os.remove(core.path(core.CONF_DIR, "install.json"))
        with self.assertRaises(core.Error):
            router.publish()


class ScriptTest(unittest.TestCase):
    def sh(self, *args):
        return subprocess.run(["sh", str(router.SCRIPT), *args], capture_output=True, text=True)

    def test_syntax(self):
        self.assertEqual(subprocess.run(["sh", "-n", str(router.SCRIPT)], capture_output=True).returncode, 0)

    def test_rejects_unknown_app_and_bad_links(self):
        self.assertNotEqual(self.sh("evil").returncode, 0)
        for link in ("http://x.example/a", "https://x.example/a;reboot", "https://x.example/a b", "https://x.example/$(id)", "https://x.example/`id`"):
            r = self.sh("--lang", "en", "nikki", link)
            self.assertNotEqual(r.returncode, 0, link)

    def test_never_starts_the_service(self):
        text = router.SCRIPT.read_text()
        self.assertNotRegex(text, r"/etc/init\.d/(nikki|openclash|passwall2) (start|restart|enable)")
        self.assertNotIn("config.enabled", text)

    def test_only_expected_hosts(self):
        import re

        hosts = set(re.findall(r"https://([A-Za-z0-9.-]+)", router.SCRIPT.read_text()))
        self.assertLessEqual(hosts, {"github.com", "api.github.com", "sourceforge.net"})


if __name__ == "__main__":
    unittest.main()
