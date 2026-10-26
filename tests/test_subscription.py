"""Подписка: настройки панели и публичные адреса."""
import unittest

from autopilot import subscription as S


class FakeApi:
    def __init__(self, settings):
        self.current = dict(settings)
        self.sent = None

    def settings(self):
        return dict(self.current)

    def update_settings(self, settings):
        self.sent = settings


class SubscriptionTest(unittest.TestCase):
    def test_configure_binds_loopback_and_enables_formats(self):
        api = FakeApi({"subPath": "/abc/", "subJsonPath": "json1", "subClashPath": "/clash1", "subListen": "", "tgBotEnable": True})
        applied = S.configure(api, "203.0.113.5")
        self.assertIs(api.sent, applied)
        self.assertEqual(applied["subListen"], "127.0.0.1")
        self.assertTrue(applied["subJsonEnable"] and applied["subClashEnable"])
        self.assertTrue(applied["subClashAutoDetect"] and applied["subJsonAutoDetect"] and applied["subHappAutoDetect"])
        self.assertEqual(applied["subURI"], "https://203.0.113.5/abc/")
        self.assertEqual((applied["subJsonPath"], applied["subClashPath"]), ("/json1/", "/clash1/"))
        self.assertFalse(applied["tgBotEnable"])
        self.assertEqual(applied["subCertFile"], "")

    def test_missing_paths_get_random_ones(self):
        applied = S.configure(FakeApi({"subPath": ""}), "203.0.113.5")
        self.assertRegex(applied["subPath"], r"^/[0-9a-f]{16}/$")

    def test_public_urls(self):
        urls = S.public_urls({"subPath": "/s/", "subJsonPath": "/j/", "subClashPath": "/c/"}, "203.0.113.5", "id42")
        self.assertEqual(urls, {"auto": "https://203.0.113.5/s/id42", "json": "https://203.0.113.5/j/id42", "clash": "https://203.0.113.5/c/id42"})

    def test_paths_list(self):
        self.assertEqual(S.paths({"subPath": "/s/", "subJsonPath": "/j/", "subClashPath": ""}), ["/s/", "/j/"])


if __name__ == "__main__":
    unittest.main()
