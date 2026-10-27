"""Адрес страницы «Подключение» с подставленной ссылкой подписки."""
import unittest

from autopilot import i18n, installer, subscription

SUB = "https://203.0.113.5/sub/abc123"


class PageLinkTest(unittest.TestCase):
    def test_page_url_carries_the_link_after_the_fragment(self):
        url = subscription.page_url(SUB)
        self.assertTrue(url.startswith("https://"))
        # часть после # не уходит на сервер: ссылка подписки не должна оказаться в пути или запросе
        base, _, fragment = url.partition("#")
        self.assertEqual(fragment, SUB)
        self.assertNotIn("203.0.113.5", base)

    def test_credentials_file_contains_the_page_link(self):
        plan = installer.Plan(host="203.0.113.5", arch="amd64", sni="a.example.com", xhttp_sni="b.example.com",
                              ssh_ports=[22], mtproto_sni="c.example.com")
        text = installer.credentials_text(plan, [], SUB, "admin")
        self.assertIn(subscription.page_url(SUB), text)
        self.assertNotIn(subscription.PAGE_URL, installer.credentials_text(plan, [], "", "admin"))

    def test_text_exists_in_both_languages(self):
        self.assertIn("install.page", i18n.RU)
        self.assertIn("install.page", i18n.EN)


if __name__ == "__main__":
    unittest.main()
