"""Проверки Telegram-уведомлений без сети и системных служб."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from autopilot import core, notify


class FakePanel:
    def __init__(self, clients=None):
        self._clients = clients or []

    def clients(self):
        return self._clients

    def inbounds(self):
        return []


class NotifyTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous = os.environ.get("AUTOPILOT_ROOT")
        os.environ["AUTOPILOT_ROOT"] = self.temp.name
        self.panel = FakePanel()
        self.active_alert = {"disk": "Диск заполнен на 91%"}
        self.unit_exists = mock.patch("autopilot.core.unit_exists", return_value=False)
        self.unit_exists.start()
        self.addCleanup(mock.patch.stopall)

    def tearDown(self):
        if self.previous is None:
            os.environ.pop("AUTOPILOT_ROOT", None)
        else:
            os.environ["AUTOPILOT_ROOT"] = self.previous
        self.temp.cleanup()

    def configured(self):
        path = core.path(notify.ENV_FILE)
        core.write_env(path, {"NOTIFY_TOKEN": "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef", "NOTIFY_CHAT": "12345"}, 0o600)
        return path

    def collect(self, *args, **kwargs):
        return dict(self.active_alert)

    def test_alert_sent_once_and_recovery_sent(self):
        self.configured()
        sent = []
        with mock.patch("autopilot.notify.collect_alerts", side_effect=self.collect):
            self.assertEqual(notify.check(self.panel, lambda message: sent.append(message) or True),
                             ["⚠️ Диск заполнен на 91%"])
            self.assertEqual(notify.check(self.panel, lambda message: sent.append(message) or True), [])
            self.active_alert.clear()
            self.assertEqual(notify.check(self.panel, lambda message: sent.append(message) or True),
                             ["✅ Снова в порядке: Диск заполнен на 91%"])
        self.assertEqual(len(sent), 2)

    def test_failed_send_is_not_remembered(self):
        self.configured()
        with mock.patch("autopilot.notify.collect_alerts", side_effect=self.collect):
            self.assertEqual(notify.check(self.panel, lambda _message: False), [])
            state = core.path(notify.STATE_FILE)
            self.assertEqual(json.loads(state.read_text()), {})
            sent = notify.check(self.panel, lambda _message: True)
            self.assertEqual(len(sent), 1)

    def test_invalid_token_rejected(self):
        with self.assertRaises(core.Error):
            notify.configure("wrong", "12345", send=lambda *_a, **_kw: True)
        self.assertFalse(core.path(notify.ENV_FILE).exists())

    def test_config_settings_are_mode_0600(self):
        notify.configure("123456:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef", "12345",
                         send=lambda *_a, **_kw: True)
        self.assertEqual(core.path(notify.ENV_FILE).stat().st_mode & 0o777, 0o600)
        self.assertTrue(notify.is_configured())

    def test_awg_client_does_not_get_separate_alert(self):
        expired = 1
        self.panel = FakePanel([
            {"email": "alice", "expiryTime": expired},
            {"email": "alice-awg2", "expiryTime": expired},
        ])
        with mock.patch("autopilot.core.unit_exists", return_value=False), \
                mock.patch("autopilot.notify.shutil.disk_usage", side_effect=OSError):
            alerts = notify.collect_alerts(self.panel, services=(), now=100)
        self.assertIn("user:alice:expired", alerts)
        self.assertNotIn("user:alice-awg2:expired", alerts)


if __name__ == "__main__":
    unittest.main()
