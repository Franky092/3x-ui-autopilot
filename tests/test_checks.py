"""Глубокие проверки и безопасное исправление в изолированном корне."""
import os
import subprocess
import tempfile
import unittest
from collections import namedtuple
from unittest import mock

from autopilot import cert, checks, core, dns, installer, nginx, sync


class Panel:
    def __init__(self, inbounds=None, clients=None, settings=None):
        self._inbounds = inbounds if inbounds is not None else []
        self._clients = clients if clients is not None else [{"subId": "abc123"}]
        self._settings = settings if settings is not None else {
            "subEnable": True, "subPort": 2096, "subPath": "/sub/"
        }

    def inbounds(self):
        return self._inbounds

    def clients(self):
        return self._clients

    def settings(self):
        return self._settings


def completed(command, stdout="", rc=0):
    return subprocess.CompletedProcess(command, rc, stdout, "")


class ChecksTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous = os.environ.get("AUTOPILOT_ROOT")
        os.environ["AUTOPILOT_ROOT"] = self.temp.name
        self.panel = Panel([
            {"port": 1000, "protocol": "vless", "listen": "", "enable": True},
            {"port": 2000, "protocol": "vmess", "listen": "127.0.0.1", "enable": True},
            {"port": 3000, "protocol": "hysteria", "enable": True},
            {"port": 4000, "protocol": "shadowsocks", "enable": True},
            {"port": 5000, "protocol": "tuic", "enable": False},
        ])
        self.ss_text = "\n".join([
            "tcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:*",
            "tcp LISTEN 0 128 0.0.0.0:1000 0.0.0.0:*",
            "tcp LISTEN 0 128 127.0.0.1:2000 0.0.0.0:*",
            "udp UNCONN 0 0 0.0.0.0:3000 0.0.0.0:*",
            "tcp LISTEN 0 128 0.0.0.0:4000 0.0.0.0:*",
            "udp UNCONN 0 0 0.0.0.0:4000 0.0.0.0:*",
        ])
        self.ufw_text = "Status: active\n" + "\n".join(
            "%d/%s ALLOW Anywhere" % rule for rule in installer.UFW_RULES)
        self.stack = mock.patch.multiple(
            core,
            unit_exists=mock.DEFAULT,
            unit_active=mock.DEFAULT,
        )
        self.mocks = self.stack.start()
        self.mocks["unit_exists"].return_value = True
        self.mocks["unit_active"].return_value = True
        self.run_patch = mock.patch.object(core, "run", side_effect=self.command)
        self.run_mock = self.run_patch.start()
        self.other_patches = [
            mock.patch.object(cert, "days_left", return_value=5),
            mock.patch.object(dns, "query", return_value=(0, 2)),
            mock.patch.object(checks.shutil, "disk_usage", return_value=namedtuple("Usage", "total used free")(100, 50, 50)),
            mock.patch.object(checks.urllib.request, "build_opener", return_value=self.opener()),
        ]
        for patcher in self.other_patches:
            patcher.start()

    @staticmethod
    def opener(status=200):
        response = mock.MagicMock()
        response.__enter__.return_value.status = status
        opener = mock.Mock()
        opener.open.return_value = response
        return opener

    def command(self, command, **kwargs):
        if command[:2] == ["nginx", "-t"]:
            return completed(command)
        if command[:2] == ["ss", "-Hltun"]:
            return completed(command, self.ss_text)
        if command[:2] == ["ufw", "status"]:
            return completed(command, self.ufw_text)
        return completed(command)

    def tearDown(self):
        for patcher in reversed(self.other_patches):
            patcher.stop()
        self.run_patch.stop()
        self.stack.stop()
        if self.previous is None:
            os.environ.pop("AUTOPILOT_ROOT", None)
        else:
            os.environ["AUTOPILOT_ROOT"] = self.previous
        self.temp.cleanup()

    def result(self, problems, problem_id):
        return next(item for item in problems if item.id == problem_id)

    def test_all_checks_pass_in_ok_state(self):
        problems = checks.run_checks(self.panel, host="203.0.113.5")
        self.assertTrue(problems)
        self.assertTrue(all(item.level == "ok" for item in problems))
        self.assertEqual(self.result(problems, "port:2000/tcp").level, "ok")
        self.assertEqual(self.result(problems, "port:3000/udp").level, "ok")
        self.assertEqual(self.result(problems, "port:4000/tcp").level, "ok")
        self.assertEqual(self.result(problems, "port:4000/udp").level, "ok")
        self.assertNotIn("port:5000/udp", [item.id for item in problems])

    def test_ports_require_exact_loopback_and_protocol_sockets(self):
        self.ss_text = "\n".join([
            "tcp LISTEN 0 128 0.0.0.0:2000 0.0.0.0:*",
            "tcp LISTEN 0 128 127.0.0.1:1000 0.0.0.0:*",
            "tcp LISTEN 0 128 0.0.0.0:3000 0.0.0.0:*",
            "tcp LISTEN 0 128 0.0.0.0:4000 0.0.0.0:*",
            "tcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:*",
        ])
        problems = checks.run_checks(self.panel, host="203.0.113.5")
        for problem_id in ("port:2000/tcp", "port:3000/udp", "port:4000/udp"):
            self.assertEqual(self.result(problems, problem_id).level, "bad", problem_id)
        self.assertEqual(self.result(problems, "port:1000/tcp").level, "ok")
        self.assertEqual(self.result(problems, "port:4000/tcp").level, "ok")
        self.assertFalse(self.result(problems, "port:1000/tcp").fixable)

    def test_missing_panel_has_one_warning_and_skips_panel_checks(self):
        problems = checks.run_checks(None, host="203.0.113.5")
        self.assertEqual([item for item in problems if item.text == "панель не отвечает"][0].level, "warn")
        self.assertEqual(sum(item.text == "панель не отвечает" for item in problems), 1)
        self.assertNotIn("subscription", [item.id for item in problems])
        self.assertFalse(any(item.id.startswith("port:") for item in problems))

    def test_service_and_nginx_config_failures(self):
        self.mocks["unit_active"].side_effect = lambda name: name != "unbound"
        original = self.command
        self.run_mock.side_effect = lambda command, **kw: completed(command, rc=1) if command[:2] == ["nginx", "-t"] else original(command, **kw)
        problems = checks.run_checks(self.panel)
        self.assertEqual(self.result(problems, "svc:unbound").level, "bad")
        self.assertTrue(self.result(problems, "svc:unbound").fixable)
        self.assertEqual(self.result(problems, "nginx-config").level, "bad")
        self.assertTrue(self.result(problems, "nginx-config").fixable)

    def test_cert_dns_subscription_ufw_and_disk_bad_states(self):
        with mock.patch.object(cert, "days_left", return_value=0), \
                mock.patch.object(dns, "query", return_value=(2, 0)), \
                mock.patch.object(checks.urllib.request, "build_opener", return_value=self.opener(503)), \
                mock.patch.object(checks.shutil, "disk_usage", return_value=namedtuple("Usage", "total used free")(100, 95, 5)):
            self.ufw_text = "Status: inactive"
            problems = checks.run_checks(self.panel, host="203.0.113.5")
        for problem_id in ("cert", "dns", "subscription", "ufw", "disk"):
            self.assertEqual(self.result(problems, problem_id).level, "bad", problem_id)
        self.assertTrue(self.result(problems, "cert").fixable)
        self.assertTrue(self.result(problems, "dns").fixable)
        self.assertFalse(self.result(problems, "ufw").fixable)

    def test_cert_missing_and_near_expiry_thresholds(self):
        for days, level, fixable in ((None, "warn", False), (1, "warn", True), (2, "ok", False)):
            with mock.patch.object(cert, "days_left", return_value=days):
                problem = self.result(checks.run_checks(self.panel), "cert")
            self.assertEqual(problem.level, level)
            self.assertEqual(problem.fixable, fixable)

    def test_ufw_only_missing_rules_are_fixable_and_empty_users_are_ok(self):
        self.ufw_text = "Status: active\n443/tcp ALLOW Anywhere\n"
        self.panel = Panel([], clients=[], settings={"subEnable": True, "subPort": 2096, "subPath": "/sub/"})
        problems = checks.run_checks(self.panel)
        self.assertTrue(self.result(problems, "ufw").fixable)
        self.assertEqual(self.result(problems, "subscription").level, "ok")
        self.assertIn("нет пользователей", self.result(problems, "subscription").text)

    def test_disk_warn_threshold_and_summary(self):
        with mock.patch.object(checks.shutil, "disk_usage", return_value=namedtuple("Usage", "total used free")(100, 80, 20)):
            problems = checks.run_checks(None)
        self.assertEqual(self.result(problems, "disk").level, "warn")
        self.assertEqual(checks.summary([checks.Problem("a", "ok", ""), checks.Problem("b", "warn", ""),
                                         checks.Problem("c", "bad", "")]), (1, 1, 1))

    def test_apply_fixes_calls_only_safe_actions(self):
        problem_list = [
            checks.Problem("svc:x-ui", "bad", "down", fixable=True),
            checks.Problem("nginx-config", "bad", "bad", fixable=True),
            checks.Problem("cert", "bad", "bad", fixable=True),
            checks.Problem("dns", "bad", "bad", fixable=True),
            checks.Problem("ufw", "bad", "bad", fixable=True),
            checks.Problem("port:44/tcp", "bad", "bad", fixable=False),
        ]
        self.ufw_text = "Status: active\n443/tcp ALLOW Anywhere\n"
        with mock.patch.object(core, "systemctl") as ctl, \
                mock.patch.object(sync, "apply") as apply, \
                mock.patch.object(cert, "paths", return_value=(core.path("full.pem"), core.path("key.pem"))) as paths, \
                mock.patch.object(cert, "renew") as renew, mock.patch.object(cert, "reload_services") as reload, \
                mock.patch.object(dns, "setup") as setup:
            result = checks.apply_fixes(problem_list, self.panel, host="203.0.113.5")
        ctl.assert_called_once_with("restart", "x-ui", check=True)
        apply.assert_called_once_with(self.panel, str(core.path("full.pem")), str(core.path("key.pem")))
        paths.assert_called_once_with()
        renew.assert_called_once_with("203.0.113.5")
        reload.assert_called_once_with()
        setup.assert_called_once_with("203.0.113.5")
        rules = [call.args[0][2] for call in self.run_mock.call_args_list
                 if call.args[0][:2] == ["ufw", "allow"]]
        self.assertEqual(rules, ["%d/%s" % rule for rule in installer.UFW_RULES if rule != (443, "tcp")])
        self.assertEqual(len(result), 5)

    def test_failed_fix_does_not_stop_later_fixes(self):
        problems = [checks.Problem("svc:x-ui", "bad", "", fixable=True),
                    checks.Problem("dns", "bad", "", fixable=True)]
        with mock.patch.object(core, "systemctl", side_effect=core.Error("нет")), \
                mock.patch.object(dns, "setup") as setup:
            result = checks.apply_fixes(problems, self.panel, host="203.0.113.5")
        self.assertIn("не удалось: нет", result[0])
        setup.assert_called_once_with("203.0.113.5")


if __name__ == "__main__":
    unittest.main()
