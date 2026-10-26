"""Проверки управления отдельной службой Mieru."""
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from autopilot import core, installer, mieru


class MieruTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old = os.environ.get("AUTOPILOT_ROOT")
        os.environ["AUTOPILOT_ROOT"] = self.tmp.name

    def tearDown(self):
        if self.old is None:
            os.environ.pop("AUTOPILOT_ROOT", None)
        else:
            os.environ["AUTOPILOT_ROOT"] = self.old
        self.tmp.cleanup()

    def test_install_skips_existing_mita(self):
        with mock.patch.object(mieru, "installed", return_value=True), \
                mock.patch.object(mieru.installer, "download") as download, \
                mock.patch.object(mieru.core, "run") as run:
            mieru.install("amd64")
        download.assert_not_called()
        run.assert_not_called()

    def test_install_pins_hashes_for_both_architectures(self):
        for arch in ("amd64", "arm64"):
            with self.subTest(arch=arch), mock.patch.object(mieru, "installed", return_value=False), \
                    mock.patch.object(mieru.installer, "download") as download, \
                    mock.patch.object(mieru.core, "run") as run, \
                    mock.patch.object(mieru.core, "systemctl") as systemctl:
                mieru.install(arch)
                args = download.call_args.args
                self.assertEqual(args[0], mieru.MITA_URL.format(version=mieru.MITA_VERSION, arch=arch))
                self.assertEqual(args[2], mieru.MITA_SHA256[arch])
                self.assertEqual(run.call_args.args[0][:2], ["dpkg", "-i"])
                systemctl.assert_called_once_with("enable", "--now", "mita", check=True)

    def test_configure_does_not_touch_existing_config(self):
        existing = {"portBindings": [{"port": 32145, "protocol": "TCP"}], "users": [{"name": "other"}]}
        with mock.patch.object(mieru, "describe", return_value=existing), \
                mock.patch.object(mieru.core, "run") as run, \
                mock.patch.object(mieru.installer, "free_port") as free_port:
            result = mieru.configure()
        self.assertIs(result, existing)
        run.assert_not_called()
        free_port.assert_not_called()

    def test_add_user_preserves_other_users_fields_and_keeps_password_out_of_argv(self):
        current = {"portBindings": [{"port": 32145, "protocol": "UDP"}], "users": [
            {"name": "foreign", "password": "secret", "quotas": {"upload": 9}}],
            "dns": {"servers": ["1.1.1.1"]}, "mtu": 1400}
        seen = {}

        def run(cmd, **kwargs):
            if cmd[:2] == ["mita", "help"]:
                return SimpleNamespace(returncode=0, stdout="replace config <JSON_FILE>", stderr="")
            if cmd[:3] == ["mita", "replace", "config"]:
                seen["cmd"] = cmd
                seen["config"] = json.loads(Path(cmd[-1]).read_text())
                seen["mode"] = stat.S_IMODE(Path(cmd[-1]).stat().st_mode)
                seen["exists_during_call"] = Path(cmd[-1]).exists()
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with mock.patch.object(mieru, "describe", return_value=current), mock.patch.object(mieru.core, "run", side_effect=run), \
                mock.patch.object(mieru, "list_users", return_value=["foreign", "new_user"]):
            result = mieru.add_user("new_user", "pw!%:@")
        self.assertEqual(result, "pw!%:@")
        self.assertEqual(seen["config"]["users"][0]["quotas"], {"upload": 9})
        self.assertEqual(seen["config"]["users"][1], {"name": "new_user", "password": "pw!%:@"})
        self.assertEqual(seen["config"]["dns"], current["dns"])
        self.assertEqual(seen["mode"], 0o600)
        self.assertTrue(seen["exists_during_call"])
        self.assertNotIn("pw!%:@", seen["cmd"])
        self.assertFalse(Path(seen["cmd"][-1]).exists())

    def test_add_user_updates_instead_of_duplicating(self):
        current = {"users": [{"name": "alice", "password": "old", "quotas": {"x": 1}}]}
        written = []

        def run(cmd, **kwargs):
            if cmd[:2] == ["mita", "help"]:
                return SimpleNamespace(returncode=0, stdout="replace config <JSON_FILE>", stderr="")
            if cmd[:3] == ["mita", "replace", "config"]:
                written.append(json.loads(Path(cmd[3]).read_text()))
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with mock.patch.object(mieru, "describe", return_value=current), mock.patch.object(mieru.core, "run", side_effect=run), \
                mock.patch.object(mieru, "list_users", return_value=["alice"]):
            mieru.add_user("alice", "new")
        self.assertEqual(len(written[0]["users"]), 1)
        self.assertEqual(written[0]["users"][0], {"name": "alice", "password": "new", "quotas": {"x": 1}})

    def test_remove_user(self):
        current = {"users": [{"name": "keep"}, {"name": "remove"}], "dns": {"x": 1}}
        seen = []

        def run(cmd, **kwargs):
            if cmd[:2] == ["mita", "help"]:
                return SimpleNamespace(returncode=0, stdout="replace config <JSON_FILE>", stderr="")
            if cmd[:3] == ["mita", "replace", "config"]:
                seen.append(json.loads(Path(cmd[3]).read_text()))
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with mock.patch.object(mieru, "describe", return_value=current), mock.patch.object(mieru.core, "run", side_effect=run):
            self.assertTrue(mieru.remove_user("remove"))
            self.assertFalse(mieru.remove_user("missing"))
        self.assertEqual(seen[0]["users"], [{"name": "keep"}])
        self.assertEqual(seen[0]["dns"], {"x": 1})

    def test_validation(self):
        for name, password in (("bad name", "pw"), ("x" * 33, "pw"), ("ok", ""), ("ok", "bad\npass"),
                               ("ok", "has space")):
            with self.subTest(name=name, password=password), self.assertRaises(core.Error):
                mieru.server_config(2000, {name: password})
        for port in (1024, 65536, True):
            with self.subTest(port=port), self.assertRaises(core.Error):
                mieru.server_config(port, {})
        with self.assertRaises(core.Error):
            mieru.server_config(2000, {}, protocol="icmp")
        with self.assertRaises(core.Error):
            mieru.server_config(2000, {}, mtu=1279)

    def test_describe_empty_invalid_and_valid(self):
        for output, expected in (("", {}), ('{"portBindings": []}', {"portBindings": []})):
            with self.subTest(output=output), mock.patch.object(mieru.core, "run", return_value=SimpleNamespace(stdout=output)):
                self.assertEqual(mieru.describe(), expected)
        with mock.patch.object(mieru.core, "run", return_value=SimpleNamespace(stdout="not json")), self.assertRaises(core.Error):
            mieru.describe()

    def test_client_profile(self):
        config = {"portBindings": [{"port": 1234, "protocol": "TCP"}, {"portRange": {"start": 2000, "end": 2002}, "protocol": "UDP"}]}
        profile = mieru.client_profile("a", "p", "example.org", config, profile="work", mtu=1350,
                                       multiplexing="MULTIPLEXING_LOW")
        item = profile["profiles"][0]
        self.assertEqual(profile["activeProfile"], "work")
        self.assertEqual(item["user"], {"name": "a", "password": "p"})
        self.assertEqual(item["servers"][0]["ipAddress"], "example.org")
        self.assertEqual(item["servers"][0]["portBindings"], config["portBindings"])
        self.assertEqual(item["mtu"], 1350)
        self.assertEqual(item["multiplexing"]["level"], "MULTIPLEXING_LOW")

    def test_client_link_escaping_and_binding_order(self):
        config = {"portBindings": [{"port": 777, "protocol": "TCP"}, {"port": 888, "protocol": "UDP"}]}
        link = mieru.client_link("a:b @", "p@ss:/?", "example.org", config, profile="my profile")
        self.assertEqual(link, "mierus://a%3Ab%20%40:p%40ss%3A%2F%3F@example.org?"
                              "handshake-mode=HANDSHAKE_NO_WAIT&mtu=1400&multiplexing=MULTIPLEXING_HIGH&"
                              "port=777&protocol=TCP&port=888&protocol=UDP&profile=my%20profile")

    def test_ports_support_range_string_for_ufw(self):
        config = {"portBindings": [{"port": 1234, "protocol": "TCP"},
                                   {"portRange": {"start": 4000, "end": 4010}, "protocol": "UDP"}]}
        self.assertEqual(mieru.ports(config), [(1234, "tcp"), ("4000-4010", "udp")])

    def test_temporary_file_removed_when_mita_fails(self):
        config = {"users": []}
        captured = []

        def fail(cmd, **kwargs):
            captured.append(cmd[-1])
            raise core.Error("mita failed")

        with mock.patch.object(mieru, "describe", return_value=config), mock.patch.object(mieru.core, "run", side_effect=fail):
            with self.assertRaises(core.Error):
                mieru.add_user("user", "password")
        self.assertFalse(Path(captured[0]).exists())

    def test_firewall_commands_and_missing_ufw(self):
        config = {"portBindings": [{"port": 32145, "protocol": "TCP"},
                                   {"portRange": {"start": 4000, "end": 4010}, "protocol": "UDP"}]}
        with mock.patch.object(mieru.shutil, "which", return_value="/usr/sbin/ufw"), \
                mock.patch.object(mieru.core, "run") as run:
            mieru.open_firewall(config)
            mieru.close_firewall(config)
        self.assertEqual([call.args[0] for call in run.call_args_list], [
            ["ufw", "allow", "32145/tcp"], ["ufw", "allow", "4000:4010/udp"],
            ["ufw", "--force", "delete", "allow", "32145/tcp"],
            ["ufw", "--force", "delete", "allow", "4000:4010/udp"]])
        self.assertTrue(all(call.kwargs == {"check": False} for call in run.call_args_list))
        with mock.patch.object(mieru.shutil, "which", return_value=None), mock.patch.object(mieru.core, "run") as run:
            mieru.open_firewall(config)
        run.assert_not_called()


class RealWorldTest(unittest.TestCase):
    """Находки при проверке на живой mita 3.37.0."""

    def test_ufw_range_uses_colon(self):
        calls = []
        from unittest import mock

        from autopilot import core, mieru

        cfg = {"portBindings": [{"protocol": "TCP", "portRange": "32145-32150"}, {"port": 6666, "protocol": "UDP"}]}
        with mock.patch("shutil.which", return_value="/usr/sbin/ufw"), \
                mock.patch.object(core, "run", side_effect=lambda cmd, **k: calls.append(list(cmd))):
            mieru.open_firewall(cfg)
            mieru.close_firewall(cfg)
        self.assertIn(["ufw", "allow", "32145:32150/tcp"], calls)
        self.assertIn(["ufw", "allow", "6666/udp"], calls)
        self.assertIn(["ufw", "--force", "delete", "allow", "32145:32150/tcp"], calls)

    def test_failed_describe_never_becomes_an_empty_config(self):
        from unittest import mock

        from autopilot import core, mieru

        bad = mock.Mock(returncode=1, stdout="", stderr="boom")
        with mock.patch.object(core, "run", side_effect=core.Error("boom")):
            with self.assertRaises(core.Error):
                mieru.add_user("anna")      # replace с пустым конфигом затёр бы чужих пользователей
            with self.assertRaises(core.Error):
                mieru.remove_user("anna")
        with mock.patch.object(core, "run", return_value=bad):
            self.assertEqual(mieru.describe(strict=False), {})

    def test_hashed_password_users_survive_a_round_trip(self):
        import json
        from unittest import mock

        from autopilot import core, mieru

        existing = {"portBindings": [{"protocol": "TCP", "portRange": "32145-32150"}],
                    "users": [{"name": "old", "password": "", "hashedPassword": "abc123"}], "loggingLevel": "INFO"}
        written = {}

        def fake_run(cmd, **kw):
            if cmd[:2] == ["mita", "help"]:
                return mock.Mock(returncode=0, stdout="replace config <JSON_FILE>", stderr="")
            if cmd[:3] == ["mita", "describe", "config"]:
                return mock.Mock(returncode=0, stdout=json.dumps(existing), stderr="")
            if cmd[:3] == ["mita", "replace", "config"]:
                written.update(json.load(open(cmd[3])))
                existing.update(written)  # mita «приняла» конфиг: следующий describe его покажет
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch.object(core, "run", side_effect=fake_run):
            mieru.add_user("anna", "S3cretPassw0rdS3cretPassw0rd")
        old = next(u for u in written["users"] if u["name"] == "old")
        self.assertEqual(old["hashedPassword"], "abc123")
        self.assertEqual(written["portBindings"], existing["portBindings"])
        self.assertEqual(len(written["users"]), 2)

    def test_bad_host_rejected_in_link(self):
        from autopilot import core, mieru

        for bad in ("1.2.3.4/evil", "a b", "host;rm", ""):
            with self.assertRaises(core.Error, msg=bad):
                mieru.client_link("anna", "pw", bad, {"portBindings": [{"port": 6666, "protocol": "TCP"}]})


class StateHooksTest(unittest.TestCase):
    def setUp(self):
        import os
        import tempfile

        self.tmp = tempfile.TemporaryDirectory()
        self.old = os.environ.get("AUTOPILOT_ROOT")
        os.environ["AUTOPILOT_ROOT"] = self.tmp.name

    def tearDown(self):
        import os

        if self.old is None:
            os.environ.pop("AUTOPILOT_ROOT", None)
        else:
            os.environ["AUTOPILOT_ROOT"] = self.old
        self.tmp.cleanup()

    def test_disabled_by_default_and_hooks_do_nothing(self):
        from autopilot import mieru

        self.assertFalse(mieru.enabled())
        self.assertIsNone(mieru.user_added("anna"))
        self.assertIsNone(mieru.link_for("anna", "1.2.3.4"))

    def test_user_hooks_track_our_users_only(self):
        from unittest import mock

        from autopilot import mieru

        mieru.save_state({"enabled": True, "users": {"keep": "pw1"}})
        with mock.patch.object(mieru, "add_user", return_value="pw2") as add, mock.patch.object(mieru, "remove_user") as rm:
            self.assertEqual(mieru.user_added("anna"), "pw2")
            self.assertEqual(mieru.user_added("keep"), "pw1")   # уже есть: пароль не меняется
            add.assert_called_once_with("anna")
            mieru.user_removed("anna")
            rm.assert_called_once_with("anna")
            mieru.user_removed("stranger")                       # чужого не удаляем
            rm.assert_called_once()
        self.assertEqual(sorted(mieru.load_state()["users"]), ["keep"])

    def test_state_file_is_private(self):
        import stat

        from autopilot import core, mieru

        mieru.save_state({"enabled": True, "users": {"a": "p"}})
        self.assertEqual(stat.S_IMODE(core.path(mieru.STATE).stat().st_mode), 0o600)

    def test_disable_removes_only_our_users(self):
        from unittest import mock

        from autopilot import mieru

        mieru.save_state({"enabled": True, "users": {"a": "p", "b": "q"}})
        with mock.patch.object(mieru, "remove_user") as rm:
            mieru.disable()
        self.assertEqual(sorted(c.args[0] for c in rm.call_args_list), ["a", "b"])
        self.assertFalse(mieru.enabled())


class OldMitaTest(unittest.TestCase):
    """mita 3.37.0: `replace config` нет, а `apply config` сам заменяет конфиг целиком (проверено в контейнере)."""

    def test_old_version_gets_the_full_config_through_apply(self):
        current = {"portBindings": [{"port": 32145, "protocol": "TCP"}],
                   "users": [{"name": "route", "password": "", "hashedPassword": "h"}], "loggingLevel": "INFO", "mtu": 0}
        applied = []

        def run(cmd, **kw):
            if cmd[:2] == ["mita", "help"]:
                return SimpleNamespace(returncode=0, stdout="apply config <JSON_FILE>\ndescribe config", stderr="")
            if cmd[:3] == ["mita", "apply", "config"]:
                applied.append(json.loads(Path(cmd[3]).read_text()))
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with mock.patch.object(mieru, "describe", return_value=current), mock.patch.object(mieru.core, "run", side_effect=run), \
                mock.patch.object(mieru, "list_users", return_value=["route", "anna"]):
            mieru.add_user("anna", "pw")
        full = applied[0]
        self.assertEqual(full["portBindings"], current["portBindings"])        # порты не потеряны
        self.assertEqual(full["users"][0], {"name": "route", "password": "", "hashedPassword": "h"})
        self.assertEqual(full["users"][1], {"name": "anna", "password": "pw"})
        self.assertNotIn("mtu", full)                                          # нулевой mtu mita не принимает обратно

    def test_replacing_a_password_drops_the_stale_hash(self):
        current = {"portBindings": [{"port": 1, "protocol": "TCP"}], "users": [{"name": "anna", "password": "", "hashedPassword": "old"}]}
        applied = []

        def run(cmd, **kw):
            if cmd[:2] == ["mita", "help"]:
                return SimpleNamespace(returncode=0, stdout="replace config", stderr="")
            if cmd[:3] == ["mita", "replace", "config"]:
                applied.append(json.loads(Path(cmd[3]).read_text()))
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with mock.patch.object(mieru, "describe", return_value=current), mock.patch.object(mieru.core, "run", side_effect=run), \
                mock.patch.object(mieru, "list_users", return_value=["anna"]):
            mieru.add_user("anna", "newpass")
        self.assertEqual(applied[0]["users"], [{"name": "anna", "password": "newpass"}])

    def test_unaccepted_user_is_reported(self):
        def run(cmd, **kw):
            return SimpleNamespace(returncode=0, stdout="replace config" if cmd[:2] == ["mita", "help"] else "", stderr="")

        with mock.patch.object(mieru, "describe", return_value={"users": []}), mock.patch.object(mieru.core, "run", side_effect=run), \
                mock.patch.object(mieru, "list_users", return_value=[]), self.assertRaises(mieru.core.Error):
            mieru.add_user("anna", "pw")


if __name__ == "__main__":
    unittest.main()


class SingleRangeTest(unittest.TestCase):
    def test_one_port_range_becomes_a_plain_port(self):
        from autopilot import mieru

        cfg = {"portBindings": [{"protocol": "TCP", "portRange": "32145-32145"}, {"protocol": "UDP", "portRange": "4000-4010"}]}
        self.assertEqual(mieru.ports(cfg), [(32145, "tcp"), ("4000-4010", "udp")])
        link = mieru.client_link("anna", "pw", "203.0.113.5", cfg)
        self.assertIn("port=32145&protocol=TCP", link)
        self.assertNotIn("32145-32145", link)
