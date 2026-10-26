"""Смена сайтов-прикрытий и портов."""
import json
import unittest
from unittest import mock

from autopilot import core, inbounds, net, protocols as P

KEYS = {"privateKey": "p", "publicKey": "q"}


class FakeApi:
    def __init__(self):
        self.items = [
            inbounds.reality_inbound(10443, "a.example.com", KEYS, "ab", host="203.0.113.5") | {"id": 1},
            inbounds.xhttp_inbound(10444, "b.example.com", KEYS, "cd", host="203.0.113.5") | {"id": 2},
            P.mtproto(10445, "c.example.com", "203.0.113.5") | {"id": 3},
            P.shadowsocks(8388) | {"id": 4},
            P.tuic(8444, "/c", "/k") | {"id": 5},
        ]
        self.updated = {}

    def inbounds(self):
        return self.items

    def update_inbound(self, inbound_id, body):
        self.updated[inbound_id] = body


ok = lambda host: True  # noqa: E731


class SiteTest(unittest.TestCase):
    def test_reality_site_changes_target_and_names_but_not_keys(self):
        api = FakeApi()
        self.assertEqual(net.set_site(api, "reality", "new.example.com", check=ok), "a.example.com")
        stream = json.loads(api.updated[1]["streamSettings"])
        real = stream["realitySettings"]
        self.assertEqual((real["target"], real["serverNames"]), ("new.example.com:443", ["new.example.com"]))
        self.assertEqual((real["privateKey"], real["shortIds"]), ("p", ["ab"]))
        self.assertEqual(stream["externalProxy"][0]["dest"], "203.0.113.5")

    def test_mtproto_site_changes_fake_tls_domain(self):
        api = FakeApi()
        net.set_site(api, "mtproto", "tg.example.com", check=ok)
        self.assertEqual(json.loads(api.updated[3]["settings"])["fakeTlsDomain"], "tg.example.com")

    def test_site_used_by_another_connection_is_refused(self):
        api = FakeApi()
        with self.assertRaises(core.Error):
            net.set_site(api, "reality", "b.example.com", check=ok)
        self.assertEqual(api.updated, {})

    def test_site_without_tls13_h2_is_refused(self):
        with self.assertRaises(core.Error):
            net.set_site(FakeApi(), "xhttp", "old.example.com", check=lambda h: False)

    def test_bad_input(self):
        for which, host in (("nope", "x.example.com"), ("reality", "bad host"), ("reality", "a.com;evil")):
            with self.assertRaises(core.Error):
                net.set_site(FakeApi(), which, host, check=ok)

    def test_overview(self):
        rows = {r["remark"]: r for r in net.overview(FakeApi())}
        self.assertEqual(rows["REALITY"]["site"], "a.example.com")
        self.assertEqual(rows["REALITY"]["public"], "443 (nginx)")
        self.assertEqual(rows["MTProto"]["site"], "c.example.com")
        self.assertEqual(rows["Shadowsocks"]["public"], "8388")


class PortTest(unittest.TestCase):
    def run_set(self, api, name, port, listening=""):
        calls = []
        done = mock.Mock(returncode=0, stdout=listening, stderr="")

        def fake(cmd, **kw):
            calls.append(list(cmd))
            return done

        with mock.patch.object(core, "run", side_effect=fake):
            result = net.set_port(api, name, port)
        return result, calls

    def test_port_change_swaps_ufw_rules_for_both_protocols(self):
        api = FakeApi()
        old, calls = self.run_set(api, "shadowsocks", 9388)
        self.assertEqual(old, 8388)
        self.assertEqual(api.updated[4]["port"], 9388)
        self.assertIn(["ufw", "allow", "9388/tcp"], calls)
        self.assertIn(["ufw", "allow", "9388/udp"], calls)
        self.assertIn(["ufw", "--force", "delete", "allow", "8388/tcp"], calls)
        self.assertIn(["ufw", "--force", "delete", "allow", "8388/udp"], calls)

    def test_udp_only_protocol(self):
        api = FakeApi()
        _, calls = self.run_set(api, "tuic", 9444)
        self.assertEqual([c for c in calls if c[0] == "ufw"],
                         [["ufw", "allow", "9444/udp"], ["ufw", "--force", "delete", "allow", "8444/udp"]])

    def test_busy_or_invalid_ports_are_refused_before_any_change(self):
        for port in (10443, 22, 0, 70000, True):
            api = FakeApi()
            with self.assertRaises(core.Error, msg=str(port)):
                self.run_set(api, "shadowsocks", port, listening="LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n")
            self.assertEqual(api.updated, {})

    def test_same_port_is_a_no_op(self):
        api = FakeApi()
        old, calls = self.run_set(api, "shadowsocks", 8388)
        self.assertEqual((old, calls, api.updated), (8388, [], {}))

    def test_cannot_change_ports_of_connections_behind_nginx(self):
        with self.assertRaises(core.Error):
            net.set_port(FakeApi(), "reality", 12345)


if __name__ == "__main__":
    unittest.main()
