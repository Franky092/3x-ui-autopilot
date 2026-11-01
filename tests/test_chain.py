"""Каскад: токен, шаблон Xray, выход (relay) и вход (chain)."""
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from autopilot import chain, core, inbounds, sync

KEY = "A" * 43
UUID_A = "11111111-1111-4111-8111-111111111111"
UUID_B = "22222222-2222-4222-8222-222222222222"
UUID_RELAY = "33333333-3333-4333-8333-333333333333"
KEYS = {"privateKey": KEY, "publicKey": "B" * 43}

TEMPLATE = {
    "inbounds": [{"tag": "api", "port": 62789}],
    "outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "blocked", "protocol": "blackhole"}],
    "routing": {"rules": [{"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
                          {"type": "field", "outboundTag": "blocked", "protocol": ["bittorrent"]}]},
}


class FakeApi:
    def __init__(self, host="203.0.113.5"):
        self.host = host
        self.items = [
            inbounds.reality_inbound(10443, "a.example.com", KEYS, "ab12", host=host) | {"id": 1, "tag": "inbound-10443"},
            inbounds.xhttp_inbound(10444, "b.example.com", KEYS, "cd34", path="/xp", host=host) | {"id": 2, "tag": "inbound-10444"},
            {"id": 3, "remark": "Shadowsocks", "tag": "inbound-8388", "port": 8388, "protocol": "shadowsocks", "listen": "",
             "settings": "{}", "streamSettings": "{}"},
        ]
        self.users = {}
        self.next_id = 10

    def inbounds(self):
        return self.items

    def clients(self):
        return [{"email": e, "uuid": v["id"], "subId": v["subId"]} for e, v in self.users.items()]

    def add_inbound(self, body):
        self.next_id += 1
        self.items.append(dict(body, id=self.next_id, tag="inbound-%d" % body["port"]))
        return {}

    def del_inbound(self, inbound_id):
        self.items = [i for i in self.items if i["id"] != inbound_id]

    def update_inbound(self, inbound_id, body):
        for i, item in enumerate(self.items):
            if item["id"] == inbound_id:
                self.items[i] = dict(item, **body)

    def new_x25519(self):
        return {"privateKey": "C" * 43, "publicKey": "D" * 43}

    def new_uuid(self):
        return UUID_RELAY

    def add_client(self, client, ids):
        self.users[client["email"]] = client
        for item in self.items:
            if item["id"] in ids and item["remark"] in ("REALITY", "XHTTP", "Relay"):
                settings = json.loads(item["settings"])
                settings["clients"] = settings.get("clients", []) + [client]
                item["settings"] = json.dumps(settings)

    def del_client(self, email):
        self.users.pop(email, None)
        for item in self.items:
            settings = json.loads(item["settings"] or "{}")
            if "clients" in settings:
                settings["clients"] = [c for c in settings["clients"] if c.get("email") != email]
                item["settings"] = json.dumps(settings)


def add_user(api, email, uuid, sub):
    api.add_client({"email": email, "id": uuid, "subId": sub, "flow": "xtls-rprx-vision"}, [1, 2])


ok_site = lambda host: True  # noqa: E731


class TokenTest(unittest.TestCase):
    def data(self):
        return {"v": 1, "exit": {"host": "203.0.113.5", "sni": "r.example.com", "pbk": KEY, "sid": "abcd", "uuid": UUID_RELAY},
                "inbounds": {"REALITY": {"sni": "a.example.com", "private": KEY, "public": KEY, "sid": "ab12"}},
                "users": [{"email": "admin", "id": UUID_A, "subId": "abc123"}]}

    def test_roundtrip(self):
        data = self.data()
        self.assertEqual(chain.decode_token(chain.encode_token(data)), data)

    def test_whitespace_from_terminal_paste_is_ignored(self):
        token = chain.encode_token(self.data())
        self.assertEqual(chain.decode_token(token[:20] + "\n  " + token[20:])["exit"]["host"], "203.0.113.5")

    def test_garbage_is_refused(self):
        for bad in ("", "hello", "ap1:", "ap1:!!!", "ap1:" + "A" * 40):
            with self.assertRaises(core.Error):
                chain.decode_token(bad)

    def test_hostile_fields_are_refused(self):
        for mutate in (
            lambda d: d["exit"].update(host="1.2.3.4;rm"), lambda d: d["exit"].update(uuid="nope"),
            lambda d: d["exit"].update(sni="bad host"), lambda d: d["inbounds"].update(MTProto={}),
            lambda d: d["users"].append({"email": "../x", "id": UUID_B, "subId": "q"}),
            lambda d: d["users"].append({"email": "ok", "id": UUID_B, "subId": "a b"}),
            lambda d: d.update(v=2),
        ):
            data = self.data()
            mutate(data)
            with self.assertRaises(core.Error, msg=str(data)):
                chain.decode_token(chain.encode_token(data))


class TemplateTest(unittest.TestCase):
    def test_chain_is_added_last_and_removed_cleanly(self):
        exit_ = {"host": "203.0.113.9", "sni": "r.example.com", "pbk": KEY, "sid": "ab", "uuid": UUID_RELAY}
        config = chain.with_chain(TEMPLATE, exit_, ["inbound-10444", "inbound-10443"])
        self.assertEqual(config["routing"]["rules"][-1], {"type": "field", "inboundTag": ["inbound-10443", "inbound-10444"], "outboundTag": "autopilot-exit"})
        self.assertEqual(config["routing"]["rules"][:2], TEMPLATE["routing"]["rules"])
        out = config["outbounds"][-1]
        self.assertEqual(out["settings"]["vnext"][0]["users"][0]["flow"], "xtls-rprx-vision")
        self.assertEqual(out["streamSettings"]["realitySettings"]["publicKey"], KEY)
        self.assertEqual(chain.without_chain(config), TEMPLATE)

    def test_applying_twice_does_not_duplicate(self):
        exit_ = {"host": "203.0.113.9", "sni": "r.example.com", "pbk": KEY, "sid": "ab", "uuid": UUID_RELAY}
        once = chain.with_chain(TEMPLATE, exit_, ["t"])
        twice = chain.with_chain(once, exit_, ["t"])
        self.assertEqual(once, twice)

    def test_input_template_is_not_mutated(self):
        before = json.dumps(TEMPLATE, sort_keys=True)
        chain.with_chain(TEMPLATE, {"host": "1.1.1.1", "sni": "x.com", "pbk": KEY, "sid": "ab", "uuid": UUID_A}, ["t"])
        self.assertEqual(json.dumps(TEMPLATE, sort_keys=True), before)

    def test_only_chained_inbounds_get_tags(self):
        self.assertEqual(chain.chain_tags(FakeApi().inbounds()), ["inbound-10443", "inbound-10444"])


class DbTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old = os.environ.get("AUTOPILOT_ROOT")
        os.environ["AUTOPILOT_ROOT"] = self.tmp.name
        db = Path(self.tmp.name, "etc/x-ui/x-ui.db")
        db.parent.mkdir(parents=True)
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE settings (id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT, value TEXT)")
        conn.commit()
        conn.close()

    def tearDown(self):
        if self.old is None:
            os.environ.pop("AUTOPILOT_ROOT")
        else:
            os.environ["AUTOPILOT_ROOT"] = self.old
        self.tmp.cleanup()

    def write_generated(self):
        path = Path(self.tmp.name, chain.GENERATED)
        path.parent.mkdir(parents=True)
        generated = dict(TEMPLATE, inbounds=TEMPLATE["inbounds"] + [{"tag": "inbound-10443"}])
        path.write_text(json.dumps(generated))

    def test_template_falls_back_to_generated_config_without_user_inbounds(self):
        self.write_generated()
        self.assertEqual(chain.read_template(), TEMPLATE)

    def test_missing_template_is_a_clear_error(self):
        with self.assertRaises(core.Error):
            chain.read_template()

    def test_write_then_read_roundtrip_and_update(self):
        chain.write_template(TEMPLATE)
        chain.write_template(dict(TEMPLATE, log={}))
        self.assertEqual(chain.read_template()["log"], {})
        conn = sqlite3.connect(Path(self.tmp.name, chain.DB))
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM settings WHERE key='xrayTemplateConfig'").fetchone()[0], 1)
        conn.close()

    def test_enable_rolls_back_template_when_panel_does_not_start(self):
        chain.write_template(TEMPLATE)
        api = FakeApi()
        data = TokenTest().data()
        calls = []

        def restart():
            calls.append(chain.active_exit(chain.read_template()))
            if len(calls) == 1:
                raise core.Error("не запустилось")

        with self.assertRaises(core.Error):
            chain.enable(api, data, restart)
        self.assertIsNotNone(calls[0])         # на первый запуск шаблон с каскадом
        self.assertIsNone(calls[1])            # потом возвращён прежний
        self.assertIsNone(chain.active_exit(chain.read_template()))

    def test_enable_then_disable(self):
        chain.write_template(TEMPLATE)
        api = FakeApi()
        chain.enable(api, TokenTest().data(), lambda: None)
        self.assertEqual(chain.active_exit(chain.read_template())["host"], "203.0.113.5")
        self.assertTrue(chain.disable(lambda: None))
        self.assertFalse(chain.disable(lambda: None))
        self.assertEqual(chain.read_template(), TEMPLATE)


class RelayTest(unittest.TestCase):
    def test_relay_creates_one_extra_reality_inbound_with_own_sni_and_no_managed_users(self):
        api = FakeApi()
        state = chain.relay_on(api, "203.0.113.5", check=ok_site)
        item = chain.relay_state(api)["item"]
        self.assertEqual((item["remark"], item["listen"], item["port"]), ("Relay", "127.0.0.1", chain.RELAY_PORT))
        self.assertNotIn(state["sni"], ("a.example.com", "b.example.com"))
        self.assertEqual(state["uuid"], UUID_RELAY)
        self.assertNotIn("Relay", inbounds.MANAGED)

    def test_relay_on_is_idempotent(self):
        api = FakeApi()
        first = chain.relay_on(api, "203.0.113.5", check=ok_site)
        second = chain.relay_on(api, "203.0.113.5", check=ok_site)
        self.assertEqual((first["sni"], first["uuid"], first["public"]), (second["sni"], second["uuid"], second["public"]))
        self.assertEqual(len([i for i in api.inbounds() if i["remark"] == "Relay"]), 1)

    def test_relay_site_must_be_free(self):
        with self.assertRaises(core.Error):
            chain.relay_on(FakeApi(), "203.0.113.5", sni="a.example.com", check=ok_site)

    def test_nginx_routes_relay_by_sni(self):
        api = FakeApi()
        chain.relay_on(api, "203.0.113.5", check=ok_site)
        layout = sync.layout_from_inbounds(api.inbounds(), "/c", "/k")
        self.assertEqual(layout.sni_routes[chain.relay_state(api)["sni"]], chain.RELAY_PORT)

    def test_token_carries_exit_mirror_and_users_but_not_the_relay_user(self):
        api = FakeApi()
        add_user(api, "admin", UUID_A, "abc123")
        chain.relay_on(api, "203.0.113.5", check=ok_site)
        data = chain.decode_token(chain.make_token(api, "203.0.113.5"))
        self.assertEqual([u["email"] for u in data["users"]], ["admin"])
        self.assertEqual(data["exit"]["uuid"], UUID_RELAY)
        self.assertEqual(set(data["inbounds"]), {"REALITY", "XHTTP"})
        self.assertEqual(data["inbounds"]["XHTTP"]["path"], "/xp")
        self.assertEqual(data["inbounds"]["REALITY"]["private"], KEY)

    def test_token_without_relay_is_refused(self):
        with self.assertRaises(core.Error):
            chain.make_token(FakeApi(), "203.0.113.5")

    def test_entry_link_added_and_removed_without_touching_direct_one(self):
        api = FakeApi()
        self.assertEqual(chain.set_entry(api, "198.51.100.7", "203.0.113.5"), ["REALITY", "XHTTP"])
        for item in api.inbounds()[:2]:
            dests = [(p["dest"], p["remark"]) for p in json.loads(item["streamSettings"])["externalProxy"]]
            self.assertEqual(dests, [("203.0.113.5", ""), ("198.51.100.7", "via-entry")])
        chain.set_entry(api, "198.51.100.8", "203.0.113.5")
        self.assertEqual(len(json.loads(api.inbounds()[0]["streamSettings"])["externalProxy"]), 2)
        chain.set_entry(api, None, "203.0.113.5")
        self.assertEqual(len(json.loads(api.inbounds()[0]["streamSettings"])["externalProxy"]), 1)

    def test_entry_must_differ_and_be_ipv4(self):
        for bad in ("203.0.113.5", "example.com", "1.2.3"):
            with self.assertRaises(core.Error):
                chain.set_entry(FakeApi(), bad, "203.0.113.5")

    def test_relay_off_removes_everything(self):
        api = FakeApi()
        chain.relay_on(api, "203.0.113.5", check=ok_site)
        self.assertTrue(chain.relay_off(api))
        self.assertIsNone(chain.relay_state(api))
        self.assertFalse(chain.relay_off(api))


class MirrorTest(unittest.TestCase):
    def test_entry_takes_keys_sites_path_and_users_from_the_token(self):
        exit_api, entry = FakeApi("203.0.113.5"), FakeApi("198.51.100.7")
        exit_api.items[1]["streamSettings"] = exit_api.items[1]["streamSettings"].replace("b.example.com", "x.example.com")
        add_user(exit_api, "admin", UUID_A, "abc123")
        add_user(exit_api, "phone", UUID_B, "def456")
        chain.relay_on(exit_api, "203.0.113.5", check=ok_site)
        data = chain.decode_token(chain.make_token(exit_api, "203.0.113.5"))

        changes = chain.apply_mirror(entry, data)

        self.assertEqual(changes["inbounds"], ["REALITY", "XHTTP"])
        real = json.loads(entry.items[0]["streamSettings"])["realitySettings"]
        self.assertEqual((real["privateKey"], real["shortIds"], real["serverNames"]), (KEY, ["ab12"], ["a.example.com"]))
        self.assertEqual(json.loads(entry.items[1]["streamSettings"])["xhttpSettings"]["path"], "/xp")
        self.assertEqual(json.loads(entry.items[0]["streamSettings"])["externalProxy"][0]["dest"], "198.51.100.7")
        self.assertEqual({u: (c["id"], c["subId"]) for u, c in entry.users.items()},
                         {"admin": (UUID_A, "abc123"), "phone": (UUID_B, "def456")})

    def test_rerun_keeps_unchanged_users_and_replaces_clashing_ones(self):
        entry = FakeApi("198.51.100.7")
        add_user(entry, "admin", "44444444-4444-4444-8444-444444444444", "oldsub")   # свой admin с другим UUID
        data = TokenTest().data()
        first = chain.apply_mirror(entry, data)
        self.assertEqual((first["users_added"], first["users_replaced"]), ([], ["admin"]))
        self.assertEqual(entry.users["admin"]["id"], UUID_A)
        again = chain.apply_mirror(entry, data)
        self.assertEqual((again["users_added"], again["users_replaced"]), ([], []))

    def test_users_missing_from_token_are_removed_and_uuid_change_applied(self):
        entry = FakeApi("198.51.100.7")
        add_user(entry, "gone", UUID_B, "zzz")
        add_user(entry, "admin", UUID_B, "abc123")      # тот же subId, но UUID другой
        changes = chain.apply_mirror(entry, TokenTest().data())
        self.assertEqual(changes["users_removed"], ["gone"])
        self.assertEqual(changes["users_replaced"], ["admin"])
        self.assertEqual(entry.users["admin"]["id"], UUID_A)

    def test_missing_inbound_changes_nothing(self):
        entry = FakeApi("198.51.100.7")
        entry.items = [i for i in entry.items if i["remark"] != "XHTTP"]
        data = TokenTest().data()
        data["inbounds"]["XHTTP"] = {"sni": "b.example.com", "private": KEY, "public": KEY, "sid": "cd34"}
        before = json.dumps(entry.items, sort_keys=True)
        with self.assertRaises(core.Error):
            chain.apply_mirror(entry, data)
        self.assertEqual(json.dumps(entry.items, sort_keys=True), before)

    def test_stale_rule_detected_and_refreshed(self):
        entry = FakeApi("198.51.100.7")
        template = chain.with_chain(TEMPLATE, TokenTest().data()["exit"], chain.chain_tags(entry.inbounds()))
        self.assertFalse(chain.stale_rule(entry, template))
        entry.items[0]["tag"] = "inbound-20000"
        self.assertTrue(chain.stale_rule(entry, template))

    def test_entry_without_server_install_is_refused(self):
        entry = FakeApi()
        entry.items = []
        with self.assertRaises(core.Error):
            chain.apply_mirror(entry, TokenTest().data())


if __name__ == "__main__":
    unittest.main()
