"""Сборщики подключений и записей клиентов."""
import json
import unittest

from autopilot import core, inbounds

KEYS = {"privateKey": "priv", "publicKey": "pub"}


class FakeApi:
    def __init__(self, existing=None, inbound_list=None):
        self.existing = existing or []
        self.inbound_list = inbound_list if inbound_list is not None else [{"id": 1, "remark": "REALITY"}, {"id": 2, "remark": "XHTTP"}]
        self.added = []

    def clients(self):
        return self.existing

    def inbounds(self):
        return self.inbound_list

    def new_uuid(self):
        return "uuid-1"

    def new_x25519(self):
        return dict(KEYS)

    def add_inbound(self, body):
        self.added.append(body)
        return {"id": len(self.added), "remark": body["remark"], "port": body["port"]}

    def add_client(self, client, ids):
        self.added.append((client, ids))


class InboundsTest(unittest.TestCase):
    def test_reality_shape(self):
        ib = inbounds.reality_inbound(443, "www.example.com", KEYS, "ab12")
        stream = json.loads(ib["streamSettings"])
        self.assertEqual(ib["protocol"], "vless")
        self.assertEqual(stream["network"], "tcp")
        self.assertEqual(stream["security"], "reality")
        real = stream["realitySettings"]
        self.assertEqual(real["target"], "www.example.com:443")
        self.assertEqual(real["serverNames"], ["www.example.com"])
        self.assertEqual(real["shortIds"], ["ab12"])
        self.assertEqual(real["settings"]["publicKey"], "pub")
        self.assertEqual(json.loads(ib["settings"])["decryption"], "none")

    def test_xhttp_shape(self):
        stream = json.loads(inbounds.xhttp_inbound(8443, "a.example.com", KEYS, "cd", path="/p")["streamSettings"])
        self.assertEqual(stream["network"], "xhttp")
        self.assertEqual(stream["xhttpSettings"]["path"], "/p")

    def test_xhttp_random_path(self):
        path = json.loads(inbounds.xhttp_inbound(8443, "a.example.com", KEYS, "cd")["streamSettings"])["xhttpSettings"]["path"]
        self.assertRegex(path, r"^/[0-9a-f]{12}$")

    def test_defaults_use_separate_keys_and_ports(self):
        api = FakeApi()
        made = inbounds.create_defaults(api, reality_port=443, xhttp_port=8443, sni="a.example.com", xhttp_sni="b.example.com")
        self.assertEqual([m["port"] for m in made], [443, 8443])
        self.assertEqual({b["remark"] for b in api.added}, {"REALITY", "XHTTP"})

    def test_proxied_reality_listens_on_loopback_and_advertises_443(self):
        ib = inbounds.reality_inbound(10443, "www.example.com", KEYS, "ab12", host="203.0.113.5")
        self.assertEqual(ib["listen"], "127.0.0.1")
        ext = json.loads(ib["streamSettings"])["externalProxy"][0]
        self.assertEqual((ext["dest"], ext["port"], ext["forceTls"]), ("203.0.113.5", 443, "same"))
        self.assertEqual(inbounds.reality_inbound(443, "a.example.com", KEYS, "ab")["listen"], "")

    def test_client_limits(self):
        c = inbounds.new_client("anna", "u", gb=5, days=1, devices=2, now=0)
        self.assertEqual(c["totalGB"], 5 * 1024 ** 3)
        self.assertEqual(c["expiryTime"], 86400000)
        self.assertEqual(c["limitIp"], 2)
        self.assertEqual(inbounds.new_client("bob", "u", now=0)["expiryTime"], 0)

    def test_bad_names_and_limits(self):
        for bad in ("", "..", "a b", "x" * 33, "a/b"):
            with self.assertRaises(core.Error, msg=bad):
                inbounds.valid_name(bad)
        with self.assertRaises(core.Error):
            inbounds.new_client("anna", "u", gb=10 ** 7)

    def test_add_user_attaches_to_both(self):
        api = FakeApi()
        inbounds.add_user(api, "anna", gb=1)
        client, ids = api.added[0]
        self.assertEqual((client["email"], ids), ("anna", [1, 2]))

    def test_duplicate_user_rejected(self):
        with self.assertRaises(core.Error):
            inbounds.add_user(FakeApi(existing=[{"email": "anna"}]), "anna")

    def test_add_user_without_inbounds(self):
        with self.assertRaises(core.Error):
            inbounds.add_user(FakeApi(inbound_list=[]), "anna")


if __name__ == "__main__":
    unittest.main()
