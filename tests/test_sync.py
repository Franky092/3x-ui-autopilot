"""Конфиг nginx из подключений панели."""
import unittest

from autopilot import core, inbounds, nginx, protocols as P, sync

KEYS = {"privateKey": "p", "publicKey": "q"}


def items():
    return [
        inbounds.reality_inbound(10443, "a.example.com", KEYS, "ab", host="203.0.113.5"),
        inbounds.xhttp_inbound(10444, "b.example.com", KEYS, "cd", host="203.0.113.5"),
        P.mtproto(10445, "c.example.com", "203.0.113.5"),
        P.vless_ws(11001, "/ws1", "203.0.113.5"),
        P.vmess_ws(11002, "/ws2", "203.0.113.5"),
        P.trojan_grpc(11003, "svc", "203.0.113.5"),
        P.shadowsocks(8388),          # публичный: nginx не касается
        P.hysteria2(443, "/c", "/k"),  # UDP: nginx не касается
    ]


class SyncTest(unittest.TestCase):
    def test_routes_built_from_inbounds(self):
        layout = sync.layout_from_inbounds(items(), "/c.pem", "/k.pem", sub_paths=["/sub1/"], sub_port=2096)
        self.assertEqual(layout.sni_routes, {"a.example.com": 10443, "b.example.com": 10444, "c.example.com": 10445})
        self.assertEqual({(r.path, r.port, r.kind) for r in layout.routes},
                         {("/ws1", 11001, "ws"), ("/ws2", 11002, "ws"), ("/svc", 11003, "grpc")})
        conf = nginx.render(layout)
        self.assertIn("a.example.com 127.0.0.1:10443;", conf)
        self.assertIn("grpc_pass grpc://127.0.0.1:11003;", conf)

    def test_disabled_inbound_is_skipped(self):
        data = items()
        data[0]["enable"] = False
        layout = sync.layout_from_inbounds(data, "/c.pem", "/k.pem")
        self.assertNotIn("a.example.com", layout.sni_routes)

    def test_duplicate_sni_rejected(self):
        data = items()
        data.append(P.mtproto(10446, "a.example.com", "203.0.113.5"))
        with self.assertRaises(core.Error):
            sync.layout_from_inbounds(data, "/c.pem", "/k.pem")


if __name__ == "__main__":
    unittest.main()
