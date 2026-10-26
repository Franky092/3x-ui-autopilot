"""Сборщики протоколов: форма тела запроса и параметры AmneziaWG."""
import base64
import json
import random
import unittest

from autopilot import protocols as P


class ProtocolsTest(unittest.TestCase):
    def test_proxied_inbounds_listen_on_loopback_and_advertise_public_tls(self):
        for body in (P.vless_ws(1, "/p", "1.2.3.4"), P.vmess_ws(2, "/q", "1.2.3.4"), P.trojan_grpc(3, "svc", "1.2.3.4")):
            self.assertEqual(body["listen"], "127.0.0.1")
            ext = json.loads(body["streamSettings"])["externalProxy"][0]
            self.assertEqual((ext["dest"], ext["port"], ext["forceTls"]), ("1.2.3.4", 443, "tls"))

    def test_ss2022_key_is_16_bytes(self):
        self.assertEqual(len(base64.b64decode(P.ss2022_key())), 16)
        self.assertEqual(json.loads(P.shadowsocks(8388)["settings"])["method"], "2022-blake3-aes-128-gcm")

    def test_hysteria_and_tuic_use_given_certificate(self):
        h = json.loads(P.hysteria2(443, "/c.pem", "/k.pem")["streamSettings"])
        self.assertEqual(h["tlsSettings"]["certificates"][0]["certificateFile"], "/c.pem")
        self.assertEqual(h["network"], "hysteria")
        t = json.loads(P.tuic(8444, "/c.pem", "/k.pem")["settings"])
        self.assertEqual((t["certificate"], t["private_key"]), ("/c.pem", "/k.pem"))

    def test_mtproto_settings(self):
        body = P.mtproto(9000, "www.samsung.com", "1.2.3.4")
        self.assertEqual(json.loads(body["settings"])["fakeTlsDomain"], "www.samsung.com")
        self.assertEqual(body["listen"], "127.0.0.1")

    def test_awg_obfuscation_is_not_plain_wireguard(self):
        for seed in range(50):
            rng = random.Random(seed)
            legacy = P.awg_obfuscation(False, rng)
            self.assertGreaterEqual(legacy["jc"], 4)
            self.assertLess(legacy["jmin"], legacy["jmax"])
            self.assertNotEqual(legacy["s2"], legacy["s1"] + 56)
            heads = {legacy["h1"], legacy["h2"], legacy["h3"], legacy["h4"]}
            self.assertEqual(len(heads), 4)
            self.assertTrue(all(int(h) >= 5 for h in heads))
            v31 = P.awg_obfuscation(True, rng)
            self.assertEqual(v31["i1"], "<r 69>")
            self.assertLessEqual(v31["s4"], 32)

    def test_awg_body_embeds_obfuscation(self):
        server = json.loads(P.amneziawg(51821, "10.8.1.0", "1.1.1.1")["settings"])["server"]
        self.assertGreater(server["jc"], 0)
        self.assertEqual(server["subnetIp"], "10.8.1.0")


if __name__ == "__main__":
    unittest.main()
