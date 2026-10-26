"""Рендер конфигурации nginx: маршруты SNI, пути WS/gRPC, защита от вредных значений."""
import unittest

from autopilot import core, nginx


def layout(**kw):
    base = dict(sni_routes={"www.microsoft.com": 10443, "dl.google.com": 10444}, cert_file="/c.pem", key_file="/k.pem")
    base.update(kw)
    return nginx.Layout(**base)


class RenderTest(unittest.TestCase):
    def test_stream_map_and_default(self):
        conf = nginx.render(layout())
        self.assertIn("www.microsoft.com 127.0.0.1:10443;", conf)
        self.assertIn("dl.google.com 127.0.0.1:10444;", conf)
        self.assertIn("default 127.0.0.1:%d;" % nginx.HTTPS_PORT, conf)
        self.assertIn("ssl_preread on;", conf)
        self.assertIn("listen 443;", conf)

    def test_ws_and_grpc_locations(self):
        conf = nginx.render(layout(routes=[nginx.Route("/ws1", 11001, "ws"), nginx.Route("/svc", 11003, "grpc")]))
        self.assertIn("location /ws1 {", conf)
        self.assertIn("proxy_pass http://127.0.0.1:11001;", conf)
        self.assertIn('proxy_set_header Connection "upgrade";', conf)
        self.assertIn("grpc_pass grpc://127.0.0.1:11003;", conf)

    def test_subscription_locations(self):
        conf = nginx.render(layout(sub_paths=["/s3cr3t/", "/j50n/", "/cl4sh/"], sub_port=2096))
        for path in ("/s3cr3t/", "/j50n/", "/cl4sh/"):
            self.assertIn("location %s {" % path, conf)
        self.assertEqual(conf.count("proxy_pass http://127.0.0.1:2096;"), 3)
        self.assertIn("proxy_set_header User-Agent $http_user_agent;", conf)

    def test_tls_files_and_loopback_only(self):
        conf = nginx.render(layout())
        self.assertIn("ssl_certificate /c.pem;", conf)
        self.assertIn("listen 127.0.0.1:%d ssl http2;" % nginx.HTTPS_PORT, conf)

    def test_hostile_values_rejected(self):
        for bad in (layout(sni_routes={"a.com; evil": 1}), layout(sni_routes={"a.com": 70000}),
                    layout(routes=[nginx.Route("/x; return 200", 1, "ws")]), layout(routes=[nginx.Route("/x", 1, "tcp")]),
                    layout(cert_file="")):
            with self.assertRaises(core.Error):
                nginx.render(bad)

    def test_sni_order_is_stable(self):
        a = nginx.render(layout(sni_routes={"b.com": 2, "a.com": 1}))
        b = nginx.render(layout(sni_routes={"a.com": 1, "b.com": 2}))
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
