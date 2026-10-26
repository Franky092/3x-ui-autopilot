"""Клиент панели против локального заглушечного сервера: заголовок токена, конверт ответа, ошибки."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from autopilot import core, panel


class Handler(BaseHTTPRequestHandler):
    seen: list = []

    def log_message(self, *args):  # без шума в выводе тестов
        pass

    def _reply(self, status, payload):
        raw = json.dumps(payload).encode() if not isinstance(payload, bytes) else payload
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode() if length else ""
        Handler.seen.append((self.command, self.path, self.headers.get("Authorization"), body))
        if self.headers.get("Authorization") != "Bearer good":
            return self._reply(401, {"success": False, "msg": "no"})
        route = self.path.split("/panel/api/", 1)[1]
        if route == "clients/list":
            return self._reply(200, {"success": True, "obj": [{"email": "a", "totalGB": 5}]})
        if route == "clients/list-wrapped":
            return self._reply(200, {"success": True, "obj": {"clients": [{"email": "w"}]}})
        if route == "inbounds/list":
            return self._reply(200, {"success": True, "obj": [{"id": 1, "port": 443}]})
        if route == "boom":
            return self._reply(200, {"success": False, "msg": "плохой запрос"})
        if route == "notjson":
            return self._reply(200, b"<html>")
        if route.startswith("clients/del/"):
            return self._reply(200, {"success": True, "obj": None})
        if route.startswith("clients/update/"):
            return self._reply(200, {"success": True, "obj": json.loads(body)})
        if route == "clients/add":
            return self._reply(200, {"success": True, "obj": json.loads(body)})
        return self._reply(404, {"success": False})

    do_GET = do_POST = _handle


class PanelClientTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        Handler.seen = []
        self.api = panel.PanelClient(self.port, "/secret/", "good")

    def test_bearer_token_and_path(self):
        self.assertEqual(self.api.clients(), [{"email": "a", "totalGB": 5}])
        method, path, auth, _ = Handler.seen[0]
        self.assertEqual((method, path, auth), ("GET", "/secret/panel/api/clients/list", "Bearer good"))

    def test_wrapped_clients_list(self):
        self.assertEqual(self.api.request("GET", "clients/list-wrapped"), {"clients": [{"email": "w"}]})

    def test_inbounds(self):
        self.assertEqual(self.api.inbounds()[0]["port"], 443)

    def test_bad_token_is_a_clear_error(self):
        bad = panel.PanelClient(self.port, "secret", "wrong")
        with self.assertRaises(core.Error) as ctx:
            bad.clients()
        self.assertIn("Токен API", str(ctx.exception))

    def test_success_false_raises(self):
        with self.assertRaises(core.Error) as ctx:
            self.api.request("GET", "boom")
        self.assertIn("плохой запрос", str(ctx.exception))

    def test_non_json_raises(self):
        with self.assertRaises(core.Error):
            self.api.request("GET", "notjson")

    def test_email_is_url_quoted(self):
        self.api.del_client("a/b c")
        self.assertTrue(Handler.seen[0][1].endswith("/clients/del/a%2Fb%20c"))

    def test_add_client_body(self):
        self.api.add_client({"email": "x"}, [1, 2])
        self.assertEqual(json.loads(Handler.seen[0][3]), {"client": {"email": "x"}, "inboundIds": [1, 2]})

    def test_link_host_is_replaced(self):
        link = "vless://uuid-1@localhost:443?flow=xtls-rprx-vision&sni=a.b#x"
        self.assertEqual(panel.with_host(link, "203.0.113.5"), "vless://uuid-1@203.0.113.5:443?flow=xtls-rprx-vision&sni=a.b#x")
        self.assertEqual(panel.with_host("vless://u@host.example:8443?x=1", "1.2.3.4"), "vless://u@1.2.3.4:8443?x=1")
        self.assertEqual(panel.with_host("not a link", "1.2.3.4"), "not a link")
        self.assertEqual(panel.with_host("tg://proxy?port=443&secret=ee1&server=localhost", "1.2.3.4"),
                         "tg://proxy?port=443&secret=ee1&server=1.2.3.4")
        self.assertEqual(panel.with_host("tg://proxy?port=18445&secret=ee1&server=localhost", "1.2.3.4"),
                         "tg://proxy?port=443&secret=ee1&server=1.2.3.4")

    def test_set_client_fields_sends_safe_body(self):
        # у записи в списке числовой id БД и uuid: в запрос обновления они попадать не должны
        self.api.clients = lambda: [{"id": 7, "uuid": "u-1", "email": "a", "subId": "s", "totalGB": 5, "expiryTime": 0,
                                     "limitIp": 0, "enable": True, "comment": "c", "privateKey": "secret"}]
        self.api.set_client_fields("a", enable=False)
        method, path, _, body = Handler.seen[-1]
        sent = json.loads(body)
        self.assertTrue(path.endswith("/clients/update/a"))
        self.assertEqual(sent["enable"], False)
        self.assertEqual(sent["totalGB"], 5)
        self.assertNotIn("id", sent)
        self.assertNotIn("privateKey", sent)

    def test_set_client_fields_validation(self):
        self.api.clients = lambda: [{"email": "a"}]
        with self.assertRaises(core.Error):
            self.api.set_client_fields("a", password="x")
        with self.assertRaises(core.Error):
            self.api.set_client_fields("missing", enable=False)

    def test_closed_port_is_a_clear_error(self):
        dead = panel.PanelClient(1, "p", "good", timeout=1)
        with self.assertRaises(core.Error):
            dead.clients()

    def test_invalid_port_rejected(self):
        with self.assertRaises(core.Error):
            panel.PanelClient(0, "p", "t")


if __name__ == "__main__":
    unittest.main()
