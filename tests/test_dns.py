"""Собственный DNS: конфиг, пакеты запросов, ожидание готовности, откат."""
import os
import socket
import struct
import tempfile
import threading
import unittest
from unittest import mock

from autopilot import core, dns


class ConfigTest(unittest.TestCase):
    def test_only_the_server_itself_may_ask(self):
        conf = dns.config_text("203.0.113.5")
        self.assertIn("interface: 127.0.0.1@5353", conf)
        self.assertIn("interface: 203.0.113.5@53", conf)
        self.assertIn("access-control: 203.0.113.5/32 allow", conf)
        self.assertIn("access-control: 0.0.0.0/0 refuse", conf)
        self.assertNotIn("forward-zone", conf)  # никаких чужих серверов-пересылщиков

    def test_hostile_host_rejected(self):
        for bad in ("1.2.3.4\n  interface: 0.0.0.0", "example.com", "::1", ""):
            with self.assertRaises(core.Error):
                dns.config_text(bad)


class PacketTest(unittest.TestCase):
    def test_query_packet(self):
        packet = dns.build_query("ubuntu.com", qid=0x1234)
        self.assertEqual(packet[:2], b"\x12\x34")
        self.assertIn(b"\x06ubuntu\x03com\x00", packet)
        self.assertEqual(packet[-4:], b"\x00\x01\x00\x01")

    def test_reply_parsing(self):
        reply = struct.pack(">HHHHHH", 7, 0x8180, 1, 2, 0, 0)
        self.assertEqual(dns.parse_reply(reply), (7, 0, 2))
        refused = struct.pack(">HHHHHH", 7, 0x8185, 1, 0, 0, 0)
        self.assertEqual(dns.parse_reply(refused), (7, 5, 0))
        for bad in (b"", b"short", struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)):
            with self.assertRaises(ValueError):
                dns.parse_reply(bad)

    def test_query_against_a_local_udp_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]

        def serve():
            data, addr = server.recvfrom(512)
            qid = struct.unpack(">H", data[:2])[0]
            server.sendto(struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0) + data[12:], addr)

        threading.Thread(target=serve, daemon=True).start()
        try:
            self.assertEqual(dns.query("127.0.0.1", port, "ubuntu.com", timeout=2), (0, 1))
        finally:
            server.close()

    def test_no_answer_raises(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", 0))
            with self.assertRaises(OSError):
                dns.query("127.0.0.1", sock.getsockname()[1], timeout=0.3)


class WaitReadyTest(unittest.TestCase):
    def test_waits_until_resolving(self):
        answers = iter([OSError("down"), (2, 0), (0, 0), (0, 1)])

        def ask(*a, **k):
            value = next(answers)
            if isinstance(value, Exception):
                raise value
            return value

        slept = []
        self.assertTrue(dns.wait_ready(sleep=slept.append, ask=ask))
        self.assertEqual(len(slept), 3)

    def test_gives_up(self):
        self.assertFalse(dns.wait_ready(attempts=3, sleep=lambda s: None, ask=lambda *a, **k: (2, 0)))


class SetupTest(unittest.TestCase):
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

    def test_bad_config_is_rolled_back(self):
        core.write_file(core.path(dns.CONF), "previous\n")
        bad = mock.Mock(returncode=1, stderr="error in line 3", stdout="")
        with mock.patch.object(core, "run", return_value=bad), self.assertRaises(core.Error):
            dns.setup("203.0.113.5")
        self.assertEqual(core.path(dns.CONF).read_text(), "previous\n")

    def test_silent_unbound_is_stopped_and_config_removed(self):
        ok = mock.Mock(returncode=0, stderr="", stdout="")
        with mock.patch.object(core, "run", return_value=ok), mock.patch.object(core, "systemctl") as ctl, \
                mock.patch.object(dns, "wait_ready", return_value=False), self.assertRaises(core.Error):
            dns.setup("203.0.113.5")
        self.assertFalse(core.path(dns.CONF).exists())
        ctl.assert_any_call("stop", "unbound")

    def test_success_leaves_the_config(self):
        ok = mock.Mock(returncode=0, stderr="", stdout="")
        with mock.patch.object(core, "run", return_value=ok), mock.patch.object(core, "systemctl"), \
                mock.patch.object(dns, "wait_ready", return_value=True):
            dns.setup("203.0.113.5")
        self.assertIn("203.0.113.5@53", core.path(dns.CONF).read_text())


if __name__ == "__main__":
    unittest.main()
