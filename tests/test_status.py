"""Проверки статуса и учёта трафика в изолированном корне."""
import datetime as dt
import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock

from autopilot import core, status


class FakePanel:
    def __init__(self, clients=None):
        self._clients = clients or []

    def clients(self):
        return self._clients

    def inbounds(self):
        return []


class StatusTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous = os.environ.get("AUTOPILOT_ROOT")
        os.environ["AUTOPILOT_ROOT"] = self.temp.name

    def tearDown(self):
        if self.previous is None:
            os.environ.pop("AUTOPILOT_ROOT", None)
        else:
            os.environ["AUTOPILOT_ROOT"] = self.previous
        self.temp.cleanup()

    def panel(self):
        return FakePanel([
            {"email": "alice", "totalGB": 1000, "traffic": {"up": 100, "down": 200}},
            {"email": "alice-awg1", "totalGB": 500, "traffic": {"up": 300, "down": 400}},
            {"email": "bob", "totalGB": 0, "traffic": {"up": 50, "down": 50}},
        ])

    def test_awg_traffic_is_folded_and_json_has_no_double(self):
        usage = status.usage_by_user(self.panel())
        self.assertEqual(usage, [
            {"user": "alice", "bytes": 1000, "limit": 1000},
            {"user": "bob", "bytes": 100, "limit": 0},
        ])
        self.assertEqual(len(json.loads(status.to_json(self.panel()))), 2)

    def test_snapshot_deltas_and_old_snapshot_cleanup(self):
        today = dt.date(2026, 10, 26)
        state = core.path("var/lib/autopilot")
        state.mkdir(parents=True)
        (state / "traffic-2026-08-01.json").write_text("{}")
        (state / "traffic-2026-10-25.json").write_text(json.dumps({"alice": 500, "bob": 25}))
        (state / "traffic-2026-10-19.json").write_text(json.dumps({"alice": 100, "bob": 10}))
        status.snapshot(self.panel(), today)
        self.assertFalse((state / "traffic-2026-08-01.json").exists())
        snapshot = json.loads((state / "traffic-2026-10-26.json").read_text())
        self.assertEqual(snapshot, {"alice": 1000, "bob": 100})
        self.assertEqual((state / "traffic-2026-10-26.json").stat().st_mode & 0o777, 0o600)
        table = status.stats_table(self.panel(), today)
        self.assertIn("500 Б", table)
        self.assertIn("900 Б", table)

    def test_missing_commands_do_not_crash_collect(self):
        def missing(command, **_kwargs):
            return subprocess.CompletedProcess(command, 127, "", "not found")

        with mock.patch("autopilot.core.run", side_effect=missing), \
                mock.patch("autopilot.core.unit_exists", return_value=False), \
                mock.patch("autopilot.core.unit_active", return_value=False):
            result = status.collect(self.panel())
        self.assertIsInstance(result, list)
        self.assertTrue(all(isinstance(item, status.Check) for item in result))

    def test_render_groups_and_exit_code(self):
        checks = [status.Check("ok", "Службы", "работает"), status.Check("bad", "Система", "диск")]
        rendered = status.render(checks)
        self.assertIn("Службы", rendered)
        self.assertIn("✗", rendered)
        self.assertEqual(status.exit_code(checks), 1)
        self.assertEqual(status.exit_code(checks[:1]), 0)


if __name__ == "__main__":
    unittest.main()
