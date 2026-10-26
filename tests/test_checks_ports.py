"""check: правила ufw учитывают изменённые порты."""
import json
import os
import tempfile
import unittest
from unittest import mock

from autopilot import checks, core, installer


class CustomPortsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old = os.environ.get("AUTOPILOT_ROOT")
        os.environ["AUTOPILOT_ROOT"] = self.tmp.name
        core.write_file(core.path(core.CONF_DIR, "install.json"), json.dumps({"ports": {"tuic": 9444}}), 0o600)

    def tearDown(self):
        if self.old is None:
            os.environ.pop("AUTOPILOT_ROOT", None)
        else:
            os.environ["AUTOPILOT_ROOT"] = self.old
        self.tmp.cleanup()

    def test_expected_rules_follow_the_changed_port(self):
        rules = checks._expected_ufw()
        self.assertIn((9444, "udp"), rules)
        self.assertNotIn((8444, "udp"), rules)
        self.assertEqual(len(rules), len(installer.UFW_RULES))

    def test_hint_texts_are_russian(self):
        import inspect
        self.assertNotIn("Reparar", inspect.getsource(checks))


if __name__ == "__main__":
    unittest.main()
