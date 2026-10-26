"""Удаление: что удаляется, что остаётся, dry-run ничего не трогает."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from autopilot import core, installer, uninstaller


class UninstallTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old = os.environ.get("AUTOPILOT_ROOT")
        os.environ["AUTOPILOT_ROOT"] = self.tmp.name
        for rel in ("etc/autopilot/install.json", "etc/x-ui/x-ui.db", "usr/local/x-ui/x-ui", "var/www/autopilot/tok/router.sh",
                    "usr/local/bin/autopilot", "etc/systemd/system/autopilot-watch.timer", "etc/systemd/system/autopilot-cert.service",
                    "etc/systemd/system/x-ui.service", "var/backups/autopilot/backup-1.tar.gz.enc", "etc/ssh/sshd_config.d/00-autopilot.conf",
                    "etc/systemd/system/other.service"):
            core.write_file(core.path(rel), "x")

    def tearDown(self):
        if self.old is None:
            os.environ.pop("AUTOPILOT_ROOT", None)
        else:
            os.environ["AUTOPILOT_ROOT"] = self.old
        self.tmp.cleanup()

    def test_targets_include_ours_only(self):
        names = {str(p.relative_to(self.tmp.name)) for p in uninstaller.targets()}
        self.assertIn("etc/x-ui", names)
        self.assertIn("etc/systemd/system/autopilot-watch.timer", names)
        self.assertIn("etc/systemd/system/autopilot-cert.service", names)
        self.assertNotIn("etc/systemd/system/other.service", names)
        self.assertNotIn("var/backups/autopilot", names)

    def test_dry_run_changes_nothing(self):
        with mock.patch.object(core, "unit_exists", return_value=True), mock.patch.object(core, "systemctl") as ctl, \
                mock.patch("shutil.which", return_value="/usr/sbin/ufw"), mock.patch.object(core, "run") as run:
            actions = uninstaller.remove(dry_run=True)
        self.assertTrue(any(a.startswith("remove ") for a in actions))
        self.assertTrue(core.path("etc/x-ui/x-ui.db").exists())
        ctl.assert_not_called()
        run.assert_not_called()

    def test_remove_deletes_files_keeps_backups_and_ssh_dropin(self):
        with mock.patch.object(core, "unit_exists", return_value=False), mock.patch.object(core, "systemctl"), \
                mock.patch.object(core, "unit_active", return_value=False), mock.patch("shutil.which", return_value=None):
            uninstaller.remove()
        self.assertFalse(core.path("etc/x-ui").exists())
        self.assertFalse(core.path("etc/autopilot").exists())
        self.assertFalse(core.path("usr/local/bin/autopilot").exists())
        self.assertFalse(core.path("etc/systemd/system/autopilot-watch.timer").exists())
        self.assertTrue(core.path("etc/systemd/system/other.service").exists())
        self.assertTrue(core.path("var/backups/autopilot/backup-1.tar.gz.enc").exists())
        self.assertEqual({p.name for p in uninstaller.kept()}, {"autopilot", "00-autopilot.conf"})

    def test_ufw_rules_never_touch_ssh(self):
        rules = uninstaller.ufw_rules()
        self.assertEqual(rules, ["%d/%s" % r for r in installer.UFW_RULES])
        self.assertNotIn("22/tcp", rules)

    def test_ufw_rules_deleted_one_by_one(self):
        calls = []
        with mock.patch.object(core, "unit_exists", return_value=False), mock.patch.object(core, "systemctl"), \
                mock.patch.object(core, "unit_active", return_value=False), mock.patch("shutil.which", return_value="/usr/sbin/ufw"), \
                mock.patch.object(core, "run", side_effect=lambda cmd, **k: calls.append(list(cmd))):
            uninstaller.remove()
        self.assertIn(["ufw", "--force", "delete", "allow", "443/tcp"], calls)
        self.assertTrue(all(c[:4] == ["ufw", "--force", "delete", "allow"] for c in calls))


if __name__ == "__main__":
    unittest.main()
