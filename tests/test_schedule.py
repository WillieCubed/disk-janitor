import os
from pathlib import Path
import plistlib
import platform
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]


@unittest.skipUnless(platform.system() == 'Darwin', 'launchd schedule')
class ScheduleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name).resolve()
        subprocess.run([str(REPO / 'bin/disk-janitor'), 'reclaim', '--schedule'], check=True,
                       capture_output=True, timeout=30,
                       env=dict(os.environ, HOME=str(self.home), DISK_JANITOR_NO_SCHED='1', DISK_JANITOR_STORAGE_ROOT='none',
                                DISK_JANITOR_HOME=str(self.home / '.disk-janitor')))

    def agent(self, name):
        with (self.home / 'Library/LaunchAgents' / name).open('rb') as stream:
            return plistlib.load(stream)

    def test_hourly_pass_maintains(self):
        self.assertIn('--maintain', self.agent('disk-janitor-reclaim.plist')['ProgramArguments'])

    def test_scheduled_passes_are_not_background_throttled(self):
        # Background QoS and low-priority IO stretch a 10 ms git status past its timeout.
        for name in ('disk-janitor-reclaim.plist', 'disk-janitor-watchdog.plist'):
            agent = self.agent(name)
            self.assertNotEqual(agent.get('ProcessType'), 'Background', name)
            self.assertFalse(agent.get('LowPriorityIO', False), name)


if __name__ == '__main__':
    unittest.main()
