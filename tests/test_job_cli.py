import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]


class PublicJobCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name).resolve()
        self.env = dict(os.environ, HOME=str(self.home), DISK_JANITOR_HOME=str(self.home / '.dj'),
                        DISK_JANITOR_NO_SCHED='1')

    def invoke(self, *args, script=None, env=None):
        return subprocess.run([str(script or REPO / 'bin/disk-janitor'), *args],
                              env=env or self.env, cwd=self.home, text=True,
                              capture_output=True, timeout=15)

    def test_help_exposes_jobs_instead_of_policy_knobs(self):
        r = self.invoke('--help')
        self.assertEqual(r.returncode, 0)
        for command in ('submit', 'status', 'logs', 'wait', 'cancel'):
            self.assertIn(command, r.stdout)
        for private in ('--write-budget', '--owner', '--restartable', '--planned-gib'):
            self.assertNotIn(private, r.stdout)

    def test_public_submit_observe_wait_logs(self):
        r = self.invoke('submit', '--', sys.executable, '-c', 'print("public proof")')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        job = r.stdout.strip()
        self.assertEqual(self.invoke('wait', job).returncode, 0)
        self.assertEqual(json.loads(self.invoke('status', job, '--json').stdout)['state'], 'succeeded')
        self.assertIn('public proof', self.invoke('logs', job).stdout)

    def test_fresh_install_contains_job_runtime(self):
        r = self.invoke('install')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual((self.home / '.dj/jobs.py').read_bytes(), (REPO / 'bin/jobs.py').read_bytes())
        installed = self.home / '.dj/disk-janitor'
        r = self.invoke('submit', '--', 'true', script=installed)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.invoke('wait', r.stdout.strip(), script=installed).returncode, 0)

    def test_broker_started_work_does_not_get_a_nested_reservation(self):
        env = dict(self.env, DISK_JANITOR_BROKER='ci-pool')
        r = self.invoke('submit', '--', 'true', env=env)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('ci-pool already admitted', r.stderr)
        self.assertFalse((self.home / '.dj/jobs').exists())

    def test_symlinked_cli_uses_its_own_release_not_unrelated_home_module(self):
        self.env['DISK_JANITOR_HOME'] = str(self.home / '.dj')
        app = self.home / '.dj'
        app.mkdir()
        (app / 'jobs.py').write_text('print("unrelated release")\n')
        launcher = self.home / 'disk-janitor'
        launcher.symlink_to(REPO / 'bin/disk-janitor')
        result = self.invoke('status', '--json', script=launcher)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), '[]')


if __name__ == '__main__':
    unittest.main()
