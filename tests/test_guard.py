import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import time
import signal
import threading

REPO = Path(__file__).resolve().parents[1]


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.sandbox = tempfile.TemporaryDirectory()
        self.home = Path(self.sandbox.name)
        self.artifacts = self.home / 'artifacts'
        self.artifacts.mkdir()
        self.marker = self.home / 'executed'
        self.env = dict(os.environ, HOME=str(self.home),
                        DISK_JANITOR_HOME=str(self.home / '.dj'))

    def tearDown(self):
        self.sandbox.cleanup()

    def run_cli(self, *args):
        return subprocess.run(['bash', str(REPO / 'bin/disk-janitor'), *args],
                              env=self.env, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=12)

    def guarded(self, *options, command=None):
        command = command or [sys.executable, '-c',
                              'from pathlib import Path; Path(' + repr(str(self.marker)) + ').touch()']
        return self.run_cli('guard', '--root-reserve-gib', '0', '--planned-gib', '0',
                            '--max-growth-gib', '.02', '--once', '--owner', 'fixture',
                            '--artifact-root', str(self.artifacts), *options, '--', *command)

    def test_low_capacity_rejects_before_command(self):
        result = self.run_cli('admit', '--root-reserve-gib', '1000000')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('reserve', result.stdout)
        self.assertFalse(self.marker.exists())

    def test_managed_guidance_integrates_image_and_runtime_workflows(self):
        result = self.run_cli('guidance')
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('disk-janitor submit', result.stdout)
        self.assertIn('build, test and local validation', result.stdout)
        self.assertIn('Do not choose disk budgets', result.stdout)
        self.assertIn('submitting permission context', result.stdout)

    def test_missing_external_mount_rejects_before_command(self):
        result = self.guarded('--volume', str(self.home / 'missing'), '0')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('mount', result.stdout)
        self.assertFalse(self.marker.exists())

    def test_retention_threshold_warns_without_blocking_safe_command(self):
        (self.artifacts / 'old-output').write_bytes(b'x' * 65536)
        result = self.guarded('--max-retained-gib', '0.000001')
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('advisory', result.stdout)
        self.assertTrue(self.marker.exists())

    def test_active_guard_is_excluded(self):
        (self.home / '.dj').mkdir()
        with open(self.home / '.dj/guard.lock', 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.guarded()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('active', result.stdout)
        self.assertFalse(self.marker.exists())

    def test_finite_job_coexists_with_persistent_guard(self):
        first_root = self.home / 'persistent'
        first_root.mkdir()
        ready, release = self.home / 'ready', self.home / 'release'
        code = ('import time; from pathlib import Path; '
                'Path(' + repr(str(ready)) + ').touch(); '
                'exec("while not Path(' + repr(str(release)) + ').exists(): time.sleep(.02)")')
        first = subprocess.Popen(['bash', str(REPO / 'bin/disk-janitor'), 'guard',
            '--root-reserve-gib', '0', '--planned-gib', '.001',
            '--max-growth-gib', '.01', '--owner', 'persistent-fixture',
            '--artifact-root', str(first_root), '--', sys.executable, '-c', code],
            env=self.env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            deadline = time.monotonic() + 4
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue(ready.exists(), 'persistent fixture did not start')
            second = self.guarded('--planned-gib', '.001', '--max-growth-gib', '.01')
            self.assertEqual(second.returncode, 0, second.stdout)
            self.assertTrue(self.marker.exists())
            self.assertIsNone(first.poll(), 'finite check must not stop the persistent service')
        finally:
            release.touch()
            output = first.communicate(timeout=5)[0]
        self.assertEqual(first.returncode, 0, output)

    def test_owner_mismatch_is_preserved(self):
        (self.artifacts / '.disk-janitor-owner.json').write_text(json.dumps({'owner': 'someone-else'}))
        result = self.guarded()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('owner', result.stdout)
        self.assertTrue((self.artifacts / '.disk-janitor-owner.json').exists())

    def test_failure_preserves_unrelated_files_and_reports_result(self):
        source = self.home / 'unique-source.txt'
        source.write_text('keep this')
        result = self.guarded(command=[sys.executable, '-c', 'raise SystemExit(7)'])
        self.assertEqual(result.returncode, 7, result.stdout)
        self.assertEqual(source.read_text(), 'keep this')
        record = json.loads((self.artifacts / '.disk-janitor-owner.json').read_text())
        self.assertEqual(record['exit_code'], 7)
        self.assertEqual(record['owner'], 'fixture')

    def test_output_overrun_preserves_running_job_and_reports_pressure(self):
        code = ('import os,time; from pathlib import Path; '
                'p=Path(os.environ["DISK_JANITOR_ARTIFACT_ROOT"]); '
                '(p/"pid").write_text(str(os.getpid())); '
                '(p/"generated").write_bytes(b"x"*262144); time.sleep(.4); '
                '(p/"completed").touch()')
        result = self.guarded('--max-retained-gib', '0.0001', '--planned-gib', '.000001', '--max-growth-gib', '.00001',
                              command=[sys.executable, '-c', code])
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('retention', result.stdout)
        self.assertIn('outputs preserved', result.stdout)
        self.assertTrue((self.artifacts / 'completed').exists())
        self.assertTrue((self.artifacts / 'generated').exists())
        pid = int((self.artifacts / 'pid').read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_capacity_wait_is_bounded_and_returns_deferred_status(self):
        (self.artifacts / 'retained').write_bytes(b'x' * 65536)
        started = time.monotonic()
        result = self.run_cli('guard','--root-reserve-gib','1000000','--planned-gib','0','--max-growth-gib','.001','--owner','fixture','--artifact-root',str(self.artifacts),'--max-retained-gib','0.000001','--deadline-seconds','.2','--',sys.executable,'-c','pass')
        self.assertEqual(result.returncode, 75, result.stdout)
        self.assertGreaterEqual(time.monotonic() - started, .2)
        self.assertLess(time.monotonic() - started, 2)
        self.assertFalse(self.marker.exists())

    def test_retention_is_rechecked_after_waiting_for_lease(self):
        (self.home / '.dj').mkdir()
        with open(self.home / '.dj/guard.lock', 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            def release():
                time.sleep(.1)
                (self.artifacts / 'newly-retained').write_bytes(b'x' * 262144)
                fcntl.flock(lock, fcntl.LOCK_UN)
            thread = threading.Thread(target=release)
            thread.start()
            result = self.run_cli('guard','--root-reserve-gib','0','--planned-gib','0','--max-growth-gib','.001','--owner','fixture','--artifact-root',str(self.artifacts),'--max-retained-gib','0.0001','--deadline-seconds','.4','--',sys.executable,'-c','pass')
            thread.join()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('advisory', result.stdout)
        self.assertTrue((self.artifacts / 'newly-retained').exists())

    def test_aggregate_retention_counts_sibling_runs(self):
        (self.home / 'older-run').write_bytes(b'x' * 262144)
        result = self.guarded('--retention-root', str(self.home),
                              '--max-retained-gib', '0.0001')
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('historical retention threshold exceeded', result.stdout)
        self.assertTrue(self.marker.exists())

    def test_normal_exit_stops_inherited_background_process(self):
        lockpath = self.home / 'child-lock'
        pidpath = self.home / 'child-pid'
        childcode = ('import fcntl,time,os,signal; from pathlib import Path; '
                     'signal.signal(signal.SIGTERM,signal.SIG_IGN); '
                     'f=open(' + repr(str(lockpath)) + ',"w"); '
                     'fcntl.flock(f,fcntl.LOCK_EX); '
                     'Path(' + repr(str(pidpath)) + ').write_text(str(os.getpid())); '
                     'time.sleep(10)')
        code = ('import subprocess,sys,time; from pathlib import Path; '
                'subprocess.Popen([sys.executable,"-c",' + repr(childcode) + '],'
                'stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); '
                'p=Path(' + repr(str(pidpath)) + '); '
                'exec("while not p.exists(): time.sleep(.01)")')
        started = time.monotonic()
        result = self.guarded(command=[sys.executable, '-c', code])
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertLess(time.monotonic() - started, 3)
        try:
            with open(lockpath, 'r') as lock:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    self.fail('owned background process survived normal command exit')
        finally:
            if pidpath.exists():
                try:
                    os.kill(int(pidpath.read_text()), signal.SIGTERM)
                except ProcessLookupError:
                    pass


if __name__ == '__main__':
    unittest.main()
