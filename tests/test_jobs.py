import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

REPO = Path(__file__).resolve().parents[1]


class JobTests(unittest.TestCase):
    def setUp(self):
        self.script = REPO / 'bin/jobs.py'
        self.assertTrue(self.script.exists(), 'durable job implementation is missing')
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name).resolve()
        self.app = self.home / '.dj'
        self.env = dict(os.environ, HOME=str(self.home), DISK_JANITOR_HOME=str(self.app),
                        CODEX_THREAD_ID='job-tests', JOB_TEST_VALUE='kept exactly')
        self.ids = []

    def tearDown(self):
        if not hasattr(self, 'tmp'):
            return
        for job in self.ids:
            try:
                self.invoke('cancel', job)
                self.invoke('wait', job, timeout=8)
            except (subprocess.TimeoutExpired, OSError):
                pass
        self.tmp.cleanup()

    def invoke(self, *args, timeout=15, env=None):
        return subprocess.run([sys.executable, str(self.script), *args], cwd=self.home,
                              env=env or self.env, text=True, capture_output=True, timeout=timeout)

    def submit(self, code):
        r = self.invoke('submit', '--', sys.executable, '-c', code)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        job = r.stdout.strip()
        self.assertRegex(job, r'^j-[0-9a-f]{32}$')
        self.ids.append(job)
        return job

    def status(self, job):
        r = self.invoke('status', job, '--json')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return json.loads(r.stdout)

    def until(self, check, seconds=12):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if check():
                return
            time.sleep(.04)
        self.fail('timed out waiting for job state')

    def test_submission_is_background_and_preserves_argv_cwd_environment(self):
        code = ('import os,time;from pathlib import Path;'
                'print(os.environ["JOB_TEST_VALUE"],flush=True);'
                'Path("working directory proof").write_text(os.getcwd());time.sleep(.4)')
        job = self.submit(code)
        self.assertEqual(self.invoke('wait', job).returncode, 0)
        self.assertEqual((self.home / 'working directory proof').read_text(), str(self.home))
        self.assertIn('kept exactly', self.invoke('logs', job).stdout)
        self.assertEqual(self.status(job)['state'], 'succeeded')

    def test_identical_commands_are_distinct_invocations(self):
        code = 'from pathlib import Path;p=Path("calls");p.open("a").write("called\\n")'
        a, b = self.submit(code), self.submit(code)
        self.assertNotEqual(a, b)
        for job in (a, b):
            self.assertEqual(self.invoke('wait', job).returncode, 0)
        self.assertEqual((self.home / 'calls').read_text().count('called'), 2)

    def test_failure_exit_code_and_logs_are_observable(self):
        job = self.submit('import sys;print("failure evidence");sys.exit(7)')
        self.assertEqual(self.invoke('wait', job).returncode, 7)
        state = self.status(job)
        self.assertEqual(state['state'], 'failed')
        self.assertEqual(state['exit_code'], 7)
        self.assertIn('failure evidence', self.invoke('logs', job).stdout)

    def test_cancel_is_guard_owned_and_terminal(self):
        job = self.submit('import time;print("started",flush=True);time.sleep(15)')
        self.until(lambda: self.status(job)['state'] == 'running')
        self.assertEqual(self.invoke('cancel', job).returncode, 0)
        self.assertEqual(self.invoke('wait', job).returncode, 143)
        self.assertEqual(self.status(job)['state'], 'cancelled')

    def test_cancel_before_admission_never_launches_command(self):
        import fcntl
        self.app.mkdir(parents=True, exist_ok=True)
        with (self.app / 'admission.lock').open('a') as gate:
            fcntl.flock(gate, fcntl.LOCK_EX)
            job = self.submit('from pathlib import Path;Path("must-not-run").touch()')
            self.assertEqual(self.status(job)['state'], 'queued')
            self.assertEqual(self.invoke('cancel', job).returncode, 0)
        self.assertEqual(self.invoke('wait', job).returncode, 143)
        self.assertFalse((self.home / 'must-not-run').exists())

    def test_worker_loss_before_admission_preserves_queued_executor(self):
        import fcntl
        self.app.mkdir(parents=True, exist_ok=True)
        with (self.app / 'admission.lock').open('a') as gate:
            fcntl.flock(gate, fcntl.LOCK_EX)
            job = self.submit('from pathlib import Path;Path("queued-once").open("a").write("once")')
            os.kill(self.status(job)['worker_pid'], signal.SIGKILL)
            self.assertEqual(self.status(job)['state'], 'queued')
        self.assertEqual(self.invoke('wait', job).returncode, 0)
        self.assertEqual((self.home / 'queued-once').read_text(), 'once')

    def test_missing_executable_has_known_failure_receipt(self):
        r = self.invoke('submit', '--', str(self.home / 'no-such-executable'))
        self.assertEqual(r.returncode, 0, r.stderr)
        job = r.stdout.strip()
        self.ids.append(job)
        self.assertEqual(self.invoke('wait', job).returncode, 127)
        self.assertEqual(self.status(job)['state'], 'failed')

    def test_guardian_loss_preserves_supervised_result(self):
        job = self.submit('import time;from pathlib import Path;Path("guardian-once").open("a").write("once");time.sleep(.6);print("survived")')
        self.until(lambda: self.status(job)['state'] == 'running' and (self.home / 'guardian-once').exists())
        os.kill(self.status(job)['guardian_pid'], signal.SIGKILL)
        self.assertEqual(self.invoke('wait', job).returncode, 0)
        self.assertEqual((self.home / 'guardian-once').read_text(), 'once')
        self.assertIn('survived', self.invoke('logs', job).stdout)

    def test_available_jobs_overlap_instead_of_serializing(self):
        jobs = []
        start = time.monotonic()
        for index in range(2):
            code = ('import json,time;from pathlib import Path;start=time.monotonic();'
                    'time.sleep(1);Path(' + repr('timing-' + str(index)) + ').write_text(json.dumps([start,time.monotonic()]))')
            jobs.append(self.submit(code))
        for job in jobs:
            self.assertEqual(self.invoke('wait', job).returncode, 0)
        intervals = [json.loads((self.home / ('timing-' + str(i))).read_text()) for i in range(2)]
        self.assertLess(max(x[0] for x in intervals), min(x[1] for x in intervals), intervals)
        evidence = {'jobs': 2, 'elapsed_seconds': time.monotonic() - start, 'intervals': intervals}
        (REPO / 'evidence/throughput.json').write_text(json.dumps(evidence, indent=2) + '\n')

    @unittest.skipUnless(sys.platform == 'darwin', 'Seatbelt inheritance is a macOS integration check')
    def test_detached_executor_inherits_submitter_sandbox(self):
        protected = self.home / 'protected'
        protected.mkdir()
        profile = '(version 1)(allow default)(deny file-write* (subpath ' + json.dumps(str(protected)) + '))'
        command = [sys.executable, '-c', 'from pathlib import Path;Path(' + repr(str(protected / 'denied')) + ').touch()']
        r = subprocess.run(['/usr/bin/sandbox-exec', '-p', profile, sys.executable, str(self.script), 'submit', '--', *command],
                           cwd=self.home, env=self.env, text=True, capture_output=True, timeout=15)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        job = r.stdout.strip()
        self.ids.append(job)
        self.assertNotEqual(self.invoke('wait', job).returncode, 0)
        self.assertFalse((protected / 'denied').exists())

    def test_other_agent_cannot_cancel_job(self):
        job = self.submit('import time;time.sleep(.5)')
        other = dict(self.env, CODEX_THREAD_ID='different-agent')
        r = self.invoke('cancel', job, env=other)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.invoke('wait', job).returncode, 0)

    def test_worker_loss_does_not_replay_and_guardian_preserves_output(self):
        code = ('import time;from pathlib import Path;'
                'Path("once").open("a").write("start\\n");print("before",flush=True);'
                'time.sleep(.6);print("after",flush=True)')
        job = self.submit(code)
        self.until(lambda: self.status(job)['state'] == 'running' and (self.home / 'once').exists())
        state = self.status(job)
        os.kill(state['worker_pid'], signal.SIGKILL)
        self.assertEqual(self.invoke('wait', job).returncode, 0)
        self.assertEqual((self.home / 'once').read_text(), 'start\n')
        self.assertIn('after', self.invoke('logs', job).stdout)

    def test_unknown_execution_is_not_replayed_by_observers(self):
        spec = importlib.util.spec_from_file_location('jobs_under_test', self.script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        store = module.Store(self.app)
        meta = store.create(['false'], self.home, self.env)
        self.ids.append(meta['id'])
        store.update(meta['id'], worker_pid=99999999, guardian_pid=99999998, launched=True)
        self.assertEqual(self.status(meta['id'])['state'], 'unknown')
        self.assertEqual(self.invoke('wait', meta['id']).returncode, 125)
        self.assertEqual(self.status(meta['id'])['state'], 'unknown')

    def test_logs_are_bounded_and_artifacts_are_retained(self):
        job = self.submit('import os;from pathlib import Path;print("x"*400000);print("TAIL");'
                          'Path(os.environ["DISK_JANITOR_ARTIFACT_ROOT"]).joinpath("proof.txt").write_text("unique proof")')
        self.assertEqual(self.invoke('wait', job).returncode, 0)
        logs = self.invoke('logs', job).stdout
        self.assertIn('TAIL', logs)
        self.assertLess(len(logs.encode()), 270000)
        self.assertEqual((Path(self.status(job)['artifact_root']) / 'proof.txt').read_text(), 'unique proof')

    def test_policy_is_not_an_agent_supplied_api(self):
        r = self.invoke('submit', '--planned-gib', '0', '--', 'true')
        self.assertEqual(r.returncode, 2)

    def test_observation_does_not_regress_during_receipt_publication(self):
        import fcntl
        spec = importlib.util.spec_from_file_location('jobs_phase_test', self.script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        store = module.Store(self.app)
        meta = store.create(['true'], self.home, self.env)
        self.ids.append(meta['id'])
        store.update(meta['id'], accepted=True, state='running')
        with (store.directory(meta['id']) / 'guardian.lock').open('w') as executor:
            fcntl.flock(executor, fcntl.LOCK_EX)
            self.assertEqual(store.view(meta['id'])['state'], 'running')


if __name__ == '__main__':
    unittest.main()
