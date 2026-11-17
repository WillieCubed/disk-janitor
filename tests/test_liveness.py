"""Acceptance: a submitted job starts or fails within seconds, whatever state it finds.

Jobs are tiny Python fixtures in a disposable home. The only thing a job may wait for is
a free slot; a hostile registry, held locks and a short disk never hold it in the queue.
"""
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / 'bin/jobs.py'
BOUND = 5


class LivenessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name).resolve()
        self.app = self.home / '.dj'
        self.registry = self.app / 'guard-reservations'
        self.registry.mkdir(parents=True, mode=0o700)
        self.release = self.home / 'release'
        self.env = dict(os.environ, HOME=str(self.home), DISK_JANITOR_HOME=str(self.app),
                        CODEX_THREAD_ID='liveness-tests')
        self.ids = []
        self.held = []

    def tearDown(self):
        self.release.touch()
        for handle in self.held:
            handle.close()
        for job in self.ids:
            try:
                self.invoke('cancel', job)
                self.invoke('wait', job, timeout=10)
            except (subprocess.TimeoutExpired, OSError):
                pass
        self.tmp.cleanup()

    def invoke(self, *args, timeout=20, env=None):
        return subprocess.run([sys.executable, str(SCRIPT), *args], cwd=self.home, env=env or self.env,
                              text=True, capture_output=True, timeout=timeout)

    def submit(self, name, hold=False, env=None):
        # The trailing `build` argument keeps the fixture out of the light class: it must use a slot.
        code = ('import time;from pathlib import Path;Path(%r).write_text(str(time.time()));' % str(self.home / name)
                + ('exec("while not Path(%r).exists() and not Path(%r).exists(): time.sleep(.02)")'
                   % (str(self.release), str(self.home / (name + '.release'))) if hold else ''))
        result = self.invoke('submit', '--', sys.executable, '-c', code, 'build', env=env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.ids.append(result.stdout.strip())
        return self.ids[-1]

    def status(self, job, env=None):
        return json.loads(self.invoke('status', job, '--json', env=env).stdout)

    def until(self, check, seconds=BOUND, message='not within the bound'):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if check():
                return
            time.sleep(.03)
        self.fail(message)

    def hold(self, name):
        handle = open(self.app / name, 'a')
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.held.append(handle)

    def garbage(self):
        dead = subprocess.Popen([sys.executable, '-c', 'pass'])
        dead.wait()
        record = {'id': 'stale', 'owner': 'gone', 'pid': dead.pid, 'command_hash': 'x', 'state': 'running',
                  'created': 1, 'budget': 2**40, 'memory': 2**40, 'class': 'feedback', 'artifact': str(self.home),
                  'retention': str(self.home / 'missing'), 'retention_identity': [1, 2], 'child': dead.pid,
                  'volumes': [{'path': '/', 'device': 1, 'reserve': 2**50, 'budget': 2**40}],
                  'finished': 1, 'retention_unsettled': True}
        (self.registry / 'stale.json').write_text(json.dumps(record))
        (self.registry / 'stale.result').write_text(json.dumps({'owner': 'someone-else', 'command_hash': 'y', 'exit_code': 0}))
        (self.registry / 'waiting-forever.json').write_text(json.dumps(dict(record, id='waiting-forever', state='waiting', child=None)))
        (self.registry / 'empty.json').write_text('')
        (self.registry / 'bytes.json').write_bytes(b'\xff\x00{not json')
        (self.registry / 'list.json').write_text('[1, 2, 3]')
        (self.registry / 'partial.json').write_text('{"id": "partial", "state": "running"}')
        (self.registry / 'directory.json').mkdir()
        (self.registry / 'link.json').symlink_to(self.registry / 'stale.json')
        (self.app / 'queue').mkdir()
        (self.app / 'queue' / ('%020d-abandoned' % 1)).write_text('')
        (self.app / 'queue' / 'not-a-ticket').write_text('')
        (self.app / 'slots').mkdir()
        (self.app / 'slots/slot-0.lock').write_text('left behind')
        (self.app / 'maintenance-intent.json').write_text(json.dumps(
            dict(version=1, token='t', created=time.time(), expires=time.time() + 120)))

    def test_garbage_registry_and_held_locks_do_not_delay_a_start(self):
        self.garbage()
        for name in ('admission.lock', 'guard.lock', 'recovery.lock'):
            self.hold(name)
        began = time.monotonic()
        job = self.submit('started')
        self.until(lambda: (self.home / 'started').exists(), message='job did not start within %d s' % BOUND)
        self.assertLess(time.monotonic() - began, BOUND)
        self.assertEqual(self.invoke('wait', job).returncode, 0)
        self.assertTrue((self.registry / 'stale.json').exists(), 'ambiguous metadata is preserved, only ignored')

    def test_dead_running_record_and_abandoned_ticket_never_occupy_the_only_slot(self):
        self.garbage()
        env = dict(self.env, DISK_JANITOR_MAX_RUNNING='1')
        job = self.submit('only-slot', env=env)
        self.until(lambda: (self.home / 'only-slot').exists(), message='a dead record held the slot')
        self.assertEqual(self.invoke('wait', job, env=env).returncode, 0)

    def test_fifty_submissions_run_at_the_limit_and_start_as_slots_free(self):
        self.garbage()
        self.hold('admission.lock')
        limit, total = 3, 50
        env = dict(self.env, DISK_JANITOR_MAX_RUNNING=str(limit))
        jobs = [self.submit('job-%02d' % index, hold=True, env=env) for index in range(total)]
        started = lambda: sorted(p.name for p in self.home.glob('job-??'))
        self.until(lambda: len(started()) == limit, seconds=20, message='the limit was not reached')
        time.sleep(1)
        self.assertEqual(started(), ['job-00', 'job-01', 'job-02'], 'exactly the limit runs, oldest first')
        waiting = self.status(jobs[10], env=env)
        self.assertEqual(waiting['state'], 'queued')
        self.assertRegex(waiting['reason'], r'waiting for a free slot: position 8 of 47; 3 of 3 slots')
        listing = self.invoke('status', env=env).stdout
        self.assertIn('waiting for a free slot', listing)
        for index in range(3):
            freed = time.monotonic()
            (self.home / ('job-%02d.release' % index)).touch()
            expected = 'job-%02d' % (limit + index)
            self.until(lambda: (self.home / expected).exists(),
                       message=expected + ' did not start within %d s of a slot freeing' % BOUND)
            self.assertLess(time.monotonic() - freed, BOUND)
            self.assertEqual(len(started()), limit + index + 1, 'one slot freed starts exactly one job')
        self.release.touch()
        for job in jobs:
            self.assertEqual(self.invoke('wait', job, env=env, timeout=60).returncode, 0)
        self.assertEqual(len(started()), total)

    def test_disk_below_the_floor_fails_in_seconds_with_the_numbers(self):
        self.garbage()
        self.hold('admission.lock')
        env = dict(self.env, DISK_JANITOR_FLOOR_GIB='100000000')
        began = time.monotonic()
        job = self.submit('never', env=env)
        waited = self.invoke('wait', job, env=env, timeout=BOUND + 3)
        self.assertLess(time.monotonic() - began, BOUND + 1)
        self.assertEqual(waited.returncode, 75, waited.stdout + waited.stderr)
        self.assertRegex(waited.stderr, r'insufficient disk: [0-9.]+ GiB free on .*, need 100000000.00 GiB; reclaim freed [0-9.]+ GiB')
        view = self.status(job, env=env)
        self.assertEqual(view['state'], 'failed')
        self.assertIn('insufficient disk', view['reason'])
        self.assertIn('Not started: insufficient disk', self.invoke('logs', job, env=env).stdout)
        self.assertFalse((self.home / 'never').exists())

    def test_light_command_starts_without_a_slot_or_disk_headroom(self):
        env = dict(self.env, DISK_JANITOR_MAX_RUNNING='1', DISK_JANITOR_FLOOR_GIB='100000000')
        blocker = open(self.app / 'slot-holder', 'w')
        (self.app / 'slots').mkdir()
        with open(self.app / 'slots/slot-0.lock', 'w') as slot:
            fcntl.flock(slot, fcntl.LOCK_EX)
            result = self.invoke('submit', '--', 'sh', '-c', 'echo light > ' + str(self.home / 'light'), env=env)
            self.ids.append(result.stdout.strip())
            self.until(lambda: (self.home / 'light').exists(), message='light job waited')
        blocker.close()

    def test_waiting_longer_than_the_maximum_fails_with_the_reason(self):
        (self.app / 'slots').mkdir()
        marker = self.home / 'ran'
        with open(self.app / 'slots/slot-0.lock', 'w') as slot:
            fcntl.flock(slot, fcntl.LOCK_EX)
            result = subprocess.run(['bash', str(REPO / 'bin/disk-janitor'), 'guard', '--owner', 'bounded',
                                     '--max-running', '1', '--max-queue-seconds', '1', '--',
                                     sys.executable, '-c', 'from pathlib import Path;Path(%r).touch()' % str(marker)],
                                    env=self.env, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 75, result.stdout + result.stderr)
        self.assertIn('no free slot after', result.stderr)
        self.assertFalse(marker.exists())


if __name__ == '__main__':
    unittest.main()
