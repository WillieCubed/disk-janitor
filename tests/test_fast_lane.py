"""Short checks wait in their own small pool, never behind builds, and keep the disk floor.

Jobs are tiny unittest fixtures in a disposable home. The build pool is held full by a
lock this test owns, which is exactly how a running build holds its slot.
"""
import fcntl
import importlib.util
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
GIB = 2 ** 30

spec = importlib.util.spec_from_file_location('fast_lane_jobs', SCRIPT)
jobs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(jobs)


def classify(command, **history):
    return jobs.lane(command, dict(jobs.policy(command), **history))


class ClassificationTests(unittest.TestCase):
    def test_interpreter_test_runners_and_probes_take_the_fast_lane(self):
        for command in (['python3', '-m', 'unittest'], ['python3', '-B', '-m', 'unittest', 'tests.test_x'],
                        ['pytest', '-q'], ['/repo/.venv/bin/python', '-m', 'pytest', 'tests'],
                        ['python3.12', '-m', 'pytest'], ['node', '--test'], ['node', '--no-warnings', '--test', 'a.test.js'],
                        ['env', 'PYTHONPATH=src', 'python3', '-m', 'unittest'], ['cargo', '--version']):
            self.assertEqual(classify(command), 'fast', command)

    def test_runners_behind_a_script_package_manager_or_cargo_take_the_build_lane(self):
        for command in (['cargo', 'test', '-p', 'core'], ['npm', 'test'], ['pnpm', 'vitest'], ['uv', 'run', 'pytest'],
                        ['node', 'build.js', '--test'], ['python3', 'run_tests.py', '-m', 'unittest'],
                        ['python3', '-c', 'import unittest; unittest.main()', 'build'],
                        ['bash', '-c', 'python3 -m unittest'], ['make', 'test'], ['gradle', 'test']):
            self.assertEqual(classify(command), 'build', command)

    def test_commands_that_run_no_build_tool_stay_light(self):
        for command in (['python3', '-c', 'print(1)'], ['git', 'push'], ['echo', 'hi']):
            self.assertEqual(classify(command), 'light', command)

    def test_a_check_that_keeps_writing_gigabytes_returns_to_the_build_lane(self):
        runner = ['python3', '-m', 'pytest']
        self.assertEqual(classify(runner, observation_count=1, least_observed_bytes=10 * GIB), 'fast',
                         'one run on a busy volume is not proof the check is heavy')
        self.assertEqual(classify(runner, observation_count=4, least_observed_bytes=GIB // 2), 'fast',
                         'a quiet run shows the check itself writes little')
        self.assertEqual(classify(runner, observation_count=2, least_observed_bytes=3 * GIB), 'build')

    def test_recorded_history_decides_the_lane_at_submission(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            store = jobs.Store(root / 'app')
            command = ['python3', '-m', 'pytest']
            self.assertEqual(jobs.job_lane(store.create(command, root, {})), 'fast')
            history = jobs.LearningStore(store.home / 'capacity-history')
            key = history.key(command, root)
            for _ in range(2):
                history.record(key, root.stat().st_dev, 3 * GIB, successful=True)
            created = store.create(command, root, {})
            self.assertEqual(jobs.job_lane(created), 'build')
            self.assertEqual(jobs.public(store.view(created['id']))['lane'], 'build')

    def test_records_from_before_lanes_keep_their_pool(self):
        self.assertEqual(jobs.job_lane({'profile': {'light': True}}), 'light')
        self.assertEqual(jobs.job_lane({'profile': {'light': False}}), 'build')

    def test_the_guard_is_told_the_lane_and_only_light_skips_the_disk_floor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            store = jobs.Store(root / 'app')
            for command, expected in ((['python3', '-m', 'unittest'], 'fast'), (['cargo', 'build'], 'build'),
                                      (['git', 'status'], 'light')):
                arguments = jobs.guard_command(store, store.create(command, root, {}))
                self.assertEqual(arguments[arguments.index('--lane') + 1], expected)
        guard = (REPO / 'bin/disk-janitor').read_text()
        self.assertIn("reserve=0 if a.lane=='light' else reserve*2**30", guard)
        self.assertIn("if a.lane!='light' and slot is None:slot=wait_for_slot()", guard)


class FastLaneTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name).resolve()
        self.app = self.home / '.dj'
        (self.app / 'slots').mkdir(parents=True, mode=0o700)
        self.release = self.home / 'release'
        self.env = dict(os.environ, HOME=str(self.home), DISK_JANITOR_HOME=str(self.app),
                        CODEX_THREAD_ID='fast-lane-tests', DISK_JANITOR_MAX_RUNNING='1')
        self.ids = []
        self.held = []
        # The fixture is a real unittest module, so the job is `python -m unittest`, the
        # command whose wait behind builds this lane exists to remove.
        (self.home / 'check_marker.py').write_text(
            'import os, time, unittest\n'
            'from pathlib import Path\n'
            'class Marker(unittest.TestCase):\n'
            '    def test_marker(self):\n'
            '        name = os.environ["MARKER"]\n'
            '        Path(name).write_text(str(time.time()))\n'
            '        while os.environ.get("HOLD") and not Path(%r).exists() and not Path(name + ".release").exists():\n'
            '            time.sleep(.02)\n' % str(self.release))

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

    def hold(self, name):
        handle = open(self.app / 'slots' / name, 'a')
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.held.append(handle)
        return handle

    def submit(self, marker, hold=False, env=None):
        environment = dict(env or self.env, MARKER=str(self.home / marker), HOLD='1' if hold else '')
        result = self.invoke('submit', '--', sys.executable, '-m', 'unittest', 'check_marker', env=environment)
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

    def test_a_test_run_starts_at_once_while_every_build_slot_is_held(self):
        self.hold('slot-0.lock')
        began = time.monotonic()
        job = self.submit('checked')
        self.until(lambda: (self.home / 'checked').exists(), message='the check waited behind a build')
        self.assertLess(time.monotonic() - began, BOUND)
        self.assertEqual(self.invoke('wait', job).returncode, 0)
        self.assertEqual(self.status(job)['lane'], 'fast')
        listing = self.invoke('status').stdout
        self.assertRegex(listing, job + r' succeeded +fast +python')

    def test_checks_beyond_the_fast_pool_wait_in_their_own_queue(self):
        env = dict(self.env, DISK_JANITOR_FAST_SLOTS='1')
        self.hold('slot-0.lock')
        first = self.submit('first', hold=True, env=env)
        self.until(lambda: (self.home / 'first').exists(), message='the first check did not start')
        second = self.submit('second', env=env)
        self.until(lambda: self.status(second, env=env).get('reason'), message='the second check showed no queue place')
        view = self.status(second, env=env)
        self.assertEqual((view['state'], view['lane']), ('queued', 'fast'))
        self.assertIn('waiting for a free fast slot: position 1 of 1; 1 of 1 fast slots', view['reason'])
        self.assertFalse((self.home / 'second').exists())
        (self.home / 'first.release').touch()
        self.until(lambda: (self.home / 'second').exists(), message='the queued check did not start when the fast slot freed')
        for job in (first, second):
            self.assertEqual(self.invoke('wait', job, env=env).returncode, 0)

    def test_a_check_below_the_disk_floor_is_refused_with_the_numbers(self):
        self.hold('slot-0.lock')
        env = dict(self.env, DISK_JANITOR_FLOOR_GIB='100000000')
        job = self.submit('never', env=env)
        waited = self.invoke('wait', job, env=env, timeout=BOUND + 5)
        self.assertEqual(waited.returncode, 75, waited.stdout + waited.stderr)
        self.assertRegex(waited.stderr, r'insufficient disk: [0-9.]+ GiB free on .*, need 100000000.00 GiB')
        view = self.status(job, env=env)
        self.assertEqual((view['state'], view['lane']), ('failed', 'fast'))
        self.assertFalse((self.home / 'never').exists())


if __name__ == '__main__':
    unittest.main()
