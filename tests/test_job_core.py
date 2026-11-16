"""Admission and pressure recovery contracts; only disposable fixture data/processes."""
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import threading
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from test_guard_concurrency import BOOTSTRAP

REPO = Path(__file__).resolve().parents[1]


class JobCoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.app = self.root / '.dj'
        self.app.mkdir(mode=0o700)
        self.env = dict(os.environ, HOME=str(self.root), DISK_JANITOR_HOME=str(self.app), FIXTURE_FREE_GIB='.1')
        self.children = []
        self.addCleanup(self.finish_children)

    def finish_children(self):
        (self.root / 'release').touch()
        for p in self.children:
            if p.poll() is None:
                p.terminate()
            try: p.communicate(timeout=5)
            except subprocess.TimeoutExpired: p.kill(); p.communicate(timeout=3)

    def spawn(self, name, *, budget='.04', extra=(), code=None, bootstrap=BOOTSTRAP):
        code = code or ('from pathlib import Path;Path(' + repr(str(self.root / name)) + ').touch()')
        args = ['guard', '--owner', name, '--job-id', name, '--root-reserve-gib', '.05',
                '--planned-gib', budget, '--warn-free-gib', '0', '--deadline-seconds', '6', *extra,
                '--', sys.executable, '-c', code]
        p = subprocess.Popen([sys.executable, '-c', bootstrap, str(REPO / 'bin/disk-janitor'), *args],
                             env=self.env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.children.append(p)
        return p

    def until(self, check):
        end = time.monotonic() + 4
        while time.monotonic() < end:
            if check(): return
            time.sleep(.02)
        self.fail('fixture did not reach expected state')

    def finish(self, p, expected=0):
        output = p.communicate(timeout=9)[0]
        self.assertEqual(p.returncode, expected, output)
        return output

    def control(self, name, cancel=False):
        parent = self.app / 'controls'
        parent.mkdir(mode=0o700, exist_ok=True)
        (parent / 'job.lock').touch(mode=0o600)
        path = parent / (name + '.json')
        path.write_text(json.dumps(dict(backend_job_id=name, owner=name, cancel_requested=cancel)))
        path.chmod(0o600)
        return path

    def test_quiet_retains_command_output(self):
        p = self.spawn('quiet', extra=['--quiet'], code='print("actual command output")')
        self.assertEqual(self.finish(p), 'actual command output\n')

    def test_control_cancels_waiting_job_without_signal(self):
        control = self.control('cancel')
        self.hold_slot()
        p = self.spawn('cancel', extra=['--job-control-file', str(control), '--max-running', '1'])
        self.until(lambda: len(list((self.app / 'queue').glob('*-cancel'))) == 1 or p.poll() is not None)
        control.write_text(json.dumps(dict(backend_job_id='cancel', owner='cancel', cancel_requested=True)))
        self.finish(p, 143)
        self.assertFalse((self.root / 'cancel').exists())

    def test_control_cancels_owned_running_group(self):
        control = self.control('running')
        p = self.spawn('running', extra=['--job-control-file', str(control)],
                       code='from pathlib import Path;import time;Path(' + repr(str(self.root / 'running')) + ').touch();time.sleep(20)')
        self.until(lambda: (self.root / 'running').exists() or p.poll() is not None)
        control.write_text(json.dumps(dict(backend_job_id='running', owner='running', cancel_requested=True)))
        self.finish(p, 143)

    def test_unaccepted_control_claims_identity_and_defers_launch(self):
        control = self.control('accept')
        item = json.loads(control.read_text())
        item['accepted'] = False
        control.write_text(json.dumps(item))
        p = self.spawn('accept', extra=['--job-control-file', str(control)])
        self.until(lambda: (self.app / 'guard-reservations/accept.json').exists() or p.poll() is not None)
        time.sleep(.2)
        self.assertIsNone(p.poll())
        self.assertFalse((self.root / 'accept').exists())
        item['accepted'] = True
        with (control.parent / 'job.lock').open('a') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            control.write_text(json.dumps(item))
        self.finish(p)
        self.assertTrue((self.root / 'accept').exists())

    def test_forbidden_optional_niceness_preserves_build(self):
        old = 'fd=int(sys.argv[1])'
        new = old + '\nos.nice=lambda *_: (_ for _ in ()).throw(PermissionError("fixture denial"))'
        bootstrap = BOOTSTRAP.replace('exec(compile(body,', 'body=body.replace(' + repr(old) + ',' + repr(new) + ')\nexec(compile(body,')
        self.finish(self.spawn('nice', extra=['--work-class', 'build'], bootstrap=bootstrap))

    def test_foreign_control_cannot_cancel_or_launch(self):
        control = self.control('foreign', True)
        control.write_text(json.dumps(dict(backend_job_id='foreign', owner='someone-else', cancel_requested=True)))
        p = self.spawn('foreign', extra=['--job-control-file', str(control)])
        self.finish(p, 125)
        self.assertFalse((self.root / 'foreign').exists())

    def hold_slot(self):
        (self.app / 'slots').mkdir(mode=0o700, exist_ok=True)
        slot = (self.app / 'slots/slot-0.lock').open('a')
        fcntl.flock(slot, fcntl.LOCK_EX)
        self.addCleanup(slot.close)
        return slot

    def test_submitted_age_is_preserved_and_orders_the_queue(self):
        slot = self.hold_slot()
        old = time.time() - 120
        late = self.spawn('late', extra=['--max-running', '1'])
        self.until(lambda: (self.app / 'guard-reservations/late.json').exists())
        hold = ('from pathlib import Path;import time;Path(' + repr(str(self.root / 'aged')) + ').touch();end=time.monotonic()+5;'
                'exec("while not Path(' + repr(str(self.root / 'release')) + ').exists() and time.monotonic()<end: time.sleep(.01)")')
        aged = self.spawn('aged', extra=['--max-running', '1', '--submitted-at', str(old)], code=hold)
        self.until(lambda: len(list((self.app / 'queue').glob('*-aged'))) == 1)
        self.assertEqual(json.loads((self.app / 'guard-reservations/aged.json').read_text())['created'], old)
        slot.close()
        self.until(lambda: (self.root / 'aged').exists())
        time.sleep(.6)
        self.assertFalse((self.root / 'late').exists(), 'the earlier submission takes the freed slot first')
        (self.root / 'release').touch()
        for p in (aged, late): self.finish(p)
        self.assertTrue((self.root / 'late').exists())

    def test_supervisor_log_survives_guardian_crash_and_is_bounded(self):
        log = self.app / 'command.log'
        started = self.root / 'log-started'
        code = ('from pathlib import Path;import time,sys;'
                'Path(' + repr(str(started)) + ').touch();time.sleep(.3);'
                'sys.stdout.write("x"*400000+"tail-marker\\n");sys.stdout.flush()')
        p = self.spawn('logging', extra=['--job-log-file', str(log)], code=code)
        self.until(lambda: started.exists() or p.poll() is not None)
        self.assertTrue(started.exists(), p.communicate(timeout=2)[0] if p.poll() is not None else '')
        p.kill(); p.communicate(timeout=2)
        result = self.app / 'guard-reservations/logging.result'
        self.until(result.exists)
        self.assertEqual(json.loads(result.read_text())['exit_code'], 0)
        self.assertLessEqual(log.stat().st_size, 256 * 1024)
        self.assertTrue(log.read_bytes().endswith(b'tail-marker\n'))

    def test_log_capture_does_not_wait_for_background_pipe_eof(self):
        log = self.app / 'background.log'
        code = 'import subprocess,sys;subprocess.Popen([sys.executable,"-c","import time;time.sleep(20)"]);print("leader done")'
        started = time.monotonic()
        self.finish(self.spawn('background', extra=['--job-log-file', str(log)], code=code))
        self.assertLess(time.monotonic() - started, 3)
        self.assertIn(b'leader done', log.read_bytes())


class PressureRecoveryTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('pressure_recovery', REPO / 'bin/recovery.py')
        self.recovery = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.recovery)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.app = self.root / '.dj'
        self.app.mkdir(mode=0o700)
        self.registry = self.app / 'guard-reservations'
        self.registry.mkdir()
        self.handles = []
        self.addCleanup(lambda: [h.close() for h in self.handles])

    def job(self, name, budget, *, created=1, state='waiting', consumed=0):
        p = self.registry / (name + '.json')
        p.write_text(json.dumps(dict(id=name, state=state, created=created, owner=name, memory=0,
            volumes=[dict(path=str(self.root), device=self.root.stat().st_dev, reserve=20, budget=budget)],
            consumed={str(self.root): consumed}, budget=budget)))
        h = p.open('a+')
        fcntl.flock(h, fcntl.LOCK_EX)
        self.handles.append(h)

    def cache(self, relative):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'generated')
        return path

    LOW_WATER = 50  # bytes; the fixtures count in bytes

    def measured(self, free):
        return (patch.object(self.recovery.shutil, 'disk_usage', side_effect=lambda _: SimpleNamespace(free=free())),
                patch.object(self.recovery.os.path, 'ismount', return_value=True),
                patch.dict(os.environ, {'DISK_JANITOR_LOW_WATER_GIB': repr(self.LOW_WATER / 2**30)}))

    def recover(self, free):
        usage, mounted, low_water = self.measured(free)
        with usage, mounted, low_water:
            return self.recovery.recover(self.root, self.app, apply=True, pressure_only=True, observer=lambda: ([], []))

    def demand(self, free):
        usage, mounted, low_water = self.measured(lambda: free)
        with usage, mounted, low_water:
            return self.recovery.pressure_demand(self.app, home=self.root)

    def test_hourly_pressure_above_low_water_preserves_cache(self):
        cache = self.cache('.gradle/caches/build-cache-1/11111111111111111111111111111111')
        self.job('memory-only', 0)
        result = self.recover(lambda: 100)
        self.assertTrue(cache.exists())
        self.assertEqual(result['status'], 'no-disk-pressure')

    def test_reservation_records_add_no_demand(self):
        self.job('oldest', 30, created=1)
        self.job('later', 1000, created=2)
        self.job('active', 50, state='running', consumed=40)
        self.assertEqual(self.demand(60), {})

    def test_demand_is_the_shortfall_below_low_water(self):
        self.job('waiting', 10 ** 12)
        demand = self.demand(45)
        self.assertEqual(demand[self.root.stat().st_dev]['deficit'], 5)

    def test_recheck_stops_after_first_removal_fits(self):
        cargo = self.cache('.cache/cargo-target/debug/incremental/crate/object.o')
        gradle = self.cache('.gradle/caches/build-cache-1/11111111111111111111111111111111')
        self.recover(lambda: 40 if cargo.exists() else 100)
        self.assertFalse(cargo.exists())
        self.assertTrue(gradle.exists())

    def test_pressure_recovery_needs_no_drain_no_admission_lock_and_no_intent(self):
        cache = self.cache('.gradle/caches/build-cache-1/11111111111111111111111111111111')
        with (self.app / 'guard.lock').open('a') as guard, (self.app / 'admission.lock').open('a') as admission:
            fcntl.flock(guard, fcntl.LOCK_SH)
            fcntl.flock(admission, fcntl.LOCK_EX)
            started = time.monotonic()
            result = self.recover(lambda: 40 if cache.exists() else 100)
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(result['status'], 'completed')
        self.assertFalse(cache.exists())
        self.assertFalse((self.app / 'maintenance-intent.json').exists())


if __name__ == '__main__': unittest.main()
