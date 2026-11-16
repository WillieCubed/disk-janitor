"""Runtime enforcement tests use only disposable owned process groups and storage."""
import importlib.util
import fcntl
import threading
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace

REPO = Path(__file__).resolve().parents[1]


class RuntimeCapacityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        path = REPO / 'bin/capacity.py'
        self.assertTrue(path.exists(), 'owned runtime capacity controller is missing')
        spec = importlib.util.spec_from_file_location('capacity_fixture', path)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def until(self, check):
        end = time.monotonic() + 3
        while time.monotonic() < end:
            if check(): return
            time.sleep(.015)
        self.fail('disposable process did not reach expected state')

    def test_pressure_freezes_only_owned_group_then_resumes_same_invocation(self):
        progress = self.root / 'progress'
        other = self.root / 'other'
        code = 'import time,signal;signal.signal(signal.SIGTERM,lambda *_:None);from pathlib import Path;p=Path({!r});exec("while True: p.open(\'a\').write(\'x\');time.sleep(.02)")'
        unrelated = subprocess.Popen([sys.executable, '-c', code.format(str(other))], start_new_session=True)
        self.addCleanup(lambda: (unrelated.kill(), unrelated.wait(timeout=3)))
        process = subprocess.Popen([sys.executable, '-c', code.format(str(progress))], start_new_session=True)
        config = dict(freeze_safe=True, volumes=[dict(path=str(self.root), device=self.root.stat().st_dev, reserve=100)],
                      identity=dict(owner='fixture', command_hash='a'*64, job_id='fixture'),
                      runtime_file=str(self.root / 'fixture.runtime'), hysteresis_bytes=10)
        free = [200]
        controller = self.module.OwnedController(process, config, probe=lambda path: free[0])
        self.addCleanup(controller.stop)
        self.until(lambda: progress.exists() and other.exists())
        free[0] = 90
        controller.sample()
        self.assertEqual(json.loads((self.root / 'fixture.runtime').read_text())['state'], 'pressure-blocked')
        time.sleep(.08)
        frozen = progress.stat().st_size
        unrelated_before = other.stat().st_size
        time.sleep(.12)
        self.assertEqual(progress.stat().st_size, frozen)
        self.assertGreater(other.stat().st_size, unrelated_before)
        free[0] = 105
        controller.sample()
        time.sleep(.06)
        self.assertEqual(progress.stat().st_size, frozen, 'resume requires hysteresis')
        free[0] = 120
        controller.sample()
        self.until(lambda: progress.stat().st_size > frozen)
        self.assertEqual(json.loads((self.root / 'fixture.runtime').read_text())['state'], 'running')

    def test_cancel_resumes_stopped_owned_group_before_teardown(self):
        process = subprocess.Popen([sys.executable, '-c', 'import time,signal;signal.signal(signal.SIGTERM,lambda *_:None);time.sleep(30)'], start_new_session=True)
        controller = self.module.OwnedController(process, dict(freeze_safe=True, volumes=[], identity={}, runtime_file=str(self.root/'runtime')))
        self.addCleanup(controller.stop)
        time.sleep(.1)
        controller.pause('fixture pressure')
        started = time.monotonic()
        controller.stop()
        self.assertIsNotNone(process.returncode)
        self.assertLess(time.monotonic()-started, 2)

    def test_frozen_group_releases_cache_fence_and_cancel_reacquires_before_thaw(self):
        progress = self.root / 'fenced-progress'
        code = 'import signal,time;from pathlib import Path;signal.signal(signal.SIGTERM,lambda *_:None);p=Path({!r});exec("while True: p.open(\'a\').write(\'x\');time.sleep(.01)")'.format(str(progress))
        process = subprocess.Popen([sys.executable, '-c', code], start_new_session=True)
        with (self.root/'guard.lock').open('a') as guard, (self.root/'guard.lock').open('a') as cleaner:
            fcntl.flock(guard, fcntl.LOCK_SH)
            controller = self.module.OwnedController(process, dict(freeze_safe=True, volumes=[], identity={}, runtime_file=str(self.root/'runtime'), guard_fd=guard.fileno()))
            self.until(lambda: progress.exists())
            controller.pause('fixture pressure')
            if not controller.guard_released:
                controller.stop()
                self.skipTest('platform restricts native stopped-group inspection; cache fence correctly stayed held')
            fcntl.flock(cleaner, fcntl.LOCK_EX | fcntl.LOCK_NB)
            frozen = progress.stat().st_size
            teardown = threading.Thread(target=controller.stop)
            teardown.start()
            try:
                time.sleep(.1)
                self.assertTrue(teardown.is_alive(), 'teardown must await active cache maintenance')
                self.assertEqual(progress.stat().st_size, frozen, 'no CONT before the shared fence is reacquired')
            finally:
                fcntl.flock(cleaner, fcntl.LOCK_UN)
                teardown.join(timeout=3)
            self.assertFalse(teardown.is_alive())
            self.assertIsNotNone(process.returncode)

    def test_observation_failure_freezes_instead_of_allowing_unobserved_writes(self):
        process = subprocess.Popen([sys.executable, '-c', 'import time,signal;signal.signal(signal.SIGTERM,lambda *_:None);time.sleep(30)'], start_new_session=True)
        def unavailable(path): raise OSError('missing required filesystem')
        controller = self.module.OwnedController(process, dict(freeze_safe=True, volumes=[dict(path=str(self.root), device=self.root.stat().st_dev, reserve=1)], identity={}, runtime_file=str(self.root/'runtime')), probe=unavailable)
        self.addCleanup(controller.stop)
        time.sleep(.1)
        controller.sample()
        self.assertTrue(controller.paused)
        self.assertIn('unavailable', json.loads((self.root/'runtime').read_text())['reason'])

    def test_controller_cancel_during_unreleased_start_gate_is_prompt_and_never_launches(self):
        start_read,start_write=os.pipe()
        with (self.root/'gate-guard').open('a') as guard:
            config=dict(runtime_file=str(self.root/'gated.runtime'),start_fd=start_read,guard_fd=guard.fileno(),identity=dict(owner='gate',command_hash='c'*64,job_id='gate'))
            process=subprocess.Popen([sys.executable,'-B',str(REPO/'bin/capacity.py'),json.dumps(config),'[]','[]'],pass_fds=(start_read,guard.fileno()),stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            try:
                self.until(lambda:(self.root/'gated.controller').exists())
                process.terminate()
                try: process.communicate(timeout=2)
                except subprocess.TimeoutExpired:self.fail('controller ignored cancellation while caller held start gate open')
                self.assertEqual(process.returncode,143)
            finally:
                if process.poll() is None:process.kill();process.communicate()
                os.close(start_read);os.close(start_write)

    def test_unrecoverable_platform_observes_pressure_without_stopping_work(self):
        progress=self.root/'unsupported-progress'
        code='import signal,time;from pathlib import Path;signal.signal(signal.SIGTERM,lambda *_:None);p=Path({!r});exec("while True: p.open(\'a\').write(\'x\');time.sleep(.01)")'.format(str(progress))
        process=subprocess.Popen([sys.executable,'-c',code],start_new_session=True)
        controller=self.module.OwnedController(process,dict(freeze_safe=False,volumes=[dict(path=str(self.root),device=self.root.stat().st_dev,reserve=100)],identity={},runtime_file=str(self.root/'unsupported.runtime')),probe=lambda path:0)
        self.addCleanup(controller.stop)
        self.until(progress.exists)
        controller.sample()
        self.assertFalse(controller.paused)
        self.assertEqual(json.loads((self.root/'unsupported.runtime').read_text())['state'],'pressure-observed')
        before=progress.stat().st_size
        self.until(lambda:progress.stat().st_size>before)

    @unittest.skipUnless(sys.platform.startswith('linux'),'Linux kernel parent-death delivery')
    def test_kernel_parent_death_cont_recovers_owned_stopped_group(self):
        # The helper owns a supervisor which installs the exact production kernel
        # contract, then freezes itself. Killing that direct parent must thaw it.
        ready=self.root/'ready';progress=self.root/'parent-death-progress'
        supervisor=("import sys,os,time,fcntl;from pathlib import Path;sys.path.insert(0,"+repr(str(REPO/'bin'))+");"
                    "from capacity import install_parent_death_resume;f=open("+repr(str(self.root/'guard'))+",'a');"
                    "assert install_parent_death_resume(f.fileno(),os.getppid());Path("+repr(str(ready))+").touch();"
                    "end=time.monotonic()+3;exec(\"while time.monotonic()<end: Path("+repr(str(progress))+ ").open('a').write('x');time.sleep(.01)\")")
        helper_code="import os,signal,subprocess,sys,time;from pathlib import Path;p=subprocess.Popen([sys.executable,'-c',"+repr(supervisor)+"],start_new_session=True);Path("+repr(str(self.root/'pid'))+").write_text(str(p.pid));exec('while True: time.sleep(1)')"
        helper=subprocess.Popen([sys.executable,'-c',helper_code])
        self.addCleanup(lambda: (helper.kill(),helper.wait()) if helper.poll() is None else None)
        self.until(lambda:ready.exists() and progress.exists())
        pid=int((self.root/'pid').read_text())
        # Only the still-live helper's direct child is signalled by this fixture.
        os.killpg(pid,signal.SIGSTOP)
        time.sleep(.05);before=progress.stat().st_size
        helper.kill();helper.wait(timeout=3)
        self.until(lambda:progress.stat().st_size>before)
        # The survivor runs a finite exit on explicit SIGTERM; direct signal target
        # is this fixture's live owned group, never metadata from a prior session.
        os.killpg(pid,signal.SIGTERM)

    def test_native_version_probe_has_light_policy_without_authorizing_replay(self):
        spec=importlib.util.spec_from_file_location('capacity_jobs_policy',REPO/'bin/jobs.py')
        jobs=importlib.util.module_from_spec(spec);spec.loader.exec_module(jobs)
        self.assertLess(jobs.policy(['cargo','--version'])['memory_gib'],1)
        self.assertLess(jobs.policy(['rustc','--help'])['disk_gib'],1)
        self.assertGreaterEqual(jobs.policy(['cargo','build'])['memory_gib'],8)

    def test_observed_capacity_learns_owned_growth_without_global_delta_attribution(self):
        history = self.module.LearningStore(self.root / 'learning')
        key = history.key(['compiler', '--secret=never-written'], str(self.root))
        baseline = dict(kind='native', disk_gib=4, memory_gib=8)
        self.assertEqual(history.predict(key, baseline)['disk_gib'], 4)
        for _ in range(3): history.record(key, self.root.stat().st_dev, 64*2**20, successful=True)
        self.assertEqual(history.predict(key, baseline)['disk_gib'], 4, 'unconfined writes cannot justify shrinkage')
        key = history.key(['confined-compiler'], str(self.root))
        for _ in range(3): history.record(key, self.root.stat().st_dev, 64*2**20, successful=True, complete=True)
        predicted = history.predict(key, baseline)
        self.assertLess(predicted['disk_gib'], 4)
        history.record(key, self.root.stat().st_dev, 8*2**30, successful=False)
        self.assertGreaterEqual(history.predict(key, baseline)['disk_gib'], 10)
        stored = ''.join(p.read_text() for p in (self.root/'learning').glob('*.json'))
        self.assertNotIn('secret', stored)
        self.assertNotIn(str(self.root), stored)


if __name__ == '__main__': unittest.main()
