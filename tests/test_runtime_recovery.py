"""Lost guardians and late evidence use only disposable local submissions."""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import sys
import unittest
import test_jobs as fixtures


class RuntimeRecoveryTests(fixtures.JobTests):
    def test_guardian_loss_before_commit_is_recovered_in_surviving_worker_context(self):
        (self.app/'slots').mkdir(parents=True, exist_ok=True)
        self.env['DISK_JANITOR_MAX_RUNNING'] = '1'
        with (self.app/'slots/slot-0.lock').open('a') as gate:
            fcntl.flock(gate, fcntl.LOCK_EX)
            job = self.submit('import os;from pathlib import Path;Path("prelaunch-once").open("a").write(os.environ["JOB_TEST_VALUE"])  # build')
            self.until(lambda: self.status(job).get('reason'))
            state = self.status(job)
            os.kill(state['guardian_pid'], signal.SIGKILL)
            self.until(lambda: self.status(job).get('guardian_pid') != state['guardian_pid'])
            self.assertEqual(self.status(job)['state'], 'queued')
        self.assertEqual(self.invoke('wait', job).returncode, 0)
        self.assertEqual((self.home/'prelaunch-once').read_text(), 'kept exactly')

    def test_inner_supervisor_loss_settles_unknown_and_preserves_outputs(self):
        job=self.submit('import os,time;from pathlib import Path;Path(os.environ["DISK_JANITOR_ARTIFACT_ROOT"]).joinpath("unique-proof").write_text("preserved");Path("writer-pid").write_text(str(os.getpid()));time.sleep(30)')
        artifact=Path(self.status(job)['artifact_root'])/'unique-proof'
        self.until(lambda:artifact.exists() and (self.app/'guard-reservations'/(job+'.runtime')).exists())
        runtime=json.loads((self.app/'guard-reservations'/(job+'.runtime')).read_text())
        os.kill(runtime['runtime_group'],signal.SIGKILL)
        try: result=self.invoke('wait',job,timeout=4)
        except __import__('subprocess').TimeoutExpired:self.fail('live controller did not settle a lost command supervisor')
        self.assertEqual(result.returncode,125)
        self.assertEqual(self.status(job)['state'],'unknown')
        self.assertEqual(artifact.read_text(),'preserved')
        spec=importlib.util.spec_from_file_location('retired_group_capacity',self.script.with_name('capacity.py'))
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        # This is read-only inspection of the disposable job's former group.
        group=module.OwnedController(type('OwnedFixture',(),dict(pid=runtime['runtime_group']))(),dict())
        self.assertTrue(group.group_retired(),'no live owned writer may outlast an unknown terminal receipt')

    def test_lost_pressure_controller_is_explicit_while_frozen_execution_lease_survives(self):
        spec=importlib.util.spec_from_file_location('lost_controller_jobs', self.script)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        store=module.Store(self.app);meta=store.create(['false'],self.home,self.env);self.ids.append(meta['id'])
        store.update(meta['id'],accepted=True,launched=True,state='running')
        registry=self.app/'guard-reservations';registry.mkdir()
        receipt=dict(owner=meta['owner'],command_hash=hashlib.sha256(json.dumps([meta['argv'],meta['cwd'],meta['owner'],meta['artifact_root']]).encode()).hexdigest())
        module.atomic_json(registry/(meta['id']+'.runtime'),dict(receipt,state='pressure-blocked',reason='filesystem reserve pressure',blocked_since=1))
        module.atomic_json(registry/(meta['id']+'.json'),dict(receipt,state='running'))
        with (registry/(meta['id']+'.json')).open('rb') as executor:
            fcntl.flock(executor,fcntl.LOCK_EX)
            observed=store.view(meta['id'])
            self.assertEqual(observed['state'],'running')
            self.assertTrue(observed.get('executor_unavailable'))
            self.assertIsNone(observed.get('pressure_blocked'),'a stale receipt is not proof the group is still paused')
            self.assertIn('controller unavailable',observed.get('reason',''))

    def test_late_captured_outcome_resolves_uncertainty_without_replaying(self):
        spec=importlib.util.spec_from_file_location('late_outcome_jobs', self.script)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        store=module.Store(self.app)
        meta=store.create(['false'],self.home,self.env)
        self.ids.append(meta['id'])
        store.update(meta['id'], accepted=True,launched=True,state='unknown',exit_code=125)
        registry=self.app/'guard-reservations';registry.mkdir()
        receipt=dict(owner=meta['owner'],command_hash=hashlib.sha256(json.dumps([meta['argv'],meta['cwd'],meta['owner'],meta['artifact_root']]).encode()).hexdigest())
        module.atomic_json(registry/(meta['id']+'.result'),dict(receipt,exit_code=125,status='outcome-uncertain'))
        module.atomic_json(registry/(meta['id']+'.outcome'),dict(receipt,exit_code=7,status='command-completed'))
        self.assertEqual(store.view(meta['id'])['state'],'failed')
        self.assertEqual(store.view(meta['id'])['exit_code'],7)
        with (registry/(meta['id']+'.json')).open('w') as execution:
            json.dump(dict(receipt,state='running'),execution);execution.flush()
            fcntl.flock(execution,fcntl.LOCK_EX)
            self.assertEqual(store.view(meta['id'])['state'],'running')


for name in fixtures.JobTests.__dict__:
    if name.startswith('test_') and name not in RuntimeRecoveryTests.__dict__:
        setattr(RuntimeRecoveryTests,name,None)

if __name__=='__main__':unittest.main()
