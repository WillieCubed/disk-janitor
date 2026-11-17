import fcntl
import hashlib
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
import test_jobs as fixtures


class ReviewRegressions(fixtures.JobTests):
    def test_cancel_after_guardian_loss_stops_owned_execution(self):
        job = self.submit('import time;from pathlib import Path;Path("orphan-start").touch();time.sleep(12)')
        self.until(lambda: self.status(job)['state'] == 'running' and (self.home / 'orphan-start').exists())
        os.kill(self.status(job)['guardian_pid'], signal.SIGKILL)
        self.assertEqual(self.invoke('cancel', job).returncode, 0)
        self.assertEqual(self.invoke('wait', job, timeout=4).returncode, 143)

    def test_missing_mount_fails_with_its_reason_and_no_launch(self):
        missing = '/Volumes/DiskJanitorMissing-' + self.home.name + '/command'
        r = self.invoke('submit', '--', missing)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        job = r.stdout.strip()
        self.ids.append(job)
        waited = self.invoke('wait', job, timeout=6)
        self.assertEqual(waited.returncode, 75, waited.stdout + waited.stderr)
        self.assertIn('required mount is absent', waited.stderr)
        self.assertEqual(self.status(job)['state'], 'failed')

    def test_custom_data_mount_below_the_floor_fails_with_the_numbers(self):
        self.app.mkdir(parents=True, exist_ok=True)
        (self.app / 'config.env').write_text('DATA_PATH="/dev"\n')
        job = self.submit('pass  # build')
        waited = self.invoke('wait', job, timeout=8)
        self.assertEqual(waited.returncode, 75, waited.stdout + waited.stderr)
        self.assertRegex(waited.stderr, r'insufficient disk: 0.00 GiB free on /dev, need 5.00 GiB')
        self.assertEqual(self.status(job)['state'], 'failed')

    def test_terminal_receipt_waits_for_execution_lease_retirement(self):
        spec = importlib.util.spec_from_file_location('review_jobs', self.script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        store = module.Store(self.app)
        meta = store.create(['true'], self.home, self.env)
        self.ids.append(meta['id'])
        store.update(meta['id'], accepted=True, state='running')
        registry = self.app / 'guard-reservations'
        registry.mkdir()
        receipt = {'owner': meta['owner'], 'command_hash': hashlib.sha256(json.dumps(
            [meta['argv'], meta['cwd'], meta['owner'], meta['artifact_root']]).encode()).hexdigest()}
        module.atomic_json(registry / (meta['id'] + '.json'), dict(receipt, state='running'))
        module.atomic_json(registry / (meta['id'] + '.result'), dict(receipt, exit_code=0))
        with (registry / (meta['id'] + '.json')).open('rb') as execution:
            fcntl.flock(execution, fcntl.LOCK_EX)
            self.assertEqual(store.view(meta['id'])['state'], 'running')
            self.assertIsNone(store.view(meta['id'])['exit_code'])
        self.assertEqual(store.view(meta['id'])['state'], 'succeeded')

    def test_signal_exit_after_guardian_loss_is_normalized(self):
        job = self.submit('import os,signal,time;from pathlib import Path;Path("signal-start").touch();time.sleep(.6);os.kill(os.getpid(),signal.SIGTERM)')
        self.until(lambda: self.status(job)['state'] == 'running' and (self.home / 'signal-start').exists())
        os.kill(self.status(job)['guardian_pid'], signal.SIGKILL)
        self.assertEqual(self.invoke('wait', job).returncode, 143)
        self.assertEqual(self.status(job)['exit_code'], 143)


# Reuse fixture helpers without rerunning inherited acceptance cases in this file.
for name in list(fixtures.JobTests.__dict__):
    if name.startswith('test_') and name not in ReviewRegressions.__dict__:
        setattr(ReviewRegressions, name, None)


if __name__ == '__main__':
    unittest.main()
