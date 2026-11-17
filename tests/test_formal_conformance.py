"""Finite receipt-observation checks at the TLA model/runtime boundary.

These check observable safety contracts, not a refinement proof of Jobs.tla.
No submitted command is executed by these tests.
"""
import hashlib
import fcntl
from contextlib import ExitStack
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    'formal_jobs_runtime', Path(__file__).resolve().parents[1] / 'bin' / 'jobs.py')
jobs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(jobs)


class FormalObservationConformance(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='janitor-conformance-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.store = jobs.Store(self.root / 'app')
        self.meta = self.store.create(['true'], self.root, {})
        self.store.update(self.meta['id'], accepted=True)
        self.receipts = self.store.home / 'guard-reservations'
        self.receipts.mkdir()
        self.receipt = {'owner': self.meta['owner'], 'command_hash': hashlib.sha256(
            json.dumps([self.meta['argv'], self.meta['cwd'], self.meta['owner'],
                        self.meta['artifact_root']]).encode()).hexdigest()}

    def write_receipt(self, suffix, **fields):
        jobs.atomic_json(self.receipts / (self.meta['id'] + suffix),
                         dict(self.receipt, **fields))

    def test_fresh_identity_and_public_nonrestartable_contract(self):
        identical = [self.meta] + [self.store.create(['true'], self.root, {}) for _ in range(2)]
        self.assertEqual(len({m['id'] for m in identical}), 3)
        for value in identical:
            self.assertEqual(value['id'], value['backend_job_id'])
            self.assertEqual(value['state'], 'queued')
            self.assertFalse(value['restartable'])

    def test_exhaustive_receipt_observations_never_launch_stored_commands(self):
        # Backend result authority wins over an older reservation. A result whose
        # proof was explicitly lost stays Unknown even when its numeric code is 0.
        results = [(None, None, None), (0, None, 'succeeded'),
                   (7, None, 'failed'), (143, None, 'cancelled'),
                   (0, 'outcome-uncertain', 'unknown'),
                   (125, 'outcome-uncertain', 'unknown')]
        result_path = self.receipts / (self.meta['id'] + '.result')
        record_path = self.receipts / (self.meta['id'] + '.json')
        with mock.patch.object(jobs.subprocess, 'Popen', side_effect=AssertionError('observer launched')):
            for record, live in ((None, False), ('waiting', False), ('waiting', True),
                                 ('running', False), ('running', True)):
                for cancel in (False, True):
                    for code, proof_status, expected_result in results:
                        with self.subTest(record=record, live=live, cancel=cancel, result=code,
                                          proof_status=proof_status), ExitStack() as stack:
                            for path in (record_path, result_path):
                                path.unlink(missing_ok=True)
                            if record:
                                self.write_receipt('.json', state=record)
                                if live:
                                    lease = stack.enter_context(record_path.open('rb'))
                                    fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            if code is not None:
                                self.write_receipt('.result', exit_code=code, status=proof_status)
                            self.store.update(self.meta['id'], cancel_requested=cancel)
                            expected = ('cancelling' if cancel else 'running') if live and code is not None else expected_result or (
                                'unknown' if not live else 'cancelling' if cancel else
                                'queued' if record == 'waiting' else 'running')
                            for _ in range(2):
                                self.assertEqual(self.store.view(self.meta['id'])['state'], expected)
                                self.assertEqual(self.store.list()[0]['state'], expected)
                            self.assertEqual(self.store.read(self.meta['id'])['backend_job_id'],
                                             self.meta['id'])

    def test_executor_lifetime_lease_loss_settles_unknown_without_replay(self):
        with mock.patch.object(jobs.subprocess, 'Popen', side_effect=AssertionError('observer launched')):
            for lease_name in ('worker.lock', 'guardian.lock'):
                for cancel in (False, True):
                    with self.subTest(lease=lease_name, cancel=cancel):
                        self.store.update(self.meta['id'], cancel_requested=cancel)
                        path = self.store.directory(self.meta['id']) / lease_name
                        with path.open('wb') as lease:
                            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            self.assertEqual(self.store.view(self.meta['id'])['state'],
                                             'cancelling' if cancel else 'queued')
                        self.assertEqual(self.store.view(self.meta['id'])['state'], 'unknown')

    def test_foreign_or_changed_command_proof_is_rejected(self):
        for field, value in [('owner', 'some-other-owner'), ('command_hash', 'changed')]:
            with self.subTest(field=field):
                payload = dict(self.receipt, exit_code=0)
                payload[field] = value
                jobs.atomic_json(self.receipts / (self.meta['id'] + '.result'), payload)
                with self.assertRaises(ValueError):
                    self.store.view(self.meta['id'])

    def test_provisional_unknown_accepts_late_authoritative_receipt_without_replay(self):
        with mock.patch.object(jobs.subprocess, 'Popen', side_effect=AssertionError('observer launched')):
            self.assertEqual(self.store.view(self.meta['id'])['state'], 'unknown')
            for code, expected in ((0, 'succeeded'), (7, 'failed'), (143, 'cancelled')):
                with self.subTest(code=code):
                    self.write_receipt('.result', exit_code=code, status='command-completed')
                    for _ in range(2):
                        value = self.store.view(self.meta['id'])
                        self.assertEqual((value['state'], value['exit_code']), (expected, code))
                        self.assertEqual(self.store.list()[0]['state'], expected)
                        self.assertEqual(value['backend_job_id'], self.meta['id'])

    def test_terminal_metadata_never_overrides_live_execution_lease(self):
        self.write_receipt('.json', state='running')
        self.write_receipt('.result', exit_code=0, status='command-completed')
        record_path = self.receipts / (self.meta['id'] + '.json')
        with record_path.open('rb') as lease, mock.patch.object(
                jobs.subprocess, 'Popen', side_effect=AssertionError('observer launched')):
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            for persisted in jobs.TERMINAL:
                for cancel in (False, True):
                    with self.subTest(persisted=persisted, cancel=cancel):
                        self.store.update(self.meta['id'], state=persisted, cancel_requested=cancel)
                        value = self.store.view(self.meta['id'])
                        self.assertEqual(value['state'], 'cancelling' if cancel else 'running')
                        self.assertIsNone(value['exit_code'])


if __name__ == '__main__':
    unittest.main()
