import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('commitments', REPO / 'bin/commitments.py')
commitments = importlib.util.module_from_spec(spec)
spec.loader.exec_module(commitments)


def claim(identifier='runner-1', **values):
    return dict(dict(id=identifier, label='linux runner', device=1, disk_bytes=40 * 2**30,
                     memory_bytes=8 * 2**30, reserve_bytes=20 * 2**30, path='/var/lib/pool'), **values)


class ProviderProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name).resolve()
        self.registry = root / 'providers'
        self.home = root / 'home/.disk-janitor'
        self.home.mkdir(parents=True, mode=0o700)
        (self.home / 'admission.lock').touch(mode=0o600)
        self.options = dict(registry=self.registry, owner_uid=os.getuid())
        self.reader = commitments.Commitments(**self.options)
        self.provider = commitments.Provider('ci-pool', **self.options)

    def bind(self):
        self.provider.bind(self.home, os.getuid())

    def test_no_registry_means_independent_admission(self):
        self.assertEqual(self.reader.claims(), [])
        with self.provider.transaction() as shared:
            self.assertIsNone(shared)

    def test_published_commitments_become_admission_records(self):
        self.bind()
        with self.provider.transaction() as shared:
            shared.publish([claim('runner-1'), claim('runner-2', device=2)])
        records = self.reader.claims(guard_home=self.home)
        self.assertEqual([r['id'] for r in records], ['ci-pool:runner-1', 'ci-pool:runner-2'])
        self.assertEqual(records[1]['volumes'][0]['device'], 2)
        self.assertEqual(records[0]['owner'], 'ci-pool linux runner')

    def test_provider_reads_running_local_jobs_under_the_lock(self):
        self.bind()
        reservations = self.home / 'guard-reservations'
        reservations.mkdir(mode=0o700)
        volume = dict(device=1, reserve=5, budget=10)
        for name, state in (('a', 'running'), ('b', 'waiting'), ('c', 'completed')):
            (reservations / (name + '.json')).write_text(json.dumps(
                dict(state=state, memory=3, budget=10, volumes=[volume])))
        with self.provider.transaction() as shared:
            self.assertEqual(shared.local_claims(), [dict(memory=3, volumes=[volume])])

    def test_registered_without_binding_is_incomplete_not_absent(self):
        (self.registry / 'ci-pool').mkdir(parents=True, mode=0o755)
        self.registry.chmod(0o755)
        claims, problems = self.reader.gather()
        self.assertEqual(claims, [])
        self.assertIn('ci-pool registration is incomplete', problems[0])

    def test_tampered_future_or_relocked_state_is_unavailable(self):
        self.bind()
        snapshot = self.registry / 'ci-pool/commitments.json'
        value = json.loads(snapshot.read_text())
        for change in (dict(claims='not a list'), dict(updated_at=10 ** 12), dict(lock_identity=[0, 0]),
                       dict(provider='other')):
            commitments.write_atomic(snapshot, dict(value, **change))
            with self.assertRaises(commitments.ProviderUnavailable):
                self.reader.claims()
        commitments.write_atomic(snapshot, value)
        (self.home / 'admission.lock').unlink()
        (self.home / 'admission.lock').touch(mode=0o600)  # replaced lock: new inode
        with self.assertRaises(commitments.ProviderUnavailable):
            self.reader.claims()

    def test_one_untrusted_provider_does_not_hide_another(self):
        self.bind()
        with self.provider.transaction() as shared:
            shared.publish([claim()])
        other = commitments.Provider('vm-host', **self.options)
        other.bind(self.home, os.getuid())
        commitments.write_atomic(self.registry / 'vm-host/commitments.json', {'version': 1})
        claims, problems = self.reader.gather()
        self.assertEqual([c['id'] for c in claims], ['ci-pool:runner-1'])
        self.assertEqual(len(problems), 1)
        self.assertIn('vm-host', problems[0])

    def test_binding_for_another_account_contributes_nothing(self):
        self.provider.bind(self.home, os.getuid())
        foreign = commitments.Commitments(**self.options, user_uid=os.getuid() + 1)
        self.assertEqual(foreign.claims(), [])

    def test_writable_registry_is_not_trusted(self):
        self.bind()
        self.registry.chmod(0o777)
        self.addCleanup(self.registry.chmod, 0o755)
        claims, problems = self.reader.gather()
        self.assertEqual(claims, [])
        self.assertTrue(problems)

    def test_snapshot_is_readable_under_a_private_daemon_umask(self):
        previous = os.umask(0o077)
        try:
            self.bind()
        finally:
            os.umask(previous)
        self.assertEqual((self.registry / 'ci-pool/commitments.json').stat().st_mode & 0o777, 0o644)


if __name__ == '__main__':
    unittest.main()
