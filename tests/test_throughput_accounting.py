import ast
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
import unittest


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        script = (Path(__file__).resolve().parents[1] / 'bin/disk-janitor').read_text()
        body = script[script.index('cmd_capacity()'):].split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
        tree = ast.parse(body)
        names = {'eligible', 'volume_budget', 'volume_consumed', 'pending_retention'}
        nodes = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name in names]
        scope = dict(time=time, os=os, sys=SimpleNamespace(platform='fixture'), memory_available=lambda: None)
        exec(compile(ast.Module(body=nodes, type_ignores=[]), '<admission-fixture>', 'exec'), scope)
        self.eligible = scope['eligible']

    def job(self, root=1, external=20, budget=20, consumed=0, overrun=False):
        return dict(owner='fixture', budget=budget, retention='external',
                    retention_limit=200, memory=0, artifact=None, overrun=overrun,
                    consumed={'/external': consumed}, volumes=[
                        dict(path='/', device=1, reserve=20, budget=root),
                        dict(path='/external', device=2, reserve=100, budget=external)])

    def test_external_output_is_not_reserved_again_on_internal_disk(self):
        self.assertIsNone(self.eligible(self.job(), [], {'/': 25, '/external': 1000}, 30))

    def test_pending_claims_use_each_actual_filesystem_budget(self):
        active = self.job(root=2, external=50, budget=50)
        self.assertIsNone(self.eligible(self.job(), [active], {'/': 25, '/external': 1000}, 30))

    def test_another_owner_overrun_is_not_a_global_completion_lock(self):
        active = self.job(root=1, external=10, budget=10, consumed=12, overrun=True)
        self.assertIsNone(self.eligible(self.job(root=1), [active], {'/': 25, '/external': 1000}, 30))

    def test_real_physical_reserve_still_blocks(self):
        self.assertIn('disk reserve', self.eligible(self.job(root=6), [], {'/': 25, '/external': 1000}, 30))

    def test_retained_outputs_not_counted_twice_as_pending(self):
        active = self.job(root=0, external=50, budget=50, consumed=40)
        incoming = self.job(root=0, external=20, budget=20)
        incoming['retention_limit'] = active['retention_limit'] = 100
        self.assertIsNone(self.eligible(incoming, [active], {'/': 25, '/external': 1000}, 60))

    def test_legacy_reservations_remain_conservative(self):
        old = self.job()
        for v in old['volumes']:
            del v['budget']
        self.assertIn('disk reserve', self.eligible(old, [], {'/': 25, '/external': 1000}, 30))

    def test_twelve_small_commitments_have_no_arbitrary_slot_limit(self):
        active = [self.job(root=.01, external=1, budget=1) for _ in range(12)]
        self.assertIsNone(self.eligible(self.job(root=.01, external=1, budget=1), active,
                                       {'/': 25, '/external': 1000}, 30))


class BudgetCLI(unittest.TestCase):
    def invoke(self, options):
        with tempfile.TemporaryDirectory() as temp:
            env = dict(os.environ, HOME=temp, DISK_JANITOR_HOME=temp+'/.dj')
            command = ['bash', str((Path(__file__).resolve().parents[1] / 'bin/disk-janitor')), 'guard',
                       '--owner', 'budget-fixture', '--root-reserve-gib', '0',
                       '--planned-gib', '0', '--once', *options, '--', sys.executable,
                       '-c', 'pass']
            return subprocess.run(command, env=env, capture_output=True, text=True, timeout=8)

    def test_explicit_zero_write_budget_can_complete_read_only_command(self):
        result = self.invoke(['--write-budget', '/', '0'])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_invalid_write_budget_fails_before_launch(self):
        for options in ([ '--write-budget', '/', '-1'],
                        [ '--write-budget', '/', 'nan'],
                        [ '--write-budget', '/not-a-required-mount', '1'],
                        [ '--write-budget', '/', '0', '--write-budget', '/', '0']):
            with self.subTest(options=options):
                result = self.invoke(options)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('budget', result.stderr)


if __name__ == '__main__':
    unittest.main()
