"""Idle Gradle build outputs in git checkouts, registry retirement and unstarved recovery.

Every repository, checkout and record is a disposable fixture in a temporary home.
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
from unittest.mock import patch
from types import SimpleNamespace

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'bin'))
SPEC = importlib.util.spec_from_file_location('worktree_recovery', REPO / 'bin/recovery.py')
recovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recovery)
IDLE = lambda: ([], [])


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name).resolve()
        self.app = self.home / '.dj'
        self.app.mkdir(mode=0o700)
        self.environment = patch.dict(os.environ, {'HOME': str(self.home), 'GIT_CONFIG_GLOBAL': os.devnull,
                                                   'GIT_CONFIG_SYSTEM': os.devnull})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        os.environ.pop('DISK_JANITOR_PROJECT_DIRS', None)

    def git(self, directory, *arguments):
        subprocess.run(['git', '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid',
                        '-C', str(directory), *arguments], check=True, capture_output=True)

    def repository(self):
        repo = self.home / 'Projects/app'
        (repo / 'feature/src/main/build').mkdir(parents=True)
        (repo / 'build.gradle.kts').write_text('// root')
        (repo / 'feature/build.gradle.kts').write_text('// module')
        (repo / 'feature/src/main/build/Source.kt').write_text('class Source')
        (repo / '.gitignore').write_text('build/\n!tools/build/\n')
        (repo / 'tools/build').mkdir(parents=True)
        (repo / 'tools/build.gradle').write_text('// scripts')
        (repo / 'tools/build/release.sh').write_text('#!/bin/sh\n')
        self.git(repo, 'init', '-q')
        self.git(repo, 'add', '-A')
        self.git(repo, 'commit', '-q', '-m', 'fixture')
        return repo

    def output(self, directory, name='classes/Generated.kt'):
        target = directory / 'build' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('generated')
        return directory / 'build'

    def recover(self, observer=IDLE, **options):
        return recovery.recover(self.home, self.app, apply=True, observer=observer, **options)


class WorktreeBuildTests(Fixture):
    def test_idle_checkout_outputs_are_removed_and_source_named_build_is_kept(self):
        repo = self.repository()
        linked = self.home / '.agent/worktrees/task'
        self.git(repo, 'worktree', 'add', '-q', str(linked), '-b', 'task')
        outputs = [self.output(repo), self.output(repo / 'feature'), self.output(linked), self.output(linked / 'feature')]
        (outputs[0] / 'js/node_modules').mkdir(parents=True)
        (outputs[0] / 'js/node_modules/link').symlink_to(repo / 'feature')
        report = self.recover()
        self.assertEqual(report['status'], 'completed')
        for path in outputs:
            self.assertFalse(path.exists(), path)
        self.assertEqual(report['counts'].get('worktree-build:removed'), 4)
        self.assertTrue((repo / 'feature/src/main/build/Source.kt').exists(), 'a build directory under src is source')
        self.assertTrue((repo / 'tools/build/release.sh').exists(), 'a build directory with tracked files is source')
        self.assertTrue((repo / 'feature/build.gradle.kts').exists())
        self.assertEqual(subprocess.run(['git', '-C', str(repo), 'status', '--porcelain'], capture_output=True, text=True).stdout, '')

    def test_next_and_turbo_outputs_beside_package_json_are_removed(self):
        repo = self.repository()
        app = repo / 'apps/web'
        app.mkdir(parents=True)
        (app / 'package.json').write_text('{}')
        (repo / 'package.json').write_text('{}')
        (repo / '.gitignore').write_text('build/\n!tools/build/\n.next/\n.turbo/\n')
        self.git(repo, 'add', '-A')
        self.git(repo, 'commit', '-q', '-m', 'node packages')
        generated = [app / '.next/cache/webpack/chunk.pack', app / '.turbo/turbo-build.log', repo / '.turbo/cache/a.tar.zst']
        for path in generated:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('generated')
        loose = repo / 'docs/.next/page.html'  # no package.json beside it
        loose.parent.mkdir(parents=True)
        loose.write_text('kept')
        report = self.recover()
        for path in generated:
            self.assertFalse(path.exists(), path)
        self.assertTrue(loose.exists())
        self.assertEqual(report['counts'].get('worktree-build:removed'), 3)

    def test_uncommitted_files_credentials_and_databases_keep_their_directory(self):
        repo = self.repository()
        (repo / 'tools/build/draft.sh').write_text('not committed, not ignored')
        (repo / 'plain/build').mkdir(parents=True)  # no Gradle build script beside it
        (repo / 'plain/build/out.bin').write_text('x')
        (repo / 'plain/.gitignore').write_text('build/\n')
        secret = self.output(repo, 'release/upload.jks')
        database = self.output(repo / 'feature', 'test-results/state.sqlite')
        self.recover()
        self.assertTrue((repo / 'tools/build/draft.sh').exists())
        self.assertTrue((repo / 'plain/build/out.bin').exists())
        self.assertTrue((secret / 'release/upload.jks').exists())
        self.assertTrue((database / 'test-results/state.sqlite').exists())

    def test_open_file_working_directory_or_live_job_keeps_the_whole_checkout(self):
        repo = self.repository()
        idle, busy, queued = (self.home / '.agent' / name for name in ('idle', 'busy', 'queued'))
        for index, checkout in enumerate((idle, busy, queued)):
            self.git(repo, 'worktree', 'add', '-q', str(checkout), '-b', 'b%d' % index)
            self.output(checkout)
        job = self.app / 'jobs' / ('j-' + 'a' * 32)
        job.mkdir(parents=True)
        (job / 'job.json').write_text(json.dumps({'cwd': str(queued / 'feature'), 'state': 'queued', 'submitted_at': 1}))
        (job / 'worker.lock').touch()
        finished = self.app / 'jobs' / ('j-' + 'b' * 32)
        finished.mkdir()
        (finished / 'job.json').write_text(json.dumps({'cwd': str(idle), 'state': 'running', 'submitted_at': 1}))
        with open(job / 'worker.lock') as lease:
            fcntl.flock(lease, fcntl.LOCK_EX)
            self.recover(observer=lambda: ([], [str(busy / 'feature/src/main/build/Source.kt'), str(repo)]))
        self.assertFalse((idle / 'build').exists(), 'a job record with no executor does not hold a checkout')
        self.assertTrue((busy / 'build').exists())
        self.assertTrue((queued / 'build').exists())

    def test_pressure_recovery_runs_beside_running_jobs_and_contended_admission(self):
        repo = self.repository()
        output = self.output(repo)
        with open(self.app / 'guard.lock', 'w') as fence, open(self.app / 'admission.lock', 'w') as admission:
            fcntl.flock(fence, fcntl.LOCK_SH)
            fcntl.flock(admission, fcntl.LOCK_EX)
            began = time.monotonic()
            report = self.recover(pressure_only=True, floors={str(recovery._mount_of(self.home)): 2**62})
        self.assertLess(time.monotonic() - began, 10)
        self.assertEqual(report['status'], 'completed')
        self.assertFalse(output.exists())

    def test_second_recovery_gives_up_within_a_second_instead_of_queueing(self):
        with open(self.app / 'recovery-pass.lock', 'w') as other:
            fcntl.flock(other, fcntl.LOCK_EX)
            began = time.monotonic()
            report = self.recover(pressure_only=True, floors={'/': 2**62})
        self.assertEqual(report['status'], 'another-recovery-or-admission')
        self.assertLess(time.monotonic() - began, 3)

    def test_recovery_lock_held_by_an_earlier_release_does_not_starve_a_pressure_pass(self):
        output = self.output(self.repository())
        with open(self.app / 'recovery.lock', 'w') as earlier:
            fcntl.flock(earlier, fcntl.LOCK_EX)
            report = self.recover(pressure_only=True, floors={str(recovery._mount_of(self.home)): 2**62})
        self.assertEqual(report['status'], 'completed')
        self.assertFalse(output.exists())

    def test_time_limit_stops_discovery(self):
        repo = self.repository()
        output = self.output(repo)
        report = self.recover(pressure_only=True, floors={str(recovery._mount_of(self.home)): 2**62}, time_limit=0)
        self.assertTrue(report.get('time_limited'))
        self.assertTrue(output.exists())

    def test_uninspectable_process_protects_caches_without_ending_the_pass(self):
        commands = [dict(pid=1, executable=None, family='unknown')]
        for kind in ('cargo-incremental', 'gradle-transform', 'xcode-derived'):
            self.assertTrue(recovery.busy(kind, Path('/nowhere'), commands, []))
        output = self.output(self.repository())
        self.recover(observer=lambda: (commands, []))
        self.assertFalse(output.exists(), 'checkout occupancy, not a compiler family, decides build outputs')


class PressureDemandTests(Fixture):
    def free(self, gib):
        return patch.object(recovery.shutil, 'disk_usage', lambda path: SimpleNamespace(free=int(gib * 2**30)))

    def test_default_demand_restores_low_water_and_ignores_every_record(self):
        registry = self.app / 'guard-reservations'
        registry.mkdir()
        (registry / 'garbage.json').write_bytes(b'\xff{')
        (registry / 'debt.json').write_text(json.dumps({'id': 'debt', 'state': 'running', 'retention_unsettled': True}))
        with self.free(12), patch.dict(os.environ, {'DISK_JANITOR_LOW_WATER_GIB': '30'}):
            demand = recovery.pressure_demand(self.app)
        self.assertEqual([round(value['deficit'] / 2**30) for value in demand.values()], [18])
        with self.free(31):
            self.assertEqual(recovery.pressure_demand(self.app), {})

    def test_refused_job_floor_and_absent_mount(self):
        mount = str(recovery._mount_of(self.home))
        with self.free(3):
            demand = recovery.pressure_demand(self.app, {mount: 5 * 2**30, str(self.home / 'unmounted'): 2**40})
        self.assertEqual(len(demand), 1)
        self.assertEqual(next(iter(demand.values()))['deficit'], 2 * 2**30)


class RegistryTests(Fixture):
    def setUp(self):
        super().setUp()
        self.registry = self.app / 'guard-reservations'
        self.registry.mkdir()

    def record(self, name, **fields):
        value = dict({'id': name, 'owner': 'owner', 'command_hash': 'hash', 'state': 'running', 'child': None}, **fields)
        (self.registry / (name + '.json')).write_text(json.dumps(value))
        return self.registry / (name + '.json')

    def test_settlement_debt_with_a_durable_result_is_retired(self):
        # The stalled record of the incident: admitted, guardian gone, never re-measured.
        path = self.record('debt', finished=1, retention_unsettled=True, artifact=str(self.home),
                           retention=str(self.home / 'gone'), retention_identity=[1, 2])
        receipt = {'owner': 'owner', 'command_hash': 'hash', 'exit_code': 125, 'status': 'outcome-uncertain'}
        (self.registry / 'debt.result').write_text(json.dumps(receipt))
        counts = recovery.sweep_registry(self.app)
        self.assertFalse(path.exists())
        self.assertEqual(json.loads((self.registry / 'debt.result').read_text()), receipt)
        self.assertEqual(counts['retired'], 1)

    def test_crashed_guardian_gets_an_uncertain_receipt_before_retirement(self):
        path = self.record('crashed')
        recovery.sweep_registry(self.app)
        self.assertFalse(path.exists())
        self.assertEqual(json.loads((self.registry / 'crashed.result').read_text())['status'], 'outcome-uncertain')

    def test_captured_outcome_resolves_an_uncertain_receipt(self):
        self.record('late')
        (self.registry / 'late.result').write_text(json.dumps({'owner': 'owner', 'command_hash': 'hash', 'exit_code': 125, 'status': 'outcome-uncertain'}))
        (self.registry / 'late.outcome').write_text(json.dumps({'owner': 'owner', 'command_hash': 'hash', 'exit_code': 0, 'status': 'command-completed'}))
        recovery.sweep_registry(self.app)
        self.assertEqual(json.loads((self.registry / 'late.result').read_text())['exit_code'], 0)

    def test_live_and_ambiguous_records_are_left_alone(self):
        live = self.record('live')
        foreign = self.record('foreign')
        (self.registry / 'foreign.result').write_text(json.dumps({'owner': 'other', 'command_hash': 'x', 'exit_code': 0}))
        garbage = self.registry / 'garbage.json'
        garbage.write_bytes(b'\xff{')
        fresh = self.registry / 'fresh.json'
        fresh.write_text('')
        (self.registry / 'folder.json').mkdir()
        survivor = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(30)'], start_new_session=True)
        self.addCleanup(survivor.wait)
        self.addCleanup(survivor.kill)
        supervised = self.record('supervised', child=survivor.pid)
        with open(live) as lease:
            fcntl.flock(lease, fcntl.LOCK_EX)
            counts = recovery.sweep_registry(self.app)
        for path in (live, foreign, garbage, fresh, supervised):
            self.assertTrue(path.exists(), path)
        self.assertFalse((self.registry / 'supervised.result').exists())
        self.assertEqual(counts['live'], 2)
        self.assertGreaterEqual(counts['ambiguous'], 3)

    def test_watchdog_pass_retires_records_and_backs_off_after_an_empty_recovery(self):
        path = self.record('crashed')
        with patch.object(recovery.shutil, 'disk_usage', lambda _: SimpleNamespace(free=2**30)):
            first = recovery.watchdog(self.home, self.app, monitor_seconds=0)
            (self.app / 'watchdog-last.json').write_text(json.dumps(first))
            second = recovery.watchdog(self.home, self.app, monitor_seconds=0)
        self.assertFalse(path.exists())
        self.assertEqual(first['registry']['retired'], 1)
        self.assertEqual(first['recovery']['status'], 'completed')
        self.assertEqual(second['recovery']['status'], 'waiting-after-empty-pass')
        self.assertEqual(first['stalled_waiters_started'], [])

    def test_watchdog_starts_the_oldest_waiter_left_beside_a_free_slot(self):
        import capacity
        with patch.dict(os.environ, {'DISK_JANITOR_MAX_RUNNING': '1'}):
            first, first_fd = capacity.join_queue(self.app, 1.0, 'first')
            second, second_fd = capacity.join_queue(self.app, 2.0, 'second')
            self.addCleanup(os.close, first_fd)
            self.addCleanup(os.close, second_fd)
            granted = recovery.start_stalled(self.app, 1.5, interval=.2)
            self.assertEqual(granted, [first.name])
            self.assertTrue(first.with_name(first.name + '.go').exists())
            slot = capacity.take_slot(self.app, 1)
            self.addCleanup(os.close, slot)
            first.with_name(first.name + '.go').unlink()
            self.assertEqual(recovery.start_stalled(self.app, 1, interval=.2), [], 'a full machine is not a stall')


class InterpreterTests(unittest.TestCase):
    SYSTEM = '/usr/bin/python3'

    def old(self):
        try:
            probe = subprocess.run([self.SYSTEM, '-c', 'import sys;raise SystemExit(sys.version_info >= (3, 10))'], timeout=20)
        except (OSError, subprocess.SubprocessError):
            return False
        return probe.returncode == 0

    def test_modules_refuse_an_old_interpreter(self):
        if not self.old():
            self.skipTest('no interpreter older than 3.10 at ' + self.SYSTEM)
        for module in ('recovery.py', 'jobs.py', 'capacity.py', 'coverage.py', 'install_runtime.py'):
            result = subprocess.run([self.SYSTEM, '-B', str(REPO / 'bin' / module), '--help'], capture_output=True, text=True, timeout=20)
            self.assertNotEqual(result.returncode, 0, module)
            self.assertIn('Python 3.10 or newer is required', result.stderr, module)

    def test_cli_selects_a_new_interpreter_when_path_finds_the_old_one_first(self):
        if not self.old():
            self.skipTest('no interpreter older than 3.10 at ' + self.SYSTEM)
        with tempfile.TemporaryDirectory() as home:
            environment = {'HOME': home, 'PATH': '/usr/bin:/bin', 'DISK_JANITOR_HOME': home + '/.dj',
                           'DISK_JANITOR_PYTHON': sys.executable}
            result = subprocess.run(['/bin/bash', str(REPO / 'bin/disk-janitor'), 'status'], env=environment,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('internal free', result.stdout)


if __name__ == '__main__':
    unittest.main()
