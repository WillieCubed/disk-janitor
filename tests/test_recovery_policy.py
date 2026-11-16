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


class RecoveryPolicyTests(unittest.TestCase):
    def setUp(self):
        module = REPO / 'bin/recovery.py'
        self.assertTrue(module.exists(), 'dynamic recovery implementation is missing')
        spec = importlib.util.spec_from_file_location('recovery', module)
        self.recovery = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.recovery)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name).resolve()
        self.app = self.home / '.dj'
        self.app.mkdir()

    def output(self, relative, contents=b'generated'):
        p = self.home / relative
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(contents)
        return p

    def recover(self, apply=True, commands=(), paths=()):
        return self.recovery.recover(self.home, self.app, apply=apply,
                                     observer=lambda: (list(commands), list(paths)))

    def test_dynamic_categories_need_no_approval_file(self):
        cargo = self.output('.cache/cargo-target/debug/incremental/crate/session/object.o')
        gradle = self.output('.gradle/caches/build-cache-1/' + 'a' * 32)
        xcode = self.output('Library/Developer/Xcode/DerivedData/App/Build/object.o')
        keep = self.output('Library/Developer/Xcode/DerivedData/App/SourcePackages/checkouts/source.swift')
        report = self.recover()
        self.assertGreater(report['removed_allocated_bytes'], 0)
        for p in [cargo, gradle, xcode]:
            self.assertFalse(p.exists(), str(p))
        self.assertTrue(keep.exists())

    def test_preview_preserves_everything(self):
        p = self.output('.cache/cargo-target/debug/incremental/crate/object.o')
        self.recover(apply=False)
        self.assertTrue(p.exists())

    def test_active_tool_and_open_path_are_preserved(self):
        cargo = self.output('.cache/cargo-target/debug/incremental/crate/object.o')
        gradle = self.output('.gradle/caches/build-cache-1/' + 'b' * 32)
        self.recover(commands=['/usr/bin/rustc --crate-name sample'], paths=[str(gradle)])
        self.assertTrue(cargo.exists())
        self.assertTrue(gradle.exists())

    def test_source_credentials_database_and_symlinks_are_preserved(self):
        root = '.cache/cargo-target/debug/incremental/'
        paths = [self.output(root + 'source/main.rs'), self.output(root + 'credential/token.json'),
                 self.output(root + 'data/personal.sqlite')]
        outside = self.output('personal/photo.jpg')
        link = self.home / (root + 'link')
        link.symlink_to(outside.parent, target_is_directory=True)
        self.recover()
        for p in paths + [outside, link]:
            self.assertTrue(p.exists(), str(p))

    def test_bad_candidate_does_not_disable_other_categories(self):
        self.output('.cache/cargo-target/debug/incremental/source/Cargo.toml')
        good = self.output('.gradle/caches/build-cache-1/' + 'c' * 32)
        self.recover()
        self.assertFalse(good.exists())

    def test_database_without_filename_extension_is_preserved(self):
        database = self.output('.gradle/caches/build-cache-1/' + 'd' * 32,
                               b'SQLite format 3\x00' + b'private database')
        self.recover()
        self.assertTrue(database.exists())

    def test_active_guard_fence_preserves_outputs(self):
        import fcntl
        p = self.output('.cache/cargo-target/debug/incremental/crate/object.o')
        with (self.app / 'guard.lock').open('a') as handle:
            fcntl.flock(handle, fcntl.LOCK_SH)
            report = self.recover()
        self.assertTrue(p.exists())
        self.assertEqual(report['status'], 'active-guard')

    def test_observation_failure_preserves_outputs(self):
        p = self.output('.cache/cargo-target/debug/incremental/crate/object.o')
        def unavailable():
            raise RuntimeError('cannot inspect activity')
        with self.assertRaises(RuntimeError):
            self.recovery.recover(self.home, self.app, apply=True, observer=unavailable)
        self.assertTrue(p.exists())

    def test_preemption_limit_and_service_exclusion(self):
        import fcntl
        registry = self.app / 'guard-reservations'
        registry.mkdir()
        (registry / 'requester.json').write_text(json.dumps({'id': 'requester', 'state': 'waiting', 'class': 'feedback'}))
        target = registry / 'target.json'
        record = {'id': 'target', 'owner': 'fixture', 'state': 'running', 'class': 'build',
                  'restartable': True, 'restart_kind': 'test', 'preemptions': 2,
                  'child': os.getpid(), 'command_hash': 'same-command'}
        target.write_text(json.dumps(record))
        with target.open('r+') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            self.assertIsNone(self.recovery.request_preemption(self.app, 'requester'))
            record.update(preemptions=0, **{'class': 'service'})
            target.write_text(json.dumps(record))
            self.assertIsNone(self.recovery.request_preemption(self.app, 'requester'))
        self.assertFalse((registry / 'target.preempt-request').exists())


class CleanerRegressionTests(unittest.TestCase):
    def test_conflicting_cleanup_modes_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            r = subprocess.run(['/bin/bash', str(REPO / 'bin/disk-janitor'), 'recover', '--dry-run', '--apply'],
                               env=dict(os.environ, HOME=td, DISK_JANITOR_HOME=str(Path(td) / '.dj')),
                               text=True, capture_output=True, timeout=10)
            self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
            self.assertIn('not allowed with argument', r.stderr)

    def test_install_copies_recovery_implementation(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            env = dict(os.environ, HOME=td, DISK_JANITOR_HOME=str(home / '.dj'), DISK_JANITOR_NO_SCHED='1')
            r = subprocess.run(['/bin/bash', str(REPO / 'bin/disk-janitor'), 'install'],
                               env=env, text=True, capture_output=True, timeout=10)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertTrue((home / '.dj/recovery.py').exists(), 'installed recovery module is missing')
            self.assertEqual((home / '.dj/recovery.py').read_bytes(), (REPO / 'bin/recovery.py').read_bytes())

    def test_scheduling_dynamic_recovery_needs_no_approval_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            env = dict(os.environ, HOME=td, DISK_JANITOR_HOME=str(home / '.dj'), DISK_JANITOR_NO_SCHED='1')
            r = subprocess.run(['/bin/bash', str(REPO / 'bin/disk-janitor'), 'reclaim', '--schedule'],
                               env=env, text=True, capture_output=True, timeout=10)
            if sys.platform != 'darwin':
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertIn('requires launchd', r.stderr)
                return
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertTrue((home / 'Library/LaunchAgents/disk-janitor-reclaim.plist').exists())

    def test_invalid_legacy_entry_does_not_block_valid_entry(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td).resolve()
            scope = home / 'project'
            scope.mkdir()
            (scope / 'package.json').write_text('{}')
            target = scope / 'node_modules'
            target.mkdir()
            (target / 'generated').write_text('output')
            old = time.time() - 48 * 3600
            for p in [target / 'generated', target, scope]:
                os.utime(p, (old, old))
            manifest = home / 'legacy.json'
            manifest.write_text(json.dumps({'version': 1, 'entries': [
                {'kind': 'unknown', 'path': str(home / 'missing'), 'scope': str(home)},
                {'kind': 'node-dependencies', 'path': str(target), 'scope': str(scope)}]}))
            r = subprocess.run(['/bin/bash', str(REPO / 'bin/disk-janitor'), 'reclaim',
                                '--manifest', str(manifest), '--apply'],
                               env=dict(os.environ, HOME=str(home), DISK_JANITOR_HOME=str(home / '.dj')),
                               text=True, capture_output=True, timeout=15)
            self.assertFalse(target.exists(), r.stdout + r.stderr)
            self.assertIn('invalid', r.stdout)

    def test_stock_bash_empty_array_dry_run(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            app = home / '.dj'
            app.mkdir()
            (app / 'approved-artifacts.json').write_text('{"version":1,"entries":[]}')
            env = dict(os.environ, HOME=td, DISK_JANITOR_HOME=str(app))
            r = subprocess.run(['/bin/bash', str(REPO / 'bin/disk-janitor'), 'run', '--dry-run'],
                               env=env, text=True, capture_output=True, timeout=15)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertNotIn('unbound variable', r.stdout + r.stderr)


if __name__ == '__main__':
    unittest.main()
