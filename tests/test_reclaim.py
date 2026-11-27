"""Only explicitly approved, idle generated output may be reclaimed."""
import json
import os
import plistlib
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
import sys

REPO = Path(__file__).resolve().parents[1]


class ReclaimTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        self.scope = self.home / 'scratch project'
        self.scope.mkdir()
        (self.scope / 'package.json').write_text('{}')
        self.output = self.scope / 'node_modules'
        self.output.mkdir()
        (self.output / 'generated.js').write_text('regenerable')
        self.env = dict(os.environ, HOME=str(self.home),
                        DISK_JANITOR_HOME=str(self.home / '.dj'))
        self.manifest = self.home / 'approved.json'
        self.entries = [dict(path=str(self.output), scope=str(self.scope),
                             kind='node-dependencies', min_idle_hours=24)]
        self.age()

    def age(self):
        old = time.time() - 48 * 3600
        for path in sorted(self.scope.rglob('*'), reverse=True):
            if not path.is_symlink():
                os.utime(path, (old, old))
        os.utime(self.scope, (old, old))

    def invoke(self, *args):
        self.manifest.write_text(json.dumps(dict(version=1, entries=self.entries)))
        return subprocess.run(['bash', str(REPO / 'bin/disk-janitor'), 'reclaim',
                               '--manifest', str(self.manifest), *args],
                              env=self.env, capture_output=True, text=True, timeout=30)

    def test_preview_preserves_output(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('eligible', result.stdout)
        self.assertTrue(self.output.exists())

    def test_apply_removes_only_approved_generated_output(self):
        source = self.scope / 'journal.txt'
        source.write_text('keep my source')
        result = self.invoke('--apply')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.output.exists(), result.stdout)
        self.assertEqual(source.read_text(), 'keep my source')

    def test_recent_nested_file_keeps_old_directory(self):
        (self.output / 'generated.js').write_text('active output')
        result = self.invoke('--apply')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.output.exists(), result.stdout)
        self.assertIn('recent', result.stdout)

    def test_live_open_file_keeps_output(self):
        with (self.output / 'generated.js').open():
            result = self.invoke('--apply')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.output.exists(), result.stdout)
        self.assertIn('active', result.stdout)

    def test_active_process_cwd_in_scope_keeps_output(self):
        child = subprocess.Popen(['sleep', '20'], cwd=self.scope)
        try:
            result = self.invoke('--apply')
        finally:
            child.terminate()
            child.wait()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.output.exists(), result.stdout)
        self.assertIn('active', result.stdout)

    def test_symlink_is_never_followed(self):
        target = self.home / 'precious'
        self.output.rename(target)
        self.output.symlink_to(target, target_is_directory=True)
        result = self.invoke('--apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((target / 'generated.js').exists())

    def test_source_directory_is_rejected(self):
        self.entries[0]['path'] = str(self.scope)
        result = self.invoke('--apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.scope / 'package.json').exists())

    def test_git_tracked_output_is_preserved(self):
        subprocess.run(['git', 'init', '-q', str(self.scope)], check=True)
        # Build a fixture index without changing the real repository's index.
        subprocess.run(['git', '-C', str(self.scope), 'update-index', '--add',
                        '--cacheinfo', '100644',
                        subprocess.check_output(['git', '-C', str(self.scope),
                            'hash-object', '-w', 'node_modules/generated.js'], text=True).strip(),
                        'node_modules/generated.js'], check=True)
        self.age()
        result = self.invoke('--apply')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.output.exists(), result.stdout)
        self.assertIn('tracked', result.stdout)

    def test_later_invalid_entry_is_reported_without_blocking_valid_cleanup(self):
        self.entries.append(dict(path=str(self.scope), scope=str(self.scope),
                                 kind='node-dependencies', min_idle_hours=24))
        result = self.invoke('--apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.output.exists())
        self.assertTrue((self.scope / "package.json").exists())

    def test_missing_retired_scope_does_not_block_other_cleanup(self):
        missing = self.home / 'retired project'
        self.entries.append(dict(path=str(missing / 'node_modules'), scope=str(missing),
                                 kind='node-dependencies', min_idle_hours=24))
        result = self.invoke('--apply')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.output.exists(), result.stdout)

    def test_swift_checkouts_and_test_results_survive(self):
        (self.scope / 'Package.swift').write_text('// package')
        self.output = self.scope / '.build/out'
        self.output.mkdir(parents=True)
        (self.output / 'compiled.o').write_text('regenerable')
        source = self.scope / '.build/checkouts/dependency.swift'
        source.parent.mkdir()
        source.write_text('keep dependency source')
        results = self.scope / 'results.xcresult'
        results.mkdir()
        (results / 'proof').write_text('test proof')
        self.entries = [dict(path=str(self.output), scope=str(self.scope),
                             kind='swift-output', min_idle_hours=24)]
        self.age()
        result = self.invoke('--apply')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.output.exists(), result.stdout)
        self.assertTrue(source.exists())
        self.assertTrue((results / 'proof').exists())

    def test_process_inspection_failure_preserves_everything(self):
        fakebin = self.home / 'bin'
        fakebin.mkdir()
        lsof = fakebin / 'lsof'
        lsof.write_text('#!/bin/sh\necho inspection-failed >&2\nexit 1\n')
        lsof.chmod(0o755)
        self.env['PATH'] = str(fakebin) + ':' + self.env['PATH']
        result = self.invoke('--apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.output.exists())
        self.assertIn('cannot inspect process use', result.stderr)

    def test_review_cannot_reduce_minimum_idle_time(self):
        self.entries[0]['min_idle_hours'] = 0
        result = self.invoke('--apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.output.exists())

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS scheduler environment')
    def test_cleanup_works_with_launchd_system_python_and_path(self):
        self.env['PATH'] = '/usr/bin:/bin:/usr/sbin:/sbin'
        result = self.invoke('--apply')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.output.exists(), result.stdout)

    def test_weekly_cleanup_preserves_old_source_checkouts(self):
        checkout = self.home / 'Projects/repo/.claude/worktrees/agent-old'
        checkout.mkdir(parents=True)
        source = checkout / 'unmerged.txt'
        source.write_text('unmerged work')
        old = time.time() - 60 * 86400
        os.utime(source, (old, old))
        os.utime(checkout, (old, old))
        config = self.home / '.dj/config.env'
        config.parent.mkdir()
        config.write_text('cargo() { :; }\ncargo-sweep() { :; }\npnpm() { :; }\n')
        result = subprocess.run(['bash', str(REPO / 'bin/disk-janitor'), 'run'],
                                env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(source.read_text(), 'unmerged work')

    @unittest.skipUnless(sys.platform == 'darwin', 'launchd schedule')
    def test_hourly_schedule_and_uninstall_are_managed(self):
        self.env['DISK_JANITOR_NO_SCHED'] = '1'
        self.env['DISK_JANITOR_STORAGE_ROOT'] = 'none'
        home = self.home / '.dj'
        home.mkdir()
        (home / 'approved-artifacts.json').write_text(json.dumps(dict(version=1, entries=self.entries)))
        result = subprocess.run(['bash', str(REPO / 'bin/disk-janitor'), 'reclaim', '--schedule'],
                                env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        plist = self.home / 'Library/LaunchAgents/disk-janitor-reclaim.plist'
        with plist.open('rb') as stream:
            schedule = plistlib.load(stream)
        self.assertEqual(schedule['StartInterval'], 3600)
        self.assertIn('--apply', schedule['ProgramArguments'])
        self.assertIn('--report', schedule['ProgramArguments'])
        result = subprocess.run(['bash', str(REPO / 'bin/disk-janitor'), 'uninstall'],
                                env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(plist.exists())


if __name__ == '__main__':
    unittest.main()
