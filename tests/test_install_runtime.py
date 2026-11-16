import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
INSTALLER = REPO / 'bin/install_runtime.py'
NAMES = ('disk-janitor', 'recovery.py', 'jobs.py', 'capacity.py', 'coverage.py',
         'runnerpools_bridge.py', 'install_runtime.py')


class AtomicRuntimeInstall(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.home = self.root / 'app'
        self.source = self.root / 'source'
        self.source.mkdir()
        self.write_source('one')

    def write_source(self, version):
        for name in NAMES:
            (self.source / name).write_text('# runtime ' + version + ' ' + name + '\n')
        (self.source / 'recovery.py').write_text('VERSION = ' + repr(version) + '\n')
        (self.source / 'disk-janitor').write_text('#!' + sys.executable + ' -B\n'
             'from pathlib import Path\nimport sys\n'
             'sys.path.insert(0,str(Path(__file__).resolve().parent))\n'
             'import recovery\nprint(recovery.VERSION)\n')
        (self.source / 'disk-janitor').chmod(0o755)

    def invoke(self):
        return subprocess.run([sys.executable, str(INSTALLER), '--source', str(self.source),
                               '--home', str(self.home)], capture_output=True, text=True, timeout=15)

    def install(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return Path(result.stdout.strip())

    def run_canonical(self):
        return subprocess.check_output([str(self.home / 'disk-janitor')], text=True, timeout=5).strip()

    def test_publishes_complete_immutable_release_and_reuses_identical_content(self):
        release = self.install()
        self.assertEqual(self.run_canonical(), 'one')
        self.assertEqual((self.home / 'current').resolve(), release)
        for name in NAMES:
            self.assertEqual((release / name).read_bytes(), (self.source / name).read_bytes())
            if name == 'disk-janitor':
                self.assertFalse((self.home / name).is_symlink())
                self.assertTrue((self.home / name).is_file())
            else:
                self.assertTrue((self.home / name).is_symlink())
                self.assertEqual(os.readlink(self.home / name), 'current/' + name)
            self.assertEqual((release / name).stat().st_mode & 0o222, 0)
        before = release.stat().st_mtime_ns
        launcher_inode = (self.home / 'disk-janitor').stat().st_ino
        self.assertEqual(self.install(), release)
        self.assertEqual((self.home / 'disk-janitor').stat().st_ino, launcher_inode)
        self.assertEqual(release.stat().st_mtime_ns, before)

    def test_upgrade_keeps_old_release_and_preserves_owned_legacy_files(self):
        self.home.mkdir()
        old = b'# previous installed helper\n'
        (self.home / 'jobs.py').write_bytes(old)
        first = self.install()
        backups = list((self.home / 'state/runtime-backups').rglob('jobs.py'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), old)
        self.write_source('two')
        second = self.install()
        self.assertNotEqual(first, second)
        self.assertEqual(self.run_canonical(), 'two')
        self.assertEqual((first / 'recovery.py').read_text(), "VERSION = 'one'\n")
        self.assertTrue(first.is_dir())

    def test_rejects_redirected_runtime_paths_without_touching_target(self):
        outside = self.root / 'outside'
        outside.mkdir()
        (outside / 'keep').write_text('private data')
        self.home.mkdir()
        (self.home / 'releases').symlink_to(outside, target_is_directory=True)
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('symlink', result.stderr)
        self.assertEqual((outside / 'keep').read_text(), 'private data')
        self.assertEqual(sorted(p.name for p in outside.iterdir()), ['keep'])
        self.assertFalse((self.home / 'current').exists())

    def test_tampered_content_addressed_release_is_rejected_before_activation(self):
        release = self.install()
        before = os.readlink(self.home / 'current')
        module = release / 'jobs.py'
        module.chmod(0o644)
        module.write_text('tampered\n')
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(os.readlink(self.home / 'current'), before)
        self.assertEqual(module.read_text(), 'tampered\n')

    def test_missing_component_preserves_previous_runtime_and_canonical_command(self):
        first = self.install()
        self.write_source('two')
        (self.source / 'capacity.py').unlink()
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('capacity.py', result.stderr)
        self.assertEqual((self.home / 'current').resolve(), first)
        self.assertEqual(self.run_canonical(), 'one')

    def test_unexpected_component_symlink_is_preserved(self):
        self.home.mkdir()
        outside = self.root / 'unrelated-helper'
        outside.write_text('preserved source')
        (self.home / 'jobs.py').symlink_to(outside)
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('symlink', result.stderr)
        self.assertEqual(outside.read_text(), 'preserved source')
        self.assertTrue((self.home / 'jobs.py').is_symlink())
        self.assertFalse((self.home / 'current').exists())

    def test_dispatcher_pins_cli_and_helpers_before_activation_changes(self):
        cli = self.source / 'disk-janitor'
        cli.write_text('#!' + sys.executable + ' -B\n'
             'from pathlib import Path\nimport sys,time\n'
             'Path(sys.argv[1]).write_text("opened")\n'
             'while not Path(sys.argv[2]).exists(): time.sleep(.01)\n'
             'sys.path.insert(0,str(Path(__file__).resolve().parent))\n'
             'import recovery\nprint("one:"+recovery.VERSION)\n')
        first = self.install()
        ready, resume = self.root / 'ready', self.root / 'resume'
        process = subprocess.Popen([str(self.home / 'disk-janitor'), str(ready), str(resume)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertTrue(ready.exists())
            self.write_source('two')
            second = self.install()
            self.assertNotEqual(first, second)
            resume.touch()
            output, error = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, error)
            self.assertEqual(output.strip(), 'one:one')
        finally:
            resume.touch()
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            if process.stdout:
                process.stdout.close()
            if process.stderr:
                process.stderr.close()

    def test_failed_final_flip_leaves_previous_complete_runtime_active(self):
        first = self.install()
        self.write_source('two')
        spec = importlib.util.spec_from_file_location('install_runtime_under_test', INSTALLER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        original_replace = os.replace
        def fail_current(source, destination):
            if Path(destination) == self.home / 'current':
                raise OSError('simulated final pointer failure')
            return original_replace(source, destination)
        with mock.patch.object(module.os, 'replace', side_effect=fail_current):
            with self.assertRaises(OSError):
                module.publish(self.source, self.home)
        self.assertEqual((self.home / 'current').resolve(), first)
        self.assertEqual(self.run_canonical(), 'one')
        for name in NAMES:
            if name != 'disk-janitor':
                self.assertEqual((self.home / name).read_bytes(), (first / name).read_bytes())


if __name__ == '__main__':
    unittest.main()
