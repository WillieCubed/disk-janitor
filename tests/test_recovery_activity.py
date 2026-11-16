"""Activity identity regressions: argv text must not pretend to be a running tool."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]


def load_recovery():
    # The default always exercises production. The override validates the isolated
    # implementation before the parent merges it into the production module.
    target = Path(os.environ.get('ACTIVITY_IMPL', REPO / 'bin/recovery.py'))
    spec = importlib.util.spec_from_file_location('recovery_activity', target)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RecoveryActivityTests(unittest.TestCase):
    def setUp(self):
        self.recovery = load_recovery()
        self.path = Path('/fixture/cache with spaces')

    def test_queued_python_arguments_are_not_executing_compilers(self):
        commands = ["/usr/bin/python3 guardian.py -- /usr/bin/rustc --crate-name next",
                    "/usr/bin/python3 guardian.py -- /usr/bin/gradle build",
                    "/usr/bin/python3 guardian.py -- /usr/bin/xcodebuild archive",
                    "/usr/bin/python3 -c print('org.gradle.launcher.GradleMain')"]
        for kind in ('cargo-incremental', 'gradle-build-cache', 'xcode-derived'):
            with self.subTest(kind=kind):
                self.assertFalse(self.recovery.busy(kind, self.path, commands, []))

    def test_direct_legacy_compiler_observers_still_protect_each_category(self):
        for kind, command in [('cargo-incremental', '/usr/bin/rustc --crate-name sample'),
                              ('cargo-object', '/usr/bin/cargo build'),
                              ('gradle-transform', '/usr/bin/gradle build'),
                              ('xcode-derived', '/usr/bin/swiftc main.swift')]:
            with self.subTest(kind=kind):
                self.assertTrue(self.recovery.busy(kind, self.path, [command], []))

    def test_open_file_paths_preserve_only_their_containing_candidate(self):
        for kind in ('cargo-incremental', 'gradle-build-cache', 'xcode-derived'):
            self.assertTrue(self.recovery.busy(kind, self.path, [], [str(self.path / 'object.o')]))
            self.assertTrue(self.recovery.busy(kind, self.path, [], [str(self.path)]))
            self.assertFalse(self.recovery.busy(kind, self.path, [], [str(self.path) + '-other/object.o']))

    def test_java_main_is_distinct_from_classpath_options_and_application_args(self):
        main = 'org.gradle.launcher.daemon.bootstrap.GradleDaemon'
        cases = [
            (['/JDK With Spaces/bin/java', '-cp', '/cache with spaces/gradle.jar', main, '8.10'], True),
            (['java', '-classpath', '/cache/' + main + '.jar', 'example.Server'], False),
            (['java', '-Dfuture=' + main, 'example.Server', main], False),
            (['java', '--module-path', '/cache with spaces', '-m', 'gradle/' + main], True),
            (['java', '-cp', '/cache with spaces', 'org.jetbrains.kotlin.daemon.KotlinCompileDaemon'], True),
        ]
        for argv, expected in cases:
            with self.subTest(argv=argv):
                self.assertEqual(self.recovery._java_build_active(argv), expected)

    def test_darwin_nul_delimited_java_argv_keeps_spaces_and_ignores_environment(self):
        argv = ['/JDK With Spaces/bin/java', '-cp', '/Gradle Home/lib/gradle.jar',
                'org.gradle.launcher.GradleMain', 'build']
        raw = len(argv).to_bytes(4, sys.byteorder, signed=True)
        raw += os.fsencode(argv[0]) + b'\0\0\0'
        raw += b'\0'.join(os.fsencode(arg) for arg in argv) + b'\0'
        raw += b'SECRET=org.jetbrains.kotlin.daemon.KotlinCompileDaemon\0'
        self.assertEqual(self.recovery._darwin_argv(raw), argv)

    def test_lsof_inspection_failure_preserves_caches(self):
        original = self.recovery.subprocess.run
        def run(args, **kwargs):
            if args[0] == 'lsof':
                return subprocess.CompletedProcess(args, 1, '', 'permission denied')
            return original(args, **kwargs)
        with patch.object(self.recovery.subprocess, 'run', side_effect=run):
            with self.assertRaises(RuntimeError):
                self.recovery.activity()

    def test_live_process_identity_inspection_failure_is_not_silently_ignored(self):
        with patch.object(self.recovery, '_process_executable', side_effect=PermissionError('denied')):
            commands, _ = self.recovery.activity()
        self.assertTrue(any(command['pid'] == os.getpid() and command['family'] == 'unknown' for command in commands))
        for kind in ('cargo-incremental', 'gradle-build-cache', 'xcode-derived'):
            self.assertTrue(self.recovery.busy(kind, self.path, commands, []))

    def test_established_exit_during_process_inspection_is_safe(self):
        original = self.recovery.subprocess.run
        def run(args, **kwargs):
            if args[0] == 'ps':
                return subprocess.CompletedProcess(args, 0, str(os.getuid()) + ' 999999 /already/exited\n', '')
            return original(args, **kwargs)
        with patch.object(self.recovery.subprocess, 'run', side_effect=run), \
             patch.object(self.recovery, '_process_executable', side_effect=ProcessLookupError()), \
             patch.object(self.recovery, '_process_exited', return_value=True):
            commands, _ = self.recovery.activity()
        self.assertEqual(commands, [])

    def test_deleted_nonbuild_executable_uses_actual_comm_without_reading_arguments(self):
        original = self.recovery.subprocess.run
        def run(args, **kwargs):
            if args[0] == 'ps':
                return subprocess.CompletedProcess(args, 0, str(os.getuid()) +
                                                   ' 999999 /Applications/Old App/browser_helper\n', '')
            return original(args, **kwargs)
        with patch.object(self.recovery.subprocess, 'run', side_effect=run), \
             patch.object(self.recovery, '_process_executable', side_effect=FileNotFoundError(2, 'deleted')), \
             patch.object(self.recovery, '_process_exited', return_value=False), \
             patch.object(self.recovery.sys, 'platform', 'darwin'):
            commands, _ = self.recovery.activity()
        for kind in ('cargo-incremental', 'gradle-build-cache', 'xcode-derived'):
            self.assertFalse(self.recovery.busy(kind, self.path, commands, []))

    def test_unreadable_live_build_executable_cannot_use_nonbuild_fallback(self):
        original = self.recovery.subprocess.run
        def run(args, **kwargs):
            if args[0] == 'ps':
                return subprocess.CompletedProcess(args, 0, str(os.getuid()) +
                                                   ' 999999 /Build Tools/rustc\n', '')
            return original(args, **kwargs)
        with patch.object(self.recovery.subprocess, 'run', side_effect=run), \
             patch.object(self.recovery, '_process_executable', side_effect=FileNotFoundError(2, 'unknown')), \
             patch.object(self.recovery, '_process_exited', return_value=False):
            commands, _ = self.recovery.activity()
        self.assertEqual(commands, [dict(pid=999999, executable=None, family='unknown')])
        self.assertTrue(self.recovery.busy('cargo-incremental', self.path, commands, []))

    def test_live_structured_argv_keeps_spaces_and_empty_application_arguments(self):
        tail = ['classpath with spaces', '', 'org.gradle.launcher.GradleMain']
        process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)', *tail])
        try:
            self.assertEqual(self.recovery._process_argv(process.pid)[-3:], tail)
        finally:
            process.terminate()
            process.wait(timeout=5)

    def test_live_queued_python_sleeper_is_not_a_compiler(self):
        process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)',
                                    '--', 'rustc', 'gradle', 'xcodebuild',
                                    'org.gradle.launcher.GradleMain'])
        try:
            commands, _ = self.recovery.activity()
            own = [item for item in commands if isinstance(item, dict) and item.get('pid') == process.pid]
            self.assertEqual(len(own), 1)
            for kind in ('cargo-incremental', 'gradle-build-cache', 'xcode-derived'):
                self.assertFalse(self.recovery.busy(kind, self.path, own, []))
        finally:
            process.terminate()
            process.wait(timeout=5)

    def test_live_native_compiler_fixture_with_spaces_is_active(self):
        with tempfile.TemporaryDirectory(prefix='compiler fixture ') as directory:
            compiler = Path(directory) / 'rustc'
            shutil.copyfile('/bin/sleep', compiler)
            compiler.chmod(0o700)
            process = subprocess.Popen([str(compiler), '30'])
            try:
                # Wait for exec; only this harmless child is ever signalled.
                deadline = time.monotonic() + 5
                own = []
                while time.monotonic() < deadline:
                    commands, _ = self.recovery.activity()
                    own = [item for item in commands if isinstance(item, dict) and item.get('pid') == process.pid]
                    if own and self.recovery.busy('cargo-incremental', self.path, own, []):
                        break
                    time.sleep(.02)
                self.assertTrue(self.recovery.busy('cargo-incremental', self.path, own, []))
            finally:
                process.terminate()
                process.wait(timeout=5)

    def test_live_open_file_remains_protected(self):
        with tempfile.TemporaryDirectory(prefix='open cache fixture ') as directory:
            candidate = Path(directory).resolve()
            target = candidate / 'object.o'
            target.write_bytes(b'generated')
            with target.open('rb'):
                commands, opened = self.recovery.activity()
                self.assertIn(str(target), opened)
                self.assertTrue(self.recovery.busy('cargo-incremental', candidate, [], opened))


class IncompleteActivityInspectionTests(unittest.TestCase):
    def test_lsof_warning_with_zero_exit_still_preserves_caches(self):
        recovery=load_recovery()
        def process(args,**kwargs):
            return subprocess.CompletedProcess(args,0,'','lsof: WARNING: output information may be incomplete\n' if args[0]=='lsof' else '')
        with patch.object(recovery.subprocess,'run',side_effect=process):
            with self.assertRaises(RuntimeError):recovery.activity()

if __name__ == '__main__':
    unittest.main()
