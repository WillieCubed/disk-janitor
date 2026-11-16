import json
import os
import pty
import select
import time
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
COVERAGE = REPO / 'bin/coverage.py'


class BuildCoverage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name).resolve()
        self.app = self.home / '.dj'
        self.env = dict(os.environ, HOME=str(self.home), DISK_JANITOR_HOME=str(self.app),
                        DISK_JANITOR_NO_SCHED='1')
        for key in ('RUNNER_ENVIRONMENT', 'RUNNERPOOL_PROFILE'):
            self.env.pop(key, None)

    def invoke(self, *args, env=None, input=None):
        return subprocess.run([sys.executable, str(COVERAGE), *args], env=env or self.env,
                              cwd=self.home, input=input, capture_output=True, text=True, timeout=30)

    def install(self):
        result = self.invoke('install-shell')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return self.app / 'shims'

    def fake_tool(self, name='make', body=None):
        directory = self.home / 'real-tools'
        directory.mkdir(exist_ok=True)
        tool = directory / name
        tool.write_text('#!' + sys.executable + '\n' + (body or
                        'import json,os,sys\nprint(json.dumps({"argv":sys.argv[1:],"cwd":os.getcwd(),"input":sys.stdin.read(),"value":os.environ.get("COVERAGE_VALUE")}))\nprint("separate stderr", file=sys.stderr)\nsys.exit(7)\n'))
        tool.chmod(0o755)
        return directory

    def test_installed_bare_tool_preserves_arguments_streams_stdin_environment_and_exit(self):
        shims = self.install()
        real = self.fake_tool()
        env = dict(self.env, PATH=str(shims) + ':' + str(real) + ':' + self.env['PATH'],
                   COVERAGE_VALUE='kept')
        result = subprocess.run(['make', 'a b', '$(no-shell)', ''], env=env, cwd=self.home,
                                input='piped input\n', capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 7, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout), {'argv':['a b','$(no-shell)',''],
                         'cwd':str(self.home),'input':'piped input\n','value':'kept'})
        self.assertEqual(result.stderr, 'separate stderr\n')
        self.assertEqual(len(list((self.app / 'guard-reservations').glob('*.result'))), 1)

    def test_interactive_terminal_preserves_foreground_process_group_without_claiming_job(self):
        shims = self.install()
        real = self.fake_tool(body='import json,os\n'
                   'try: print(json.dumps({"foreground":os.tcgetpgrp(0)==os.getpgrp()}))\n'
                   'except OSError as error: print(json.dumps({"error":error.errno}))\n')
        env = dict(self.env, PATH=str(shims) + ':' + str(real) + ':' + self.env['PATH'])
        child, master = pty.fork()
        if child == 0:
            os.chdir(self.home)
            os.execvpe('make', ['make'], env)
        output = b''
        deadline = time.monotonic() + 15
        try:
            while time.monotonic() < deadline:
                if not select.select([master], [], [], .1)[0]:
                    continue
                try:
                    data = os.read(master, 65536)
                except OSError:
                    break
                if not data:
                    break
                output += data
            _, status = os.waitpid(child, 0)
        finally:
            os.close(master)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0, output)
        self.assertEqual(json.loads(output.decode().strip()), {"foreground": True})
        self.assertFalse((self.app / 'jobs').exists())

    def test_any_terminal_standard_descriptor_preserves_unmanaged_command(self):
        shims = self.install()
        real = self.fake_tool(body='raise SystemExit(0)\n')
        env = dict(self.env, PATH=str(shims) + ':' + str(real) + ':' + self.env['PATH'])
        for terminal in (0, 1, 2):
            with self.subTest(terminal=terminal):
                master, slave = pty.openpty()
                try:
                    result = subprocess.run(['make'], env=env, cwd=self.home,
                        stdin=slave if terminal == 0 else subprocess.DEVNULL,
                        stdout=slave if terminal == 1 else subprocess.PIPE,
                        stderr=slave if terminal == 2 else subprocess.PIPE, timeout=15)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertFalse((self.app / 'jobs').exists())
                finally:
                    os.close(master)
                    os.close(slave)

    def test_bare_build_is_observable_with_public_status_wait_and_real_exit(self):
        result = self.invoke('exec', '--', sys.executable, '-c', 'raise SystemExit(9)')
        status = subprocess.run(['/bin/bash', str(REPO / 'bin/disk-janitor'), 'status', '--json'],
                                env=self.env, cwd=self.home, capture_output=True, text=True, timeout=15)
        self.assertEqual(status.returncode, 0, status.stderr)
        records = json.loads(status.stdout)
        self.assertEqual(len(records), 1, status.stdout)
        self.assertEqual(result.returncode, 9, result.stdout + result.stderr)
        self.assertEqual(records[0]['state'], 'failed')
        self.assertEqual(records[0]['exit_code'], 9)
        wait = subprocess.run(['/bin/bash', str(REPO / 'bin/disk-janitor'), 'wait', records[0]['id']],
                              env=self.env, cwd=self.home, capture_output=True, text=True, timeout=15)
        self.assertEqual(wait.returncode, 9, wait.stdout + wait.stderr)

    def test_shell_install_is_idempotent_and_uninstall_preserves_user_edits(self):
        profile = self.home / '.zshrc'
        profile.write_text('export USER_SETTING=original\n')
        self.install()
        self.install()
        profile.write_text(profile.read_text() + 'export LATER_SETTING=retained\n')
        result = self.invoke('uninstall-shell')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(profile.read_text(), 'export USER_SETTING=original\nexport LATER_SETTING=retained\n')
        self.assertFalse((self.home / '.zshenv').exists())
        self.assertFalse((self.app / 'shims').exists())

    @unittest.skipUnless(Path('/bin/zsh').is_file(), 'zsh is not installed')
    def test_new_zsh_shell_intercepts_without_manual_activation(self):
        self.install()
        real = self.fake_tool(body='print("guarded tool")\n')
        env = dict(self.env, PATH=str(real) + ':' + self.env['PATH'])
        result = subprocess.run(['/bin/zsh', '-c', 'make'], env=env, cwd=self.home,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, 'guarded tool\n')
        self.assertEqual(len(list((self.app / 'guard-reservations').glob('*.result'))), 1)

    def test_nested_bare_tool_reuses_actual_guard_instead_of_reserving_twice(self):
        shims = self.install()
        real = self.fake_tool(body='import subprocess\nraise SystemExit(subprocess.call(["cargo", "check"]))\n')
        cargo = real / 'cargo'
        cargo.write_text('#!' + sys.executable + '\nprint("nested child")\n')
        cargo.chmod(0o755)
        env = dict(self.env, PATH=str(shims) + ':' + str(real) + ':' + self.env['PATH'])
        result = subprocess.run(['make'], env=env, cwd=self.home,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, 'nested child\n')
        self.assertEqual(len(list((self.app / 'guard-reservations').glob('*.result'))), 1)

    def test_forged_runner_environment_does_not_authorize_unreserved_execution(self):
        output = self.home / 'not-executed'
        env = dict(self.env, RUNNER_ENVIRONMENT='self-hosted', DISK_JANITOR_COVERED='1')
        result = self.invoke('exec', '--', sys.executable, '-c',
                             'from pathlib import Path; Path("not-executed").touch()', env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('RunnerPools', result.stderr)
        self.assertFalse(output.exists())

    def test_shell_symlink_rejection_preserves_other_startup_files(self):
        target = self.home / 'dotfiles-zshrc'
        target.write_text('private dotfiles\n')
        (self.home / '.zshrc').symlink_to(target)
        result = self.invoke('install-shell')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(target.read_text(), 'private dotfiles\n')
        self.assertFalse((self.home / '.zshenv').exists())

    def test_live_sibling_reservation_does_not_cover_caller(self):
        registry = self.app / 'guard-reservations'
        registry.mkdir(parents=True)
        record = registry / 'sibling.json'
        holder = subprocess.Popen([sys.executable, '-c',
            'import fcntl,json,os,sys,time\n'
            'with open(sys.argv[1], "w+") as f:\n'
            ' fcntl.flock(f,fcntl.LOCK_EX)\n'
            ' json.dump({"state":"running","child":os.getpid()},f);f.flush()\n'
            ' print("ready",flush=True)\n'
            ' time.sleep(30)\n', str(record)],
            stdout=subprocess.PIPE, text=True, start_new_session=True)
        self.addCleanup(lambda: holder.stdout.close())
        def stop_holder():
            holder.terminate()
            holder.wait(timeout=5)
        self.addCleanup(stop_holder)
        self.assertEqual(holder.stdout.readline().strip(), 'ready')
        env = dict(self.env, RUNNER_ENVIRONMENT='self-hosted')
        result = self.invoke('exec', '--', sys.executable, '-c', 'print("must not run")', env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assertIn('RunnerPools', result.stderr)

    def test_shim_resolution_avoids_recursion_when_state_home_changes(self):
        shims = self.install()
        real = self.fake_tool()
        env = dict(self.env, DISK_JANITOR_HOME=str(self.home / 'different-state'),
                   PATH=str(shims) + ':' + str(real) + ':' + self.env['PATH'])
        result = subprocess.run([sys.executable, '-c',
             'import sys;sys.path.insert(0,sys.argv[1]);import coverage;'
             'print(coverage.real_command([sys.argv[2]],shim=True)[0])',
             str(REPO / 'bin'), str(shims / 'make')], env=env,
             cwd=self.home, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(real / 'make'))

    def test_missing_real_tool_fails_without_recursing_or_accepting_work(self):
        shims = self.install()
        result = subprocess.run([str(shims / 'ninja')], env=dict(self.env, PATH=str(shims)),
                                cwd=self.home, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 127, result.stdout + result.stderr)
        self.assertFalse((self.app / 'guard-reservations').exists())


if __name__ == '__main__':
    unittest.main()
