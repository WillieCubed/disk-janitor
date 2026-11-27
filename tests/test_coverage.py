import fcntl
import json
import os
import pty
import select
import time
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
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
                        DISK_JANITOR_NO_SCHED='1', DISK_JANITOR_STORAGE_ROOT='none')
        for key in ('DISK_JANITOR_BROKER',):
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

    def test_forged_broker_environment_does_not_authorize_unreserved_execution(self):
        output = self.home / 'not-executed'
        env = dict(self.env, DISK_JANITOR_BROKER='ci-pool', DISK_JANITOR_COVERED='1')
        result = self.invoke('exec', '--', sys.executable, '-c',
                             'from pathlib import Path; Path("not-executed").touch()', env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('ci-pool already admitted', result.stderr)
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
        env = dict(self.env, DISK_JANITOR_BROKER='ci-pool')
        result = self.invoke('exec', '--', sys.executable, '-c', 'print("must not run")', env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assertIn('ci-pool already admitted', result.stderr)

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


PROBE = (
    'import json,os,sys\n'
    'sys.path.insert(0,sys.argv[1]);sys.dont_write_bytecode=True\n'
    'import coverage\n'
    'from pathlib import Path\n'
    'json.dump({"covered":coverage.covered(Path(sys.argv[2])),"pgid":os.getpgrp(),"sid":os.getsid(0)},open(sys.argv[3],"w"))\n')

# Runs as the job controller: a session leader that publishes a locked running
# record and a runtime file naming its supervisor, as the real guard does.
CONTROLLER = (
    'import fcntl,json,os,subprocess,sys,time\n'
    'home,scenario,ready=sys.argv[1:4]\n'
    'registry=home+"/guard-reservations";os.makedirs(registry,mode=0o700,exist_ok=True)\n'
    'supervisor=subprocess.Popen([sys.executable,"-c",sys.argv[4],*sys.argv[5:]],start_new_session=True,stdin=subprocess.PIPE)\n'
    'identity={"owner":"job:test","command_hash":"h","job_id":"j-test"}\n'
    'record=open(registry+"/j-test.json","w+");fcntl.flock(record,fcntl.LOCK_EX)\n'
    'json.dump(dict(identity,id="j-test",state="running",child=os.getpid(),runtime_file=registry+"/j-test.runtime"),record);record.flush()\n'
    'fd=os.open(registry+"/j-test.runtime",os.O_WRONLY|os.O_CREAT,0o600)\n'
    'os.write(fd,json.dumps(dict(identity,controller_pid=os.getpid(),runtime_group=supervisor.pid,state="running")).encode());os.close(fd)\n'
    'open(ready,"w").write("1")\n'
    'supervisor.stdin.write(b"go");supervisor.stdin.close()\n'
    'supervisor.wait()\n')

SUPERVISOR = 'import sys;sys.stdin.read()\nexec(open(sys.argv[1]).read())\n'


class NestedJobCoverage(unittest.TestCase):
    """A process is covered by the job whose controller is its real ancestor, wherever its group or session is."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.app = self.root / '.dj'
        self.app.mkdir()
        (self.root / 'probe.py').write_text(PROBE)
        self.controller = None
        self.addCleanup(self.stop)

    def stop(self):
        if self.controller and self.controller.poll() is None:
            self.controller.terminate()
            self.controller.wait(timeout=10)

    def probe_command(self, name):
        return [sys.executable, str(self.root / 'probe.py'), str(REPO / 'bin'), str(self.app), str(self.root / name)]

    def result(self, name, timeout=30):
        path = self.root / name
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.exists() and path.read_text():
                return json.loads(path.read_text())
            time.sleep(.05)
        self.fail('probe ' + name + ' never reported')

    def run_job(self, scenario):
        """Start a job whose supervisor runs the scenario source; the probe command is argv[2]."""
        (self.root / 'scenario.py').write_text(scenario)
        ready = self.root / 'ready'
        self.controller = subprocess.Popen(
            [sys.executable, '-c', CONTROLLER, str(self.app), 'scenario', str(ready), SUPERVISOR,
             str(self.root / 'scenario.py'), json.dumps(self.probe_command('inside'))],
            start_new_session=True)
        deadline = time.monotonic() + 15
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(.02)
        self.assertTrue(ready.exists())

    def test_direct_same_group_child_of_the_command_is_covered(self):
        self.run_job('import json,subprocess,sys\n'
                     'probe=json.loads(sys.argv[2])\n'
                     'cargo=subprocess.Popen([sys.executable,"-c","import subprocess,sys;subprocess.run(sys.argv[1:])",*probe])\n'
                     'cargo.wait()\n')
        inside = self.result('inside')
        self.assertTrue(inside['covered'])
        self.assertEqual(inside['pgid'], inside['sid'])

    def test_turbo_style_task_in_its_own_process_group_is_covered(self):
        self.run_job('import json,os,subprocess,sys\n'
                     'probe=json.loads(sys.argv[2])\n'
                     'subprocess.run(probe,preexec_fn=lambda:os.setpgid(0,0))\n')
        inside = self.result('inside')
        self.assertTrue(inside['covered'])
        self.assertNotEqual(inside['pgid'], inside['sid'])

    def test_gradle_daemon_style_grandchild_in_another_session_is_covered(self):
        self.run_job('import json,subprocess,sys\n'
                     'probe=json.loads(sys.argv[2])\n'
                     'client=subprocess.Popen([sys.executable,"-c",'
                     '"import subprocess,sys;subprocess.run([sys.executable,\'-c\',\'import subprocess,sys;'
                     'subprocess.run(sys.argv[1:])\',*sys.argv[1:]],start_new_session=True)",*probe])\n'
                     'client.wait()\n')
        inside = self.result('inside')
        self.assertTrue(inside['covered'])
        self.assertEqual(inside['pgid'], inside['sid'])
        self.assertNotEqual(inside['sid'], os.getsid(self.controller.pid))

    def test_unrelated_process_with_forged_environment_is_not_covered(self):
        self.run_job('import time;time.sleep(30)\n')
        env = dict(os.environ, DISK_JANITOR_BROKER='ci-pool', DISK_JANITOR_COVERED='1',
                   DISK_JANITOR_JOB_ID='j-test', DISK_JANITOR_HOME=str(self.app))
        subprocess.run(self.probe_command('outside'), env=env, timeout=30, check=True)
        self.assertFalse(self.result('outside')['covered'])

    def test_orphan_reparented_away_from_the_job_is_not_covered(self):
        self.run_job('import json,subprocess,sys\n'
                     'probe=json.loads(sys.argv[2])\n'
                     'import os\n'
                     'waiter="import os,subprocess,sys,time\\nwhile os.getppid()==int(sys.argv[1]):time.sleep(.02)\\n'
                     'subprocess.run(sys.argv[2:])"\n'
                     'subprocess.Popen([sys.executable,"-c",waiter,str(os.getpid()),*probe],start_new_session=True)\n')
        inside = self.result('inside')
        self.assertFalse(inside['covered'])

    def test_record_rewrite_never_exposes_an_empty_or_torn_reservation(self):
        sys.path.insert(0, str(REPO / 'bin'))
        sys.dont_write_bytecode = True
        import capacity
        path = self.root / 'record.json'
        with open(path, 'w+') as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            capacity.rewrite_in_place(path, held.fileno(), b'{"state":"waiting"}')
            stop = threading.Event()
            torn = []

            def reader():
                while not stop.is_set():
                    try:
                        json.loads(path.read_text())
                    except ValueError as error:
                        torn.append(str(error))

            thread = threading.Thread(target=reader)
            thread.start()
            try:
                for index in range(3000):
                    payload = json.dumps({'state': 'running', 'consumed': 'x' * (index % 2 * 4000)}).encode()
                    self.assertTrue(capacity.rewrite_in_place(path, held.fileno(), payload))
            finally:
                stop.set()
                thread.join()
            self.assertEqual(torn, [])
            self.assertEqual(json.loads(path.read_text())['consumed'], 'x' * 4000)

    def test_rewrite_refuses_a_file_that_is_not_the_locked_one(self):
        sys.path.insert(0, str(REPO / 'bin'))
        sys.dont_write_bytecode = True
        import capacity
        path = self.root / 'record.json'
        path.write_text('{}')
        with open(self.root / 'other.json', 'w+') as held:
            self.assertFalse(capacity.rewrite_in_place(path, held.fileno(), b'{"x":1}'))
        self.assertEqual(path.read_text(), '{}')


if __name__ == '__main__':
    unittest.main()
