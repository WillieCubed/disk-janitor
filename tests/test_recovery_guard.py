import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from test_guard_concurrency import BOOTSTRAP

REPO = Path(__file__).resolve().parents[1]


class RecoveryGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name).resolve()
        self.app = self.home / '.dj'
        self.app.mkdir()
        shutil.copy2(REPO / 'bin/recovery.py', self.app / 'recovery.py')
        for module in ('capacity.py','commitments.py'):
            shutil.copy2(REPO/'bin'/module,self.app/module)
        self.env = dict(os.environ, HOME=str(self.home), DISK_JANITOR_HOME=str(self.app), FIXTURE_FREE_GIB='.1')
        self.children = []

    def tearDown(self):
        (self.home / 'release').touch()
        for p in self.children:
            if p.poll() is None:
                p.terminate()
            try:
                p.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.communicate(timeout=3)
        self.tmp.cleanup()

    def until(self, check):
        end = time.monotonic() + 10
        while time.monotonic() < end:
            if check():
                return
            time.sleep(.03)
        self.fail('timed out waiting for fixture state')

    def spawn(self, name, code, extra=()):
        out = self.home / ('out-' + name)
        out.mkdir()
        args = ['guard', '--owner', name, '--job-id', name, '--artifact-root', str(out),
                '--root-reserve-gib', '.05', '--planned-gib', '.04', '--warn-free-gib', '0',
                '--recovery-after-seconds', '.1', '--deadline-seconds', '15', '--max-running', '1', *extra,
                '--', sys.executable, '-c', code]
        bootstrap=BOOTSTRAP.replace("str(Path(sys.argv[1]).resolve().parent)","str(Path(os.environ['DISK_JANITOR_HOME']).resolve())")
        script=getattr(self,'fixture_script',REPO/'bin/disk-janitor')
        if getattr(self,'fixture_script',None):bootstrap=BOOTSTRAP
        p = subprocess.Popen([sys.executable, '-c', bootstrap, str(script), *args],
                             env=self.env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.children.append(p)
        return p

    def test_waiting_job_calls_recovery_without_agent_restart(self):
        # A fixture recovery executable changes the observed capacity; the guarded
        # command itself is the real one-shot action and must execute exactly once.
        capacity = self.home / 'capacity'
        capacity.write_text('.02')
        self.env['FIXTURE_FREE_FILE'] = str(capacity)
        (self.app / 'recovery.py').write_text('from pathlib import Path\nPath(' + repr(str(capacity)) + ').write_text(".1")\n')
        marker = self.home / 'ran'
        p = self.spawn('recover', 'from pathlib import Path;Path(' + repr(str(marker)) + ').write_text("once")')
        output = p.communicate(timeout=12)[0]
        self.assertEqual(p.returncode, 0, output)
        self.assertEqual(marker.read_text(), 'once')

    def test_real_cache_recovery_resumes_waiting_command_exactly_once(self):
        capacity=self.home/'capacity';capacity.write_text('.02');self.env['FIXTURE_FREE_FILE']=str(capacity)
        unit=self.home/'.gradle/caches/9.4.1/transforms'/('a'*32)
        (unit/'transformed').mkdir(parents=True)
        (unit/'metadata.bin').write_bytes(b'gradle metadata');(unit/'results.bin').write_bytes(b'gradle results')
        cache=unit/'transformed/output.jar';cache.write_bytes(b'PK\x03\x04regenerable')
        target=Path(os.environ.get('RECOVERY_BASELINE',str(REPO/'bin/recovery.py')))
        adapter=("import importlib.util\nfrom pathlib import Path\nfrom types import SimpleNamespace\n"
                 "s=importlib.util.spec_from_file_location('actual_recovery',"+repr(str(target))+");m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\n"
                 "cache=Path("+repr(str(cache))+")\n"
                 "m.shutil.disk_usage=lambda _:SimpleNamespace(free=int((.02 if cache.exists() else .1)*2**30))\n"
                 "m.os.path.ismount=lambda _:True\noriginal=m.recover\n"
                 "def recover(*args,**kw):\n kw['observer']=lambda:([],[])\n result=original(*args,**kw)\n"
                 " if not cache.exists():Path("+repr(str(capacity))+").write_text('.1')\n return result\n"
                 "m.recover=recover\nm.main()\n")
        (self.app/'recovery.py').write_text(adapter)
        release=self.app/'releases'/'fixture-v1';release.mkdir(parents=True)
        shutil.copy2(REPO/'bin/disk-janitor',release/'disk-janitor')
        for module in ('recovery.py','capacity.py','commitments.py'):
            (self.app/module).rename(release/module)
            (self.app/module).symlink_to('current/'+module)
        (self.app/'current').symlink_to('releases/fixture-v1')
        self.fixture_script=self.app/'disk-janitor';self.fixture_script.symlink_to('current/disk-janitor')
        marker=self.home/'executions'
        code='from pathlib import Path;p=Path('+repr(str(marker))+');p.write_text(p.read_text()+"run\\n" if p.exists() else "run\\n")'
        process=self.spawn('real-recovery',code,['--deadline-seconds','4'])
        output=process.communicate(timeout=9)[0]
        self.assertEqual(process.returncode,0,output)
        self.assertEqual(marker.read_text(),'run\n');self.assertFalse(cache.exists())

    def test_only_explicit_restartable_build_yields_then_retries(self):
        marker = self.home / 'attempts'
        done = self.home / 'interactive'
        code = ('from pathlib import Path;import time;'
                'p=Path(' + repr(str(marker)) + ');'
                'p.write_text(p.read_text()+"run\\n" if p.exists() else "run\\n");'
                'end=time.monotonic()+10;'
                'exec("while not Path(' + repr(str(done)) + ').exists() and time.monotonic()<end: time.sleep(.03)")')
        a = self.spawn('background', code, ['--work-class', 'build', '--restartable', '--restart-kind', 'test'])
        self.until(marker.exists)
        b = self.spawn('interactive', 'from pathlib import Path;Path(' + repr(str(done)) + ').touch()')
        b_output = b.communicate(timeout=12)[0]
        self.assertEqual(b.returncode, 0, b_output)
        a_output = a.communicate(timeout=12)[0]
        self.assertEqual(a.returncode, 0, a_output)
        self.assertEqual(marker.read_text(), 'run\nrun\n')
        result = json.loads((self.app / 'guard-reservations/background.result').read_text())
        self.assertEqual(result['exit_code'], 0)

    def test_unmarked_running_job_is_never_preempted(self):
        marker = self.home / 'started'
        release = self.home / 'release'
        code = ('from pathlib import Path;import time;Path(' + repr(str(marker)) + ').touch();'
                'end=time.monotonic()+8;'
                'exec("while not Path(' + repr(str(release)) + ').exists() and time.monotonic()<end: time.sleep(.03)")')
        a = self.spawn('protected', code, ['--work-class', 'build'])
        self.until(marker.exists)
        b = self.spawn('waiter', 'pass')
        time.sleep(.8)
        self.assertIsNone(a.poll())
        self.assertFalse((self.app / 'guard-reservations/protected.preempt-request').exists())
        release.touch()
        for p in (a, b):
            output = p.communicate(timeout=12)[0]
            self.assertEqual(p.returncode, 0, output)


if __name__ == '__main__':
    unittest.main()
