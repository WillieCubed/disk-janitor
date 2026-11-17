"""Tiny synthetic processes; no real host lease or heavyweight workload is used."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

REPO=Path(__file__).resolve().parents[1]
BOOTSTRAP=r'''
import os,sys,shutil,subprocess
from pathlib import Path
from types import SimpleNamespace
os.environ['DISK_JANITOR_RUNTIME_DIR']=str(Path(sys.argv[1]).resolve().parent)
script=Path(sys.argv[1]).read_text();body=script[script.index('cmd_capacity()'):].split("<<'PY'\n",1)[1].split('\nPY\n',1)[0]
shutil.disk_usage=lambda path:SimpleNamespace(free=int(float(Path(os.environ['FIXTURE_FREE_FILE']).read_text() if os.environ.get('FIXTURE_FREE_FILE') else os.environ['FIXTURE_FREE_GIB'])*2**30))
original=subprocess.run
def run(args,*a,**kw):
 if args[:3]==['sysctl','-n','kern.memorystatus_vm_pressure_level']:
  return subprocess.CompletedProcess(args,0,Path(os.environ['FIXTURE_PRESSURE_FILE']).read_text() if os.environ.get('FIXTURE_PRESSURE_FILE') else os.environ.get('FIXTURE_PRESSURE','1'),'')
 return original(args,*a,**kw)
subprocess.run=run
sys.argv=['-',os.environ['HOME'],os.environ['DISK_JANITOR_HOME']]+sys.argv[2:]
exec(compile(body,'isolated-guard-under-test','exec'))
'''

class ConcurrentGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.processes=[]
        self.env=dict(os.environ,HOME=str(self.root),DISK_JANITOR_HOME=str(self.root/'.dj'),FIXTURE_FREE_GIB='.1')
        self.release=self.root/'release'
    def tearDown(self):
        self.release.touch()
        for p in self.processes:
            if p.poll() is None:
                try:p.communicate(timeout=6)
                except subprocess.TimeoutExpired:p.terminate();p.communicate(timeout=3)
        self.temp.cleanup()
    def code(self,name,hold=False):
        return ('import time;from pathlib import Path;'
                'p=Path('+repr(str(self.root/name))+');f=p.open("a");f.write("run\\n");f.close();'
                'end=time.monotonic()+4;'
                +('exec("while not Path('+repr(str(self.release))+').exists() and time.monotonic()<end: time.sleep(.01)")' if hold else ''))
    def spawn(self,name,hold=False,job=None,once=False,pressure='1'):
        artifact=self.root/('out-'+name);artifact.mkdir(exist_ok=True)
        args=['guard','--root-reserve-gib','.05','--planned-gib','.04','--max-growth-gib','.04','--max-running','1',
              '--owner',name,'--artifact-root',str(artifact),'--deadline-seconds','5']
        if job:args+=['--job-id',job]
        if once:args+=['--once']
        args+=['--',sys.executable,'-c',self.code(name,hold)]
        env=dict(self.env,FIXTURE_PRESSURE=pressure)
        p=subprocess.Popen([sys.executable,'-c',BOOTSTRAP,str(REPO/'bin/disk-janitor'),*args],env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        self.processes.append(p);return p
    def until(self,predicate):
        end=time.monotonic()+4
        while not predicate() and time.monotonic()<end:time.sleep(.01)
        self.assertTrue(predicate())
    def finish(self,p,code=0):
        out=p.communicate(timeout=7)[0];self.assertEqual(p.returncode,code,out);return out
    def test_one_slot_runs_one_job_and_the_waiter_starts_when_it_frees(self):
        a=self.spawn('a',True);b=self.spawn('b',True)
        self.until(lambda:(self.root/'a').exists() or (self.root/'b').exists());time.sleep(.15)
        self.assertEqual(sum((self.root/name).exists() for name in ['a','b']),1,'one slot runs one job')
        self.assertIsNone(a.poll());self.assertIsNone(b.poll())
        self.release.touch();self.finish(a);self.finish(b)
        self.assertTrue((self.root/'a').exists());self.assertTrue((self.root/'b').exists())
    def test_live_and_completed_reattachment_never_repeats(self):
        a=self.spawn('same',True,job='stable');self.until(lambda:(self.root/'same').exists())
        b=self.spawn('same',True,job='stable');time.sleep(.15);self.release.touch();self.finish(a);self.finish(b)
        self.finish(self.spawn('same',True,job='stable'))
        self.assertEqual((self.root/'same').read_text(),'run\n')
    def test_cancelled_waiter_does_not_stop_active_work(self):
        a=self.spawn('holder',True);self.until(lambda:(self.root/'holder').exists())
        b=self.spawn('cancel',job='cancel');self.until(lambda:(self.root/'.dj/guard-reservations/cancel.json').exists())
        b.terminate();self.finish(b,143);self.assertIsNone(a.poll());self.assertFalse((self.root/'cancel').exists())
        self.release.touch();self.finish(a);self.finish(self.spawn('after'))
    def test_crashed_waiter_can_resume_once(self):
        a=self.spawn('holder',True);self.until(lambda:(self.root/'holder').exists())
        b=self.spawn('resume',job='resume');self.until(lambda:(self.root/'.dj/guard-reservations/resume.json').exists())
        b.kill();b.communicate(timeout=2);c=self.spawn('resume',job='resume');self.release.touch();self.finish(a);self.finish(c)
        self.assertEqual((self.root/'resume').read_text(),'run\n')
    def test_running_owner_crash_keeps_child_and_reattaches_once(self):
        a=self.spawn('survivor',True,job='survivor');self.until(lambda:(self.root/'survivor').exists())
        a.kill();a.wait(timeout=2);a.stdout.close();b=self.spawn('survivor',True,job='survivor');time.sleep(.1)
        self.assertEqual((self.root/'survivor').read_text(),'run\n');self.release.touch();self.finish(b)
    def test_live_reservation_is_not_reclaimed_from_pid_metadata(self):
        a=self.spawn('holder',True,job='holder');self.until(lambda:(self.root/'holder').exists())
        p=self.root/'.dj/guard-reservations/holder.json';self.until(lambda:json.loads(p.read_text()).get('child') is not None)
        record=json.loads(p.read_text());record['pid']=99999999;p.write_text(json.dumps(record))
        b=self.spawn('other',once=True);self.finish(b,75);self.assertFalse((self.root/'other').exists())
        self.release.touch();self.finish(a)
    def test_low_disk_fails_at_once_and_never_waits(self):
        self.env['FIXTURE_FREE_GIB']='.02'
        started=time.monotonic();out=self.finish(self.spawn('low-disk',job='low-disk'),75)
        self.assertLess(time.monotonic()-started,6)
        self.assertIn('insufficient disk: 0.02 GiB free on',out);self.assertIn('need 0.05 GiB; reclaim freed 0.00 GiB',out)
        self.assertFalse((self.root/'low-disk').exists())
        result=json.loads((self.root/'.dj/guard-reservations/low-disk.result').read_text())
        self.assertEqual((result['exit_code'],result['status'],result['no_launch']),(75,'refused',True))
        self.assertEqual(json.loads((self.root/'.dj/guard-reservations/low-disk.json').read_text())['state'],'refused')
    @unittest.skipUnless(sys.platform == 'darwin', 'macOS sysctl admission-pressure source')
    def test_critical_memory_pressure_fails_without_launch(self):
        p=self.spawn('memory',once=True,pressure='4');out=self.finish(p,75)
        self.assertIn('critical memory pressure',out);self.assertFalse((self.root/'memory').exists())

if __name__=='__main__':unittest.main()
