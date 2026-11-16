"""Capacity inventory failures must defer safely, never start unmeasured work."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
BOOTSTRAP = r'''
import os,sys,subprocess
from pathlib import Path
os.environ['DISK_JANITOR_RUNTIME_DIR']=str(Path(sys.argv[1]).resolve().parent)
script=Path(sys.argv[1]).read_text()
body=script[script.index('cmd_capacity()'):].split("<<'PY'\n",1)[1].split('\nPY\n',1)[0]
original=subprocess.run
calls=0
def run(args,*a,**kw):
 global calls
 if args[:3]==['sysctl','-n','kern.memorystatus_vm_pressure_level']:
  return subprocess.CompletedProcess(args,0,'1','')
 if args[0]=='du':
  calls+=1
  mode=os.environ['INVENTORY_FIXTURE']
  if mode=='timeout' or mode=='recover' and calls==1 or kw.get('timeout',0)<4:
   raise subprocess.TimeoutExpired(args,kw.get('timeout'))
  return subprocess.CompletedProcess(args,0,os.environ.get('INVENTORY_KIB','1')+'\t'+args[-1]+'\n','')
 return original(args,*a,**kw)
subprocess.run=run
sys.argv=['-',os.environ['HOME'],os.environ['DISK_JANITOR_HOME']]+sys.argv[2:]
exec(compile(body,'inventory-guard-under-test','exec'))
'''

class InventoryGuardTests(unittest.TestCase):
    def invoke(self, mode, limit='1', size='1'):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        artifact = root / 'artifact'
        artifact.mkdir()
        marker = root / 'executed'
        env = dict(os.environ, HOME=str(root), DISK_JANITOR_HOME=str(root / '.dj'),
                   INVENTORY_FIXTURE=mode, INVENTORY_KIB=size)
        args = ['guard', '--root-reserve-gib', '0', '--planned-gib', '0',
                '--max-growth-gib', '.01', '--max-retained-gib', limit,
                '--deadline-seconds', '20', '--owner', 'inventory-fixture',
                '--artifact-root', str(artifact), '--', sys.executable, '-c',
                'from pathlib import Path;Path('+repr(str(marker))+').write_text("once")']
        result = subprocess.run([sys.executable, '-c', BOOTSTRAP,
                                 str(REPO / 'bin/disk-janitor'), *args], env=env,
                                capture_output=True, text=True, timeout=25)
        return result, marker

    def test_four_second_scan_is_allowed_without_relaxing_capacity(self):
        result, marker = self.invoke('slow')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(marker.read_text(), 'once')

    def test_inventory_timeouts_never_delay_or_refuse_a_launch(self):
        for mode in ('recover', 'timeout'):
            result, marker = self.invoke(mode)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn('Waiting', result.stderr)
            self.assertEqual(marker.read_text(), 'once')
        self.assertIn('measurement timed out', result.stderr)
        self.assertIn('Storage advisory', result.stderr)

    def test_slow_scan_reports_excess_retention_as_advisory(self):
        result, marker = self.invoke('slow', limit='.000001', size='100')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('historical retention threshold exceeded', result.stderr)
        self.assertTrue(marker.exists())

if __name__ == '__main__':
    unittest.main()
