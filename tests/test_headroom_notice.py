import os,subprocess,sys,tempfile,unittest
from pathlib import Path
SCRIPT=str(Path(__file__).resolve().parents[1] / 'bin/disk-janitor')
class HeadroomNotice(unittest.TestCase):
 def invoke(self,threshold):
  with tempfile.TemporaryDirectory() as h:
   return subprocess.run(['bash',SCRIPT,'guard','--root-reserve-gib','0','--planned-gib','0','--once','--owner','headroom-fixture','--warn-free-gib',threshold,'--',sys.executable,'-c','print("finished")'],env=dict(os.environ,HOME=h,DISK_JANITOR_HOME=h+'/.dj'),capture_output=True,text=True,timeout=8)
 def test_early_notice_does_not_block_or_kill(self):
  r=self.invoke('1000000');self.assertEqual(r.returncode,0,r.stderr);self.assertIn('Storage headroom warning',r.stderr);self.assertIn('finished',r.stdout);self.assertEqual(r.stderr.count('Storage headroom warning'),1)
 def test_zero_disables_notice(self):
  r=self.invoke('0');self.assertEqual(r.returncode,0,r.stderr);self.assertNotIn('Storage headroom warning',r.stderr)
 def test_nonfinite_threshold_rejected(self):
  r=self.invoke('nan');self.assertNotEqual(r.returncode,0);self.assertIn('finite',r.stderr)
if __name__=='__main__':unittest.main()
