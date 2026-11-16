"""Authorized cache discovery, preservation and bounded bulk recovery."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
REPO = Path(__file__).resolve().parents[1]
MACHO = bytes.fromhex('cffaedfe0c0000010000000001000000')
RSIC = b'RSIC\x00\x00\x1d1.91.1 compiler cache'
class BulkRecoveryTests(unittest.TestCase):
    def setUp(self):
        s=importlib.util.spec_from_file_location('bulk_recovery',REPO/'bin/recovery.py');self.r=importlib.util.module_from_spec(s);s.loader.exec_module(self.r)
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.home=Path(self.tmp.name).resolve();self.app=self.home/'.dj';self.app.mkdir()
    def file(self,relative,data=b'generated'):
        p=self.home/relative;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);return p
    def cargo(self,name,data):
        base='.cache/cargo-target/debug/';self.file(base+'.cargo-lock',b'');(self.home/base/'.fingerprint').mkdir(exist_ok=True);return self.file(base+'deps/'+name,data)
    def transform(self,n,extra=None):
        base='.gradle/caches/9.4.1/transforms/'+format(n,'032x')+'/'
        self.file(base+'metadata.bin',b'gradle-metadata');self.file(base+'results.bin',b'gradle-results');p=self.file(base+'transformed/library.jar',b'PK\x03\x04generated-classes')
        if extra:self.file(base+extra[0],extra[1])
        return p
    def recover(self,observer=None,apply=True):return self.r.recover(self.home,self.app,apply=apply,observer=observer or (lambda:([],[])))
    def test_many_existing_xcode_units_use_bounded_process_inspection(self):
        paths=[self.file('Library/Developer/Xcode/DerivedData/App'+str(n)+'/Build/object.o') for n in range(32)];calls=[]
        result=self.recover(observer=lambda:(calls.append(True) or [],[]))
        self.assertTrue(all(not p.exists() for p in paths),result);self.assertLessEqual(len(calls),4,'process inspection must be per batch, not per entry')
    def test_marked_gradle_transform_cache_is_recovered(self):
        p=self.transform(1);result=self.recover();self.assertFalse(p.exists(),result)
    def test_unmarked_gradle_directory_is_preserved(self):
        p=self.file('.gradle/caches/9.4.1/transforms/'+'a'*32+'/personal.txt');self.recover();self.assertTrue(p.exists())
    def test_positive_cargo_dependency_objects_are_recovered(self):
        paths=[self.cargo('crate-'+'a'*16+'.rcgu.o',MACHO),self.cargo('libcrate-'+'b'*16+'.rlib',b'!<arch>\ncompiler archive'),self.cargo('libcrate-'+'c'*16+'.rmeta',b'rust\x00\x00\x00\x0acompiler metadata')]
        source=self.file('.cache/cargo-target/debug/deps/main.rs',b'fn main() {}');exported=self.file('.cache/cargo-target/debug/libunique.a',b'!<arch>\nretained artifact');self.recover()
        self.assertTrue(all(not p.exists() for p in paths));self.assertTrue(source.exists());self.assertTrue(exported.exists())
    def test_wrong_magic_and_unproven_cargo_locations_survive(self):
        paths=[self.cargo('crate-'+'d'*16+'.rcgu.o',b'SQLite format 3\x00private'),self.cargo('libcrate-'+'e'*16+'.rlib',b'private source text'),self.file('.cache/cargo-target/custom/deps/crate-'+'f'*16+'.rcgu.o',MACHO)];self.recover()
        for p in paths:self.assertTrue(p.exists(),str(p))
    def test_credential_named_compiler_crate_needs_positive_compiler_proof(self):
        good=self.file('.cache/cargo-target/debug/incremental/relay_credential_provider-abc123/s-hash/query-cache.bin',RSIC);bad=self.file('.cache/cargo-target/debug/incremental/secret_crate-xyz123/s-hash/token.json',b'private credential');self.recover();self.assertFalse(good.exists());self.assertTrue(bad.exists())
    def test_protected_gradle_entry_does_not_poison_other_entries(self):
        good=self.transform(1);source=self.transform(2,('transformed/main.rs',b'uncommitted source'));database=self.transform(3,('transformed/data',b'SQLite format 3\x00private'));self.recover();self.assertFalse(good.exists());self.assertTrue(source.exists());self.assertTrue(database.exists())
    def test_new_source_after_validation_preserves_the_unit(self):
        output=self.transform(1);source=output.parent/'main.rs';calls=[]
        def observer():
            calls.append(True)
            if len(calls)==2:source.write_text('uncommitted source')
            return [],[]
        self.recover(observer=observer);self.assertTrue(source.exists());self.assertTrue(output.exists())
    def test_symlink_substitution_after_validation_preserves_external_data(self):
        output=self.transform(1);outside=self.file('personal/data.txt',b'irreplaceable');unit=output.parents[1];moved=unit.with_name(unit.name+'-moved');calls=[]
        def observer():
            calls.append(True)
            if len(calls)==2:unit.rename(moved);unit.symlink_to(outside.parent,target_is_directory=True)
            return [],[]
        self.recover(observer=observer);self.assertTrue(outside.exists());self.assertTrue((moved/'transformed/library.jar').exists())
    def test_parent_git_repository_uncommitted_output_is_preserved(self):
        subprocess.run(['git','init','-q',str(self.home)],check=True);p=self.file('.gradle/caches/build-cache-1/22222222222222222222222222222222',b'private uncommitted data');self.recover();self.assertTrue(p.exists())
    def test_many_marked_transforms_are_removed_in_one_bounded_batch(self):
        paths=[self.transform(n) for n in range(512)];calls=[];result=self.recover(observer=lambda:(calls.append(True) or [],[]));self.assertTrue(all(not p.exists() for p in paths),result);self.assertLessEqual(len(calls),4)
    def test_explicit_preview_keeps_new_cache_categories(self):
        cargo=self.cargo('crate-'+'a'*16+'.rcgu.o',MACHO);gradle=self.transform(1);self.recover(apply=False);self.assertTrue(cargo.exists());self.assertTrue(gradle.exists())
    def test_credential_named_dependency_object_requires_compiled_proof(self):
        good=self.cargo('librelay_credential_provider-'+'a'*16+'.rlib',b'!<arch>\ncompiler archive')
        bad=self.cargo('libprivate_token-'+'b'*16+'.rlib',b'private credential')
        self.recover();self.assertFalse(good.exists());self.assertTrue(bad.exists())
    def test_pressure_inventory_is_sampled_per_batch_not_per_entry(self):
        import fcntl,json
        from types import SimpleNamespace
        from unittest.mock import patch
        paths=[self.transform(n) for n in range(512)];registry=self.app/'guard-reservations';registry.mkdir()
        p=registry/'waiting.json';p.write_text(json.dumps({'id':'waiting','owner':'fixture','state':'waiting','created':1,'memory':0,'budget':1000000000,'consumed':{},'volumes':[{'path':str(self.home),'device':self.home.stat().st_dev,'reserve':20,'budget':1000000000}]}))
        original=self.r.pressure_demand;calls=[]
        def measured(*args,**kw):calls.append(True);return original(*args,**kw)
        with p.open('a+') as lease,patch.object(self.r,'pressure_demand',side_effect=measured),patch.object(self.r.shutil,'disk_usage',side_effect=lambda _:SimpleNamespace(free=40 if any(x.exists() for x in paths) else 2000000000)),patch.object(self.r.os.path,'ismount',return_value=True):
            fcntl.flock(lease,fcntl.LOCK_EX);result=self.r.recover(self.home,self.app,apply=True,pressure_only=True,observer=lambda:([],[]),floors={str(self.home):1000000020})
        self.assertTrue(all(not x.exists() for x in paths),result);self.assertLessEqual(len(calls),8,'pressure registry scans must be bounded per batch')
    def test_next_batch_uses_remaining_physical_deficit(self):
        import fcntl,json
        from types import SimpleNamespace
        from unittest.mock import patch
        paths=[self.file('.cache/cargo-target/debug/incremental/crate'+str(n)+'/object.o',b'x'*4096) for n in range(6)]
        unit=self.r.snapshot(paths[0].parent,self.home,kind='cargo-incremental')[1]
        registry=self.app/'guard-reservations';registry.mkdir();p=registry/'waiting.json'
        p.write_text(json.dumps({'id':'waiting','owner':'fixture','state':'waiting','created':1,'memory':0,'budget':3*unit,'consumed':{},'volumes':[{'path':str(self.home),'device':self.home.stat().st_dev,'reserve':20,'budget':3*unit}]}))
        def physical(_):
            removed=sum(not x.exists() for x in paths)
            return SimpleNamespace(free=20+(3*unit if removed>=4 else removed*2*unit//3))
        with p.open('a+') as lease,patch.object(self.r.shutil,'disk_usage',side_effect=physical),patch.object(self.r.os.path,'ismount',return_value=True):
            fcntl.flock(lease,fcntl.LOCK_EX);self.r.recover(self.home,self.app,apply=True,pressure_only=True,observer=lambda:([],[]),floors={str(self.home):20+3*unit})
        self.assertEqual(sum(not x.exists() for x in paths),4,'remeasured capacity must shrink the next batch rather than churn two extra caches')
    def test_independent_gradle_task_cache_entries_preserve_protected_neighbors(self):
        base='.gradle/caches/build-cache-1/'
        good=self.file(base+'a'*32);database=self.file(base+'b'*32,b'SQLite format 3\x00private');personal=self.file(base+'personal.sqlite',b'private')
        self.recover();self.assertFalse(good.exists());self.assertTrue(database.exists());self.assertTrue(personal.exists())
    def test_open_gradle_task_entry_does_not_block_closed_entry(self):
        base='.gradle/caches/build-cache-1/';closed=self.file(base+'a'*32);opened=self.file(base+'b'*32)
        self.recover(observer=lambda:([],[str(opened)]));self.assertFalse(closed.exists());self.assertTrue(opened.exists())
    def test_late_inspection_failure_keeps_completed_bulk_evidence_in_cli_report(self):
        import contextlib,io,json,os
        from unittest.mock import patch
        paths=[self.file('Library/Developer/Xcode/DerivedData/App'+str(n)+'/Build/object.o') for n in range(2050)]
        calls=[];original=self.r.recover;report_path=self.home/'report.json'
        def observer():
            calls.append(True)
            if len(calls)==3:raise RuntimeError('inspection became unavailable')
            return [],[]
        def recover(*args,**kw):kw['observer']=observer;return original(*args,**kw)
        with patch.dict(os.environ,HOME=str(self.home),DISK_JANITOR_HOME=str(self.app)),patch.object(self.r,'recover',side_effect=recover),patch.object(self.r.sys,'argv',['recovery.py','--apply','--report',str(report_path)]),contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as outcome:self.r.main()
        self.assertEqual(outcome.exception.code,1)
        result=json.loads(report_path.read_text());self.assertEqual(result['status'],'inspection-unavailable')
        self.assertEqual(sum(not p.exists() for p in paths),2048)
        self.assertGreater(result['removed_allocated_bytes'],0,'completed deletion evidence must survive a later inspection failure')
        self.assertEqual(result['counts']['xcode-derived:removed'],2048)
        self.assertTrue(result['filesystems'])
    def test_live_gradle_cache_lock_preserves_task_outputs(self):
        base='.gradle/caches/build-cache-1/';output=self.file(base+'a'*32);lock=self.file(base+'build-cache-1.lock',b'lock metadata')
        self.recover(observer=lambda:([],[str(lock)]));self.assertTrue(output.exists());self.assertTrue(lock.exists())
if __name__=='__main__':unittest.main()
