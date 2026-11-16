"""A paused admitted writer can request authorized recovery without a second job."""
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

REPO=Path(__file__).resolve().parents[1]


class PausedDemandTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve();self.app=self.root/'.dj';self.registry=self.app/'guard-reservations'
        self.registry.mkdir(parents=True,mode=0o700)
        spec=importlib.util.spec_from_file_location('paused_recovery',REPO/'bin/recovery.py')
        self.module=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.module)
        self.path=self.registry/'paused.json'
        self.record=dict(id='paused',owner='owner',command_hash='a'*64,state='running',created=1,budget=50,consumed={},volumes=[dict(path=str(self.root),device=self.root.stat().st_dev,reserve=20,budget=50)])
        self.path.write_text(json.dumps(self.record));self.path.chmod(0o600)
        self.runtime=self.registry/'paused.runtime'
        self.record['runtime_file']=str(self.runtime);self.path.write_text(json.dumps(self.record))
        self.runtime.write_text(json.dumps(dict(version=1,job_id='paused',owner='owner',command_hash='a'*64,state='pressure-blocked',hysteresis_bytes=10)))
        self.runtime.chmod(0o600)

    def demand(self):
        with self.path.open('rb') as executor:
            fcntl.flock(executor,fcntl.LOCK_EX)
            with patch.object(self.module.shutil,'disk_usage',return_value=SimpleNamespace(free=15)),patch.object(self.module.os.path,'ismount',return_value=True),patch.dict(os.environ,{'DISK_JANITOR_LOW_WATER_GIB':'0'}):
                return self.module.pressure_demand(self.app,home=self.root)

    def test_solo_pressure_blocked_writer_requests_reserve_plus_hysteresis(self):
        demand=self.demand()
        self.assertIn(self.root.stat().st_dev,demand)
        self.assertEqual(demand[self.root.stat().st_dev]['deficit'],15)
        self.assertEqual(demand[self.root.stat().st_dev]['required'],30,'its reserve plus hysteresis, never its whole command again')

    def test_runtime_identity_mismatch_is_skipped_without_a_veto(self):
        item=json.loads(self.runtime.read_text());item['command_hash']='b'*64;self.runtime.write_text(json.dumps(item))
        self.assertEqual(self.demand(),{})

    def test_negative_hysteresis_is_skipped_without_a_veto(self):
        item=json.loads(self.runtime.read_text());item['hysteresis_bytes']=-1;self.runtime.write_text(json.dumps(item))
        self.assertEqual(self.demand(),{})

    def test_running_without_paused_observation_does_not_request_recovery(self):
        self.runtime.unlink()
        self.assertEqual(self.demand(),{})


if __name__=='__main__':unittest.main()
