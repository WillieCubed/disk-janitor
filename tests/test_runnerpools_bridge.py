"""Disposable real broker journal/admission transactions; no provider requests."""
import fcntl
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
sys.path.insert(0, str(REPO / 'bin'))
import runnerpools_bridge as bridge

SCRIPTS = REPO / 'integration/runnerpools/reviewed-runtime'
sys.path.insert(0, str(SCRIPTS))
import pool_runtime as runtime
import pool_host as host

GIB = 2**30
GUARD_BOOTSTRAP = '''import os,sys,shutil
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,str(Path(sys.argv[1]).parent))
import runnerpools_bridge
original=runnerpools_bridge.UserBridge
config=sys.argv[2]
runnerpools_bridge.UserBridge=lambda:original(config_path=config,root_uid=os.getuid())
shutil.disk_usage=lambda path:SimpleNamespace(free=40*2**30)
source=Path(sys.argv[1]).read_text()
body=source[source.index('cmd_capacity()'):].split("<<'PY'\\n",1)[1].split('\\nPY\\n',1)[0]
sys.argv=['-',os.environ['HOME'],os.environ['DISK_JANITOR_HOME']]+sys.argv[3:]
exec(compile(body,'fixture-actual-local-guard','exec'))
'''


def profile(name='studio'):
    return dict(schema_version=1, id=name, owner=dict(login='Example', id=101, type='Organization'),
                pools=dict(linux=dict(capacity=1, image_source='ghcr.io/example/base@sha256:'+'a'*64,
                    cpus=4, memory_gib=8, disk_gib=15, runner_version='2.330.0', runner_digest='b'*64)),
                consumers=[dict(repo='Example/project', id=201, workflow='.github/workflows/checks.yml', pools=['linux'])])


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / 'local'
        self.home.mkdir(mode=0o700)
        (self.home / 'guard-reservations').mkdir(mode=0o700)
        self.lock = self.home / 'admission.lock'
        self.lock.touch(mode=0o600)
        self.config = self.root / 'public/config.json'
        self.config.parent.mkdir(mode=0o755)
        self.states = self.root / 'pools'
        info = self.lock.stat()
        self.binding = dict(version=1, user_uid=os.getuid(), guard_home=str(self.home),
                            lock_identity=[info.st_dev, info.st_ino], state_root=str(self.states))
        self.config.write_text(json.dumps(self.binding))
        self.broker = runtime.control.BrokerBridge(config_path=self.config, root_uid=os.getuid())
        self.reader = bridge.UserBridge(config_path=self.config, root_uid=os.getuid())
        self.p = profile()
        self.worker = mock.Mock(return_value=dict(clean=True))
        self.controller = runtime.Runtime(self.p, self.states / self.p['id'], mock.Mock(), self.worker,
            global_root=self.states, storage_uid=os.getuid(), cpu_count=32, memory_bytes=64*GIB,
            free_bytes=40*GIB, resource_bridge=self.broker, health=lambda *a:None)
        # Initial authoritative refresh, like the first daemon resource pass.
        with self.controller._resources():
            pass

    def local(self, budget=10*GIB, device=None, state='running'):
        item = dict(state=state, memory=GIB, budget=budget, pid=999999999,
                    volumes=[dict(device=self.states.stat().st_dev if device is None else device,
                                  reserve=20*GIB, budget=budget)], consumed={})
        (self.home / 'guard-reservations/local.json').write_text(json.dumps(item))
        return item

    def admit(self, controller=None):
        return (controller or self.controller)._admit('linux', 11)

    def test_ci_first_is_visible_to_local_admission_without_nested_reservation(self):
        record = self.admit()
        with self.lock.open() as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            claims = self.reader.claims(guard_home=self.home)
        self.assertEqual(len(claims), 1)
        self.assertEqual(claims[0]['budget'], 15*GIB)
        self.assertEqual(claims[0]['memory'], 8*GIB)
        self.assertIn(record['generation'], claims[0]['id'])
        self.assertFalse(list((self.home / 'guard-reservations').iterdir()))
        self.assertEqual(40*GIB-claims[0]['budget']-10*GIB < 20*GIB, True)

    def test_ci_first_defers_actual_local_guard_without_launch(self):
        self.admit()
        marker = self.root / 'must-not-launch'
        env = dict(os.environ, HOME=str(self.root), DISK_JANITOR_HOME=str(self.home),
                   DISK_JANITOR_RUNTIME_DIR=str(REPO / 'bin'))
        result = subprocess.run([sys.executable, '-c', GUARD_BOOTSTRAP, str(REPO / 'bin/disk-janitor'),
            str(self.config), 'guard', '--root-reserve-gib', '0', '--planned-gib', '10', '--owner', 'local', '--max-running', '2',
            '--once', '--', sys.executable, '-c', 'from pathlib import Path;Path('+repr(str(marker))+').touch()'],
            env=env, text=True, capture_output=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertTrue(marker.exists(), 'one CI runner leaves the second slot to local work')
        marker.unlink()
        (self.home / 'slots').mkdir(exist_ok=True)
        with (self.home / 'slots/slot-0.lock').open('a') as running:
            fcntl.flock(running, fcntl.LOCK_EX)
            result = subprocess.run([sys.executable, '-c', GUARD_BOOTSTRAP, str(REPO / 'bin/disk-janitor'),
                str(self.config), 'guard', '--root-reserve-gib', '0', '--owner', 'local', '--max-running', '2',
                '--once', '--', sys.executable, '-c', 'from pathlib import Path;Path('+repr(str(marker))+').touch()'],
                env=env, text=True, capture_output=True, timeout=8)
        self.assertEqual(result.returncode, 75, result.stdout+result.stderr)
        self.assertFalse(marker.exists())
        self.assertIn('1 held by RunnerPools CI runners', result.stdout+result.stderr)

    def test_local_first_defers_real_broker_before_vm_preparation(self):
        self.local()
        with self.assertRaises(runtime.CapacityWaiting):
            self.admit()
        self.assertFalse((self.states / 'studio/slots/linux.json').exists())
        self.worker.assert_not_called()
        self.assertEqual(self.reader.claims(), [])

    def test_local_commit_and_ci_admit_cannot_use_the_same_sample(self):
        ready = self.root / 'ready'
        release = self.root / 'release'
        item = self.local(state='waiting')
        code = '''import fcntl,json,sys,time
from pathlib import Path
lock,path,ready,release=sys.argv[1:]
with open(lock) as stream:
 fcntl.flock(stream,fcntl.LOCK_EX)
 Path(ready).touch()
 while not Path(release).exists(): time.sleep(.005)
 item=json.loads(Path(path).read_text());item['state']='running';Path(path).write_text(json.dumps(item))
'''
        proc = subprocess.Popen([sys.executable, '-c', code, str(self.lock),
            str(self.home / 'guard-reservations/local.json'), str(ready), str(release)])
        try:
            end = time.monotonic()+3
            while not ready.exists() and time.monotonic()<end:
                time.sleep(.005)
            self.assertTrue(ready.exists())
            import threading
            outcome = []
            def attempt():
                try:
                    self.admit()
                except Exception as error:
                    outcome.append(error)
            thread = threading.Thread(target=attempt)
            thread.start()
            time.sleep(.05)
            self.assertTrue(thread.is_alive(), 'broker must wait for exact local commit mutex')
            release.touch()
            thread.join(3)
            self.assertIsInstance(outcome[0], runtime.CapacityWaiting)
            self.assertEqual(proc.wait(timeout=3), 0)
        finally:
            release.touch()
            proc.wait(timeout=3)

    def test_uncertain_cleanup_retains_commitment_and_success_releases(self):
        record = self.admit()
        self.controller._unregister_idle = lambda _:None
        self.controller._owned = lambda _:None
        self.worker.return_value = dict(clean=False)
        with self.assertRaises(runtime.Failure):
            self.controller._cleanup('linux', record)
        self.assertEqual(len(self.reader.claims()), 1)
        self.assertEqual(self.controller._read(self.controller._path('linux'))['state'], 'cleanup-required')
        self.worker.return_value = dict(clean=True)
        self.controller._cleanup('linux', record)
        self.assertEqual(self.reader.claims(), [])

    def test_snapshot_is_durable_before_generation_journal_commit(self):
        original = runtime.control.atomic_write
        observed = []
        def write(path, content, **kwargs):
            if Path(path).name == 'linux.json':
                observed.append(len(self.reader.claims()))
                raise OSError('fixture journal interruption')
            return original(path, content, **kwargs)
        with mock.patch.object(runtime.control, 'atomic_write', side_effect=write):
            with self.assertRaises(OSError):
                self.admit()
        self.assertEqual(observed, [1])
        self.worker.assert_not_called()

    def test_lifetimes_are_explicit_never_pid_or_snapshot_expiry_release(self):
        self.admit()
        self.reader.clock = lambda:time.time()+365*86400
        self.assertEqual(len(self.reader.claims()), 1)
        self.assertEqual(self.controller._scan()[0]['state'], 'creating')
        self.local()
        with self.broker.transaction(self.states):
            self.assertEqual(len(self.broker.local_claims()), 1)

    def test_stopped_controller_empty_snapshot_allows_safe_local_admission(self):
        self.reader.clock = lambda:time.time()+365*86400
        self.assertEqual(self.reader.claims(), [])

    def test_future_snapshot_is_unavailable_without_releasing_commitment(self):
        self.admit()
        self.reader.clock = lambda:0
        with self.assertRaises(bridge.BridgeUnavailable):
            self.reader.claims()
        self.assertEqual(len(self.controller._scan()), 1)

    def test_tampered_binding_snapshot_and_lock_fail_closed(self):
        self.admit()
        snapshot = self.config.parent / 'commitments.json'
        saved = snapshot.read_bytes()
        snapshot.chmod(0o666)
        with self.assertRaises(bridge.BridgeUnavailable):self.reader.claims()
        snapshot.chmod(0o644)
        snapshot.write_text('{"version":1,"version":1}')
        with self.assertRaises(bridge.BridgeUnavailable):self.reader.claims()
        snapshot.write_bytes(saved)
        replacement = self.home / 'replacement'
        replacement.touch(mode=0o600)
        replacement.replace(self.lock)
        with self.assertRaises(bridge.BridgeUnavailable):self.reader.claims()
        with self.assertRaises(runtime.CapacityWaiting):self.admit()

    def test_local_disk_claims_are_scoped_to_physical_device(self):
        self.local(device=self.states.stat().st_dev+1)
        self.admit()

    def test_waiting_local_work_has_no_duplicate_active_commitment(self):
        self.local(state='waiting')
        self.admit()

    def test_cancelled_local_work_releases_only_confirmed_owned_teardown(self):
        item = self.local(state='cancelled')
        with self.assertRaises(runtime.CapacityWaiting):
            self.admit()
        item['cancellation_teardown_confirmed'] = True
        (self.home / 'guard-reservations/local.json').write_text(json.dumps(item))
        self.admit()

    def test_actual_guard_cancel_then_ci_admission_without_other_local_job(self):
        env = dict(os.environ, HOME=str(self.root), DISK_JANITOR_HOME=str(self.home),
                   DISK_JANITOR_RUNTIME_DIR=str(REPO / 'bin'))
        (self.home / 'slots').mkdir(exist_ok=True)
        running = (self.home / 'slots/slot-0.lock').open('a')
        self.addCleanup(running.close)
        fcntl.flock(running, fcntl.LOCK_EX)
        process = subprocess.Popen([sys.executable, '-c', GUARD_BOOTSTRAP, str(REPO / 'bin/disk-janitor'),
            str(self.config), 'guard', '--root-reserve-gib', '20', '--planned-gib', '60', '--owner', 'cancelled', '--max-running', '1',
            '--job-id', 'cancelled', '--deadline-seconds', '4', '--', sys.executable, '-c', 'raise SystemExit(99)'],
            env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            path = self.home / 'guard-reservations/cancelled.json'
            end = time.monotonic()+3
            while not path.exists() and time.monotonic()<end:
                time.sleep(.005)
            self.assertTrue(path.exists())
            process.terminate()
            output = process.communicate(timeout=5)[0]
            self.assertEqual(process.returncode, 143, output)
            item = json.loads(path.read_text())
            self.assertEqual(item['state'], 'cancelled')
            self.assertTrue(item.get('cancellation_teardown_confirmed'))
            self.admit()  # No intervening local acquire/read_jobs reconciliation.
        finally:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=5)

    def test_every_installed_profile_shares_one_export(self):
        second = runtime.Runtime(profile('personal'), self.states / 'personal', mock.Mock(), self.worker,
            global_root=self.states, storage_uid=os.getuid(), cpu_count=32, memory_bytes=64*GIB,
            free_bytes=80*GIB, resource_bridge=self.broker, health=lambda *a:None)
        self.admit()
        self.admit(second)
        self.assertEqual(len(self.reader.claims()), 2)

    def test_absent_binding_is_legacy_but_partial_activation_blocks(self):
        absent = self.root / 'absent/config.json'
        reader = bridge.UserBridge(config_path=absent, root_uid=os.getuid())
        self.assertEqual(reader.claims(), [])
        absent.parent.mkdir()
        with self.assertRaises(bridge.BridgeUnavailable):reader.claims()

    def test_public_snapshot_readable_under_private_daemon_umask(self):
        previous = os.umask(0o077)
        try:
            self.admit()
        finally:
            os.umask(previous)
        import stat
        snapshot = self.config.parent / 'commitments.json'
        self.assertEqual(stat.S_IMODE(snapshot.stat().st_mode), 0o644)


class NativeProvisionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.owner_home = self.root / 'owner'
        self.home = self.owner_home / '.disk-janitor'
        self.home.mkdir(parents=True, mode=0o700)
        (self.home / 'guard-reservations').mkdir(mode=0o700)
        (self.home / 'admission.lock').touch(mode=0o600)
        (self.home / 'runnerpools_bridge.py').write_bytes((REPO / 'bin/runnerpools_bridge.py').read_bytes())
        (self.home / 'disk-janitor').write_bytes((REPO / 'bin/disk-janitor').read_bytes())
        self.p = profile()
        self.install = self.root / 'installed/studio'
        self.install.mkdir(parents=True)
        protected_control = self.install / 'process_control.py'
        protected_control.write_bytes((SCRIPTS / 'process_control.py').read_bytes())
        (self.install / 'pool_runtime.py').write_bytes((SCRIPTS / 'pool_runtime.py').read_bytes())
        import hashlib
        receipt = {name:hashlib.sha256((self.install / name).read_bytes()).hexdigest()
                   for name in ('process_control.py', 'pool_runtime.py')}
        (self.install / 'runtime.json').write_text(json.dumps(receipt))
        self.state = self.root / 'states/studio'
        self.state.mkdir(parents=True)
        self.config = self.root / 'public/config.json'
        from types import SimpleNamespace
        account = SimpleNamespace(pw_uid=os.getuid(), pw_dir=str(self.owner_home))
        def directory(path, mode=0o755):
            path.mkdir(mode=mode, exist_ok=True)
        patches = [mock.patch.object(host, 'protected', side_effect=lambda path, **kw:Path(path).lstat()),
                   mock.patch.object(host, 'root_directory', side_effect=directory),
                   mock.patch.object(host.pwd, 'getpwuid', return_value=account),
                   mock.patch.object(host, 'paths', return_value=dict(state=self.state, install=self.install)),
                   mock.patch.object(host, 'installed_profiles', return_value=[(self.install/'profile.json',self.p)]),
                   mock.patch.object(host, 'verify_install'), mock.patch.object(host, '_idle_repair_slots'),
                   mock.patch.object(host.control, 'CONFIG', self.config)]
        self.patches = []
        for patch in patches:
            self.patches.append(patch.start())
            self.addCleanup(patch.stop)

    def test_native_installer_commits_snapshot_before_binding_under_both_locks(self):
        real_write = host.control.atomic_write
        order = []
        def write(path, value, **kwargs):
            order.append(Path(path).name)
            return real_write(path, value, **kwargs)
        with mock.patch.object(host.control, 'atomic_write', side_effect=write):
            host._join_local_admission(self.p, self.owner_home)
        self.assertEqual(order, ['commitments.json', 'config.json'])
        self.assertEqual(json.loads(self.config.read_text())['guard_home'], str(self.home))
        self.assertEqual(bridge.UserBridge(config_path=self.config, root_uid=os.getuid()).claims(), [])
        host.verify_install.assert_called_once_with(self.p)
        host._idle_repair_slots.assert_called_once_with(self.p)

    def test_native_join_blocks_mismatched_local_half(self):
        (self.home / 'runnerpools_bridge.py').write_text('mismatch')
        with self.assertRaises(runtime.Failure):
            host._join_local_admission(self.p, self.owner_home)
        self.assertFalse(self.config.parent.exists())

    def test_native_join_preserves_active_generations(self):
        host._idle_repair_slots.side_effect = runtime.Failure('active generation preserved')
        with self.assertRaises(runtime.Failure):
            host._join_local_admission(self.p, self.owner_home)
        self.assertFalse(self.config.parent.exists())

    def test_native_join_checks_every_discovered_installed_profile(self):
        other = profile('other')
        host.installed_profiles.return_value.append((self.install/'other.json', other))
        host._join_local_admission(self.p, self.owner_home)
        self.assertEqual(host.verify_install.call_count, 2)
        self.assertEqual(host._idle_repair_slots.call_count, 2)

    def test_native_join_validates_actual_atomic_release_layout(self):
        import install_runtime
        install_runtime.publish(REPO / 'bin', self.home)
        host._join_local_admission(self.p, self.owner_home)
        self.assertTrue(self.config.exists())
        # An owned symlink is insufficient: only the complete canonical release
        # with its exact manifest and hashes is accepted by the root reader.
        alias = self.home / 'runnerpools_bridge.py'
        alias.unlink()
        alias.symlink_to(REPO / 'bin/runnerpools_bridge.py')
        with self.assertRaises(runtime.Failure):
            host._local_admission_runtime(self.home, os.getuid())

    def test_native_join_rejects_corrupted_immutable_release(self):
        import install_runtime
        release = install_runtime.publish(REPO / 'bin', self.home)
        component = release / 'coverage.py'
        component.chmod(0o644)
        component.write_text('tampered')
        component.chmod(0o444)
        with self.assertRaises(runtime.Failure):
            host._join_local_admission(self.p, self.owner_home)
        self.assertFalse(self.config.parent.exists())

    def test_native_join_rejects_profile_without_identical_broker_adapter(self):
        path = self.install / 'runtime.json'
        receipt = json.loads(path.read_text())
        receipt['pool_runtime.py'] = '0'*64
        path.write_text(json.dumps(receipt))
        with self.assertRaises(runtime.Failure):
            host._join_local_admission(self.p, self.owner_home)
        self.assertFalse(self.config.parent.exists())


if __name__ == '__main__':
    unittest.main()
