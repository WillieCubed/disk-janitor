#!/usr/bin/env python3
"""Durable local job submission. Policy belongs to the guard, not its clients."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import subprocess
import sys
import time
import uuid
sys.path.insert(0, str(Path(__file__).resolve().parent))
from capacity import LearningStore

TERMINAL = frozenset({'succeeded', 'failed', 'cancelled', 'unknown'})
STATES = frozenset({'queued', 'running', 'cancelling'}) | TERMINAL
GIB = 2 ** 30


def client_identity(environment):
    agent = environment.get('CODEX_THREAD_ID') or environment.get('CLAUDE_SESSION_ID')
    label = 'agent:' + agent if agent else 'user:' + str(os.getuid())
    return hashlib.sha256(label.encode()).hexdigest()[:24], bool(agent)


def policy(command):
    """Estimates only. Executable names never authorize command replay."""
    executable = Path(command[0]).name.lower()
    if (executable in ('cargo','rustc','rustfmt','swift','swiftc','xcodebuild')
            and len(command)==2 and command[1] in ('--version','-V','--help','-h','-version','-help')):
        return {'kind':'probe','disk_gib':.05,'memory_gib':.25}
    if executable in ('true', 'false', 'echo', 'printf'):
        return {'kind': 'small', 'disk_gib': .05, 'memory_gib': .125}
    if executable in ('pytest', 'py.test') or (executable.startswith('python') and command[1:3] == ['-m', 'unittest']):
        return {'kind': 'checks', 'disk_gib': 1, 'memory_gib': 2}
    if executable in ('cargo', 'gradle', 'gradlew', 'xcodebuild', 'swift', 'swiftc', 'rustc'):
        return {'kind': 'native', 'disk_gib': 4, 'memory_gib': 8}
    return {'kind': 'general', 'disk_gib': 2, 'memory_gib': 2}


def mount_root(path):
    path = Path(path).resolve()
    while not path.is_mount() and path.parent != path:
        path = path.parent
    return path


def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_json(path, value):
    temporary = path.with_name(path.name + '.tmp-' + uuid.uuid4().hex)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'w') as output:
            json.dump(value, output)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()


def lease_held(path):
    try:
        if path.is_symlink() or path.stat().st_uid != os.getuid():
            raise ValueError('unsafe executor lease')
        with path.open('rb') as stream:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return False
            except BlockingIOError:
                return True
    except FileNotFoundError:
        return False


class Store:
    def __init__(self, app_home=None):
        self.home = Path(app_home or os.environ.get('DISK_JANITOR_HOME', str(Path.home() / '.disk-janitor')))
        if self.home.is_symlink():
            raise ValueError('job state directory must not be a symlink')
        self.home = self.home.resolve()
        self.root = self.home / 'jobs'

    def directory(self, job):
        if not re.fullmatch(r'j-[0-9a-f]{32}', job):
            raise ValueError('invalid job ID')
        p = self.root / job
        if p.is_symlink() or p.resolve() != p:
            raise ValueError('unsafe job directory')
        return p

    def read(self, job):
        p = self.directory(job) / 'job.json'
        if p.is_symlink() or p.stat().st_uid != os.getuid():
            raise ValueError('unsafe job record')
        value = json.loads(p.read_text())
        if value.get('id') != job or value.get('backend_job_id') != job:
            raise ValueError('job identity mismatch')
        return value

    @contextmanager
    def locked(self, job):
        directory = self.directory(job)
        lock = directory / 'job.lock'
        if lock.is_symlink():
            raise ValueError('unsafe job lock')
        descriptor = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'a') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            yield directory

    def update(self, job, **changes):
        with self.locked(job) as directory:
            value = self.read(job)
            # Immutable identity and submitted command cannot be edited through lifecycle updates.
            if set(changes) & {'id', 'backend_job_id', 'owner', 'argv', 'cwd', 'submitted_at'}:
                raise ValueError('submission identity is immutable')
            value.update(changes)
            value['updated_at'] = time.time()
            atomic_json(directory / 'job.json', value)
            return value

    def create(self, command, cwd, environment):
        if not command or not all(isinstance(x, str) and '\x00' not in x for x in command):
            raise ValueError('submit requires a command')
        if self.root.is_symlink():
            raise ValueError('unsafe job store')
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root.chmod(0o700)
        job = 'j-' + uuid.uuid4().hex
        directory = self.directory(job)
        directory.mkdir(mode=0o700)
        artifacts = directory / 'artifacts'
        artifacts.mkdir(mode=0o700)
        owner, agent = client_identity(environment)
        learning = LearningStore(self.home / 'capacity-history')
        observation_key = learning.key(command, cwd)
        profile = learning.predict(observation_key, policy(command))
        value = {'version': 1, 'id': job, 'backend_job_id': job, 'owner': 'job:' + owner,
                 'client': owner, 'agent_client': agent, 'submitted_at': time.time(),
                 'argv': list(command), 'label': Path(command[0]).name,
                 'cwd': str(Path(cwd).resolve()), 'artifact_root': str(artifacts),
                 'profile': profile, 'observation_key': observation_key, 'restartable': False, 'state': 'queued',
                 'output_mode': 'retained', 'accepted': False, 'worker_pid': None, 'guardian_pid': None,
                 'launched': False, 'cancel_requested': False, 'exit_code': None}
        with self.locked(job):
            atomic_json(directory / 'job.json', value)
        fsync_directory(self.root)
        return value

    def backend(self, value, suffix):
        path = self.home / 'guard-reservations' / (value['backend_job_id'] + suffix)
        try:
            if path.is_symlink() or path.stat().st_uid != os.getuid():
                raise ValueError('unsafe guardian receipt')
            data = json.loads(path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return None  # A held legacy reservation is updated in place, or retired after its receipt.
        if data.get('owner') != value['owner']:
            raise ValueError('guardian owner does not match job')
        expected = hashlib.sha256(json.dumps([value['argv'], value['cwd'], value['owner'], value['artifact_root']]).encode()).hexdigest()
        if data.get('command_hash') != expected:
            raise ValueError('guardian command identity mismatch')
        if suffix in {'.result', '.outcome'} and (type(data.get('exit_code')) is not int or not 0 <= data['exit_code'] <= 255):
            raise ValueError('invalid guardian outcome')
        return data

    def outcome(self, value):
        result = self.backend(value, '.result')
        captured = self.backend(value, '.outcome')
        if captured is not None and (result is None or result.get('status') == 'outcome-uncertain'):
            return captured
        return result

    def view(self, job):
        value = self.read(job)
        result = self.outcome(value)
        record = self.backend(value, '.json')
        state = value['state']
        code = value.get('exit_code')
        if result is not None and lease_held(self.home / 'guard-reservations' / (value['id'] + '.json')):
            state = 'cancelling' if value.get('cancel_requested') else 'running'
            code = None
        elif result is not None:
            code = result['exit_code']
            if result.get('status') == 'outcome-uncertain':
                state, code = 'unknown', 125
            else:
                state = 'succeeded' if code == 0 else 'cancelled' if code == 143 else 'failed'
        elif lease_held(self.home / 'guard-reservations' / (value['id'] + '.json')):
            code = None
            state = ('cancelling' if value.get('cancel_requested') else
                     'queued' if record and record.get('state') == 'waiting' else
                     'running' if record or value.get('state') == 'running' else 'queued')
        elif state not in TERMINAL:
            directory = self.directory(job)
            executor_present = lease_held(directory / 'worker.lock') or lease_held(directory / 'guardian.lock')
            if executor_present:
                state = ('cancelling' if value.get('cancel_requested') else
                         'running' if value.get('state') == 'running' else 'queued')
            elif value.get('accepted') or value.get('launched'):
                late = self.outcome(value)
                if late is not None:
                    code = late['exit_code']
                    state = ('unknown' if late.get('status') == 'outcome-uncertain' else
                             'succeeded' if code == 0 else 'cancelled' if code == 143 else 'failed')
                    if state == 'unknown':code = 125
                else:
                    state, code = 'unknown', 125
        value = dict(value, state=state, exit_code=code)
        runtime = self.backend(value, '.runtime')
        if state not in TERMINAL and runtime is not None and runtime.get('state') in {'pressure-blocked','pressure-observed'}:
            available=lease_held(self.home/'guard-reservations'/(job+'.controller'))
            blocked=runtime['state']=='pressure-blocked'
            reason=runtime.get('reason')
            if not available:reason='prior '+runtime['state']+' observation; controller unavailable; execution preserved without replay'
            value.update(pressure_blocked=blocked if available else None, pressure_observed=True if available else None, reason=reason,
                         enforcement=runtime.get('enforcement'), blocked_since=runtime.get('blocked_since'), executor_unavailable=not available)
        return value

    def list(self):
        if not self.root.exists():
            return []
        values = []
        for p in self.root.iterdir():
            if re.fullmatch(r'j-[0-9a-f]{32}', p.name) and not p.is_symlink():
                try:
                    values.append(self.view(p.name))
                except (OSError, ValueError):
                    pass
        return sorted(values, key=lambda j: j['submitted_at'])


def public(value):
    # Commands may contain credentials. Public status includes an executable label,
    # not argument strings or the submitting environment.
    return {key: value.get(key) for key in ('id', 'state', 'label', 'submitted_at', 'updated_at',
            'exit_code', 'cwd', 'artifact_root', 'worker_pid', 'guardian_pid', 'reason', 'restartable',
            'output_mode', 'pressure_blocked', 'pressure_observed', 'enforcement', 'blocked_since', 'executor_unavailable')}


def submit(store, command):
    if os.environ.get('RUNNER_ENVIRONMENT') == 'self-hosted' or os.environ.get('RUNNERPOOL_PROFILE'):
        raise ValueError('RunnerPools already owns this execution; submit through its existing broker')
    meta = store.create(command, Path.cwd(), os.environ)
    read_fd, write_fd = os.pipe()
    environment = dict(os.environ, DISK_JANITOR_READY_FD=str(write_fd))
    worker = subprocess.Popen([sys.executable, '-B', str(Path(__file__).resolve()), '_worker', meta['id']],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              env=environment, start_new_session=True, pass_fds=(write_fd,))
    os.close(write_fd)
    try:
        ready, _, _ = select.select([read_fd], [], [], 10)
        if not ready or os.read(read_fd, 16) != b'ready':
            # The startup worker cannot launch until acceptance is durably committed.
            store.update(meta['id'], state='failed', exit_code=125, reason='executor did not become ready')
            raise RuntimeError('executor did not become ready; no command accepted')
        store.update(meta['id'], accepted=True)
    finally:
        os.close(read_fd)
    return meta['id']


def guard_command(store, meta):
    profile = meta['profile']
    command = [str(Path(__file__).resolve().with_name('disk-janitor')), 'guard',
               '--owner', meta['owner'], '--job-id', meta['id'],
               '--artifact-root', meta['artifact_root'], '--retention-root', meta['artifact_root'],
               '--planned-gib', str(profile['disk_gib']),
               '--memory-gib', str(profile['memory_gib']), '--warn-free-gib', '0', '--quiet',
               '--submitted-at', str(meta['submitted_at']),
               '--job-control-file', str(store.directory(meta['id']) / 'job.json'),
               '--job-log-file', str(store.directory(meta['id']) / 'output.log')]
    mounts = {}
    external = Path('/Volumes/WillieDrive')
    if external.is_mount():
        mounts[str(external)] = (100, profile.get('disk_by_device', {}).get(str(external.stat().st_dev), profile['disk_gib']))
    cwd_mount = mount_root(meta['cwd'])
    internal_devices = {Path('/').stat().st_dev, Path.home().stat().st_dev}
    if cwd_mount.stat().st_dev not in internal_devices and str(cwd_mount) not in mounts:
        mounts[str(cwd_mount)] = (1, profile.get('disk_by_device', {}).get(str(cwd_mount.stat().st_dev), profile['disk_gib']))
    # Explicit external path arguments retain their required mount, even if it is absent.
    for arg in meta['argv']:
        match = re.match(r'^(/Volumes/[^/]+)(?:/|$)', arg)
        if match and match[1] not in mounts:
            mount = Path(match[1])
            mounts[match[1]] = (100 if mount == external else 1, profile['disk_gib'])
    for path, (reserve, budget) in mounts.items():
        command += ['--volume', path, str(reserve), '--write-budget', path, str(budget)]
    return command + ['--', *meta['argv']]


def worker(store, job):
    ready_fd = int(os.environ.pop('DISK_JANITOR_READY_FD', '-1'))
    if ready_fd < 0:
        raise ValueError('workers require a submitting execution context')
    directory = store.directory(job)
    descriptor = os.open(directory / 'worker.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'a') as worker_lease:
        try:
            fcntl.flock(worker_lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('this job already has an execution worker')
        meta = store.update(job, worker_pid=os.getpid())
        diagnostic = directory / 'guardian.log'
        output_fd = os.open(diagnostic, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        lifetime_fd = os.open(directory / 'guardian.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        fcntl.flock(lifetime_fd, fcntl.LOCK_EX)
        try:
            with os.fdopen(output_fd, 'ab', buffering=0) as output:
                ready_sent = False
                retry_delay = .1
                while True:
                    # The same still-live worker is the permission-context custodian.
                    # Reacquire the executor lease for each prelaunch replacement.
                    if lifetime_fd < 0:
                        lifetime_fd = os.open(directory / 'guardian.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
                        fcntl.flock(lifetime_fd, fcntl.LOCK_EX)
                    guardian = subprocess.Popen(guard_command(store, meta), cwd=meta['cwd'],
                                                stdout=output, stderr=subprocess.STDOUT,
                                                stdin=subprocess.DEVNULL, pass_fds=(lifetime_fd,))
                    store.update(job, guardian_pid=guardian.pid, launched=True)
                    os.close(lifetime_fd)
                    lifetime_fd = -1
                    if not ready_sent:
                        os.write(ready_fd, b'ready'); os.close(ready_fd); ready_sent = True
                    deadline = time.monotonic() + 10
                    while not store.read(job).get('accepted'):
                        if guardian.poll() is not None: break
                        if time.monotonic() > deadline:
                            store.update(job, cancel_requested=True); break
                        time.sleep(.02)
                    while guardian.poll() is None: time.sleep(.1)
                    code = guardian.returncode
                    # Reap first, then fence the exact launch decision. Neither an
                    # observer nor a new worker may reconstruct a lost context.
                    with store.locked(job):
                        current = store.read(job)
                        backend = store.backend(current, '.json')
                        recoverable = (current.get('accepted') and not current.get('execution_committed')
                                       and not current.get('cancel_requested')
                                       and not lease_held(store.home / 'guard-reservations' / (job+'.json'))
                                       and store.outcome(current) is None
                                       and (backend is None or backend.get('child') is None))
                    if not recoverable: break
                    # Backoff protects against a broken executable without limiting
                    # recovery of accepted work. Cancellation remains cooperative.
                    store.update(job, state='queued', exit_code=None, reason='recovering executor before command launch')
                    time.sleep(retry_delay)
                    retry_delay = min(3, retry_delay*1.6)

        finally:
            if lifetime_fd >= 0:
                os.close(lifetime_fd)
        result = store.outcome(meta)
        if result is None and lease_held(store.home / 'guard-reservations' / (meta['id'] + '.json')):
            # A surviving owned supervisor may still be executing and will publish
            # the receipt. Frontend loss does not revoke that execution lease.
            return code
        if result is None:
            # Missing proof is not proof that an arbitrary command did nothing.
            store.update(job, state='unknown', exit_code=125,
                         reason='guardian ended without an authoritative command receipt')
        else:
            state = ('unknown' if result.get('status') == 'outcome-uncertain' else
                     'succeeded' if result['exit_code'] == 0 else
                     'cancelled' if result['exit_code'] == 143 else 'failed')
            store.update(job, state=state, exit_code=result['exit_code'])

        return code


def cancel(store, job):
    meta = store.view(job)
    identity, agent = client_identity(os.environ)
    if agent and identity != meta['client']:
        raise PermissionError('another agent owns this job')
    if meta['state'] not in TERMINAL:
        store.update(job, cancel_requested=True)
    return store.view(job)


def logs(store, job, follow=False):
    meta = store.view(job)
    log = store.directory(job) / 'output.log'
    if meta.get('output_mode') == 'foreground':
        print('This job used foreground streams; output was delivered to its caller and was not retained.', file=sys.stderr)
        return
    emitted = b''
    while True:
        data = log.read_bytes() if log.exists() and not log.is_symlink() else b''
        if not emitted:
            chunk = data
        elif data.startswith(emitted):
            chunk = data[len(emitted):]
        else:
            # A bounded tail has rotated. Reopen by name rather than following a
            # replaced inode; disclose possible overlap instead of inventing offsets.
            marker = emitted[-min(4096, len(emitted)):]
            match = data.rfind(marker)
            if match >= 0:
                chunk = data[match + len(marker):]
            else:
                print('[earlier diagnostic output expired]', file=sys.stderr)
                chunk = data
        if chunk:
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
        emitted = data
        if not follow or store.view(job)['state'] in TERMINAL:
            return
        time.sleep(.1)


def main():
    parser = argparse.ArgumentParser(description='Submit work. Observe jobs. Scheduling and recovery are automatic.')
    sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('submit', help='submit a command with automatic resource policy')
    p.add_argument('command', nargs=argparse.REMAINDER)
    p = sub.add_parser('status', aliases=['jobs', 'show'], help='show the queue or one job')
    p.add_argument('job', nargs='?')
    p.add_argument('--json', action='store_true')
    p = sub.add_parser('logs', help='read bounded diagnostic output; command artifacts are retained')
    p.add_argument('job')
    p.add_argument('-f', '--follow', action='store_true')
    for name in ('wait', 'cancel', '_worker'):
        p = sub.add_parser(name, help=argparse.SUPPRESS if name == '_worker' else name + ' for one job')
        p.add_argument('job')
    args = parser.parse_args()
    store = Store()
    try:
        if args.action == 'submit':
            command = args.command[1:] if args.command[:1] == ['--'] else args.command
            if args.command[:1] != ['--'] or not command:
                parser.error('use submit -- COMMAND; resource policy is automatic')
            print(submit(store, command), flush=True)
        elif args.action in ('status', 'jobs', 'show'):
            values = public(store.view(args.job)) if args.job else [public(j) for j in store.list()]
            if args.json:
                print(json.dumps(values))
            elif args.job:
                print(f"{values['id']} {values['state']} exit={values['exit_code']}")
                if values.get('pressure_observed') or values.get('executor_unavailable'):
                    phase='executor-unavailable' if values.get('executor_unavailable') else 'pressure-blocked' if values.get('pressure_blocked') else 'pressure-observed'
                    print(phase+': '+str(values.get('reason') or 'capacity observation'))
                print('artifacts: ' + values['artifact_root'])
            else:
                print(f"{shutil.disk_usage('/').free/GIB:.1f} GiB internal free")
                for j in values:
                    phase='executor-unavailable' if j.get('executor_unavailable') else 'pressure-blocked' if j.get('pressure_blocked') else 'pressure-observed' if j.get('pressure_observed') else j['state']
                    print(f"{j['id']} {phase:10} {j['label']}")
        elif args.action == 'logs':
            logs(store, args.job, args.follow)
        elif args.action == 'wait':
            while True:
                meta = store.view(args.job)
                if meta['state'] in TERMINAL:
                    print(meta['id'] + ' ' + meta['state'])
                    return meta['exit_code'] if meta['exit_code'] is not None else 125
                time.sleep(.1)
        elif args.action == 'cancel':
            meta = cancel(store, args.job)
            print(meta['id'] + ' ' + meta['state'])
        elif args.action == '_worker':
            return worker(store, args.job)
        return 0
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        print('disk-janitor: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
