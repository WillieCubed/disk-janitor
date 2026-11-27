#!/usr/bin/env python3
"""Owned runtime pressure control and bounded, secret-free observation history.

This is cooperative group enforcement, not a filesystem quota. A controller owns
an unreaped session leader; persisted PIDs never authorize process signals.
"""
import sys
if sys.version_info < (3, 10):
    raise SystemExit('disk-janitor: Python 3.10 or newer is required; this is ' + sys.version.split()[0])
import fcntl
import hashlib
import json
import math
import os
import plistlib
import re
import select
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import time
import uuid

GIB = 2**30


RECORD_SIZE = 4096


def rewrite_in_place(path, held, data):
    """Replace a locked file's content so a lock-free reader always sees valid JSON.

    Truncating first leaves the file empty for a moment, and shrinking it after
    a longer record lets a reader that sized its buffer from the old length cut
    the next one short. The record is instead padded with spaces, which JSON
    ignores, to a fixed size and written over the old one in a single write; the
    file never shrinks. The lock stays on the original inode, so this writes
    through a second descriptor and refuses any other file.
    """
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_NOFOLLOW)
    except OSError:
        return False
    try:
        if os.fstat(descriptor).st_ino != os.fstat(held).st_ino:
            return False
        os.pwrite(descriptor, data.ljust(max(RECORD_SIZE, os.fstat(descriptor).st_size)), 0)
        return True
    finally:
        os.close(descriptor)


def atomic_json(path, value):
    path = Path(path)
    if path.is_symlink(): raise ValueError('unsafe runtime metadata')
    temporary = path.with_name(path.name+'.tmp-'+uuid.uuid4().hex)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'w') as output:
            json.dump(value, output); output.flush(); os.fsync(output.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)
    finally:
        if temporary.exists(): temporary.unlink()


STORAGE_PER_SLOT = 16 * GIB


def storage_roots():
    """Volumes build output may land on: the home volume plus the external storage roots."""
    roots = [Path.home()]
    roots += [Path(entry) for entry in os.environ.get('DISK_JANITOR_STORAGE_ROOTS', '').split(':') if entry]
    return roots


def storage_free(roots=None):
    """Free bytes across distinct filesystems; an absent or unreadable root adds nothing."""
    seen, free = set(), 0
    for root in storage_roots() if roots is None else roots:
        try:
            device = Path(root).stat().st_dev
            if device not in seen:
                seen.add(device)
                free += shutil.disk_usage(root).free
        except OSError:
            continue
    return free


def slot_limit():
    """How many build jobs run at once before the machine is oversubscribed.

    Builds wait on I/O and linking for much of their run, so two cores carry one job. Each
    job also gets 16 GiB of memory and 16 GiB of free space on the volumes its output can
    use, external storage roots included. The fewest of the three wins.
    DISK_JANITOR_MAX_RUNNING overrides it.
    """
    configured = os.environ.get('DISK_JANITOR_MAX_RUNNING', '')
    if configured.isdigit() and int(configured) > 0:
        return int(configured)
    try:
        memory = os.sysconf('SC_PHYS_PAGES') * os.sysconf('SC_PAGE_SIZE')
    except (ValueError, OSError):
        memory = 16 * GIB
    disk = storage_free() // STORAGE_PER_SLOT
    return max(1, min((os.cpu_count() or 4) // 2, memory // (16 * GIB), disk))


def _apfs_info(mount):
    try:
        output = subprocess.run(['diskutil', 'info', '-plist', str(mount)], capture_output=True,
                                timeout=10, check=False).stdout
        return plistlib.loads(output) if output else {}
    except (OSError, ValueError, subprocess.SubprocessError, plistlib.InvalidFileException):
        return {}


def external_storage_root(volumes=Path('/Volumes'), info=_apfs_info):
    """The mounted external volume with the most free space that can hold build output.

    Only writable APFS or HFS+ volumes off the internal disk qualify: Cargo, pnpm cloning
    and Xcode need clonefile, permissions and case handling that exFAT does not give.
    """
    best, best_free = None, -1
    try:
        candidates = sorted(volumes.iterdir())
    except OSError:
        return None
    for mount in candidates:
        try:
            if mount.is_symlink() or not os.path.ismount(mount) or not os.access(mount, os.W_OK):
                continue
            details = info(mount)
            if details.get('Internal', True) or not details.get('WritableVolume', False):
                continue
            if details.get('FilesystemType') not in ('apfs', 'hfs'):
                continue
            free = shutil.disk_usage(mount).free
        except OSError:
            continue
        if free > best_free:
            best, best_free = mount, free
    return best


def _private_directory(app_home, name):
    directory = Path(app_home) / name
    if directory.is_symlink(): raise ValueError('unsafe ' + name + ' directory')
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    return directory


FAST_SLOTS = 3

# Each lane is its own pool of slot locks and its own queue, so a short check never waits
# behind a build and a build never counts a check against its own limit.
LANES = {'build': ('slot-%d.lock', 'queue'), 'fast': ('fast-slot-%d.lock', 'fast-queue')}


def fast_slot_limit():
    """How many short checks run at once beside the builds. DISK_JANITOR_FAST_SLOTS overrides it."""
    configured = os.environ.get('DISK_JANITOR_FAST_SLOTS', '')
    if configured.isdigit() and int(configured) > 0:
        return int(configured)
    return FAST_SLOTS


def lane_limit(lane):
    return fast_slot_limit() if lane == 'fast' else slot_limit()


def take_slot(app_home, limit, lane='build'):
    """Hold a slot for as long as the returned descriptor stays open, or return None.

    The kernel lock is the slot: a holder that dies frees it, and no record can occupy one.
    """
    directory = _private_directory(app_home, 'slots')
    for index in range(limit):
        descriptor = os.open(directory / (LANES[lane][0] % index), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return descriptor
        except BlockingIOError:
            os.close(descriptor)
    return None


def slots_busy(app_home, limit, lane='build'):
    busy = 0
    for index in range(limit):
        try:
            descriptor = os.open(Path(app_home) / 'slots' / (LANES[lane][0] % index), os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            continue
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            busy += 1
        finally:
            os.close(descriptor)
    return busy


def _ticket_name(name):
    return len(name) > 21 and name[:20].isdigit() and name[20] == '-' and not name.endswith('.go')


def join_queue(app_home, created, job_id, lane='build'):
    """Queue behind earlier submissions. Returns the ticket path and its locked descriptor.

    The ticket is published already locked, and its lock is what makes it count: a waiter
    that dies leaves the queue with no cleanup, and a stale file is never a place in line.
    """
    directory = _private_directory(app_home, LANES[lane][1])
    ticket = directory / ('%020d-%s' % (int(created * 1e6), job_id))
    staged = directory / ('.joining-' + uuid.uuid4().hex)
    descriptor = os.open(staged, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.replace(staged, ticket)
    except BaseException:
        os.close(descriptor)
        if staged.exists(): staged.unlink()
        raise
    return ticket, descriptor


def waiting_tickets(app_home, fresh_seconds=5, lane='build'):
    """Tickets, oldest first, whose waiter holds its lock and has polled recently.

    A ticket nobody holds is removed. One whose waiter stopped polling is ignored, so a
    stuck process cannot keep the jobs behind it from a free slot.
    """
    directory = Path(app_home) / LANES[lane][1]
    try:
        names = sorted(name for name in os.listdir(directory) if _ticket_name(name))
    except OSError:
        return []
    live = []
    for name in names:
        path = directory / name
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            continue
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            if time.time() - os.fstat(descriptor).st_mtime <= fresh_seconds: live.append(name)
        else:
            for stale in (path, path.with_name(name + '.go')):
                try: stale.unlink()
                except OSError: pass
        finally:
            os.close(descriptor)
    return live


def queue_view(app_home, job_id=None, lane='build'):
    """One lane's slot use and queue order for status and the watchdog; never an admission input."""
    limit = lane_limit(lane)
    waiting = waiting_tickets(app_home, lane=lane)
    position = next((index + 1 for index, name in enumerate(waiting) if name[21:] == job_id), None)
    return dict(limit=limit, busy=slots_busy(app_home, limit, lane), waiting=waiting, position=position)


def _durable_json(path, payload):
    temporary = path.with_name(path.name + '.receipt-' + os.urandom(8).hex())
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as output:
        json.dump(payload, output)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def sweep_registry(app_home):
    """Retire reservation records that no guardian or process group still owns.

    A record is removed only after its outcome is durable: a crashed guardian's command gets
    an explicit uncertain receipt, so it is never replayed. Nothing here is consulted before
    a job starts, and no output is touched. Anything unreadable or contradictory is counted
    and left in place.
    """
    registry = Path(app_home) / 'guard-reservations'
    counts = {'live': 0, 'waiting': 0, 'retired': 0, 'ambiguous': 0}
    try:
        names = [entry.name for entry in os.scandir(registry) if entry.name.endswith('.json')]
    except OSError:
        return counts
    for name in names:
        path = registry / name
        try:
            descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
            with os.fdopen(descriptor, 'r+') as handle:
                info = os.fstat(handle.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                    raise ValueError('unsafe reservation')
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    counts['live'] += 1
                    try:
                        counts['waiting'] += json.load(handle).get('state') == 'waiting'
                    except (ValueError, AttributeError):
                        pass
                    continue
                if info.st_size == 0:
                    # A claim that never recorded an admission. Recent ones may still be opening.
                    if time.time() - info.st_mtime > 60:
                        path.unlink()
                        counts['retired'] += 1
                    continue
                item = json.load(handle)
                if not isinstance(item, dict) or item['id'] + '.json' != name:
                    raise ValueError('reservation identity mismatch')
                group = item.get('child')
                if group:
                    try:
                        os.killpg(group, 0)
                    except ProcessLookupError:
                        pass
                    else:
                        counts['live'] += 1  # A supervised command outlived its guardian.
                        continue
                outcome, captured = registry / (item['id'] + '.result'), registry / (item['id'] + '.outcome')
                def receipt(source):
                    with os.fdopen(os.open(source, os.O_RDONLY | os.O_NOFOLLOW)) as stream:
                        saved = json.load(stream)
                    if saved.get('owner') != item['owner'] or saved.get('command_hash') != item['command_hash']:
                        raise ValueError('receipt belongs to another command')
                    return saved
                result = receipt(outcome) if os.path.lexists(outcome) else None
                if os.path.lexists(captured) and (result is None or result.get('status') == 'outcome-uncertain'):
                    known = receipt(captured)
                    if type(known.get('exit_code')) is int and 0 <= known['exit_code'] <= 255:
                        _durable_json(outcome, known)
                        result = known
                if result is None and item.get('state') != 'waiting':
                    # An admitted command whose guardian vanished: its effects are unknown.
                    _durable_json(outcome, {'owner': item['owner'], 'command_hash': item['command_hash'],
                                            'exit_code': 125, 'status': 'outcome-uncertain'})
                path.unlink()
                counts['retired'] += 1
        except (OSError, ValueError, KeyError, TypeError, OverflowError, PermissionError):
            counts['ambiguous'] += 1
    return counts


def request_preemption(app_home, requester_id):
    """Request cooperative yield; only the owning guardian may stop its child."""
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', requester_id):
        return None
    registry = Path(app_home) / 'guard-reservations'
    requester_path = registry / (requester_id + '.json')
    if requester_path.is_symlink():
        return None
    requester = json.loads(requester_path.read_text())
    if not isinstance(requester, dict) or requester.get('state') != 'waiting':
        return None
    for p in registry.glob('*.json'):
        if p.is_symlink() or p == requester_path:
            continue
        try:
            target = json.loads(p.read_text())
            if (not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', str(target.get('id','')))
                    or target.get('state') != 'running' or target.get('restartable') is not True
                    or target.get('restart_kind') not in ('build', 'test', 'preview')
                    or target.get('class') == 'service' or target.get('preemptions', 0) >= 2
                    or not target.get('child') or target.get('class') == requester.get('class')):
                continue
            if requester.get('class') != 'feedback' or target.get('class') != 'build':
                continue
            # A held registry lock confirms an owning guardian is still present.
            with p.open('r+') as handle:
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    continue
                except BlockingIOError:
                    pass
            message = {'id': target['id'], 'owner': target['owner'],
                       'command_hash': target['command_hash'], 'child': target['child'],
                       'requester': requester_id, 'created': time.time()}
            destination = registry / (target['id'] + '.preempt-request')
            if destination.is_symlink():
                continue
            temporary = destination.with_name(destination.name + '.' + str(os.getpid()))
            temporary.write_text(json.dumps(message))
            os.replace(temporary, destination)
            return target['id']
        except (OSError, ValueError, KeyError, AttributeError, TypeError):
            continue
    return None


class LearningStore:
    """At most 256 hashed keys; 16 per-filesystem pressure observations per key."""
    def __init__(self, root): self.root = Path(root)

    @staticmethod
    def key(command, cwd):
        return hashlib.sha256(json.dumps([command, str(Path(cwd).resolve())]).encode()).hexdigest()

    def _path(self, key):
        if len(key) != 64 or any(c not in '0123456789abcdef' for c in key): raise ValueError('invalid observation key')
        return self.root / (key+'.json')

    def read(self, key):
        path = self._path(key)
        try:
            if path.is_symlink() or path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
                raise ValueError('unsafe observation record')
            value = json.loads(path.read_text())
            if value.get('version') != 1: return []
            return [s for s in value.get('samples', [])[-16:]
                    if type(s.get('bytes')) is int and s['bytes'] >= 0 and type(s.get('device')) is int]
        except (FileNotFoundError, json.JSONDecodeError): return []

    def predict(self, key, baseline):
        result = dict(baseline)
        samples = self.read(key)
        if not samples: return result
        observed = max(s['bytes'] for s in samples)
        # Decrease only after repeat success; a single large/failed observation
        # raises the estimate immediately. Incomplete filesystem pressure envelopes
        # may raise estimates but never establish an owned-output confinement proof.
        learned = max(.05, observed/GIB*1.5+.05)
        if len([s for s in samples if s.get('successful') and s.get('complete')]) >= 3 and all(s.get('complete') for s in samples):
            result['disk_gib'] = learned
        else:
            result['disk_gib'] = max(result['disk_gib'], learned)
        result['observation_count'] = len(samples)
        # Each sample is the volume's free-space drop while the job ran, so other jobs' writes
        # inflate it. The smallest sample is the closest bound on what this command itself writes.
        result['least_observed_bytes'] = min(s['bytes'] for s in samples)
        result['disk_by_device'] = {str(device):max(baseline['disk_gib'], max(s['bytes'] for s in samples if s['device']==device)/GIB*1.5+.05) for device in {s['device'] for s in samples}}
        result['observed_devices'] = sorted({s['device'] for s in samples})
        return result

    def record(self, key, device, observed_bytes, *, successful, complete=False):
        if type(device) is not int or type(observed_bytes) is not int or observed_bytes < 0:
            raise ValueError('invalid filesystem pressure observation')
        if self.root.is_symlink(): raise ValueError('unsafe observation directory')
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.root.stat().st_uid != os.getuid() or self.root.stat().st_mode & 0o077:
            raise ValueError('unsafe observation directory')
        fence = self.root / 'history.lock'
        descriptor = os.open(fence, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'a') as stream:
            end = time.monotonic() + 1
            while True:
                try:
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    # An observation is optional; a job's completion never waits for one.
                    if time.monotonic() >= end: raise OSError('observation history is busy')
                    time.sleep(.01)
            samples = self.read(key)
            samples.append(dict(device=device, bytes=observed_bytes, successful=bool(successful), complete=bool(complete), source='owned-allocation' if complete else 'filesystem-pressure-envelope'))
            atomic_json(self._path(key), dict(version=1, samples=samples[-16:], updated=time.time()))
            records = sorted((p for p in self.root.glob('*.json') if not p.is_symlink()), key=lambda p:p.stat().st_mtime)
            for path in records[:-256]: path.unlink()  # Owned bounded learning metadata only.


def install_parent_death_resume(guard_fd, expected_parent):
    """Linux kernel thaws this owned supervisor if its controller dies.

    SIGCONT wakes the supervisor first. Before forwarding CONT to its own live
    group, it reacquires the shared cache fence; no recorded PID authorizes this.
    Platforms without this kernel contract must never freeze arbitrary work.
    """
    if not sys.platform.startswith('linux'): return False
    import ctypes
    previous = signal.getsignal(signal.SIGCONT)
    def continued(*_):
        fcntl.flock(guard_fd, fcntl.LOCK_SH)
        signal.signal(signal.SIGCONT, signal.SIG_IGN)
        try: os.killpg(os.getpgrp(), signal.SIGCONT)
        finally: signal.signal(signal.SIGCONT, continued)
    signal.signal(signal.SIGCONT, continued)
    library=ctypes.CDLL(None,use_errno=True)
    library.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
    library.prctl.restype=ctypes.c_int
    if library.prctl(1,signal.SIGCONT,0,0,0) != 0:  # PR_SET_PDEATHSIG.
        signal.signal(signal.SIGCONT,previous)
        return False
    if os.getppid()!=expected_parent: continued()
    return True


class OwnedController:
    def __init__(self, process, config, *, probe=None):
        self.process = process
        self.config = config
        self.probe = probe or (lambda path: shutil.disk_usage(path).free)
        self.paused = False
        self.blocked_since = None
        self.reason = None
        self.guard_fd = config.get('guard_fd')
        self.guard_released = False
        self.stopped = False
        self.last_free = {}
        self.baseline = None
        self.peak_decrease = {}

    def publish(self, state, reason=None):
        atomic_json(self.config['runtime_file'], dict(self.config.get('identity', {}), version=1,
                    controller_pid=os.getpid(), runtime_group=self.process.pid, state=state,
                    enforcement='recoverable-suspension' if self.config.get('freeze_safe') else 'observation-only',
                    blocked_since=self.blocked_since, reason=reason, updated_at=time.time(),
                    hysteresis_bytes=self.config.get('hysteresis_bytes',16*2**20),
                    free=self.last_free, peak_physical_decrease=self.peak_decrease,
                    peak_by_device={str(v['device']):max(self.peak_decrease.get(w['path'],0) for w in self.config['volumes'] if w['device']==v['device']) for v in self.config['volumes']}))

    def _group_states(self):
        """Inspect only this owned group through native kernel interfaces.

        macOS ABI constants/fields match sys/proc_info.h in the installed SDK;
        Linux stat fields follow the kernel proc interface. Access denial retains
        the cache fence rather than treating unavailable inspection as inactivity.
        """
        members = []
        if sys.platform == 'darwin':
            import ctypes
            class ShortInfo(ctypes.Structure):
                _fields_ = [(name, ctypes.c_uint32) for name in ('pid','ppid','pgid','status')] + [('comm',ctypes.c_char*16)] + [(name,ctypes.c_uint32) for name in ('flags','uid','gid','ruid','rgid','svuid','svgid','reserved')]
            library = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
            library.proc_listpids.argtypes = [ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_int]
            library.proc_listpids.restype = ctypes.c_int
            library.proc_pidinfo.argtypes = [ctypes.c_int,ctypes.c_int,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_int]
            library.proc_pidinfo.restype = ctypes.c_int
            ctypes.set_errno(0)
            size = library.proc_listpids(2,self.process.pid,None,0)
            if size==0 and ctypes.get_errno():raise OSError(ctypes.get_errno(),'owned group enumeration unavailable')
            if size < 0 or size > 4*100000: raise OSError('owned group enumeration unavailable')
            if size==0:return []
            buffer = (ctypes.c_int * (size//4+256))()
            ctypes.set_errno(0)
            count = library.proc_listpids(2,self.process.pid,buffer,ctypes.sizeof(buffer))
            if count==0 and ctypes.get_errno():raise OSError(ctypes.get_errno(),'owned group enumeration unavailable')
            if count < 0 or count >= ctypes.sizeof(buffer): raise OSError('owned group enumeration incomplete')
            for pid in buffer[:count//4]:
                if not pid: continue
                info = ShortInfo()
                if library.proc_pidinfo(pid,13,0,ctypes.byref(info),ctypes.sizeof(info)) != ctypes.sizeof(info): raise OSError('owned group identity unavailable')
                if info.pid != pid or info.pgid != self.process.pid or info.uid != os.getuid(): raise OSError('owned group identity changed')
                members.append('stopped' if info.status==4 else 'zombie' if info.status==5 else 'running')  # SSTOP, SZOMB.
        elif sys.platform.startswith('linux'):
            for path in Path('/proc').iterdir():
                if not path.name.isdigit(): continue
                try:
                    fields = (path/'stat').read_text().rsplit(') ',1)[1].split()
                    if int(fields[2]) == self.process.pid:
                        if path.stat().st_uid != os.getuid(): raise OSError('owned group identity changed')
                        members.append('stopped' if fields[0] in ('T','t') else 'zombie' if fields[0]=='Z' else 'running')
                except FileNotFoundError: continue
        else:raise OSError('native owned group inspection unavailable')
        return members

    def group_stopped(self):
        try:
            members=self._group_states()
            return bool(members) and all(state in {'stopped','zombie'} for state in members)
        except (OSError,ValueError,IndexError):return False

    def group_retired(self):
        try:return all(state=='zombie' for state in self._group_states())
        except (OSError,ValueError,IndexError):return False

    def pause(self, reason):
        if self.stopped: return
        if not self.config.get('freeze_safe',False):
            observed_reason=reason+'; recoverable suspension unavailable on this platform'
            if self.reason==observed_reason:return
            self.reason=observed_reason
            self.publish('pressure-observed',self.reason)
            return
        if not self.paused:
            # The session leader remains our direct unreaped child until stop().
            os.killpg(self.process.pid, signal.SIGSTOP)
            self.paused = True
            self.blocked_since = time.time()
            # SIGSTOP delivery to every member must be observed before maintenance
            # may acquire the shared cache fence. Failure leaves the fence held.
            end = time.monotonic()+.5
            while not self.group_stopped() and time.monotonic() < end: time.sleep(.01)
            if self.guard_fd is not None and self.group_stopped():
                fcntl.flock(self.guard_fd, fcntl.LOCK_UN)
                self.guard_released = True
        if self.reason==reason:return
        self.reason = reason
        self.publish('pressure-blocked', reason)

    def _reacquire(self):
        if self.guard_released:
            fcntl.flock(self.guard_fd, fcntl.LOCK_SH)
            self.guard_released = False

    def resume(self):
        if not self.paused or self.stopped: return
        self._reacquire()  # No CONT while an exclusive cache cleaner may be active.
        os.killpg(self.process.pid, signal.SIGCONT)
        self.paused = False
        self.blocked_since = None
        self.reason = None
        self.publish('running')

    def sample(self):
        if self.stopped: return
        free = {}
        try:
            for volume in self.config['volumes']:
                path = Path(volume['path'])
                if path.is_symlink() or path.stat().st_dev != volume['device']:
                    raise OSError('required filesystem identity changed')
                if volume.get('mount_required') and not path.is_mount():
                    raise OSError('required filesystem disappeared')
                free[str(path)] = self.probe(path)
            self.last_free = free
            if self.baseline is None: self.baseline = free.copy()
            for path, available in free.items():
                self.peak_decrease[path] = max(self.peak_decrease.get(path, 0), self.baseline[path]-available, 0)
            threshold = self.config.get('hysteresis_bytes', 16*2**20) if self.paused else 0
            breached = [v['path'] for v in self.config['volumes'] if free[v['path']] < v['reserve']+threshold]
            if breached: self.pause('filesystem reserve pressure: '+','.join(breached))
            elif self.paused: self.resume()
            elif self.reason is not None:
                self.reason=None
                self.publish('running')
        except (OSError, ValueError) as error:
            self.pause('filesystem observation unavailable: '+type(error).__name__)

    def stop(self):
        if self.stopped: return
        self._reacquire()
        # Resume pending termination delivery before any attempt to reap. This
        # process object, never a stored PID, pins our owned session leader.
        try:
            os.killpg(self.process.pid, signal.SIGCONT)
            os.killpg(self.process.pid, signal.SIGTERM)
            time.sleep(.2)
            os.killpg(self.process.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        except PermissionError:
            if not self.group_retired():raise
        self.process.wait(timeout=4)
        self.stopped = True
        self.paused = False
        self.publish('completed')


def controller_main(config, supervisor, inherited):
    """Retain the submitter context and reservation through pressure and frontend loss."""
    stopping = [False]
    guardian_pid = os.getppid()
    signal.signal(signal.SIGTERM, lambda *_: stopping.__setitem__(0, True))
    signal.signal(signal.SIGINT, lambda *_: stopping.__setitem__(0, True))
    controller_lease=Path(config['runtime_file']).with_suffix('.controller')
    descriptor=os.open(controller_lease,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    info=os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077:raise ValueError('unsafe controller lease')
    fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
    # Kept only here; the command/supervisor never inherits this ownership proof.
    start_fd = config.pop('start_fd')
    try:
        while not stopping[0]:
            ready,_,_=select.select([start_fd],[],[],.1)
            if ready:
                if os.read(start_fd,1)!=b'1':return 125
                break
            if os.getppid()!=guardian_pid:return 125
        if stopping[0]:
            atomic_json(config['runtime_file'],dict(config['identity'],version=1,state='completed',no_launch=True,controller_pid=os.getpid(),runtime_group=None))
            return 143
    finally: os.close(start_fd)
    # The inline supervisor waits for its direct controller, not the frontend.
    supervisor[6] = str(os.getpid())
    gate_read, gate_write = os.pipe()
    ready_read, ready_write = os.pipe()
    lifetime_read,lifetime_write=os.pipe()
    environment = dict(os.environ, DISK_JANITOR_START_FD=str(gate_read),
                       DISK_JANITOR_CONTROLLER_READY_FD=str(ready_write),
                       DISK_JANITOR_GUARD_FD=str(config['guard_fd']),
                       DISK_JANITOR_SUPERVISOR_LIFETIME_FD=str(lifetime_write))
    process = subprocess.Popen(supervisor, stdin=None if config.get('foreground_stdio') else subprocess.DEVNULL,
                               env=environment, start_new_session=True,
                               pass_fds=tuple(inherited)+(gate_read,ready_write,lifetime_write))
    os.close(gate_read);os.close(ready_write);os.close(lifetime_write)
    controller = OwnedController(process, config)
    try:
        ready=[]
        end=time.monotonic()+10
        while not ready and time.monotonic()<end and not stopping[0]:
            ready,_,_=select.select([ready_read],[],[],.1)
        if not ready:raise RuntimeError('supervisor readiness cancelled or unavailable')
        proof=os.read(ready_read,1)
        if proof not in (b'0',b'1'):raise RuntimeError('supervisor readiness missing')
        config['freeze_safe']=proof==b'1'
    except BaseException:
        controller.stop()
        raise
    finally:os.close(ready_read)
    controller.publish('running')
    os.write(gate_write, b'1'); os.close(gate_write)
    outcome_path = Path(config['outcome_file'])
    last_recovery = 0
    recovery = None
    try:
        while not stopping[0]:
            control=config.get('control_file')
            cancelled=False
            if control:
                try:
                    path=Path(control)
                    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
                    with os.fdopen(descriptor) as stream:
                        info=os.fstat(stream.fileno());item=json.load(stream)
                    cancelled=(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode&0o077
                               and item.get('backend_job_id')==config['identity']['job_id']
                               and item.get('owner')==config['identity']['owner'] and item.get('cancel_requested') is True)
                except (OSError,ValueError,KeyError):pass
            if cancelled:
                controller.stop()
                atomic_json(config['result_file'],dict(config['identity'],exit_code=143,status='cancelled'))
                while os.getppid()==guardian_pid and not stopping[0]: time.sleep(.05)
                return 143
            if outcome_path.exists():
                if outcome_path.is_symlink(): raise ValueError('unsafe command outcome')
                outcome = json.loads(outcome_path.read_text())
                if any(outcome.get(k) != v for k,v in config['identity'].items() if k in {'owner','command_hash'}):
                    raise ValueError('command outcome identity mismatch')
                controller.stop()
                try:
                    learning=LearningStore(Path(config['runtime_file']).parent.parent/'capacity-history')
                    for device in {v['device'] for v in config['volumes']}:
                        envelope=max(controller.peak_decrease.get(v['path'],0) for v in config['volumes'] if v['device']==device)
                        learning.record(config['learning_key'],device,envelope,successful=outcome['exit_code']==0)
                except (OSError,ValueError,KeyError):pass
                atomic_json(config['result_file'], outcome)
                while os.getppid()==guardian_pid and not stopping[0]: time.sleep(.05)
                return outcome['exit_code']
            ended,_,_=select.select([lifetime_read],[],[],0)
            if ended and os.read(lifetime_read,1)==b'':
                # Never reap before signalling: the direct supervisor leader still
                # pins its group ID. A completed capture can race this EOF check.
                if outcome_path.exists():continue
                controller.stop()
                uncertain=dict(config['identity'],exit_code=125,status='outcome-uncertain',reason='command supervisor exited without a durable outcome')
                atomic_json(config['result_file'],uncertain)
                try:os.write(inherited[0],(json.dumps({'error':uncertain['reason']})+'\n').encode())
                except BrokenPipeError:pass
                while os.getppid()==guardian_pid and not stopping[0]:time.sleep(.05)
                return 125
            controller.sample()
            if recovery is not None and recovery.poll() is not None: recovery=None
            if controller.paused and controller.guard_released and recovery is None and time.monotonic()-last_recovery >= 30:
                last_recovery = time.monotonic()
                module = Path(__file__).with_name('recovery.py')
                # Existing recovery owns classification, activity proof and native
                # deletion. Run it independently so observation/cancellation stays
                # responsive; reacquiring its fence precedes any thaw or teardown.
                recovery = subprocess.Popen([sys.executable, '-B', str(module), '--apply', '--pressure-only',
                              '--report', str(Path(config['runtime_file']).parent.parent/'recovery-last.json')],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(.2)
    finally:
        controller.stop()
        os.close(lifetime_read)
    return 143


if __name__ == '__main__' and sys.argv[1:] == ['storage-root']:
    print(external_storage_root() or '')
elif __name__ == '__main__' and sys.argv[1:] == ['slot-limit']:
    print(slot_limit())
elif __name__ == '__main__':
    raise SystemExit(controller_main(json.loads(sys.argv[1]), json.loads(sys.argv[2]), json.loads(sys.argv[3])))
