"""Shared admission transaction; no command execution or PID based authority.

The native installer owns the binding and snapshot. Broker order is its resource
lock then the bound user's admission mutex; local admission takes only that mutex.
An absent binding is legacy (unjoined) mode. Once joined, uncertainty fails closed.
"""
from contextlib import contextmanager
import fcntl
import json
import math
import os
from pathlib import Path
import re
import stat
import time
import uuid

CONFIG = Path('/Library/Application Support/RunnerPoolsAdmission/config.json')
ACTIVE = {'creating', 'registered', 'busy', 'cleanup', 'cleanup-required'}


class BridgeUnavailable(RuntimeError):
    pass


def _require(value):
    if not value:
        raise BridgeUnavailable('shared RunnerPools admission state is unavailable; commitments preserved')


def _pairs(rows):
    value = {}
    for key, item in rows:
        _require(key not in value)
        value[key] = item
    return value


def _number(value):
    return type(value) in (int, float) and 0 <= value < 2**63 and math.isfinite(value)


def _directory(path, uid):
    info = Path(path).lstat()
    _require(stat.S_ISDIR(info.st_mode) and info.st_uid == uid and not info.st_mode & 0o022)
    return info


def _read(path, uid, limit=262144):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        _require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_nlink == 1
                 and not info.st_mode & 0o022 and info.st_size <= limit)
        value = json.load(stream, object_pairs_hook=_pairs)
        _require(type(value) is dict)
        return value


def _atomic(path, value):
    temporary = path.with_name('.'+path.name+'.'+uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, sort_keys=True)
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)  # Root daemons may inherit umask 077.
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if temporary.exists():
            temporary.unlink()


class UserBridge:
    def __init__(self, *, config_path=CONFIG, root_uid=0, user_uid=None, clock=time.time):
        # Explicit arguments are for imported disposable fixtures. Production
        # callers use the protected fixed path, never environment variables.
        self.path = Path(config_path)
        self.root_uid = root_uid
        self.user_uid = os.getuid() if user_uid is None else user_uid
        self.clock = clock

    def binding(self):
        try:
            _directory(self.path.parent, self.root_uid)
            value = _read(self.path, self.root_uid)
        except FileNotFoundError:
            # A partial activation is joined and must not be mistaken for legacy.
            if self.path.parent.exists():
                raise BridgeUnavailable('shared admission activation is incomplete')
            return None
        _require(set(value) == {'version', 'user_uid', 'guard_home', 'lock_identity', 'state_root'})
        _require(value['version'] == 1 and type(value['user_uid']) is int and value['user_uid'] >= 0)
        for name in ('guard_home', 'state_root'):
            _require(type(value[name]) is str and Path(value[name]).is_absolute()
                     and '..' not in Path(value[name]).parts)
        _require(type(value['lock_identity']) is list and len(value['lock_identity']) == 2
                 and all(type(x) is int and x >= 0 for x in value['lock_identity']))
        return value

    def claims(self, *, guard_home=None):
        try:
            binding = self.binding()
            if binding is None:
                return []
            _require(binding['user_uid'] == self.user_uid)
            if guard_home is not None:
                _require(Path(guard_home) == Path(binding['guard_home']))
            lock = Path(binding['guard_home']) / 'admission.lock'
            info = lock.lstat()
            _require(not stat.S_ISLNK(info.st_mode) and [info.st_dev, info.st_ino] == binding['lock_identity'])
            snapshot = _read(self.path.parent / 'commitments.json', self.root_uid)
            _require(set(snapshot) == {'version', 'updated_at', 'user_uid', 'lock_identity', 'claims'})
            _require(snapshot['version'] == 1 and snapshot['user_uid'] == self.user_uid
                     and snapshot['lock_identity'] == binding['lock_identity'])
            # This is a durable commitment, not a lease. A stopped controller
            # cannot admit another VM without updating it under this mutex.
            # Age never releases a claim or prevents independent safe work.
            _require(_number(snapshot['updated_at']) and 0 <= self.clock()-snapshot['updated_at'])
            _require(type(snapshot['claims']) is list and len(snapshot['claims']) <= 256)
            result, identities = [], set()
            for claim in snapshot['claims']:
                _require(type(claim) is dict and set(claim) == {'profile', 'platform', 'generation', 'device', 'disk_bytes', 'memory_bytes', 'reserve_bytes'})
                _require(type(claim['profile']) is str and re.fullmatch(r'[a-z][a-z0-9-]{0,19}', claim['profile'])
                         and claim['platform'] in ('linux', 'macos') and type(claim['generation']) is str
                         and re.fullmatch(r'[0-9a-f]{32}', claim['generation']))
                _require(all(type(claim[x]) is int and 0 <= claim[x] < 2**63 for x in ('device', 'disk_bytes', 'memory_bytes', 'reserve_bytes')))
                identity = '/'.join(claim[x] for x in ('profile', 'platform', 'generation'))
                _require(identity not in identities)
                identities.add(identity)
                result.append(dict(id='runnerpools:'+identity, owner='RunnerPools '+claim['profile']+'/'+claim['platform'],
                    state='running', memory=claim['memory_bytes'], budget=claim['disk_bytes'], consumed={}, artifact=None,
                    volumes=[dict(path=binding['state_root'], device=claim['device'], budget=claim['disk_bytes'], reserve=claim['reserve_bytes'])]))
            return result
        except (OSError, ValueError, TypeError, KeyError) as error:
            raise BridgeUnavailable('shared RunnerPools admission state is unavailable; commitments preserved') from error


class BrokerBridge(UserBridge):
    """Called only from the protected broker, never a privileged user command."""
    @contextmanager
    def transaction(self, state_root):
        binding = self.binding()
        if binding is None:
            yield None
            return
        _require(Path(binding['state_root']) == Path(state_root))
        home = Path(binding['guard_home'])
        _directory(home, binding['user_uid'])
        fd = os.open(home / 'admission.lock', os.O_RDWR | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            _require(stat.S_ISREG(info.st_mode) and info.st_uid == binding['user_uid'] and info.st_nlink == 1
                     and not info.st_mode & 0o022 and [info.st_dev, info.st_ino] == binding['lock_identity'])
            fcntl.flock(fd, fcntl.LOCK_EX)
            self.current = binding
            self.check_lock()
            yield self
            self.check_lock()
        finally:
            self.current = None
            os.close(fd)

    def check_lock(self):
        info = (Path(self.current['guard_home']) / 'admission.lock').lstat()
        _require(stat.S_ISREG(info.st_mode) and [info.st_dev, info.st_ino] == self.current['lock_identity'])

    def local_claims(self):
        self.check_lock()
        directory = Path(self.current['guard_home']) / 'guard-reservations'
        _directory(directory, self.current['user_uid'])
        paths = list(directory.glob('*.json'))
        _require(len(paths) <= 4096)
        claims = []
        for path in paths:
            item = _read(path, self.current['user_uid'])
            _require(item.get('state') in {'waiting', 'running', 'settling', 'completed', 'cancelled'})
            if item['state'] == 'cancelled':
                # Only the guard's live owned process object can establish
                # teardown. Older/uncertain cancellations retain the full claim.
                if item.get('cancellation_teardown_confirmed') is True:
                    continue
            elif item['state'] != 'running' or item.get('retention_unsettled'):
                continue
            _require(_number(item.get('memory')) and _number(item.get('budget'))
                     and type(item.get('volumes')) is list and len(item['volumes']) <= 64)
            volumes = []
            for volume in item['volumes']:
                _require(type(volume) is dict and type(volume.get('device')) is int and volume['device'] >= 0
                         and _number(volume.get('reserve')) and _number(volume.get('budget', item['budget'])))
                # Do not credit consumption from user metadata: physical free
                # bytes already account for actual allocation. Keep full claim.
                volumes.append(dict(device=volume['device'], reserve=volume['reserve'], budget=volume.get('budget', item['budget'])))
            claims.append(dict(memory=item['memory'], volumes=volumes))
        return claims

    def publish(self, records, device):
        self.check_lock()
        claims = [dict(profile=r['profile_id'], platform=r['platform'], generation=r['generation'], device=device,
                       **{k:r['resources'][k] for k in ('disk_bytes', 'memory_bytes', 'reserve_bytes')})
                  for r in records if r['state'] in ACTIVE]
        _atomic(self.path.parent / 'commitments.json', dict(version=1, updated_at=self.clock(),
                user_uid=self.current['user_uid'], lock_identity=self.current['lock_identity'], claims=claims))
