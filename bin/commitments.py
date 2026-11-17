"""Shared admission with external work brokers: a file protocol, no command execution.

A broker that starts its own work on this machine (a CI runner pool, a VM host)
registers as a provider. disk-janitor counts the provider's published commitments
against its own admission, and the provider can count disk-janitor's running jobs
against its admission, both under disk-janitor's admission lock. The protocol is
specified in docs/admission-protocol.md.

No registry means independent admission. Once a provider is registered, missing,
malformed, replaced or future-dated state makes that provider unavailable: its
commitments are preserved rather than silently released.
"""
from contextlib import contextmanager
import fcntl
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
import uuid

VERSION = 1
REGISTRY = Path('/Library/Application Support/disk-janitor/providers' if sys.platform == 'darwin'
                else '/var/lib/disk-janitor/providers')
PROVIDER_NAME = re.compile(r'[a-z][a-z0-9-]{0,31}')
CLAIM_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}')
MAX_CLAIMS = 256


class ProviderUnavailable(RuntimeError):
    pass


def _require(value, provider='provider'):
    if not value:
        raise ProviderUnavailable(f'{provider} admission state is unavailable; its commitments are preserved')


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


def write_atomic(path, value):
    """Publish one JSON document readable by the user even under a private daemon umask."""
    path = Path(path)
    temporary = path.with_name('.' + path.name + '.' + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, sort_keys=True)
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
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


class Commitments:
    """disk-janitor's side: read every registered provider's commitments for this user."""

    def __init__(self, *, registry=REGISTRY, owner_uid=0, user_uid=None, clock=time.time):
        # Explicit arguments exist for disposable test fixtures. Production callers use
        # the fixed root-owned registry, never an environment variable.
        self.registry = Path(registry)
        self.owner_uid = owner_uid
        self.user_uid = os.getuid() if user_uid is None else user_uid
        self.clock = clock

    def providers(self):
        try:
            _directory(self.registry, self.owner_uid)
            names = sorted(entry.name for entry in self.registry.iterdir())
        except FileNotFoundError:
            return []
        except OSError as error:
            raise ProviderUnavailable('the provider registry is unreadable') from error
        return [name for name in names if PROVIDER_NAME.fullmatch(name)]

    def binding(self, provider):
        directory = self.registry / provider
        try:
            _directory(directory, self.owner_uid)
            value = _read(directory / 'binding.json', self.owner_uid)
        except FileNotFoundError:
            # A registered provider without a binding is a partial activation, not absent.
            raise ProviderUnavailable(f'{provider} registration is incomplete')
        except (OSError, ValueError) as error:
            raise ProviderUnavailable(f'{provider} binding is unreadable') from error
        _require(set(value) == {'version', 'provider', 'user_uid', 'guard_home', 'lock_identity'}, provider)
        _require(value['version'] == VERSION and value['provider'] == provider, provider)
        _require(type(value['user_uid']) is int and value['user_uid'] >= 0, provider)
        _require(type(value['guard_home']) is str and Path(value['guard_home']).is_absolute()
                 and '..' not in Path(value['guard_home']).parts, provider)
        _require(type(value['lock_identity']) is list and len(value['lock_identity']) == 2
                 and all(type(x) is int and x >= 0 for x in value['lock_identity']), provider)
        return value

    def claims(self, *, guard_home=None):
        """Every bound provider's commitments for this user, as admission records.

        Raises ProviderUnavailable naming the first provider whose state cannot be
        trusted; callers decide whether to proceed without that provider's claims.
        """
        result = []
        for provider in self.providers():
            result.extend(self.provider_claims(provider, guard_home=guard_home))
        return result

    def gather(self, *, guard_home=None):
        """Claims from every trustworthy provider, and a message for each one that is not."""
        result, problems = [], []
        try:
            providers = self.providers()
        except ProviderUnavailable as error:
            return [], [str(error)]
        for provider in providers:
            try:
                result.extend(self.provider_claims(provider, guard_home=guard_home))
            except ProviderUnavailable as error:
                problems.append(str(error))
        return result, problems

    def provider_claims(self, provider, *, guard_home=None):
        try:
            binding = self.binding(provider)
            if binding['user_uid'] != self.user_uid:
                return []  # Bound to another account's disk-janitor.
            if guard_home is not None:
                _require(Path(guard_home) == Path(binding['guard_home']), provider)
            info = (Path(binding['guard_home']) / 'admission.lock').lstat()
            _require(not stat.S_ISLNK(info.st_mode) and [info.st_dev, info.st_ino] == binding['lock_identity'], provider)
            snapshot = _read(self.registry / provider / 'commitments.json', self.owner_uid)
            _require(set(snapshot) == {'version', 'provider', 'updated_at', 'user_uid', 'lock_identity', 'claims'}, provider)
            _require(snapshot['version'] == VERSION and snapshot['provider'] == provider
                     and snapshot['user_uid'] == self.user_uid and snapshot['lock_identity'] == binding['lock_identity'], provider)
            # A commitment is durable, not a lease: age never releases it.
            _require(_number(snapshot['updated_at']) and 0 <= self.clock() - snapshot['updated_at'], provider)
            _require(type(snapshot['claims']) is list and len(snapshot['claims']) <= MAX_CLAIMS, provider)
            result, identities = [], set()
            for claim in snapshot['claims']:
                _require(type(claim) is dict and set(claim) == {'id', 'label', 'device', 'disk_bytes', 'memory_bytes',
                                                                'reserve_bytes', 'path'}, provider)
                _require(type(claim['id']) is str and CLAIM_ID.fullmatch(claim['id']) and claim['id'] not in identities, provider)
                _require(type(claim['label']) is str and 0 < len(claim['label']) <= 80, provider)
                _require(type(claim['path']) is str and Path(claim['path']).is_absolute(), provider)
                _require(all(type(claim[x]) is int and 0 <= claim[x] < 2**63
                             for x in ('device', 'disk_bytes', 'memory_bytes', 'reserve_bytes')), provider)
                identities.add(claim['id'])
                result.append(dict(id=provider + ':' + claim['id'], owner=provider + ' ' + claim['label'],
                                   state='running', memory=claim['memory_bytes'], budget=claim['disk_bytes'],
                                   consumed={}, artifact=None,
                                   volumes=[dict(path=claim['path'], device=claim['device'],
                                                 budget=claim['disk_bytes'], reserve=claim['reserve_bytes'])]))
            return result
        except ProviderUnavailable:
            raise
        except (OSError, ValueError, TypeError, KeyError) as error:
            raise ProviderUnavailable(f'{provider} admission state is unavailable; its commitments are preserved') from error


class Provider(Commitments):
    """A broker's side, run by the broker as the registry owner, never by a user command."""

    def __init__(self, name, **options):
        super().__init__(**options)
        _require(PROVIDER_NAME.fullmatch(name))
        self.name = name
        self.current = None

    @contextmanager
    def transaction(self):
        """Hold disk-janitor's admission lock for one admission decision.

        Lock order: the broker's own resource lock first, then this one. Yields None
        when the provider is not bound, meaning independent admission.
        """
        try:
            binding = self.binding(self.name)
        except ProviderUnavailable:
            if not (self.registry / self.name).exists():
                yield None
                return
            raise
        home = Path(binding['guard_home'])
        _directory(home, binding['user_uid'])
        fd = os.open(home / 'admission.lock', os.O_RDWR | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            _require(stat.S_ISREG(info.st_mode) and info.st_uid == binding['user_uid'] and info.st_nlink == 1
                     and not info.st_mode & 0o022 and [info.st_dev, info.st_ino] == binding['lock_identity'], self.name)
            fcntl.flock(fd, fcntl.LOCK_EX)
            self.current = binding
            self._check_lock()
            yield self
            self._check_lock()
        finally:
            self.current = None
            os.close(fd)

    def _check_lock(self):
        info = (Path(self.current['guard_home']) / 'admission.lock').lstat()
        _require(stat.S_ISREG(info.st_mode) and [info.st_dev, info.st_ino] == self.current['lock_identity'], self.name)

    def local_claims(self):
        """disk-janitor's admitted, running jobs: memory and per-device disk they hold."""
        self._check_lock()
        directory = Path(self.current['guard_home']) / 'guard-reservations'
        _directory(directory, self.current['user_uid'])
        paths = list(directory.glob('*.json'))
        _require(len(paths) <= 4096, self.name)
        claims = []
        for path in paths:
            item = _read(path, self.current['user_uid'])
            _require(item.get('state') in {'waiting', 'running', 'settling', 'completed', 'cancelled'}, self.name)
            if item['state'] == 'cancelled':
                # Only confirmed teardown releases a cancelled job's claim.
                if item.get('cancellation_teardown_confirmed') is True:
                    continue
            elif item['state'] != 'running' or item.get('retention_unsettled'):
                continue
            _require(_number(item.get('memory')) and _number(item.get('budget'))
                     and type(item.get('volumes')) is list and len(item['volumes']) <= 64, self.name)
            volumes = []
            for volume in item['volumes']:
                _require(type(volume) is dict and type(volume.get('device')) is int and volume['device'] >= 0
                         and _number(volume.get('reserve')) and _number(volume.get('budget', item['budget'])), self.name)
                volumes.append(dict(device=volume['device'], reserve=volume['reserve'],
                                    budget=volume.get('budget', item['budget'])))
            claims.append(dict(memory=item['memory'], volumes=volumes))
        return claims

    def publish(self, claims):
        """Replace this provider's commitments; publish before committing the work they cover."""
        self._check_lock()
        write_atomic(self.registry / self.name / 'commitments.json',
                     dict(version=VERSION, provider=self.name, updated_at=self.clock(),
                          user_uid=self.current['user_uid'], lock_identity=self.current['lock_identity'],
                          claims=list(claims)))

    def bind(self, guard_home, user_uid):
        """Register this provider against one user's disk-janitor home (run once at setup)."""
        lock = Path(guard_home) / 'admission.lock'
        info = lock.lstat()
        _require(stat.S_ISREG(info.st_mode) and info.st_uid == user_uid, self.name)
        directory = self.registry / self.name
        directory.mkdir(mode=0o755, parents=True, exist_ok=True)
        _directory(directory, self.owner_uid)
        identity = [info.st_dev, info.st_ino]
        # Commitments first: a binding without a snapshot would read as incomplete.
        write_atomic(directory / 'commitments.json', dict(version=VERSION, provider=self.name, updated_at=self.clock(),
                                                          user_uid=user_uid, lock_identity=identity, claims=[]))
        write_atomic(directory / 'binding.json', dict(version=VERSION, provider=self.name, user_uid=user_uid,
                                                      guard_home=str(guard_home), lock_identity=identity))
