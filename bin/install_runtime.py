#!/usr/bin/env python3
"""Publish one complete immutable runtime and activate it with one symlink flip."""
import sys
if sys.version_info < (3, 10):
    raise SystemExit('disk-janitor: Python 3.10 or newer is required; this is ' + sys.version.split()[0])
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

COMPONENTS = ('disk-janitor', 'recovery.py', 'jobs.py', 'capacity.py', 'coverage.py',
              'commitments.py', 'install_runtime.py')
COMPONENT_NAME = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}')


def sync_dir(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def safe_dir(path):
    if path.is_symlink():
        raise ValueError('runtime directory must not be a symlink: ' + str(path))
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise ValueError('unsafe runtime directory: ' + str(path))


def read_file(path, source=False):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        allowed = (os.getuid(), 0) if source else (os.getuid(),)
        if not stat.S_ISREG(info.st_mode) or info.st_uid not in allowed or info.st_mode & 0o022:
            raise ValueError('unsafe runtime component: ' + str(path))
        return stream.read(), stat.S_IMODE(info.st_mode)


def write_file(path, data, mode):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
        os.fchmod(stream.fileno(), mode)


def launcher_bytes():
    # Version-independent dispatcher: resolve the activation pointer before the
    # kernel opens any version-dependent CLI body. Never import runtime helpers.
    return b'''#!/usr/bin/env python3
# managed-by: disk-janitor stable runtime dispatcher
import os,re,stat,sys
from pathlib import Path
try:
    home=Path(__file__).resolve(strict=True).parent
    pointer=home/'current'
    info=pointer.lstat()
    if info.st_uid!=os.getuid() or not stat.S_ISLNK(info.st_mode):
        raise RuntimeError('runtime pointer is not an owned symlink')
    target=os.readlink(pointer)
    if re.fullmatch(r'releases/[0-9a-f]{64}',target) is None:
        raise RuntimeError('runtime pointer target is invalid')
    executable=str(home/target/'disk-janitor')
    os.execv(executable,[executable,*sys.argv[1:]])
except (OSError,RuntimeError) as error:
    print('disk-janitor: '+str(error),file=sys.stderr)
    raise SystemExit(1)
'''


def publish_launcher(home):
    destination = home / 'disk-janitor'
    expected = launcher_bytes()
    if not destination.is_symlink() and destination.exists():
        data, mode = read_file(destination)
        if data == expected and mode == 0o555:
            return
    temporary = home / ('.dispatcher-' + uuid.uuid4().hex)
    write_file(temporary, expected, 0o555)
    try:
        os.replace(temporary, destination)
        sync_dir(home)
    finally:
        if temporary.exists():
            temporary.unlink()


def inventory(contents):
    return {name: {'sha256': hashlib.sha256(contents[name]).hexdigest(),
                   'mode': 0o555 if name == 'disk-janitor' else 0o444}
            for name in COMPONENTS}


def release_id(entries):
    return hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def verify_release_directory(path):
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or path.is_symlink()
            or info.st_uid != os.getuid() or info.st_mode & 0o222):
        raise ValueError('unsafe immutable runtime release: ' + str(path))


def verify_release(path, entries):
    verify_release_directory(path)
    if set(p.name for p in path.iterdir()) != set(entries) | {'manifest.json'}:
        raise ValueError('unexpected file in immutable runtime release')
    manifest, mode = read_file(path / 'manifest.json')
    if mode != 0o444 or json.loads(manifest) != {'version': 1, 'components': entries}:
        raise ValueError('runtime release manifest mismatch')
    for name, expected in entries.items():
        data, mode = read_file(path / name)
        if mode != expected['mode'] or hashlib.sha256(data).hexdigest() != expected['sha256']:
            raise ValueError('runtime release checksum or mode mismatch: ' + name)


def stage_release(releases, contents):
    entries = inventory(contents)
    destination = releases / release_id(entries)
    if destination.exists() or destination.is_symlink():
        verify_release(destination, entries)
        return destination
    stage = releases / ('.stage-' + uuid.uuid4().hex)
    stage.mkdir(mode=0o700)
    # An interrupted stage is preserved, never recursively removed as user data.
    for name, data in contents.items():
        write_file(stage / name, data, entries[name]['mode'])
    manifest = (json.dumps({'version': 1, 'components': entries}, sort_keys=True) + '\n').encode()
    write_file(stage / 'manifest.json', manifest, 0o444)
    sync_dir(stage)
    stage.chmod(0o555)
    os.rename(stage, destination)
    sync_dir(releases)
    verify_release(destination, entries)
    return destination


def replace_link(path, target):
    temporary = path.with_name('.' + path.name + '.link-' + uuid.uuid4().hex)
    os.symlink(target, temporary)
    try:
        os.replace(temporary, path)
        sync_dir(path.parent)
    finally:
        if temporary.is_symlink():
            temporary.unlink()


def validate_current(home):
    current = home / 'current'
    if not current.exists() and not current.is_symlink():
        return None
    info = current.lstat()
    if not current.is_symlink() or info.st_uid != os.getuid():
        raise ValueError('runtime current pointer must be an owned symlink')
    target = os.readlink(current)
    if not re.fullmatch(r'releases/[0-9a-f]{64}', target):
        raise ValueError('runtime current symlink has an unexpected target')
    release = home / target
    verify_release_directory(release)
    manifest, _ = read_file(release / 'manifest.json')
    payload = json.loads(manifest)
    # The current release may come from an older version with a different
    # component set; it is verified against its own manifest.
    entries = payload.get('components') if isinstance(payload, dict) else None
    if (not isinstance(entries, dict) or payload.get('version') != 1 or 'disk-janitor' not in entries
            or any(not isinstance(name, str) or not COMPONENT_NAME.fullmatch(name) for name in entries)):
        raise ValueError('invalid current runtime manifest')
    if release.name != release_id(entries):
        raise ValueError('current runtime digest mismatch')
    verify_release(release, entries)
    return release


@contextmanager
def installation_lock(home):
    descriptor = os.open(home / '.runtime-install.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'a') as lock:
        info = os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError('unsafe runtime installation lock')
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def publish(source, home):
    source, home = Path(source).resolve(), Path(home).absolute()
    # Validate every state path before staging or replacing anything.
    safe_dir(home)
    releases = home / 'releases'
    safe_dir(releases)
    safe_dir(home / 'state')
    backups = home / 'state' / 'runtime-backups'
    safe_dir(backups)
    contents = {name: read_file(source / name, source=True)[0] for name in COMPONENTS}
    with installation_lock(home):
        previous = validate_current(home)
        legacy = {}
        for name in COMPONENTS:
            alias = home / name
            if alias.is_symlink():
                if alias.lstat().st_uid != os.getuid() or os.readlink(alias) != 'current/' + name:
                    raise ValueError('unexpected runtime component symlink: ' + name)
                if previous is None:
                    raise ValueError('runtime component alias has no current release: ' + name)
            elif alias.exists():
                data, mode = read_file(alias)
                if name == 'disk-janitor' and data == launcher_bytes():
                    if mode != 0o555:
                        raise ValueError('runtime dispatcher mode differs')
                    continue
                if name == 'disk-janitor' and previous is not None:
                    raise ValueError('unexpected runtime dispatcher content')
                legacy[name] = data
                key = hashlib.sha256(data).hexdigest()
                folder = backups / key
                safe_dir(folder)
                backup = folder / name
                if backup.exists() or backup.is_symlink():
                    saved, _ = read_file(backup)
                    if saved != data:
                        raise ValueError('existing runtime backup differs: ' + name)
                else:
                    write_file(backup, data, mode & 0o777)
                    sync_dir(folder)
        candidate = stage_release(releases, contents)
        if previous is None:
            # First migration: aliases initially serve byte-for-byte legacy
            # components. This prevents partially converting a regular install
            # from mixing helper versions before the final activation flip.
            baseline = stage_release(releases, dict(contents, **legacy))
            replace_link(home / 'current', 'releases/' + baseline.name)
        for name in COMPONENTS:
            if name == 'disk-janitor':
                continue
            alias = home / name
            if not alias.is_symlink():
                replace_link(alias, 'current/' + name)
        publish_launcher(home)
        replace_link(home / 'current', 'releases/' + candidate.name)
        if previous is not None:
            retire_dropped_aliases(home, previous)
        return candidate


def retire_dropped_aliases(home, previous):
    # Aliases of components the active release no longer ships would dangle.
    # Only the installer's own alias form is removed.
    names = json.loads(read_file(previous / 'manifest.json')[0])['components']
    removed = False
    for name in set(names) - set(COMPONENTS):
        alias = home / name
        if (alias.is_symlink() and alias.lstat().st_uid == os.getuid()
                and os.readlink(alias) == 'current/' + name):
            alias.unlink()
            removed = True
    if removed:
        sync_dir(home)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path, help='complete reviewed bin directory')
    parser.add_argument('--home', required=True, type=Path, help='owned installation home')
    args = parser.parse_args()
    try:
        print(publish(args.source, args.home))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print('disk-janitor: runtime installation failed: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
