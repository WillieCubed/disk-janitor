"""Pinned portable Python and a system-shell-only first administrator handoff."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile
import tempfile

from pool_config import Failure, load, paths, require, validate
import process_control as control

RELEASE = '20261013'
VERSION = '3.14.8'
ASSET = 'cpython-3.14.8+20261013-aarch64-apple-darwin-install_only.tar.gz'
SHA256 = '709f419d175eb015f810b68aa54bdae1d776c9824cb362aa701c93b0a9f2a9e7'
URL = 'https://github.com/astral-sh/python-build-standalone/releases/download/'+RELEASE+'/'+ASSET.replace('+', '%2B')


def python_path(profile):
    return paths(profile)['install']/'runtime/python/bin/python3.14'


def _digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024*1024), b''):
            value.update(chunk)
    return value.hexdigest()


def _metadata(path):
    return Path(path).lstat()


def _protected(path, *, directory=False):
    info = _metadata(path)
    require(info.st_uid == 0 and not info.st_mode & 0o022
            and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1),
            'Portable Python path is unsafe: '+json.dumps(str(path))
            +' (uid='+str(info.st_uid)+', mode='+oct(stat.S_IMODE(info.st_mode))+'); preserve it and stop.')
    return info


def _cache_directory():
    return Path.home()/'.cache/runner-pools/python'/RELEASE


def archive(*, allow_download=True):
    require(type(allow_download) is bool, 'Archive download permission must be explicit.')
    directory = _cache_directory()
    if allow_download:
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    else:
        require(directory.is_dir() and not directory.is_symlink(),
                'Pinned portable Python recovery archive is not cached; no tools were downloaded or installed.')
    info = directory.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
            'Portable Python cache must be an owner-private directory.')
    target = directory/ASSET
    try:
        if not allow_download:
            info = target.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o600 and _digest(target) == SHA256,
                    'Pinned portable Python recovery archive differs; preserve it.')
            return target
        with control.file_lock(directory/'.download.lock'):
            if not target.exists() and not target.is_symlink():
                with tempfile.TemporaryDirectory(prefix='download-', dir=directory) as temporary:
                    result = control.run(['gh', 'release', 'download', RELEASE, '--repo', 'astral-sh/python-build-standalone',
                                          '--pattern', ASSET, '--dir', temporary], timeout=300)
                    downloaded = Path(temporary)/ASSET
                    require(result.returncode == 0 and downloaded.is_file() and not downloaded.is_symlink()
                            and _digest(downloaded) == SHA256, 'Pinned official portable Python download failed or differs.')
                    control.atomic_write(target, downloaded.read_bytes(), mode=0o600)
            info = target.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o600 and _digest(target) == SHA256,
                    'Pinned portable Python archive cache differs; preserve it.')
    except (OSError, control.StateError):
        raise Failure('Portable Python cache is unavailable; preserve it and resume setup.') from None
    return target


def _archive_manifest(archive_path):
    require(_digest(archive_path) == SHA256, 'Pinned official portable Python archive digest differs.')
    entries = {}
    try:
        with tarfile.open(archive_path, 'r:gz') as package:
            for member in package.getmembers():
                name = member.name.rstrip('/')
                parts = PurePosixPath(name).parts
                require(re.fullmatch(r'[A-Za-z0-9_./+@=,()-]+', name) and parts and parts[0] == 'python'
                        and str(PurePosixPath(name)) == name and '..' not in parts and name not in entries
                        and not member.mode & 0o7000, 'Portable Python archive has an unsupported path or mode.')
                if member.isdir():
                    entry = {'type': 'directory'}
                elif member.isfile():
                    stream = package.extractfile(member)
                    require(stream is not None, 'Portable Python archive has an unreadable file.')
                    with stream:
                        entry = {'type': 'file', 'sha256': hashlib.file_digest(stream, 'sha256').hexdigest()}
                elif member.issym():
                    # The pinned archive uses sibling-only aliases. Do not expand
                    # root bootstrap's link resolver to arbitrary symlink graphs.
                    require(bool(re.fullmatch(r'[A-Za-z0-9_+.-]+', member.linkname))
                            and member.linkname not in ('.', '..'), 'Portable Python link escapes its pinned sibling namespace.')
                    entry = {'type': 'symlink', 'target': member.linkname}
                else:
                    raise Failure('Portable Python archive contains a special file or hard link.')
                entries[name] = entry
    except (OSError, tarfile.TarError, ValueError):
        raise Failure('Portable Python archive is malformed; preserve it.') from None
    # The official install-only archive omits directory members. Record every
    # parent that the native extractor must create, rejecting file/link parents.
    for name in list(entries):
        for parent in PurePosixPath(name).parents:
            if str(parent) == '.':
                break
            require(entries.setdefault(str(parent), {'type': 'directory'}) == {'type': 'directory'},
                    'Portable Python archive places a member below a file or link.')
    require(entries.get('python') == {'type': 'directory'}
            and entries.get('python/bin/python3.14', {}).get('type') == 'file', 'Portable Python archive lacks its exact interpreter.')
    for name, entry in entries.items():
        parent = str(PurePosixPath(name).parent)
        if name != 'python':
            require(entries.get(parent) == {'type': 'directory'}, 'Portable Python archive omits an exact parent directory.')
        if entry['type'] == 'symlink':
            require(entries.get(str(PurePosixPath(name).parent/entry['target']), {}).get('type') == 'file',
                    'Portable Python alias does not name a pinned sibling file.')
    return dict(schema_version=1, version=VERSION, release=RELEASE, sha256=SHA256, entries=entries)


def verify(profile):
    """Verify every protected runtime entry before reuse; never repair in place."""
    root = paths(profile)['install']/'runtime'
    try:
        for parent in reversed(root.parents):
            _protected(parent, directory=True)
        _protected(root, directory=True)
        receipt_path = root/'runtime.json'
        _protected(receipt_path)
        require(receipt_path.stat().st_size <= 2*1024*1024, 'Portable Python receipt is too large.')
        receipt = json.loads(receipt_path.read_text())
        require(isinstance(receipt, dict) and set(receipt) == {'schema_version', 'version', 'release', 'sha256', 'entries'}
                and type(receipt['schema_version']) is int and receipt['schema_version'] == 1
                and receipt['version'] == VERSION and receipt['release'] == RELEASE and receipt['sha256'] == SHA256
                and isinstance(receipt['entries'], dict)
                and all(isinstance(entry, dict) for entry in receipt['entries'].values()),
                'Portable Python receipt differs from the reviewed pin.')
        actual = set()
        for directory, dirs, files in os.walk(root, followlinks=False):
            for name in dirs+files:
                actual.add(str((Path(directory)/name).relative_to(root)))
        require(actual == set(receipt['entries']) | {'runtime.json'}, 'Portable Python has missing or unknown entries; preserve it.')
        for name, entry in receipt['entries'].items():
            require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_./+@=,()-]+', name)
                    and PurePosixPath(name).parts[0] == 'python' and '..' not in PurePosixPath(name).parts
                    and str(PurePosixPath(name)) == name and isinstance(entry, dict), 'Portable Python receipt path is invalid.')
            path = root/name
            info = _metadata(path)
            kind = entry.get('type')
            if kind == 'symlink':
                require(set(entry) == {'type', 'target'} and info.st_uid == 0 and stat.S_ISLNK(info.st_mode)
                        and isinstance(entry['target'], str) and re.fullmatch(r'[A-Za-z0-9_+.-]+', entry['target'])
                        and entry['target'] not in ('.', '..') and os.readlink(path) == entry['target']
                        and receipt['entries'].get(str(PurePosixPath(name).parent/entry['target']), {}).get('type') == 'file',
                        'Portable Python link differs from its exact internal target.')
            else:
                require(kind in ('file', 'directory') and set(entry) == ({'type', 'sha256'} if kind == 'file' else {'type'}),
                        'Portable Python receipt entry is invalid.')
                _protected(path, directory=kind == 'directory')
                if kind == 'file':
                    require(isinstance(entry['sha256'], str) and re.fullmatch(r'[a-f0-9]{64}', entry['sha256'])
                            and _digest(path) == entry['sha256'], 'Portable Python file differs from its immutable receipt.')
        interpreter = python_path(profile)
        require(interpreter.is_file() and not interpreter.is_symlink() and os.access(interpreter, os.X_OK),
                'Pinned portable Python interpreter is not executable.')
    except (OSError, ValueError, TypeError):
        raise Failure('Portable Python verification failed; preserve its protected installation.') from None
    return {key: receipt[key] for key in ('version', 'release', 'sha256')}


# All variable values are separate argv items. Only system executables run until
# archive, links, complete tree and staged source hashes have been verified.
_OUTER = r'''
set -eu
umask 077
step='validate host namespace'; location='/'
fail() { /usr/bin/printf 'ERROR Portable Python bootstrap failed during %s (%s); preserve state and resume setup.\n' "$step" "$location"; exit 1; }
protect_dir() {
  location=$1
  [ -d "$1" ] && [ ! -L "$1" ] || fail
  [ "$(/usr/bin/stat -f %u "$1")" = 0 ] || fail
  mode=$(/usr/bin/stat -f %Lp "$1")
  [ $((0$mode & 0022)) = 0 ] || fail
}
[ "$(/usr/bin/id -u)" = 0 ] || fail
id=$1; inner=$2; shift 2
case "$id" in ''|*[!a-z0-9-]*|-*|*-|*--*) fail;; esac
case "$id" in [a-z]*) :;; *) fail;; esac
[ ${#id} -le 20 ] || fail
base='/Library/Application Support/RunnerPools'
for directory in / /Library '/Library/Application Support'; do protect_dir "$directory"; done
if [ ! -e "$base" ] && [ ! -L "$base" ]; then /bin/mkdir -m 755 "$base"; fi
protect_dir "$base"
install="$base/$id"
if [ ! -e "$install" ] && [ ! -L "$install" ]; then /bin/mkdir -m 755 "$install"; fi
protect_dir "$install"
lock="$install/.bootstrap.lock"
if [ ! -e "$lock" ] && [ ! -L "$lock" ]; then (set -C; : > "$lock") || fail; fi
[ -f "$lock" ] && [ ! -L "$lock" ] && [ "$(/usr/bin/stat -f %u:%Lp:%l "$lock")" = '0:600:1' ] || fail
exec /usr/bin/lockf -k -s -t 0 "$lock" /bin/sh -c "$inner" runner-pools-locked "$install" "$@"
'''

_INNER = r'''
set -eu
umask 077
trap 'echo "ERROR Portable Python bootstrap interrupted; preserve state and resume the same setup."; exit 130' INT
trap 'echo "ERROR Portable Python bootstrap interrupted; preserve state and resume the same setup."; exit 143' TERM
trap 'echo "ERROR Portable Python bootstrap interrupted; preserve state and resume the same setup."; exit 129' HUP
install=$1; identity=$2; owner=$3; archive_hash=$4; bundle=$5
step='validate private staging'; location=$install
fail() { /usr/bin/printf 'ERROR Portable Python bootstrap failed during %s (%s); preserve state and resume setup.\n' "$step" "$location"; exit 1; }
stage="$install/.bootstrap-$identity"
protect() {
  location=$1
  [ ! -L "$1" ] && [ "$(/usr/bin/stat -f %u "$1")" = 0 ] || fail
  mode=$(/usr/bin/stat -f %Lp "$1")
  [ $((0$mode & 0022)) = 0 ] || fail
}
if [ ! -e "$stage" ] && [ ! -L "$stage" ]; then /bin/mkdir -m 700 "$stage"; fi
[ -d "$stage" ] || fail; protect "$stage"
[ "$(/usr/bin/stat -f %Lp "$stage")" = 700 ] || fail
copy_checked() {
  source=$1; target=$2; expected=$3
  step='copy and hash pinned inputs'; location=$target
  if [ -e "$target" ] || [ -L "$target" ]; then
    [ -f "$target" ] || fail; protect "$target"
    [ "$(/usr/bin/stat -f %l "$target")" = 1 ] || fail
    actual=$(/usr/bin/shasum -a 256 "$target"); actual=${actual%% *}
    [ "$actual" = "$expected" ] || fail
  else
    temporary=$(/usr/bin/mktemp "$stage/.copy.XXXXXXXX")
    /bin/cat "$source" > "$temporary" || fail
    actual=$(/usr/bin/shasum -a 256 "$temporary"); actual=${actual%% *}
    [ "$actual" = "$expected" ] || fail
    /bin/chmod 644 "$temporary"
    /bin/mv "$temporary" "$target"
  fi
}
'''  # Exact, captured snapshot hashes are appended as literal validated hex/name pairs.

_FINISH = r'''
copy_checked "$bundle/python.tar.gz" "$stage/python.tar.gz" "$archive_hash"
check_tree() {
  runtime=$1
  step='verify complete Python tree'; location=$runtime
  [ -d "$runtime" ] || fail; protect "$runtime"
  [ -f "$runtime/runtime.json" ] || fail; protect "$runtime/runtime.json"
  /usr/bin/cmp -s "$runtime/runtime.json" "$stage/runtime.json" || fail
  location=$runtime
  actual_entries=$(/usr/bin/mktemp "$stage/.entries.XXXXXXXX")
  (cd "$runtime" && /usr/bin/find . -print | /usr/bin/sed -e '/^\.$/d' -e 's|^\./||' | LC_ALL=C /usr/bin/sort) > "$actual_entries"
  /usr/bin/cmp -s "$actual_entries" "$stage/runtime.entries" || fail
  bad=$(/usr/bin/find "$runtime" ! -type l \( ! -user root -o -perm -0020 -o -perm -0002 \) -print)
  [ -z "$bad" ] || fail
  while IFS= read -r directory; do [ -d "$runtime/$directory" ] && [ ! -L "$runtime/$directory" ] || fail; done < "$stage/runtime.directories"
  while read -r expected path; do
    [ -L "$runtime/$path" ] && [ "$(/usr/bin/readlink "$runtime/$path")" = "$expected" ] || fail
    [ "$(/usr/bin/stat -f %u "$runtime/$path")" = 0 ] || fail
  done < "$stage/runtime.links"
  while read -r expected path; do
    [ -f "$runtime/$path" ] && [ ! -L "$runtime/$path" ] && [ "$(/usr/bin/stat -f %l "$runtime/$path")" = 1 ] || fail
  done < "$stage/runtime.sha256"
  (cd "$runtime" && /usr/bin/shasum -a 256 -c "$stage/runtime.sha256") >/dev/null 2>&1 || fail
  [ -x "$runtime/python/bin/python3.14" ] || fail
}
runtime="$install/runtime"
if [ -e "$runtime" ] || [ -L "$runtime" ]; then
  check_tree "$runtime"
else
  step='validate pinned archive paths'; location="$stage/python.tar.gz"
  listing=$(/usr/bin/mktemp "$stage/.listing.XXXXXXXX")
  /usr/bin/tar -tzf "$stage/python.tar.gz" > "$listing" || fail
  /usr/bin/awk '/^\// {exit 1} !/^python(\/|$)/ {exit 1} {n=split($0,a,"/"); for(i=1;i<=n;i++) if(a[i]=="..") exit 1}' "$listing" || fail
  extraction=$(/usr/bin/mktemp -d "$stage/.extract.XXXXXXXX")
  step='extract pinned Python'; location=$extraction
  /usr/bin/tar -xzf "$stage/python.tar.gz" -C "$extraction" --no-same-owner || fail
  /usr/bin/find "$extraction" -type d -exec /bin/chmod 755 '{}' +
  /usr/bin/find "$extraction" -type f -exec /bin/chmod go-w '{}' +
  /bin/cp "$stage/runtime.json" "$extraction/runtime.json"
  /bin/chmod 644 "$extraction/runtime.json"
  check_tree "$extraction"
  /bin/mv "$extraction" "$install/runtime"
fi
check_tree "$install/runtime"
exec "$install/runtime/python/bin/python3.14" -I -B "$stage/runner_pool.py" host-control --operation install --profile "$stage/profile.json" --tart-archive "$stage/tart.tar.gz" --owner-home "$owner"
'''


@contextmanager
def bootstrap(profile, source, snapshot, tart_archive, python_archive, owner_home, payload, *, repair_runtime=False, recover_blocked=False):
    """Snapshot unprivileged inputs and yield an argv valid only in this context."""
    require(type(repair_runtime) is bool, 'Runtime repair permission must be an explicit boolean.')
    require(type(recover_blocked) is bool and (not recover_blocked or repair_runtime),
            'Blocked runner recovery requires explicit reviewed runtime repair.')
    profile = validate(profile)
    require(isinstance(payload, (tuple, list)) and payload and len(payload) == len(set(payload))
            and 'runner_pool.py' in payload and all(isinstance(name, str) and re.fullmatch(r'[a-z][a-z0-9_]*\.py', name)
                                                  for name in payload), 'Bootstrap payload must contain exact trusted Python filenames.')
    require(load(snapshot) == profile, 'Bootstrap snapshot differs from the selected organization profile.')
    require(Path(owner_home).is_absolute() and '\n' not in str(owner_home), 'Bootstrap requires an exact operator home.')
    manifest = _archive_manifest(python_archive)
    if recover_blocked:
        verify(profile)  # This path cannot extract or replace a missing interpreter.
    python_raw = Path(python_archive).read_bytes()
    require(hashlib.sha256(python_raw).hexdigest() == SHA256, 'Portable Python changed while taking its bootstrap snapshot.')
    with tempfile.TemporaryDirectory(prefix='runner-pools-bootstrap-') as temporary:
        bundle = Path(temporary)
        contents = {name: (Path(source)/name).read_bytes() for name in payload}
        contents.update({'profile.json': (json.dumps(profile, sort_keys=True)+'\n').encode(),
                         'tart.tar.gz': Path(tart_archive).read_bytes(),
                         'runtime.json': (json.dumps(manifest, sort_keys=True)+'\n').encode(),
                         'runtime.entries': ''.join(name+'\n' for name in sorted([*manifest['entries'], 'runtime.json'])).encode(),
                         'runtime.directories': ''.join(name+'\n' for name, item in sorted(manifest['entries'].items())
                                                       if item['type'] == 'directory').encode(),
                         'runtime.links': ''.join(item['target']+' '+name+'\n' for name, item in sorted(manifest['entries'].items())
                                                 if item['type'] == 'symlink').encode(),
                         'runtime.sha256': ''.join(item['sha256']+'  '+name+'\n' for name, item in sorted(manifest['entries'].items())
                                                  if item['type'] == 'file').encode()})
        # Bind explicit repair intent into the root-verified bootstrap identity.
        if repair_runtime:
            contents['repair-request.json'] = (b'{"repair_runtime":true,"recover_blocked":true}\n' if recover_blocked
                                               else b'{"repair_runtime":true}\n')
        if recover_blocked:
            # Operator bundle, protected snapshot and a full atomic-copy scratch
            # allowance, including filesystem blocks for the known metadata files.
            block = max(os.statvfs(bundle).f_frsize, os.statvfs(paths(profile)['install']).f_frsize)
            inputs = sum((len(blob)+block-1)//block*block+block for blob in [*contents.values(), python_raw])
            available = min(shutil.disk_usage(bundle).free, shutil.disk_usage(paths(profile)['install']).free)
            require(available >= 3*inputs,
                    'There is not enough disk space for the bounded recovery snapshot; existing runners were preserved.')
        hashes = {name: hashlib.sha256(content).hexdigest() for name, content in contents.items()}
        identity = hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()
        for name, content in contents.items():
            control.atomic_write(bundle/name, content, mode=0o600)
        control.atomic_write(bundle/'python.tar.gz', python_raw, mode=0o600)
        require(_digest(bundle/'python.tar.gz') == SHA256, 'Portable Python changed while taking its bootstrap snapshot.')
        copies = '\n'.join('copy_checked "$bundle/'+name+'" "$stage/'+name+'" '+digest
                           for name, digest in sorted(hashes.items()))
        finish = _FINISH.rstrip() + (' --repair-runtime' if repair_runtime else '') \
            + (' --recover-blocked' if recover_blocked else '') + '\n'
        inner = _INNER+'\n'+copies+'\n'+finish
        yield ['/usr/bin/sudo', '-n', '/usr/bin/env', '-i', 'PATH=/usr/bin:/bin:/usr/sbin:/sbin',
               '/bin/sh', '-c', _OUTER, 'runner-pools-bootstrap', profile['id'], inner,
               identity, str(owner_home), SHA256, str(bundle)]
