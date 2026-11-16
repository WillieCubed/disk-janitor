#!/usr/bin/env python3
"""Discover disposable compiler caches; never require per-path approvals."""
import argparse
import ctypes
import errno
import shlex
import sys
from contextlib import ExitStack
import fcntl
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import time
import uuid


def _darwin_argv(raw):
    """Decode KERN_PROCARGS2 without losing spaces or reading environment values."""
    if len(raw) < 5:
        raise ValueError('short process argument record')
    count = int.from_bytes(raw[:4], sys.byteorder, signed=True)
    if count < 1 or count > len(raw):
        raise ValueError('invalid process argument count')
    start = raw.find(b'\0', 4)
    if start < 0:
        raise ValueError('missing process executable terminator')
    while start < len(raw) and raw[start] == 0:
        start += 1
    argv = []
    for _ in range(count):
        end = raw.find(b'\0', start)
        if end < 0:
            raise ValueError('truncated process arguments')
        argv.append(os.fsdecode(raw[start:end]))
        start = end + 1
    return argv

def _process_executable(pid):
    if sys.platform == 'darwin':
        library = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
        library.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        library.proc_pidpath.restype = ctypes.c_int
        buffer = ctypes.create_string_buffer(4096)
        if library.proc_pidpath(pid, buffer, len(buffer)) <= 0:
            error = ctypes.get_errno() or errno.EIO
            raise OSError(error, 'cannot inspect process executable')
        return os.fsdecode(buffer.value)
    if sys.platform.startswith('linux'):
        return os.readlink('/proc/' + str(pid) + '/exe').removesuffix(' (deleted)')
    raise OSError('unsupported process inspection platform')

def _process_argv(pid):
    if sys.platform == 'darwin':
        library = ctypes.CDLL(None, use_errno=True)
        library.sysctl.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.c_uint,
                                   ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
                                   ctypes.c_void_p, ctypes.c_size_t]
        library.sysctl.restype = ctypes.c_int
        # CTL_KERN, KERN_PROCARGS2. The kernel provides the required buffer size.
        mib = (ctypes.c_int * 3)(1, 49, pid)
        size = ctypes.c_size_t(0)
        if library.sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0:
            raise OSError(ctypes.get_errno(), 'cannot size process arguments')
        if size.value < 5 or size.value > 16 * 1024 * 1024:
            raise ValueError('invalid process argument buffer size')
        buffer = ctypes.create_string_buffer(size.value)
        if library.sysctl(mib, 3, buffer, ctypes.byref(size), None, 0) != 0:
            raise OSError(ctypes.get_errno(), 'cannot inspect process arguments')
        return _darwin_argv(buffer.raw[:size.value])
    if sys.platform.startswith('linux'):
        raw = Path('/proc/' + str(pid) + '/cmdline').read_bytes()
        if not raw or not raw.endswith(b'\0'):
            raise ValueError('missing process arguments')
        return [os.fsdecode(arg) for arg in raw[:-1].split(b'\0')]
    raise OSError('unsupported process inspection platform')

def _process_exited(pid):
    """Only established exit/zombie state permits ignoring an inspection race."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    if sys.platform.startswith('linux'):
        try:
            state = Path('/proc/' + str(pid) + '/stat').read_text().rsplit(')', 1)[1].split()[0]
            return state in ('Z', 'X')
        except FileNotFoundError:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return True
        except (OSError, IndexError):
            pass
    elif sys.platform == 'darwin':
        state = subprocess.run(['ps', '-p', str(pid), '-o', 'stat='],
                               capture_output=True, text=True, timeout=5)
        if state.returncode == 0 and state.stdout.strip().startswith('Z'):
            return True
        if state.returncode == 1 and not state.stdout.strip() and not state.stderr.strip():
            return True
    return False

def _java_build_active(argv):
    """Inspect the launcher entrypoint, never a classpath/property/application arg."""
    mains = {'org.gradle.launcher.daemon.bootstrap.GradleDaemon',
             'org.gradle.wrapper.GradleWrapperMain', 'org.gradle.launcher.GradleMain',
             'org.gradle.launcher.bootstrap.GradleMain',
             'org.gradle.process.internal.worker.GradleWorkerMain',
             'worker.org.gradle.process.internal.worker.GradleWorkerMain',
             'org.jetbrains.kotlin.daemon.KotlinCompileDaemon'}
    paired = {'-cp', '-classpath', '--class-path', '-p', '--module-path',
              '--upgrade-module-path', '--add-modules', '--limit-modules',
              '--add-exports', '--add-opens', '--add-reads', '--patch-module',
              '--enable-native-access', '--source', '--describe-module', '-d'}
    index = 1
    while index < len(argv):
        argument = argv[index]
        if argument.startswith('@'):
            # Java expands response files before selecting its entrypoint, so the
            # entrypoint cannot be read from argv. Gradle starts every worker this
            # way. Count the process as an active build: Gradle caches stay
            # protected, and other categories remain reclaimable.
            return True
        if argument in ('-jar', '-m', '--module'):
            if index + 1 >= len(argv):
                raise ValueError('missing Java entrypoint')
            target = argv[index + 1]
            if argument == '-jar':
                return bool(re.fullmatch(r'gradle-(?:wrapper|launcher)(?:-[0-9][\w.+-]*)?\.jar',
                                         os.path.basename(target)))
            return target.partition('/')[2] in mains
        if argument.startswith('--module='):
            return argument.partition('=')[2].partition('/')[2] in mains
        if argument in paired:
            if index + 1 >= len(argv):
                raise ValueError('missing Java option value')
            index += 2
            continue
        if argument in ('-version', '--version', '-help', '--help', '-?', '--list-modules'):
            return False
        if argument == '--':
            index += 1
            return index < len(argv) and argv[index] in mains
        if argument.startswith('-'):
            index += 1
            continue
        return argument in mains
    return False

def _native_activity_family(executable):
    name = os.path.basename(executable)
    if name in ('cargo', 'rustc'):
        return 'cargo'
    if name in ('gradle', 'gradlew'):
        return 'gradle'
    if name in ('xcodebuild', 'swift-frontend', 'swiftc', 'XCBBuildService'):
        return 'xcode'
    return None

def activity():
    # comm is an executable field, used only to enumerate owned PIDs. Full command
    # strings flatten argv boundaries and let queued guardians impersonate builds.
    processes = subprocess.run(['ps', '-axo', 'uid=,pid=,comm='],
                               capture_output=True, text=True, timeout=15, check=True)
    commands = []
    for line in processes.stdout.splitlines():
        fields = line.strip().split(None, 2)
        if len(fields) != 3:
            raise RuntimeError('process listing is incomplete; caches preserved')
        if fields[0] != str(os.getuid()):
            continue
        pid = int(fields[1])
        try:
            try:
                executable = _process_executable(pid)
            except FileNotFoundError:
                # macOS proc_pidpath cannot resolve a still-running app whose
                # binary was replaced by an update. ps comm remains the actual
                # executable name, with spaces intact, never its future argv.
                # Restrict this fallback to unambiguous unrelated executables.
                comm = fields[2]
                if (sys.platform != 'darwin' or not os.path.isabs(comm) or
                        _native_activity_family(comm) or os.path.basename(comm) == 'java'):
                    raise
                executable = comm
            family = _native_activity_family(executable)
            if os.path.basename(executable) == 'java':
                argv = _process_argv(pid)
                if _process_executable(pid) != executable:
                    raise ValueError('process changed executable during inspection')
                family = 'gradle' if _java_build_active(argv) else None
            # Never return argv, properties, environment values, or classpaths.
            commands.append(dict(pid=pid, executable=executable, family=family))
        except (OSError, ValueError) as error:
            if not _process_exited(pid):
                raise RuntimeError('process inspection failed; caches preserved') from error
    opened = subprocess.run(['lsof', '-nP', '-a', '-u', str(os.getuid()), '-Fpn'],
                            capture_output=True, text=True, timeout=30)
    if opened.returncode not in (0, 1) or opened.stderr.strip():
        raise RuntimeError('activity inspection failed; caches preserved')
    return commands, [line[1:].removesuffix(' (deleted)')
                      for line in opened.stdout.splitlines() if line.startswith('n/')]

def busy(kind, path, commands, opened):
    family = 'cargo' if kind.startswith('cargo-') else 'gradle' if kind.startswith('gradle-') else 'xcode'
    for command in commands:
        if isinstance(command, dict):
            if command.get('family') == family:
                return True
            continue
        # Compatibility for deterministic existing observers. These are supplied
        # command strings, never the lossy output of ps used for live Java argv.
        try:
            argv = shlex.split(command)
        except ValueError:
            raise RuntimeError('observer command is ambiguous; caches preserved')
        if not argv:
            continue
        observed = _native_activity_family(argv[0])
        if os.path.basename(argv[0]) == 'java':
            observed = 'gradle' if _java_build_active(argv) else None
        if observed == family:
            return True
    return any(p == str(path) or p.startswith(str(path) + '/') for p in opened)

# Cache discovery and validation remain restricted to known generated layouts.
OBJECT_MAGIC = (b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xce\xfa\xed\xfe',
                b'\x7fELF', b'BC\xc0\xde', b'\xde\xc0\x17\x0b')
PROTECTED_SUFFIXES = {'.rs', '.swift', '.kt', '.java', '.c', '.cpp', '.h', '.m', '.mm',
    '.py', '.js', '.jsx', '.ts', '.tsx', '.go', '.rb', '.sh', '.bash', '.zsh', '.cc', '.hpp',
    '.cs', '.html', '.css', '.toml', '.yaml', '.yml', '.sqlite', '.sqlite3', '.sqlite-wal',
    '.sqlite-shm', '.db', '.db-wal', '.db-shm', '.rdb', '.mdb', '.key', '.pem', '.p12',
    '.pfx', '.jks', '.keystore'}


def _plain(path, directory=False):
    try:
        info = path.lstat()
        return info.st_uid == os.getuid() and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
    except FileNotFoundError:
        return False


def _cargo_profiles(cargo):
    for entry in cargo.iterdir():
        if not _plain(entry, True):
            continue
        proven = _plain(entry / '.cargo-lock') and _plain(entry / '.fingerprint', True)
        if entry.name in ('debug', 'release') or proven:
            yield entry
        else:
            for profile in entry.iterdir():
                if _plain(profile, True) and (profile.name in ('debug', 'release') or
                        (_plain(profile / '.cargo-lock') and _plain(profile / '.fingerprint', True))):
                    yield profile


def candidates(home):
    cargo = home / '.cache/cargo-target'
    if _plain(cargo, True):
        for profile in _cargo_profiles(cargo):
            incremental = profile / 'incremental'
            if _plain(incremental, True):
                for unit in incremental.iterdir():
                    if _plain(unit, True):
                        yield 'cargo-incremental', unit
            deps = profile / 'deps'
            if (_plain(profile / '.cargo-lock') and _plain(profile / '.fingerprint', True)
                    and _plain(deps, True)):
                for path in deps.iterdir():
                    if path.suffix in ('.o', '.rlib', '.rmeta') and _plain(path):
                        yield 'cargo-object', path
    caches = home / '.gradle/caches'
    if _plain(caches, True):
        for root in caches.glob('build-cache-*'):
            if re.fullmatch(r'build-cache-[0-9]+', root.name) and _plain(root, True):
                # Gradle task keys are independent regenerable units. Unknown
                # entries, metadata and lock files remain in the cache root.
                for entry in root.iterdir():
                    if re.fullmatch(r'[0-9a-f]{32}(?:[0-9a-f]{32})?', entry.name) and _plain(entry):
                        yield 'gradle-build-cache', entry
        for version in caches.iterdir():
            if not re.fullmatch(r'\d+(?:\.\d+)+(?:[-.][A-Za-z0-9]+)*', version.name) or not _plain(version, True):
                continue
            transforms = version / 'transforms'
            if not _plain(transforms, True):
                continue
            for unit in transforms.iterdir():
                if (re.fullmatch(r'[0-9a-f]{32}', unit.name) and _plain(unit, True)
                        and _plain(unit / 'metadata.bin') and _plain(unit / 'results.bin')
                        and _plain(unit / 'transformed', True)):
                    yield 'gradle-transform', unit
    derived = home / 'Library/Developer/Xcode/DerivedData'
    if _plain(derived, True):
        for path in derived.iterdir():
            if path.name.endswith('.noindex') or path.name == 'SDKExplicitPrecompiledModules':
                yield 'xcode-derived', path
            elif _plain(path, True):
                for generated in ('Build', 'Index.noindex', 'ModuleCache.noindex', 'CompilationCache.noindex',
                                  'SDKExplicitPrecompiledModules', 'SDKStatCaches.noindex'):
                    target = path / generated
                    if target.exists():
                        yield 'xcode-derived', target


def _scope(kind, home):
    if kind.startswith('cargo-'):
        return home / '.cache/cargo-target'
    if kind.startswith('gradle-'):
        return home / '.gradle/caches'
    return home / 'Library/Developer/Xcode/DerivedData'


class _SourceGuard:
    def __init__(self, home):
        self.home = home
        self.scopes = {}

    def clear(self):
        self.scopes.clear()

    def check(self, path, kind):
        scope = _scope(kind, self.home)
        if scope not in self.scopes:
            probe = subprocess.run(['git', '-C', str(scope), 'rev-parse', '--show-toplevel'],
                                   capture_output=True, text=True, timeout=10)
            protected = []
            if probe.returncode == 0:
                repo = Path(probe.stdout.strip()).resolve()
                listing = subprocess.run(['git', '-C', str(repo), 'ls-files', '-z', '--cached', '--others',
                                          '--exclude-standard', '--', str(scope.relative_to(repo))],
                                         capture_output=True, timeout=10, check=True)
                protected = [repo / os.fsdecode(p) for p in listing.stdout.split(b'\x00') if p]
            elif 'not a git repository' not in probe.stderr:
                raise RuntimeError('cannot establish source state')
            self.scopes[scope] = protected
        if any(p == path or p.is_relative_to(path) or path.is_relative_to(p) for p in self.scopes[scope]):
            raise ValueError('tracked or uncommitted work preserved')


def _compiled(path, header, size):
    if path.suffix == '.o':
        return len(header) >= 4 and header.startswith(OBJECT_MAGIC)
    if path.suffix == '.rlib':
        return header.startswith(b'!<arch>\n')
    if path.suffix == '.rmeta':
        return header.startswith(b'rust\x00\x00\x00')
    if path.suffix == '.bin':
        return path.name in ('query-cache.bin', 'dep-graph.bin', 'work-products.bin') and header.startswith((b'RSIC', b'rust'))
    return size == 0 and bool(re.fullmatch(r's-[A-Za-z0-9_-]+\.lock', path.name))


def _signature(path, info):
    return (str(path), info.st_dev, info.st_ino, info.st_mode, info.st_uid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_blocks)


def snapshot(path, home, *, kind='xcode-derived', source_guard=None):
    if not path.is_relative_to(home) or path == home or path.resolve() != path:
        raise ValueError('noncanonical cache path')
    (source_guard or _SourceGuard(home)).check(path, kind)
    rows, allocated, inodes = [], 0, set()
    paths = [path]
    if path.is_dir():
        def failed(error):
            raise error
        for root, dirs, files in os.walk(path, followlinks=False, onerror=failed):
            paths.extend(Path(root) / name for name in dirs + files)
    credential_name = False
    compiler_only = kind == 'cargo-object' or (kind == 'cargo-incremental' and bool(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*-[a-z0-9]+', path.name)))
    for item in paths:
        info = item.lstat()
        if info.st_uid != os.getuid() or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise ValueError('symlink, special file, or ownership mismatch')
        if item.suffix.lower() in PROTECTED_SUFFIXES or item.name in {'.git', 'Cargo.toml', 'Package.swift', 'package.json', 'credentials', 'credential', 'secrets', '.env', 'build.gradle', 'build.gradle.kts'}:
            raise ValueError('source, credentials or database preserved')
        credential_name |= bool(re.search(r'credential|secret|token|password|keychain', item.name, re.I))
        if stat.S_ISREG(info.st_mode):
            descriptor = os.open(item, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                current = os.fstat(descriptor)
                if _signature(item, current) != _signature(item, info):
                    raise ValueError('cache changed during inspection')
                header = os.read(descriptor, 16)
            finally:
                os.close(descriptor)
            if header == b'SQLite format 3\x00':
                raise ValueError('database preserved')
            compiled = _compiled(item, header, info.st_size)
            compiler_only &= compiled
            if kind == 'cargo-object':
                hashed = (bool(re.fullmatch(r'lib[A-Za-z0-9_]+-[0-9a-f]{16}\.(?:rlib|rmeta)', item.name))
                          or bool(re.fullmatch(r'[A-Za-z0-9_]+-[0-9a-f]{16}[.A-Za-z0-9_-]*\.o', item.name)))
                if not compiled or not hashed:
                    raise ValueError('not a proven generated Cargo dependency object')
        rows.append(_signature(item, info))
        inode = info.st_dev, info.st_ino
        if inode not in inodes:
            allocated += info.st_blocks * 512
            inodes.add(inode)
    if credential_name and not compiler_only:
        raise ValueError('credentials preserved; compiler-only proof unavailable')
    return rows, allocated


def _unchanged(path, rows):
    try:
        if path.resolve() != path:
            return False
        return all(_signature(Path(row[0]), Path(row[0]).lstat()) == row for row in rows)
    except (OSError, ValueError):
        return False


class _OpenPaths:
    def __init__(self, paths, home):
        self.parents = set()
        prefixes = [str(_scope(kind, home)) for kind in ('cargo-incremental', 'gradle-build-cache', 'xcode-derived')]
        for path in paths:
            if not isinstance(path, str):
                raise ValueError('invalid open-file observation')
            if not any(path == root or path.startswith(root + '/') for root in prefixes):
                continue
            while path:
                self.parents.add(path)
                path = path.rpartition('/')[0]

    def intersects(self, path):
        return str(path) in self.parents


def _activity_view(observer, home):
    commands, opened = observer()
    families = {prefix: busy(kind, Path('/__janitor_activity_probe__'), commands, [])
                for prefix, kind in [('cargo', 'cargo-incremental'), ('gradle', 'gradle-build-cache'), ('xcode', 'xcode-derived')]}
    return families, _OpenPaths(opened, home)


def _unit_busy(kind, path, view):
    family = kind.partition('-')[0]
    if kind == 'gradle-build-cache':
        lock = path.parent / (path.parent.name + '.lock')
        if view[1].intersects(lock):
            return True
    return view[0][family] or view[1].intersects(path)


def _native_remove(paths):
    # argv arrays only: no shell expansion; bound argv bytes for Darwin/Linux.
    pending, size = [], 0
    for path in paths:
        encoded = len(os.fsencode(path)) + 1
        if pending and size + encoded > 96 * 1024:
            subprocess.run(['/bin/rm', '-rf', '--', *pending], check=True, capture_output=True)
            pending, size = [], 0
        pending.append(str(path)); size += encoded
    if pending:
        subprocess.run(['/bin/rm', '-rf', '--', *pending], check=True, capture_output=True)


def _recover_batches(home, app_home, *, apply, pressure_only, observer, report):
    guard = _SourceGuard(home)
    view = _activity_view(observer, home)
    demand = pressure_demand(app_home) if pressure_only else None
    pending, allocated, nodes = [], 0, 0
    report['counts'] = {}
    report['batches'] = 0
    report['filesystems'] = {}
    report['entry_details_omitted'] = 0

    def note(entry, status, reason=None):
        entry['status'] = status
        if reason:
            entry['reason'] = str(reason)[:300]
        key = entry['kind'] + ':' + status
        report['counts'][key] = report['counts'].get(key, 0) + 1
        if len(report['entries']) < 256:
            report['entries'].append(entry)
        else:
            report['entry_details_omitted'] += 1

    def physical(path):
        device = str(path.stat().st_dev)
        if device not in report['filesystems']:
            root = path if path.is_dir() else path.parent
            while root.parent != root and root.parent.stat().st_dev == int(device):
                root = root.parent
            report['filesystems'][device] = dict(path=str(root), free_before=shutil.disk_usage(root).free)
        return device

    def flush():
        nonlocal pending, allocated, nodes, view, demand
        if not pending:
            return True
        fresh = _activity_view(observer, home) if apply else view
        guard.clear()
        demand = pressure_demand(app_home) if pressure_only else None
        selected = []
        for kind, path, rows, entry in pending:
            try:
                if pressure_only and path.stat().st_dev not in demand:
                    note(entry, 'not-required'); continue
                if _unit_busy(kind, path, fresh):
                    note(entry, 'active'); continue
                guard.check(path, kind)
                if not _unchanged(path, rows):
                    note(entry, 'changed'); continue
                selected.append((path, entry))
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                note(entry, 'preserved', error)
        error = None
        if apply and selected:
            try:
                _native_remove([path for path, _ in selected])
            except (OSError, subprocess.SubprocessError) as caught:
                error = caught
            report['batches'] += 1
        for path, entry in selected:
            if not apply:
                note(entry, 'eligible')
            elif not os.path.lexists(path):
                note(entry, 'removed')
                report['removed_allocated_bytes'] += entry['allocated_bytes']
            else:
                note(entry, 'preserved', error or 'native removal left cache present')
        for measure in report['filesystems'].values():
            measure['free_after'] = shutil.disk_usage(measure['path']).free
            measure['net_free_bytes'] = measure['free_after'] - measure['free_before']
        pending, allocated, nodes = [], 0, 0
        view = fresh
        if pressure_only:
            demand = pressure_demand(app_home)
            report['remaining_demand'] = demand
            return bool(demand)
        return True

    for kind, path in candidates(home):
        try:
            if pressure_only:
                if not demand:
                    break
                if path.stat().st_dev not in demand:
                    continue
            entry = dict(kind=kind, path=str(path), allocated_bytes=0)
            if _unit_busy(kind, path, view):
                note(entry, 'active'); continue
            rows, size = snapshot(path, home, kind=kind, source_guard=guard)
            entry['allocated_bytes'] = size
            physical(path)
            pending.append((kind, path, rows, entry))
            allocated += size; nodes += len(rows)
            target = min(2 * 1024 ** 3, max(v['deficit'] for v in demand.values())) if pressure_only else 2 * 1024 ** 3
            if len(pending) >= 2048 or nodes >= 65536 or allocated >= target:
                if not flush():
                    break
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            note(dict(kind=kind, path=str(path), allocated_bytes=0), 'preserved', error)
    flush()


def settled_without_writer(registry, item):
    """Whether an admitted record whose guard has exited holds settlement debt only.

    Admission already treats such a record as debt with no future disk or memory use: its
    outcome is durably recorded for the same owner and command, and its process group has
    retired. It has no live consumer of the caches, so it must not veto reclamation.
    """
    if not item.get('retention_unsettled'):
        return False
    group = item.get('child')
    if group:
        try:
            os.killpg(group, 0)
        except ProcessLookupError:
            pass
        except (PermissionError, TypeError, ValueError, OverflowError):
            return False
        else:
            return False
    try:
        descriptor = os.open(registry / (str(item['id']) + '.result'), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor) as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                return False
            saved = json.load(stream)
    except (OSError, ValueError, KeyError):
        return False
    return (isinstance(saved, dict) and saved.get('owner') == item.get('owner')
            and saved.get('command_hash') == item.get('command_hash'))


def pressure_demand(app_home):
    """Fresh per-device deficit of the oldest owned waiter, never queued totals.

    Registry locks prove live ownership; PIDs do not. Unknown admitted state
    preserves caches. Caller serializes decisions with admission.lock.
    """
    jobs = []
    registry = Path(app_home) / 'guard-reservations'
    if registry.is_symlink():
        raise RuntimeError('unsafe pressure registry')
    for path in registry.glob('*.json'):
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor) as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise RuntimeError('unsafe pressure reservation')
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                owned = False
            except BlockingIOError:
                owned = True
            item = json.load(handle)
            current = os.lstat(path)
            if (current.st_dev,current.st_ino)!=(info.st_dev,info.st_ino):
                raise RuntimeError('pressure reservation identity changed; caches preserved')
        if item.get('state') not in ('running', 'waiting'):
            continue
        if not owned:
            if item.get('state') == 'running' and not settled_without_writer(registry, item):
                raise RuntimeError('admitted reservation has uncertain ownership; caches preserved')
            continue
        if not isinstance(item.get('created'), (int, float)) or not math.isfinite(item['created']):
            raise RuntimeError('invalid pressure reservation age')
        for v in item['volumes']:
            for number in (v['reserve'], v.get('budget', item['budget']), item.get('consumed', {}).get(v['path'], 0)):
                if not isinstance(number, (int, float)) or not math.isfinite(number) or number < 0:
                    raise RuntimeError('invalid pressure reservation budget')
        jobs.append(item)
    paused = []
    for item in jobs:
        if item['state'] != 'running' or not item.get('runtime_file'): continue
        runtime = registry / (item['id']+'.runtime')
        if item['runtime_file'] != str(runtime) or runtime.resolve() != runtime:
            raise RuntimeError('unsafe pressure runtime path; caches preserved')
        try:
            descriptor = os.open(runtime, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(descriptor) as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                    raise RuntimeError('unsafe pressure runtime; caches preserved')
                observed = json.load(stream)
            if (observed.get('version') != 1 or observed.get('owner') != item['owner']
                    or observed.get('command_hash') != item.get('command_hash') or observed.get('job_id') != item['id']):
                raise RuntimeError('pressure runtime identity mismatch; caches preserved')
            if observed.get('state') == 'pressure-blocked':
                hysteresis = observed.get('hysteresis_bytes')
                if type(hysteresis) not in (int,float) or not math.isfinite(hysteresis) or hysteresis < 0:
                    raise RuntimeError('invalid pressure runtime hysteresis; caches preserved')
                paused.append(dict(item, _pressure_hysteresis=hysteresis))
        except FileNotFoundError: continue
        except (OSError,ValueError,TypeError) as error:
            raise RuntimeError('pressure runtime cannot be inspected; caches preserved') from error
    waiting = [j for j in jobs if j['state'] == 'waiting']
    if not waiting and not paused: return {}
    # Resume admitted frozen writers before accumulating additional write demand.
    oldest = min(paused or waiting, key=lambda j: (j['created'], j['id']))
    active = [j for j in jobs if j['state'] == 'running']
    demand = {}
    for volume in oldest['volumes']:
        device = volume['device']
        if device in demand:
            continue
        path = Path(volume['path'])
        if path.resolve() != path or not os.path.ismount(path) or path.stat().st_dev != device:
            raise RuntimeError('required pressure filesystem is missing or changed; caches preserved')
        frozen = oldest.get('_pressure_hysteresis')
        required = 0 if frozen is not None else max(v.get('budget', oldest['budget']) for v in oldest['volumes'] if v['device'] == device)
        reserve = max([v['reserve'] for v in oldest['volumes'] if v['device'] == device] +
                      [v['reserve'] for job in active for v in job['volumes'] if v['device'] == device])
        if frozen is not None: reserve += frozen
        claims = 0
        for job in active:
            same = [v for v in job['volumes'] if v['device'] == device]
            if same:
                claims += max(0, max(v.get('budget', job['budget']) for v in same) -
                              max(job.get('consumed', {}).get(v['path'], 0) for v in same))
        free = shutil.disk_usage(path).free
        if frozen is not None: claims = 0  # Actual reserve, not a second whole-command commitment, permits safe thaw.
        deficit = max(0, reserve + claims + required - free)
        if deficit:
            demand[device] = dict(path=str(path), deficit=deficit, required=required,
                                  reserve=reserve, active_remaining=claims, free=free,
                                  oldest_job_id=oldest['id'])
    return demand


def recover(home, app_home, *, apply=False, pressure_only=False, drain_seconds=30, observer=activity):
    home, app_home = Path(home).resolve(), Path(app_home).resolve()
    app_home.mkdir(parents=True, exist_ok=True)
    report = {'applied': apply, 'pressure_only': pressure_only, 'started_at': time.time(), 'status': 'completed',
              'entries': [], 'removed_allocated_bytes': 0}
    intent_path = app_home / 'maintenance-intent.json'
    intent_token = None
    with ExitStack() as stack:
        def fence(name):
            p = app_home / name
            descriptor = os.open(p, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                os.close(descriptor)
                raise RuntimeError('unsafe recovery fence')
            return stack.enter_context(os.fdopen(descriptor, 'a+'))
        recovery = fence('recovery.lock')
        try:
            fcntl.flock(recovery, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            report['status'] = 'another-recovery-or-admission'
            return report
        admission, guard = fence('admission.lock'), fence('guard.lock')
        try:
            if pressure_only:
                try: fcntl.flock(admission, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    report['status'] = 'another-recovery-or-admission'
                    return report
                try:
                    demand = pressure_demand(app_home)
                    report['initial_demand'] = demand
                    if not demand:
                        report['status'] = 'no-disk-pressure'
                        return report
                    if apply:
                        # Admission checks this short-lived intent while holding
                        # its mutex. It drains finite users without disrupting any
                        # service. No category lease is claimed without a proven
                        # transitive runner contract; global exclusion remains.
                        if intent_path.is_symlink():
                            raise RuntimeError('unsafe maintenance intent')
                        intent_token = uuid.uuid4().hex
                        created = time.time()
                        temporary = intent_path.with_name(intent_path.name + '.' + intent_token)
                        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                        with os.fdopen(descriptor, 'w') as stream:
                            json.dump(dict(version=1, token=intent_token, created=created,
                                           expires=created + min(120, max(1, drain_seconds + 60))), stream)
                            stream.flush(); os.fsync(stream.fileno())
                        os.replace(temporary, intent_path)
                finally:
                    fcntl.flock(admission, fcntl.LOCK_UN)
                # Never wait for the global fence while holding admission.lock:
                # existing guardians need that mutex to finish and release it.
                deadline = time.monotonic() + (max(0, min(60, drain_seconds)) if apply else 0)
                while True:
                    try:
                        fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if time.monotonic() >= deadline:
                            report['status'] = 'active-guard'
                            return report
                        time.sleep(min(.05, max(0, deadline - time.monotonic())))
                # Once global exclusion is held, admission cannot launch a child.
                # Waiting for its short decision here cannot deadlock a finisher.
                fcntl.flock(admission, fcntl.LOCK_EX)
                demand = pressure_demand(app_home)
                if not demand:
                    report['status'] = 'no-disk-pressure'
                    return report
            else:
                for handle, name in ((admission, 'admission.lock'), (guard, 'guard.lock')):
                    try: fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        report['status'] = 'active-guard' if name == 'guard.lock' else 'another-recovery-or-admission'
                        return report
            try:
                _recover_batches(home, app_home, apply=apply, pressure_only=pressure_only,
                                 observer=observer, report=report)
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                # Keep authoritative completed work if a later batch cannot be
                # inspected. Direct callers still receive the original error;
                # the CLI publishes this partial report and exits nonzero.
                report.update(status='inspection-unavailable', error=str(error), completed_at=time.time())
                for measure in report.get('filesystems', {}).values():
                    try:
                        measure['free_after'] = shutil.disk_usage(measure['path']).free
                        measure['net_free_bytes'] = measure['free_after'] - measure['free_before']
                    except OSError as measurement_error:
                        measure['measurement_error'] = str(measurement_error)
                error.recovery_report = report
                raise
            report['completed_at'] = time.time()
        finally:
            if intent_token:
                # Only this recovery's intent is removed; a crashed owner leaves
                # an expiring hint which cannot fence work without recovery.lock.
                try:
                    if not intent_path.is_symlink() and json.loads(intent_path.read_text()).get('token') == intent_token:
                        intent_path.unlink()
                except (FileNotFoundError, ValueError):
                    pass
    return report


def request_preemption(app_home, requester_id):
    """Request cooperative yield; only the owning guardian may stop its child."""
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', requester_id):
        return None
    registry = Path(app_home) / 'guard-reservations'
    requester_path = registry / (requester_id + '.json')
    if requester_path.is_symlink():
        return None
    requester = json.loads(requester_path.read_text())
    if requester.get('state') != 'waiting':
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
        except (OSError, ValueError, KeyError):
            continue
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--apply', action='store_true')
    mode.add_argument('--dry-run', action='store_true')
    parser.add_argument('--report', type=Path)
    parser.add_argument('--requester')
    parser.add_argument('--pressure-only', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    home = Path.home()
    app_home = Path(os.environ.get('DISK_JANITOR_HOME', str(home / '.disk-janitor')))
    try:
        # Preserve explicit bounded cooperative yield before waiting for the
        # global fence; services and unmarked jobs remain untouched.
        preempted = request_preemption(app_home, args.requester) if args.requester else None
        result = recover(home, app_home, apply=args.apply, pressure_only=args.pressure_only)
        if args.requester:
            result['preemption_requested'] = preempted
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        result = getattr(error, 'recovery_report', None) or {
            'applied': args.apply, 'status': 'inspection-unavailable',
            'error': str(error), 'removed_allocated_bytes': 0, 'completed_at': time.time()}
    if args.report:
        temporary = args.report.with_name(args.report.name + '.' + str(os.getpid()))
        temporary.write_text(json.dumps(result) + '\n')
        os.replace(temporary, args.report)
    print(json.dumps(result))
    if result.get('status') == 'inspection-unavailable':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
