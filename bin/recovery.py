#!/usr/bin/env python3
"""Discover disposable compiler caches; never require per-path approvals."""
import sys
if sys.version_info < (3, 10):
    raise SystemExit('disk-janitor: Python 3.10 or newer is required; this is ' + sys.version.split()[0])
import argparse
import ctypes
import errno
import shlex
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
        except (OSError, ValueError):
            if not _process_exited(pid):
                # What this process builds is unknown: it counts as active for every
                # compiler family, and the remaining inspection continues.
                commands.append(dict(pid=pid, executable=None, family='unknown'))
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
            if command.get('family') in (family, 'unknown'):
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


def _cargo_candidates(home):
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


def _gradle_candidates(home):
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


def _xcode_candidates(home):
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


GRADLE_SCRIPTS = frozenset({'build.gradle', 'build.gradle.kts', 'settings.gradle', 'settings.gradle.kts'})
# Background access below these home folders is blocked or prompts on macOS.
PRIVACY_GATED = frozenset({'Documents', 'Desktop', 'Downloads', 'Library'})


def _git(directory, *arguments):
    return subprocess.run(['git', '--literal-pathspecs', '-c', 'core.fsmonitor=false', '-C', str(directory), *arguments],
                          capture_output=True, timeout=10, env=dict(os.environ, GIT_OPTIONAL_LOCKS='0'))


def _project_roots(home):
    listed = os.environ.get('DISK_JANITOR_PROJECT_DIRS')
    roots = [Path(name) for name in listed.split(os.pathsep) if name] if listed else [home / 'Projects']
    return [root for root in roots if root.is_absolute() and root not in (home, Path('/'))]


def worktrees(home):
    """Checkouts of the repositories under the project directories, wherever git placed them."""
    repositories = []
    for root in _project_roots(home):
        if not _plain(root, True):
            continue
        for directory, names, _ in os.walk(root, followlinks=False):
            if '.git' in names:
                repositories.append(Path(directory))
                names[:] = []
            elif len(Path(directory).relative_to(root).parts) >= 2:
                names[:] = []
            else:
                names[:] = sorted(name for name in names if not name.startswith('.') and name != 'node_modules')
    found = []
    for repository in repositories:
        try:
            listing = _git(repository, 'worktree', 'list', '--porcelain')
        except (OSError, subprocess.SubprocessError):
            continue
        if listing.returncode:
            continue
        for line in listing.stdout.split(b'\n'):
            if not line.startswith(b'worktree '):
                continue
            checkout = Path(os.fsdecode(line[9:]))
            try:
                gated = checkout.relative_to(home).parts[:1]
                if (checkout not in found and gated and gated[0] not in PRIVACY_GATED
                        and checkout.resolve() == checkout and _plain(checkout, True)
                        and os.path.lexists(checkout / '.git')):
                    found.append(checkout)
            except (OSError, ValueError):
                continue
    return found


def _build_outputs(checkout, deadline=None):
    """Topmost Gradle `build` directories of one checkout, each beside a Gradle build script."""
    for directory, names, files in os.walk(checkout, followlinks=False):
        if deadline is not None and time.monotonic() >= deadline:
            return
        if directory != str(checkout) and '.git' in names + files:
            names[:] = []  # A nested checkout answers for itself.
            continue
        if 'build' in names and not GRADLE_SCRIPTS.isdisjoint(files):
            yield Path(directory) / 'build'
        names[:] = sorted(name for name in names
                          if name not in ('build', 'src', 'node_modules') and not name.startswith('.'))


def _worktree_candidates(home, occupied=None, deadline=None):
    for checkout in worktrees(home):
        if deadline is not None and time.monotonic() >= deadline:
            return
        if occupied is not None and occupied(checkout):
            continue  # Nothing in an occupied checkout is reclaimable; do not walk it.
        for output in _build_outputs(checkout, deadline):
            if _plain(output, True):
                yield 'worktree-build', output


def _checkout_of(path):
    for parent in path.parents:
        if os.path.lexists(parent / '.git'):
            return parent
    raise ValueError('build output is outside a checkout')


RETIRE_IDLE_SECONDS = 48 * 3600


def _git_text(directory, *arguments):
    result = _git(directory, *arguments)
    return os.fsdecode(result.stdout).strip() if result.returncode == 0 else None


def _linked_git_dir(checkout):
    """The private git directory of a linked worktree; None for a main checkout or submodule."""
    marker = checkout / '.git'
    if not _plain(marker):
        return None
    text = marker.read_text(errors='replace').strip()
    if not text.startswith('gitdir: '):
        return None
    git_dir = Path(text[8:])
    if not git_dir.is_absolute():
        git_dir = (checkout / git_dir).resolve()
    if git_dir.parent.name != 'worktrees' or not _plain(git_dir, True):
        return None
    return git_dir


def _default_branch(checkout):
    head = _git_text(checkout, 'symbolic-ref', '--quiet', 'refs/remotes/origin/HEAD')
    if head:
        return head
    for name in ('refs/remotes/origin/main', 'refs/remotes/origin/master'):
        if _git(checkout, 'rev-parse', '--verify', '--quiet', name).returncode == 0:
            return name
    return None


def retirement(checkout, now=None):
    """Why a linked worktree's work is finished, or raise ValueError saying why it is kept.

    Finished means every commit stays reachable after the checkout goes: its HEAD is in
    the remote default branch, or its branch was deleted upstream (a merged pull request)
    and the local branch keeps the commits. The checkout must also be clean, unlocked and
    untouched for RETIRE_IDLE_SECONDS, so a worktree just created from main is not mistaken
    for finished work.
    """
    git_dir = _linked_git_dir(checkout)
    if git_dir is None:
        raise ValueError('not a linked worktree')
    if os.path.lexists(git_dir / 'locked'):
        raise ValueError('locked with git worktree lock')
    status = _git(checkout, 'status', '--porcelain=v1', '--untracked-files=all', '--ignore-submodules=none')
    if status.returncode:
        raise RuntimeError('cannot establish source state')
    if status.stdout.strip():
        raise ValueError('uncommitted work preserved')
    times = [p.stat().st_mtime for p in (git_dir / 'HEAD', git_dir / 'index', git_dir / 'logs/HEAD')
             if os.path.lexists(p)]
    committed = _git_text(checkout, 'log', '-1', '--format=%ct')
    if committed:
        times.append(float(committed))
    if not times or (now or time.time()) - max(times) < RETIRE_IDLE_SECONDS:
        raise ValueError('recently active')
    head = _git_text(checkout, 'rev-parse', '--verify', 'HEAD')
    if not head:
        raise RuntimeError('cannot read HEAD')
    default = _default_branch(checkout)
    if default and _git(checkout, 'merge-base', '--is-ancestor', head, default).returncode == 0:
        return head, 'merged into ' + default.removeprefix('refs/remotes/')
    branch = _git_text(checkout, 'symbolic-ref', '--quiet', 'HEAD')
    if branch and _git_text(checkout, 'for-each-ref', '--format=%(upstream:track)', branch) == '[gone]':
        return head, 'branch deleted upstream; kept locally as ' + branch.removeprefix('refs/heads/')
    if default and branch and _squash_merged(checkout, head, default):
        return head, 'squash-merged into ' + default.removeprefix('refs/remotes/') + '; kept locally as ' + \
            branch.removeprefix('refs/heads/')
    raise ValueError('work not merged')


def _squash_merged(checkout, head, default):
    """Whether the branch's combined change already landed in default as one commit.

    A squash merge leaves none of the branch's commits in default, so the whole change is
    folded into one probe commit on the merge base and git cherry looks for a commit in
    default with the same patch.
    """
    base = _git_text(checkout, 'merge-base', default, head)
    if not base or base == head:
        return False
    probe = _git_text(checkout, 'commit-tree', head + '^{tree}', '-p', base, '-m', 'disk-janitor squash probe')
    if not probe:
        return False
    cherry = _git_text(checkout, 'cherry', default, probe)
    return bool(cherry) and cherry.startswith('-')


def _main_checkout(checkout):
    common = _git_text(checkout, 'rev-parse', '--path-format=absolute', '--git-common-dir')
    if not common:
        raise RuntimeError('cannot find the main checkout')
    return Path(common).parent


def _allocated(path, deadline=None):
    total = 0
    for directory, names, files in os.walk(path, followlinks=False):
        if deadline is not None and time.monotonic() >= deadline:
            break
        for name in names + files:
            try:
                total += os.lstat(os.path.join(directory, name)).st_blocks * 512
            except OSError:
                continue
    return total


def _retire_worktrees(home, report, note, view, view_now, *, apply, demand=None, deadline=None):
    """Remove clean, idle linked worktrees whose work is finished, with git, keeping every branch.

    view is the pass's activity observation; view_now observes again just before a removal.
    """
    if view[1].unknown:
        return
    for checkout in worktrees(home):
        if deadline is not None and time.monotonic() >= deadline:
            return
        if _linked_git_dir(checkout) is None:
            continue
        entry = dict(kind='worktree-retire', path=str(checkout), allocated_bytes=0)
        try:
            if demand is not None and checkout.stat().st_dev not in demand:
                continue
            if view[1].occupied(checkout):
                note(entry, 'active'); continue
            head, reason = retirement(checkout)
            entry['finished'] = reason
            entry['allocated_bytes'] = _allocated(checkout, deadline)
            if not apply:
                note(entry, 'eligible'); continue
            # Prove it again at the moment of removal: occupancy, cleanliness and HEAD.
            fresh = view_now()
            if fresh[1].unknown or fresh[1].occupied(checkout):
                note(entry, 'active'); continue
            if retirement(checkout)[0] != head:
                note(entry, 'changed'); continue
            removal = _git(_main_checkout(checkout), 'worktree', 'remove', str(checkout))
            if removal.returncode or os.path.lexists(checkout):
                note(entry, 'preserved', os.fsdecode(removal.stderr).strip() or 'git kept the worktree'); continue
            note(entry, 'removed')
            report['removed_allocated_bytes'] += entry['allocated_bytes']
        except ValueError as kept:
            report['worktrees_kept'] = report.get('worktrees_kept', 0) + 1
            entry['reason'] = str(kept)
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            note(entry, 'preserved', error)


LOG_TAIL_BYTES = 8 * 1024 ** 2


def _log_cap_bytes():
    try:
        megabytes = float(os.environ.get('DISK_JANITOR_LOG_CAP_MB', '256'))
    except ValueError:
        megabytes = 256
    return int(max(megabytes, 16) * 1024 ** 2)


def service_logs(home):
    """Output files of the user's launchd agents: launchd appends to them and never rotates them."""
    import plistlib
    agents = home / 'Library/LaunchAgents'
    found = []
    try:
        entries = sorted(agents.iterdir())
    except OSError:
        return found
    for plist in entries:
        if plist.suffix != '.plist' or not _plain(plist):
            continue
        try:
            with plist.open('rb') as stream:
                job = plistlib.load(stream)
        except (OSError, ValueError, plistlib.InvalidFileException):
            continue
        if not isinstance(job, dict):
            continue
        for key in ('StandardOutPath', 'StandardErrorPath'):
            name = job.get(key)
            if not isinstance(name, str) or not name.startswith('/'):
                continue
            path = Path(name)
            try:
                if path not in found and path.resolve() == path and path.is_relative_to(home) and _plain(path):
                    found.append(path)
            except OSError:
                continue
    return found


def _cap_service_logs(home, report, note, *, apply, demand=None):
    """Keep each oversized service log's recent tail in <log>.1 and empty the log in place.

    launchd opens these files for appending, so the service keeps writing at the new end;
    truncating in place, not replacing the file, is what lets it continue without a restart.
    """
    cap = _log_cap_bytes()
    for path in service_logs(home):
        entry = dict(kind='service-log', path=str(path), allocated_bytes=0)
        try:
            info = path.lstat()
            if info.st_size <= cap or (demand is not None and info.st_dev not in demand):
                continue
            entry['allocated_bytes'] = info.st_blocks * 512
            if not apply:
                note(entry, 'eligible'); continue
            tail = path.with_name(path.name + '.1')
            if os.path.lexists(tail) and not _plain(tail):
                note(entry, 'preserved', 'previous tail is not a plain file'); continue
            temporary = path.with_name(path.name + '.1.' + str(os.getpid()))
            with path.open('rb') as source, temporary.open('wb') as copy:
                source.seek(max(0, info.st_size - LOG_TAIL_BYTES))
                source.readline()  # start the kept tail at a line boundary
                shutil.copyfileobj(source, copy)
            os.replace(temporary, tail)
            os.truncate(path, 0)
            note(entry, 'removed')
            report['removed_allocated_bytes'] += entry['allocated_bytes']
        except OSError as error:
            note(entry, 'preserved', error)


def candidates(home, occupied=None, deadline=None):
    # Outputs of checkouts nobody occupies go first: shared caches still serve active work.
    for discover in (lambda root: _worktree_candidates(root, occupied, deadline),
                     _cargo_candidates, _gradle_candidates, _xcode_candidates):
        try:
            yield from discover(home)
        except (OSError, ValueError, subprocess.SubprocessError):
            continue  # One unreadable category does not hide the others.


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

    def _checkout(self, checkout):
        # Every directory holding a file git tracks or would add: all else is ignored output.
        if checkout not in self.scopes:
            listing = _git(checkout, 'ls-files', '-z', '--cached', '--others', '--exclude-standard')
            if listing.returncode:
                raise RuntimeError('cannot establish source state')
            kept = set()
            for name in listing.stdout.split(b'\x00'):
                name = os.fsdecode(name).rpartition('/')[0]
                while name and name not in kept:
                    kept.add(name)
                    name = name.rpartition('/')[0]
            self.scopes[checkout] = kept
        return self.scopes[checkout]

    def check(self, path, kind):
        if kind == 'worktree-build':
            checkout = _checkout_of(path)
            if str(path.relative_to(checkout)) in self._checkout(checkout):
                raise ValueError('tracked or uncommitted work preserved')
            return
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


KEPT_OUTPUT_SUFFIXES = frozenset({'.sqlite', '.sqlite3', '.sqlite-wal', '.sqlite-shm', '.db', '.db-wal',
    '.db-shm', '.rdb', '.mdb', '.key', '.pem', '.p12', '.pfx', '.jks', '.keystore'})


def _snapshot_output(path):
    """Signatures of one ignored Gradle output tree.

    Generated sources and links belong here, so the cache rules for source suffixes do not
    apply; credentials, databases and special files still preserve the whole directory.
    """
    rows, allocated, inodes = [], 0, set()
    def failed(error):
        raise error
    paths = [path]
    for root, dirs, files in os.walk(path, followlinks=False, onerror=failed):
        paths.extend(Path(root) / name for name in dirs + files)
    for item in paths:
        info = item.lstat()
        if info.st_uid != os.getuid() or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)
                                              or stat.S_ISLNK(info.st_mode)):
            raise ValueError('special file or ownership mismatch')
        if (item.suffix.lower() in KEPT_OUTPUT_SUFFIXES
                or item.name in {'.git', '.env', 'credentials', 'credential', 'secrets'}):
            raise ValueError('credentials or database preserved')
        rows.append(_signature(item, info))
        inode = info.st_dev, info.st_ino
        if inode not in inodes:
            allocated += info.st_blocks * 512
            inodes.add(inode)
    return rows, allocated


def snapshot(path, home, *, kind='xcode-derived', source_guard=None):
    if not path.is_relative_to(home) or path == home or path.resolve() != path:
        raise ValueError('noncanonical cache path')
    (source_guard or _SourceGuard(home)).check(path, kind)
    if kind == 'worktree-build':
        return _snapshot_output(path)
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
        self.every = paths
        self.inside = None
        self.unknown = None
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

    def occupied(self, root):
        """Whether an open file, a working directory or a live job sits inside root."""
        if self.inside is None:
            self.inside = set()
            for path in self.every:
                while path and path not in self.inside:
                    self.inside.add(path)
                    path = path.rpartition('/')[0]
        return str(root) in self.inside


def _lease_held(path):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return False
    with os.fdopen(descriptor) as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
    return False


def job_directories(app_home):
    """Working directories of submitted jobs that still have an executor or were just created."""
    app_home = Path(app_home)
    try:
        entries = list(os.scandir(app_home / 'jobs'))
    except FileNotFoundError:
        return []
    found = []
    for entry in entries:
        if not re.fullmatch(r'j-[0-9a-f]{32}', entry.name):
            continue
        directory = Path(entry.path)
        live = (_lease_held(directory / 'worker.lock') or _lease_held(directory / 'guardian.lock')
                or _lease_held(app_home / 'guard-reservations' / (entry.name + '.json')))
        try:
            descriptor = os.open(directory / 'job.json', os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(descriptor) as stream:
                value = json.load(stream)
            cwd, submitted = value['cwd'], value.get('submitted_at', 0)
            if not isinstance(cwd, str) or not isinstance(submitted, (int, float)):
                raise ValueError('invalid job record')
        except (OSError, ValueError, KeyError, TypeError):
            if live:
                raise RuntimeError('a live job has no readable working directory; build outputs preserved')
            continue
        if live or (value.get('state') in ('queued', 'running') and 0 <= time.time() - submitted < 60):
            found.append(cwd)
    return found


def _activity_view(observer, home, app_home=None):
    commands, opened = observer()
    unknown = None
    if app_home is not None:
        try:
            opened = list(opened) + job_directories(app_home)
        except RuntimeError as error:
            unknown = str(error)
    families = {prefix: busy(kind, Path('/__janitor_activity_probe__'), commands, [])
                for prefix, kind in [('cargo', 'cargo-incremental'), ('gradle', 'gradle-build-cache'), ('xcode', 'xcode-derived')]}
    paths = _OpenPaths(opened, home)
    paths.unknown = unknown
    return families, paths


def _unit_busy(kind, path, view):
    if kind == 'worktree-build':
        # Occupancy of the whole checkout decides, not a compiler family: any open file,
        # working directory or live job inside it keeps every output it has.
        if view[1].unknown:
            raise RuntimeError(view[1].unknown)
        return view[1].occupied(_checkout_of(path))
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


def _recover_batches(home, app_home, *, apply, pressure_only, observer, report, floors=None, deadline=None):
    guard = _SourceGuard(home)
    view = _activity_view(observer, home, app_home)
    demand = pressure_demand(app_home, floors) if pressure_only else None
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
        fresh = _activity_view(observer, home, app_home) if apply else view
        guard.clear()
        demand = pressure_demand(app_home, floors) if pressure_only else None
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
            demand = pressure_demand(app_home, floors)
            report['remaining_demand'] = demand
            return bool(demand)
        return True

    def occupied(checkout):
        return bool(view[1].unknown) or view[1].occupied(checkout)

    # Finished checkouts go first: retiring one frees its build output with it.
    _retire_worktrees(home, report, note, view, lambda: _activity_view(observer, home, app_home),
                      apply=apply, demand=demand if pressure_only else None, deadline=deadline)
    _cap_service_logs(home, report, note, apply=apply, demand=demand if pressure_only else None)

    for kind, path in candidates(home, occupied, deadline):
        if deadline is not None and time.monotonic() >= deadline:
            break
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
    if deadline is not None and time.monotonic() >= deadline:
        report['time_limited'] = True
    flush()


LOW_WATER_GIB = 30


def _lock_within(handle, seconds):
    """Take an exclusive lock or give up at a deadline; never queue behind a holder unbounded."""
    end = time.monotonic() + seconds
    while True:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            if time.monotonic() >= end:
                return False
            time.sleep(.02)


def _mount_of(path):
    # The topmost directory on the same device. macOS firmlinks put a home on the data
    # volume without making any of its ancestors a mount point.
    path = Path(path).resolve()
    device = path.stat().st_dev
    while path.parent != path and path.parent.stat().st_dev == device:
        path = path.parent
    return path


def _filesystem_root(path):
    return os.path.ismount(path) or path.parent == path or path.parent.stat().st_dev != path.stat().st_dev


def _paused_floors(app_home):
    """Free space each pressure-frozen writer needs before its controller may thaw it."""
    floors = {}
    registry = Path(app_home) / 'guard-reservations'
    try:
        records = [entry.path for entry in os.scandir(registry) if entry.name.endswith('.json')]
    except OSError:
        return floors
    for name in records:
        try:
            path = Path(name)
            if not _lease_held(path):
                continue  # Only a held registry lock proves a live writer; PIDs do not.
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(descriptor) as stream:
                item = json.load(stream)
            runtime = registry / (str(item['id']) + '.runtime')
            if item.get('state') != 'running' or item.get('runtime_file') != str(runtime):
                continue
            descriptor = os.open(runtime, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(descriptor) as stream:
                info = os.fstat(stream.fileno())
                observed = json.load(stream)
            hysteresis = observed.get('hysteresis_bytes')
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077
                    or observed.get('version') != 1 or observed.get('owner') != item['owner']
                    or observed.get('command_hash') != item.get('command_hash') or observed.get('job_id') != item['id']
                    or observed.get('state') != 'pressure-blocked'
                    or type(hysteresis) not in (int, float) or not math.isfinite(hysteresis) or hysteresis < 0):
                continue
            for volume in item['volumes']:
                reserve = volume['reserve']
                if type(reserve) not in (int, float) or not math.isfinite(reserve) or reserve < 0:
                    raise ValueError('invalid reserve')
                floors[volume['path']] = max(floors.get(volume['path'], 0), reserve + hysteresis)
        except (OSError, ValueError, KeyError, TypeError):
            continue  # One unreadable record is skipped; it never vetoes recovery.
    return floors


def low_water_floors(home, app_home):
    """Free space kept available without being asked, so a starting job rarely meets its floor."""
    try:
        low_water = float(os.environ.get('DISK_JANITOR_LOW_WATER_GIB', LOW_WATER_GIB))
    except ValueError:
        low_water = LOW_WATER_GIB
    if not math.isfinite(low_water) or low_water < 0:
        low_water = LOW_WATER_GIB
    floors = {str(_mount_of(home)): low_water * 2**30}
    for name, required in _paused_floors(app_home).items():
        floors[name] = max(floors.get(name, 0), required)
    return floors


def pressure_demand(app_home, floors=None, home=None):
    """Per-device shortfall below the free space recovery maintains.

    floors maps a mount to the free bytes required there; a refused job supplies its own
    floor. Without one, the home filesystem is kept above the low-water mark and
    pressure-frozen writers get what their thaw needs. No reservation record adds demand,
    and an unreadable record or an absent mount is skipped.
    """
    if floors is None:
        floors = low_water_floors(home or Path.home(), app_home)
    demand = {}
    for name, required in floors.items():
        try:
            path = Path(name)
            if path.resolve() != path or not _filesystem_root(path):
                continue
            device, free = path.stat().st_dev, shutil.disk_usage(path).free
        except OSError:
            continue
        deficit = max(0, int(required) - free)
        if deficit > demand.get(device, {}).get('deficit', 0):
            demand[device] = dict(path=str(path), deficit=deficit, required=int(required), free=free)
    return demand


def recover(home, app_home, *, apply=False, pressure_only=False, drain_seconds=30, observer=activity,
            floors=None, time_limit=None):
    home, app_home = Path(home).resolve(), Path(app_home).resolve()
    app_home.mkdir(parents=True, exist_ok=True)
    report = {'applied': apply, 'pressure_only': pressure_only, 'started_at': time.time(), 'status': 'completed',
              'entries': [], 'removed_allocated_bytes': 0}
    deadline = time.monotonic() + time_limit if time_limit is not None else None
    with ExitStack() as stack:
        def fence(name):
            p = app_home / name
            descriptor = os.open(p, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                os.close(descriptor)
                raise RuntimeError('unsafe recovery fence')
            return stack.enter_context(os.fdopen(descriptor, 'a+'))
        # One recovery of this kind at a time; a second would only repeat the inspection.
        # Guardians of earlier releases hold recovery.lock almost continuously while they
        # wait, so a pressure pass has a fence of its own and is never starved by them.
        if not _lock_within(fence('recovery-pass.lock'), 1 if pressure_only else 0):
            report['status'] = 'another-recovery-or-admission'
            return report
        admission, guard = fence('admission.lock'), fence('guard.lock')
        if pressure_only:
            if floors is None:
                floors = low_water_floors(home, app_home)
            demand = pressure_demand(app_home, floors)
            report['initial_demand'] = demand
            if not demand:
                report['status'] = 'no-disk-pressure'
                return report
            # Running jobs share the guard fence for their whole life, so it is neither
            # awaited nor taken here: per-unit activity proof decides what is idle, and no
            # job waits for a recovery.
        else:
            for handle, name in ((fence('recovery.lock'), 'recovery.lock'), (admission, 'admission.lock'), (guard, 'guard.lock')):
                if not _lock_within(handle, 0):
                    report['status'] = 'active-guard' if name == 'guard.lock' else 'another-recovery-or-admission'
                    return report
        try:
            _recover_batches(home, app_home, apply=apply, pressure_only=pressure_only,
                             observer=observer, report=report, floors=floors, deadline=deadline)
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
    return report


def _runtime():
    # Record retirement and preemption requests live with the runtime controller, which a
    # guardian already loads; this module is also run as a script and replaced in fixtures.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import capacity
    return capacity


def sweep_registry(app_home):
    return _runtime().sweep_registry(app_home)


def request_preemption(app_home, requester_id):
    return _runtime().request_preemption(app_home, requester_id)


def start_stalled(app_home, seconds, interval=2):
    """Watch the queue; a job waiting beside a free slot is a fault, so let the oldest start.

    The same oldest ticket seen twice with a slot free gets a grant its waiter honours
    without regard to order. Nothing is signalled and no job is started from here.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from capacity import queue_view
    granted, previous = [], None
    end = time.monotonic() + seconds
    while True:
        view = queue_view(app_home)
        oldest = view['waiting'][0] if view['waiting'] and view['busy'] < view['limit'] else None
        if oldest and oldest == previous:
            grant = Path(app_home) / 'queue' / (oldest + '.go')
            if not grant.is_symlink() and not grant.exists():
                with os.fdopen(os.open(grant, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600), 'w') as output:
                    json.dump(dict(at=time.time(), busy=view['busy'], limit=view['limit']), output)
                granted.append(oldest)
        previous = oldest
        if time.monotonic() + interval >= end:
            return granted
        time.sleep(interval)


def watchdog(home, app_home, monitor_seconds=50):
    """One scheduled pass: retire dead registry records, restore free space to low water,
    then watch for a job left waiting beside a free slot."""
    report = {'started_at': time.time()}
    began = time.monotonic()
    try:
        # First, before any slower work: a waiter beside a free slot is started promptly.
        report['stalled_waiters_started'] = start_stalled(app_home, min(6, monitor_seconds))
    except (OSError, ValueError, ImportError) as error:
        report['stalled_waiters_started'] = {'error': str(error)}
    try:
        report['registry'] = sweep_registry(app_home)
    except (OSError, ValueError, RuntimeError) as error:
        report['registry'] = {'error': str(error)}
    # A pass that found nothing to remove is not repeated every minute: discovery walks
    # every checkout and cache, and what is busy now is usually busy a minute later.
    retry_at = 0
    try:
        with open(Path(app_home) / 'watchdog-last.json') as stream:
            retry_at = float(json.load(stream).get('recovery_retry_at', 0))
    except (OSError, ValueError, TypeError, AttributeError):
        pass
    if time.time() < retry_at <= time.time() + 600:
        report.update(recovery={'status': 'waiting-after-empty-pass'}, recovery_retry_at=retry_at)
    else:
        try:
            report['recovery'] = recover(home, app_home, apply=True, pressure_only=True, time_limit=45)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            report['recovery'] = getattr(error, 'recovery_report', None) or {
                'status': 'inspection-unavailable', 'error': str(error), 'removed_allocated_bytes': 0}
        if report['recovery'].get('status') == 'completed' and not report['recovery'].get('removed_allocated_bytes'):
            report['recovery_retry_at'] = time.time() + 600
    try:
        if isinstance(report['stalled_waiters_started'], list):
            report['stalled_waiters_started'] += start_stalled(app_home, monitor_seconds - (time.monotonic() - began))
    except (OSError, ValueError, ImportError) as error:
        report['stalled_waiters_started'] = {'error': str(error)}
    report['completed_at'] = time.time()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--apply', action='store_true')
    mode.add_argument('--dry-run', action='store_true')
    parser.add_argument('--report', type=Path)
    parser.add_argument('--requester')
    parser.add_argument('--pressure-only', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--need', action='append', default=[], metavar='MOUNT=BYTES', help=argparse.SUPPRESS)
    parser.add_argument('--time-limit', type=float, help=argparse.SUPPRESS)
    parser.add_argument('--watchdog', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    home = Path.home()
    app_home = Path(os.environ.get('DISK_JANITOR_HOME', str(home / '.disk-janitor')))
    if args.watchdog:
        result = watchdog(home, app_home)
        destination = app_home / 'watchdog-last.json'
        temporary = destination.with_name(destination.name + '.' + str(os.getpid()))
        temporary.write_text(json.dumps(result) + '\n')
        os.replace(temporary, destination)
        return
    try:
        floors = None
        for need in args.need:
            mount, _, required = need.rpartition('=')
            floors = dict(floors or {}, **{mount: float(required)})
        if args.time_limit is not None and not (math.isfinite(args.time_limit) and args.time_limit > 0):
            raise ValueError('invalid time limit')
        # Preserve explicit bounded cooperative yield before waiting for the
        # global fence; services and unmarked jobs remain untouched.
        preempted = request_preemption(app_home, args.requester) if args.requester else None
        result = recover(home, app_home, apply=args.apply, pressure_only=args.pressure_only,
                         floors=floors, time_limit=args.time_limit)
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
