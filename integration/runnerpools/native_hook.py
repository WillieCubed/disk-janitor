def _local_admission_runtime(home, uid):
    """Read the exact owned immutable release without executing user code."""
    components = ('disk-janitor', 'recovery.py', 'jobs.py', 'capacity.py', 'coverage.py',
                  'runnerpools_bridge.py', 'install_runtime.py')
    def read(path, expected_mode=None):
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_nlink == 1
                    and not info.st_mode & 0o022 and info.st_size <= 4*1024*1024
                    and (expected_mode is None or stat.S_IMODE(info.st_mode) == expected_mode),
                    "Local admission runtime component metadata is unsafe.")
            return stream.read()
    module, cli = home / 'runnerpools_bridge.py', home / 'disk-janitor'
    if not module.is_symlink() and not cli.is_symlink():
        return {'runnerpools_bridge.py':read(module), 'disk-janitor':read(cli)}
    current = home / 'current'
    info = current.lstat()
    require(stat.S_ISLNK(info.st_mode) and info.st_uid == uid,
            "Local admission current pointer is not an owned canonical alias.")
    target = os.readlink(current)
    require(re.fullmatch(r'releases/[0-9a-f]{64}', target) is not None,
            "Local admission current pointer redirects outside its owned release.")
    protected(home / 'releases', directory=True, uid=uid)
    release = home / target
    info = protected(release, directory=True, uid=uid)
    require(stat.S_IMODE(info.st_mode) == 0o555,
            "Local admission release directory must be immutable.")
    require(set(path.name for path in release.iterdir()) == set(components) | {'manifest.json'},
            "Local admission release has unexpected components.")
    manifest = json.loads(read(release / 'manifest.json', 0o444), object_pairs_hook=_unique)
    require(type(manifest) is dict and set(manifest) == {'version', 'components'}
            and manifest['version'] == 1 and type(manifest['components']) is dict
            and set(manifest['components']) == set(components),
            "Local admission release manifest is invalid.")
    entries = manifest['components']
    require(hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(',', ':')).encode()).hexdigest() == release.name,
            "Local admission release identity differs from its manifest.")
    contents = {}
    for name in components:
        alias = home / name
        info = alias.lstat()
        if name == 'disk-janitor':
            require(hashlib.sha256(read(alias, 0o555)).hexdigest() == control.ADMISSION_LAUNCHER_SHA256,
                    "Local admission dispatcher differs from its reviewed stable content.")
        else:
            require(stat.S_ISLNK(info.st_mode) and info.st_uid == uid
                    and os.readlink(alias) == 'current/'+name,
                    "Local admission component alias redirects outside its canonical release.")
        expected = entries[name]
        mode = 0o555 if name == 'disk-janitor' else 0o444
        require(type(expected) is dict and set(expected) == {'mode', 'sha256'}
                and expected['mode'] == mode and type(expected['sha256']) is str
                and re.fullmatch(r'[0-9a-f]{64}', expected['sha256']) is not None,
                "Local admission manifest component metadata is invalid.")
        contents[name] = read(release / name, mode)
        require(hashlib.sha256(contents[name]).hexdigest() == expected['sha256'],
                "Local admission release checksum differs.")
    return contents


def _join_local_admission(profile, owner_home):
    """Native installer only: join verified idle brokers to the real local owner.

    This runs after exact runtime publication and before its ordinary activation;
    it uses the same resource/mutex order as the broker. No submitted command,
    environment identity or user-authored path becomes privileged execution.
    """
    owner_home = Path(owner_home)
    owner = protected(owner_home, directory=True, uid=owner_home.lstat().st_uid)
    account = pwd.getpwuid(owner.st_uid)
    require(account.pw_uid >= 500 and Path(account.pw_dir) == owner_home,
            "Shared admission requires the native owner's exact account home.")
    home = owner_home / '.disk-janitor'
    protected(home, directory=True, uid=account.pw_uid)
    protected(home / 'guard-reservations', directory=True, uid=account.pw_uid)
    contents = _local_admission_runtime(home, account.pw_uid)
    require(hashlib.sha256(contents['runnerpools_bridge.py']).hexdigest() == control.ADMISSION_BRIDGE_SHA256,
            "Install the matching local admission bridge before joining CI capacity.")
    require(b'from runnerpools_bridge import UserBridge' in contents['disk-janitor']
            and b'.claims(guard_home=home)' in contents['disk-janitor'],
            "The installed local admission guard lacks its reviewed bridge hook.")
    state_root = paths(profile)['state'].parent
    with control.file_lock(state_root / '.resources.lock'):
        profiles = installed_profiles(paths(profile)['install'].parent, read=read_profile)
        require(bool(profiles), "Shared admission requires validated installed profiles.")
        for _, installed in profiles:
            verify_install(installed)
            receipt = json.loads((paths(installed)['install'] / 'runtime.json').read_text(), object_pairs_hook=_unique)
            require(all(receipt.get(name) == hashlib.sha256(
                (paths(profile)['install'] / name).read_bytes()).hexdigest()
                for name in ('process_control.py', 'pool_runtime.py')),
                "Every installed pool must use the same reviewed admission bridge and broker adapter before joining.")
            _idle_repair_slots(installed)
        lock = home / 'admission.lock'
        descriptor = os.open(lock, os.O_RDWR | os.O_NOFOLLOW)
        try:
            import fcntl
            info = os.fstat(descriptor)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == account.pw_uid
                    and not info.st_mode & 0o022 and info.st_nlink == 1,
                    "Local admission mutex metadata is unsafe; preserve it.")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            current = lock.lstat()
            require((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino),
                    "Local admission mutex changed during native joining.")
            binding = dict(version=1, user_uid=account.pw_uid, guard_home=str(home),
                           lock_identity=[info.st_dev, info.st_ino], state_root=str(state_root))
            destination = control.CONFIG
            if destination.exists() or destination.is_symlink():
                require(control.UserBridge(config_path=destination).binding() == binding,
                        "A different local account is already bound to shared CI admission.")
            root_directory(destination.parent)
            # Both admissions are held. Publish empty (all slots validated idle)
            # before the binding becomes visible. Interrupted activation blocks
            # new work; it never silently resumes legacy admission.
            control.atomic_write(destination.parent / 'commitments.json', json.dumps(dict(
                version=1, updated_at=time.time(), user_uid=account.pw_uid,
                lock_identity=binding['lock_identity'], claims=[])).encode(), mode=0o644)
            control.atomic_write(destination, json.dumps(binding, sort_keys=True).encode(), mode=0o644)
        finally:
            os.close(descriptor)
