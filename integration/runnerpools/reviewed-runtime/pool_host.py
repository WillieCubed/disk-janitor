"""Protected native host installation and unprivileged worker transport."""

from contextlib import ExitStack, contextmanager
from functools import wraps
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import plistlib
import pwd
import re
import shutil
import signal
import stat
import subprocess
import tarfile
import threading
import tempfile
import time
import uuid
from types import SimpleNamespace

import macos_host
import pool_python
import pool_config as config
import process_control as control
from pool_config import Failure, _unique, load, paths, require, username, validate

TART_VERSION = "2.41.1"
TART_SHA256 = "e680a734febccfce7d4e910c1f7f13fc3b00f19a181c945e2d746de3214c32c2"
PAYLOAD = (
    "runner_pool.py",
    "pool_setup.py",
    "pool_config.py",
    "pool_policy.py",
    "pool_auth.py",
    "pool_vm.py",
    "pool_guest.py",
    "pool_host.py",
    "pool_runtime.py",
    "pool_account.py",
    "pool_python.py",
    "macos_host.py",
    "self_hosted_runner.py",
    "process_control.py",
    "runner_console.py",
    "runner_fleet.py",
    "runner_recovery.py",
    "runner_routing.py",
    "runner_recovery_setup.py",
    "runner_migration.py",
)
_SETUP_LOCKS = threading.local()


@contextmanager
def setup_lock(profile):
    """One per-profile mutation lock, reentrant only on this exact thread."""
    state = paths(profile)["state"]
    key = str(state / "setup.lock")
    active = getattr(_SETUP_LOCKS, "active", None)
    if active is None:
        active = _SETUP_LOCKS.active = set()
    if key in active:
        yield
        return
    protected(state, directory=True)
    with control.file_lock(state / "setup.lock"):
        active.add(key)
        try:
            yield
        finally:
            active.remove(key)


def serialized_setup(function):
    @wraps(function)
    def wrapped(profile, *args, **kwargs):
        with setup_lock(profile):
            require_no_shared_migration(
                profile,
                token=kwargs.get("migration_token")
                if function.__name__ == "activate"
                else None,
            )
            return function(profile, *args, **kwargs)

    return wrapped


def protected(path, *, directory=False, uid=0):
    path = Path(path)
    info = path.lstat()
    require(
        not stat.S_ISLNK(info.st_mode)
        and info.st_uid == uid
        and not info.st_mode & 0o022
        and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)),
        f"Protected host path rejected: {path} (uid={info.st_uid}, mode={stat.S_IMODE(info.st_mode):04o}); expected uid={uid}, no group/other write, and "
        + ("a directory." if directory else "a regular file."),
    )
    return info


def _profile_document(path, *, installed=False):
    """Read one bounded regular profile through the protected filesystem boundary."""
    path = Path(path).expanduser()
    info = path.lstat()
    config.require(
        stat.S_ISREG(info.st_mode)
        and not path.is_symlink()
        and info.st_size <= 1024 * 1024,
        "Profile must be a bounded regular file, not a symlink.",
    )
    if installed:
        protected(path)
    return json.loads(path.read_text(), object_pairs_hook=config._unique)


def read_profile(path, *, installed=False):
    """Validate the complete selected account configuration."""
    return config.validate(_profile_document(path, installed=installed))


def read_profile_identity(path):
    """Read only a protected account identity for scoped discovery."""
    return config.profile_identity(_profile_document(path, installed=True))


def installed_profiles(root, *, read=None, owner_logins=None):
    """Check every protected identity, and fully validate the requested accounts only."""
    read = read or read_profile
    if owner_logins is not None:
        require(
            isinstance(owner_logins, (tuple, list, set, frozenset))
            and bool(owner_logins)
            and all(isinstance(login, str) and login.strip() for login in owner_logins),
            "Select at least one nonempty account login.",
        )
        owner_logins = {login.casefold() for login in owner_logins}
    root = Path(root)
    if not root.exists() and not root.is_symlink():
        return []
    protected(root, directory=True)
    entries = list(root.iterdir())
    config.require(
        len(entries) <= 128,
        "Installed organization discovery is too large; select an explicit --profile.",
    )
    profiles, ids, owners, logins = [], set(), set(), set()
    for entry in sorted(entries):
        if entry.name == "controller-app.json":
            info = protected(entry)
            config.require(
                info.st_nlink == 1 and info.st_size <= 4096,
                "Shared controller registration has unsafe metadata; preserve it and inspect.",
            )
            config.app_reference(
                json.loads(entry.read_text(), object_pairs_hook=config._unique)
            )
            continue
        if entry.name == ".accounts.lock":
            # Native account allocation shares this root-owned lock across
            # organizations. Inspect metadata only; never open, lock or alter it.
            info = protected(entry)
            config.require(
                stat.S_IMODE(info.st_mode) == 0o600
                and info.st_nlink == 1
                and info.st_size == 0,
                "Native account allocation lock has unexpected metadata; preserve it and inspect.",
            )
            continue
        protected(entry, directory=True)
        path = entry / "profile.json"
        profile = (
            read_profile_identity(path)
            if owner_logins is not None
            else read(path, installed=True)
        )
        config.require(
            profile["id"] == entry.name,
            "Installed profile namespace differs from its directory.",
        )
        owner = profile["owner"]
        config.require(
            profile["id"] not in ids
            and owner["id"] not in owners
            and owner["login"].casefold() not in logins,
            "Installed organization identities are duplicated; select and reconcile the exact installation.",
        )
        ids.add(profile["id"])
        owners.add(owner["id"])
        logins.add(owner["login"].casefold())
        if owner_logins is None or owner["login"].casefold() in owner_logins:
            if owner_logins is not None:
                selected = read(path, installed=True)
                require(
                    config.profile_identity(selected) == profile,
                    "Selected account identity changed during discovery; inspect it again.",
                )
                profile = selected
            profiles.append((path, profile))
    return profiles


def root_directory(path, mode=0o755):
    path = Path(path)
    if not path.exists():
        protected(path.parent, directory=True)
        # Bootstrap deliberately inherits umask077. Publish the requested
        # protected mode atomically, without a crash window between mkdir and
        # chmod or modifying any pre-existing directory. Installation is a
        # single-threaded native handoff; the prior process umask is restored.
        previous = os.umask(0o022)
        try:
            try:
                path.mkdir(mode=mode)
            except FileExistsError:
                pass  # Another organization may have created the common parent.
        finally:
            os.umask(previous)
    protected(path, directory=True)
    require(
        stat.S_IMODE(path.stat().st_mode) == mode,
        "Protected host directory mode differs; preserve it.",
    )


def native(argv, context, *, data=None, timeout=60, allowed=(0,)):
    try:
        result = control.run(
            argv,
            input=data,
            timeout=timeout,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
    except (OSError, subprocess.TimeoutExpired) as original:
        error = Failure(
            context + " unavailable or timed out; inspect the exact native service."
        )
        error.check = config.diagnostic_check(context)
        error.native_operation = "native"
        error.native_kind = next(
            (
                kind.__name__
                for kind in (
                    FileNotFoundError,
                    PermissionError,
                    subprocess.TimeoutExpired,
                )
                if isinstance(original, kind)
            ),
            "OSError",
        )
        if (
            isinstance(original, OSError)
            and type(original.errno) is int
            and 0 <= original.errno <= 65535
        ):
            error.native_errno = original.errno
        raise error from None
    if result.returncode not in allowed:
        error = Failure(
            context
            + f" failed (exit {result.returncode}); native output is suppressed."
        )
        error.check = config.diagnostic_check(context)
        error.native_operation = "native"
        if type(result.returncode) is int and -255 <= result.returncode <= 255:
            error.exit_code = result.returncode
        raise error
    return result


def service_spec(profile):
    p = paths(profile)
    return {
        "Label": "com.github.runner-pools." + profile["id"],
        "ProgramArguments": [
            str(pool_python.python_path(profile)),
            "-I",
            "-B",
            str(p["install"] / "runner_pool.py"),
            "daemon",
            "--profile",
            str(p["profile"]),
        ],
        "WorkingDirectory": str(p["install"]),
        "EnvironmentVariables": {
            "HOME": "/var/root",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "PYTHONUNBUFFERED": "1",
        },
        "RunAtLoad": True,
        "KeepAlive": True,
        "SessionCreate": True,
        "StandardOutPath": str(p["state"] / "controller.stdout.log"),
        "StandardErrorPath": str(p["state"] / "controller.stderr.log"),
    }


def validate_pool_health(value):
    """One controller pool record: known states, reasons and bounded facts only."""
    states = {
        "starting",
        "idle",
        "creating",
        "preparing",
        "registered",
        "busy",
        "cleanup-required",
        "blocked",
        "retrying",
        "drained",
        "waiting",
        "unavailable",
    }
    require(
        isinstance(value, dict)
        and set(value)
        <= {
            "state",
            "reason",
            "attempt",
            "retry_at",
            "generation",
            "diagnostics",
            "proof",
            "retrying",
            "prepared",
        }
        and value.get("state") in states
        and (
            "reason" not in value
            or value["reason"]
            in (
                "provider_unavailable",
                "native_unavailable",
                "capacity_unavailable",
                "image_upgrade",
                "provider_finishing",
                "unsafe_state",
                "operation_failed",
                "power_unavailable",
                "thermal_unavailable",
                "memory_unavailable",
                "account_turn",
                "host_capacity",
                "job_disk_exceeded",
                "owner_logged_out",
            )
        )
        and (
            "diagnostics" not in value
            or isinstance(value["diagnostics"], list)
            and len(value["diagnostics"]) <= 32
        )
        and (
            "attempt" not in value
            or type(value["attempt"]) is int
            and 0 <= value["attempt"] <= 3
        )
        and (
            "generation" not in value
            or isinstance(value["generation"], str)
            and re.fullmatch(r"[a-f0-9]{32}", value["generation"])
        )
        and ("retry_at" not in value or type(value["retry_at"]) in (int, float))
        and ("retrying" not in value or type(value["retrying"]) is bool)
        and (
            "prepared" not in value
            or value["prepared"] is True
            and value.get("state") == "idle"
        )
        and (
            "proof" not in value
            or isinstance(value["proof"], dict)
            and set(value["proof"]) == {"generation", "registered_at"}
            and isinstance(value["proof"]["generation"], str)
            and re.fullmatch(r"[a-f0-9]{32}", value["proof"]["generation"])
            and isinstance(value["proof"]["registered_at"], str)
            and re.fullmatch(
                r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value["proof"]["registered_at"]
            )
        ),
        "Controller pool health differs; preserve it.",
    )
    if "diagnostics" in value:
        config.validate_diagnostics(value["diagnostics"])


def inspect_service(profile):
    """Read exact public service identity and fresh health; never open private journals."""
    p, expected = paths(profile), service_spec(profile)
    present = p["plist"].exists() or p["plist"].is_symlink()
    if present:
        info = protected(p["plist"])
        require(
            info.st_size <= 65536
            and info.st_nlink == 1
            and plistlib.loads(p["plist"].read_bytes()) == expected,
            "Existing startup service differs; preserve it.",
        )
    result = native(
        ["/bin/launchctl", "print", "system/" + expected["Label"]],
        "Inspect exact pool controller",
        allowed=(0, 113),
    )
    status = {
        "loaded": result.returncode == 0,
        "pid": None,
        "fresh": False,
        "pools": {},
    }
    if not status["loaded"]:
        return status
    require(
        present, "A controller is loaded without its exact startup file; preserve it."
    )
    lines = {line.strip() for line in result.stdout.splitlines()}
    arguments, reading_arguments = [], False
    for line in result.stdout.splitlines():
        value = line.strip()
        if value == "arguments = {":
            require(
                not reading_arguments and not arguments,
                "Loaded controller arguments are ambiguous; preserve it.",
            )
            reading_arguments = True
        elif reading_arguments:
            if value == "}":
                break
            arguments.append(value)
    require(
        "path = " + str(p["plist"]) in lines
        and "program = " + expected["ProgramArguments"][0] in lines
        and arguments == expected["ProgramArguments"],
        "Loaded controller identity differs; preserve it.",
    )
    pids = re.findall(r"^\s*pid = ([1-9][0-9]*)\s*$", result.stdout, re.MULTILINE)
    if len(pids) != 1:
        return status  # launchd may be waiting to restart the same service.
    status["pid"] = int(pids[0])
    target = p["install"] / "health.json"
    if not target.exists() and not target.is_symlink():
        return status
    info = protected(target)
    require(
        info.st_size <= 65536 and info.st_nlink == 1,
        "Controller health metadata differs; preserve it.",
    )
    health = json.loads(target.read_text(), object_pairs_hook=_unique)
    # An older schema or stale controller is unavailable, never healthy.
    if not isinstance(health, dict) or set(health) != {
        "profile",
        "controller",
        "pools",
    }:
        return status
    controller, pools = health["controller"], health["pools"]
    if not (
        health["profile"] == profile["id"]
        and isinstance(controller, dict)
        and set(controller) == {"pid", "instance", "updated_at"}
        and type(controller["pid"]) is int
        and controller["pid"] == status["pid"]
        and isinstance(controller["instance"], str)
        and re.fullmatch(r"[a-f0-9]{32}", controller["instance"])
        and type(controller["updated_at"]) in (int, float)
        and 0 <= time.time() - controller["updated_at"] <= 20
        and isinstance(pools, dict)
        and set(pools) <= set(profile["pools"])
    ):
        return status
    for value in pools.values():
        validate_pool_health(value)
    status.update(fresh=True, pools=pools)
    return status


def verify_baseline(profile, *, required=True):
    """Validate immutable policy while accounting for protected shared-App adoption."""
    target = paths(profile)["install"] / "baseline-profile.json"
    if not required and not target.exists() and not target.is_symlink():
        return None  # An interrupted first install may not have published it yet.
    for parent in (target.parent.parent, target.parent):
        protected(parent, directory=True)
    info = protected(target)
    require(
        info.st_nlink == 1 and info.st_size <= 2 * 1024 * 1024,
        "Installed baseline profile has unsafe metadata; preserve it.",
    )
    baseline = load(target)
    import pool_policy as policy

    if "github_app" in profile:
        baseline = dict(baseline, github_app=profile["github_app"])
    if "controller_app" in profile and "controller_app" not in baseline:
        require(
            shared_controller_reference() == profile["controller_app"],
            "Added controller identity differs from the protected shared registration.",
        )
        baseline = dict(baseline, controller_app=profile["controller_app"])
    return policy._extension(baseline, profile)[0]


def verify_install(profile):
    p = paths(profile)
    for parent in (p["install"].parent, p["install"]):
        protected(parent, directory=True)
    pool_python.verify(profile)
    protected(p["install"] / "runtime.json")
    receipt = json.loads((p["install"] / "runtime.json").read_text())
    from runner_migration import LEGACY

    require(
        isinstance(receipt, dict)
        and set(receipt) in (LEGACY, frozenset(PAYLOAD))
        and all(
            isinstance(v, str) and re.fullmatch(r"[a-f0-9]{64}", v)
            for v in receipt.values()
        ),
        "Installed runtime receipt differs.",
    )
    for name in receipt:
        target = p["install"] / name
        protected(target)
        require(
            hashlib.sha256(target.read_bytes()).hexdigest() == receipt[name],
            "Installed runtime source differs; drain and deliberately reinstall before activation.",
        )
    verify_baseline(profile)
    protected(p["profile"])
    require(
        load(p["profile"]) == validate(profile),
        "Installed organization profile differs.",
    )
    protected(p["state"], directory=True)


def _public_enrollment_plan(profile):
    """Read one exact protected public intent without touching credentials."""
    target = paths(profile)["install"] / "enrollment.json"
    if not target.exists() and not target.is_symlink():
        return None
    protected(target.parent, directory=True)
    info = protected(target)
    require(
        stat.S_IMODE(info.st_mode) == 0o644
        and info.st_nlink == 1
        and info.st_size <= 2 * 1024 * 1024,
        "Pending enrollment metadata is unsafe; preserve it.",
    )
    plan = json.loads(target.read_text(), object_pairs_hook=_unique)
    require(
        isinstance(plan, dict) and set(plan) == {"before", "after"},
        "Pending enrollment intent is malformed.",
    )
    import pool_policy as policy

    before, after = policy._extension(plan["before"], plan["after"])
    require(
        validate(profile) in (before, after),
        "Pending enrollment belongs to another installed policy.",
    )
    old = {(item["repo"], item["workflow"]): item for item in before["consumers"]}
    changed = [
        item
        for item in after["consumers"]
        if old.get((item["repo"], item["workflow"])) != item
    ]
    require(
        len(changed) == 1,
        "Pending enrollment must identify one exact consumer; preserve its transaction.",
    )
    return {"before": before, "after": after, "consumer": changed[0]}


def pending_enrollment(profile):
    plan = _public_enrollment_plan(profile)
    return None if plan is None else {"consumer": plan["consumer"]}


def prepare_account(profile, owner_home):
    from pool_account import prepare

    return prepare(profile, owner_home)


def image_upgrade_pending(profile, *, public=False):
    p = paths(profile)
    target = p["install" if public else "state"] / "image-upgrade.json"
    if not target.exists() and not target.is_symlink():
        if not public:
            return image_upgrade_pending(profile, public=True)
        return False
    info = protected(target)
    require(
        info.st_nlink == 1 and info.st_size <= 262144,
        "Image replacement marker is unsafe; preserve it.",
    )
    value = json.loads(target.read_text(), object_pairs_hook=_unique)
    require(
        isinstance(value, dict)
        and value.get("schema_version") == 1
        and value.get("stage")
        in (
            "planned",
            "staging",
            "verified",
            "quiescing",
            "publishing",
            "resuming",
            "complete",
        ),
        "Image replacement marker is invalid; preserve it.",
    )
    identity = value.get("profile") if public else value.get("before", {}).get("id")
    require(
        identity == profile["id"],
        "Image replacement belongs to another account; preserve it.",
    )
    return value["stage"] != "complete"


def shared_migration_pending(profile):
    marker = paths(profile)["install"] / "shared-controller-migration.json"
    if not marker.exists() and not marker.is_symlink():
        # Native callers also catch an interrupted first checkpoint from older
        # candidates; only the migration can reconstruct its public mirror.
        private = paths(profile)["state"] / "shared-controller-migration.json"
        if os.geteuid() == 0 and (private.exists() or private.is_symlink()):
            protected(private)
            return True
        return False
    info = protected(marker)
    require(info.st_size <= 131072, "Shared migration receipt exceeds its bound.")
    value = json.loads(marker.read_text(), object_pairs_hook=config._unique)
    require(
        isinstance(value, dict)
        and value.get("schema_version") == 1
        and value.get("profile") == profile["id"]
        and value.get("stage")
        in (
            "prepared",
            "quiesced",
            "stopped",
            "recovering",
            "publishing",
            "resuming",
            "complete",
        ),
        "Shared controller migration receipt is invalid; preserve it.",
    )
    return value["stage"] != "complete"


def require_no_shared_migration(profile, *, token=None):
    if not shared_migration_pending(profile):
        return
    if token is not None:
        private = paths(profile)["state"] / "shared-controller-migration.json"
        info = protected(private)
        require(
            info.st_size <= 131072,
            "Private shared migration receipt exceeds its bound.",
        )
        value = json.loads(private.read_text(), object_pairs_hook=config._unique)
        require(
            isinstance(token, str)
            and re.fullmatch(r"[a-f0-9]{32}", token)
            and value.get("token") == token
            and value.get("stage") == "resuming"
            and value.get("after") == profile,
            "Only the owning shared migration may activate its verified replacement.",
        )
        return
    raise Failure(
        "Finish the shared controller migration with hypertext runners migrate --org "
        + profile["owner"]["login"]
        + " --shared-app --apply before changing runners."
    )


def require_no_image_upgrade(profile, *, allow_shared_migration=False):
    if not allow_shared_migration:
        require_no_shared_migration(profile)
    require(
        not image_upgrade_pending(profile),
        "Finish the pending image replacement before changing this account profile or runtime.",
    )


def publish_unactivated_runtime(profile, contents, *, allow_configured=False):
    """Publish reviewed setup source only while the installation is inactive.

    Configured installations require explicit repair and confirmed idle slots.
    Interrupted generations are reconciled before source publication. Operating
    installations remain outside this boundary.
    """
    require_no_image_upgrade(profile)
    require(
        type(allow_configured) is bool,
        "Runtime repair permission must be an explicit boolean.",
    )
    # Preserve the initial-setup boundary before entering any native operation.
    if not allow_configured:
        require(
            "github_app" not in profile,
            "Configured runtime source differs; preserve it for an explicit drained upgrade.",
        )
    with setup_lock(profile), ExitStack() as locks:
        require_no_image_upgrade(profile)
        if allow_configured:
            p = paths(profile)
            for name in (
                "controller.lock",
                *(platform + ".lock" for platform in sorted(profile["pools"])),
            ):
                locks.enter_context(control.file_lock(p["state"] / name))
        _publish_unactivated_runtime(
            profile, contents, allow_configured=allow_configured
        )


def _repair_slot_records(profile):
    """Decode every existing journal before any recovery or source mutation."""
    from pool_runtime import Runtime
    import runner_fleet as fleet

    slots = paths(profile)["state"] / "slots"
    if not slots.exists() and not slots.is_symlink():
        return []
    info = protected(slots, directory=True)
    # _read is the authoritative strict journal decoder and has no side effects.
    reader = object.__new__(Runtime)
    reader.uid = info.st_uid
    expected = {platform + ".json" for platform in profile["pools"]}
    records = []
    for path in slots.iterdir():
        require(
            path.name in expected,
            "Unknown slot file prevents preactivation runtime repair; preserve it.",
        )
        record = reader._read(path)
        require(
            record is not None, "Runtime repair slot disappeared; preserve its state."
        )
        require(
            record["profile_id"] == profile["id"] and record["platform"] == path.stem,
            "Runtime repair slot belongs to another pool; preserve its state.",
        )
        if record["state"] != "idle":
            parsed = fleet.parse_runner(
                record["name"], profile["id"], record["platform"]
            )
            require(
                parsed is not None
                and parsed["host_id"] == profile.get("fleet", {}).get("host_id"),
                "Runtime repair slot belongs to another host; its runner and build environment were preserved.",
            )
        records.append(record)
    return records


def _idle_repair_slots(profile):
    require(
        all(record["state"] == "idle" for record in _repair_slot_records(profile)),
        "Runtime repair requires every existing slot to be idle; preserve its generation.",
    )


def _recover_repair_slots(profile):
    records = _repair_slot_records(profile)
    if all(record["state"] == "idle" for record in records):
        return
    from pool_auth import GitHubApp
    from pool_runtime import Runtime

    p = paths(profile)
    # Existing worker bytes are verified before this function is called. No
    # source changes until provider removal and native cleanup are confirmed.
    runtime = Runtime(
        profile,
        p["state"],
        GitHubApp(profile, p["state"]).api,
        Worker(profile),
        storage_uid=protected(p["state"], directory=True).st_uid,
        health=lambda status: None,
    )  # The host-control stdout remains one JSON object.
    for record in records:
        if record["state"] != "idle":
            # publish_unactivated_runtime owns every platform lock already.
            # Reuse the broker's recovery body without reacquiring that lock.
            result = runtime._recover(record["platform"])
            platform_name = {"linux": "Linux", "macos": "macOS"}[record["platform"]]
            require(
                result.get("state") == "idle",
                platform_name + " runner is busy. Its job will keep running. "
                "Continue setup when it finishes.",
            )
    _idle_repair_slots(profile)


def validate_maintenance(plan, profile):
    require(
        isinstance(plan, dict)
        and set(plan)
        == {"schema_version", "profile", "before", "after", "token", "stage"}
        and type(plan["schema_version"]) is int
        and plan["schema_version"] == 1
        and plan["profile"] == profile
        and isinstance(plan["token"], str)
        and re.fullmatch("[a-f0-9]{32}", plan["token"]) is not None
        and plan["stage"] in ("draining", "stopped", "restoring", "resuming"),
        "Runner recovery intent does not match this organization; existing state was preserved.",
    )
    for key in ("before", "after"):
        require(
            isinstance(plan[key], dict)
            and set(plan[key]) == set(PAYLOAD)
            and all(
                isinstance(v, str) and re.fullmatch("[a-f0-9]{64}", v)
                for v in plan[key].values()
            ),
            "Runner recovery source receipt is invalid; existing state was preserved.",
        )
    return plan


def _maintenance_read(path, profile):
    info = protected(path)
    require(
        info.st_nlink == 1 and info.st_size <= 65536,
        "Runner recovery record has unsafe metadata.",
    )
    return validate_maintenance(
        json.loads(path.read_text(), object_pairs_hook=_unique), profile
    )


def maintenance_update_required(profile, status, *, enrollment=False):
    """Decide from public health before prompting; root repeats every check."""
    require(
        type(enrollment) is bool, "Pending enrollment eligibility must be explicit."
    )
    if not status.get("loaded"):
        p = paths(profile)
        require(
            not any(
                marker.exists() or marker.is_symlink()
                for marker in (p["plist"], p["install"] / "health.json")
            ),
            "The runner startup state is unavailable; its service and recovery records were preserved.",
        )
        return False  # Preserve the existing preactivation repair path.
    require(
        status.get("fresh")
        and set(status.get("pools", {})) == set(profile["pools"])
        and all(
            value.get("state")
            in (
                "idle",
                "waiting",
                "blocked",
                "unavailable",
                "preparing",
                "creating",
                "starting",
                "retrying",
            )
            or (enrollment and value.get("state") == "drained")
            for value in status["pools"].values()
        ),
        "The runner controller is active, deliberately paused, or its state is stale; "
        "existing jobs and pauses were preserved. Continue the update when it is idle.",
    )
    return True


def _maintenance_save(profile, plan, stage):
    plan = validate_maintenance(dict(plan, stage=stage), profile)
    raw = (json.dumps(plan, sort_keys=True) + "\n").encode()
    p = paths(profile)
    # Private intent precedes its public discovery marker and every native change.
    for target, mode in (
        (p["state"] / "maintenance.json", 0o600),
        (p["install"] / "maintenance.json", 0o644),
    ):
        if target.exists() or target.is_symlink():
            _maintenance_read(target, profile)
        control.atomic_write(target, raw, mode=mode)
    return plan


def _maintenance_sources(profile, contents, plan):
    p = paths(profile)
    after = {
        name: hashlib.sha256(content).hexdigest() for name, content in contents.items()
    }
    require(
        set(after) == set(PAYLOAD) and after == plan["after"],
        "A different runner update is pending; its original recovery transaction was preserved.",
    )
    saved = p["install"] / "runtime.json"
    protected(saved)
    actual = json.loads(saved.read_text(), object_pairs_hook=_unique)
    require(
        actual in (plan["before"], plan["after"]),
        "Installed runtime receipt changed outside runner recovery.",
    )
    mixed = False
    for name in PAYLOAD:
        target = p["install"] / name
        protected(target)
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        require(
            digest in (plan["before"][name], plan["after"][name]),
            "Installed source changed outside runner recovery; the controller and images were preserved.",
        )
        mixed = mixed or digest != actual[name]
    if mixed:
        target = p["state"] / "runtime-repair.json"
        protected(target)
        require(
            json.loads(target.read_text(), object_pairs_hook=_unique)
            == {k: plan[k] for k in ("before", "after")},
            "Partial source publication does not match the saved recovery transaction.",
        )


def _restart_lost_repair_pause(profile, contents, plan):
    """Re-quiesce an unchanged original runtime whose stopped intent lost its pause."""
    p = paths(profile)
    public = p["install"] / "maintenance.json"
    require(
        public.exists() and _maintenance_read(public, profile) == plan,
        "Runner recovery records disagree; preserve the installation and inspect.",
    )
    require(
        not any(
            path.exists() or path.is_symlink()
            for path in (
                p["state"] / "runtime-repair.json",
                p["state"] / "enrollment.json",
                p["install"] / "enrollment.json",
            )
        ),
        "Another publication or enrollment intent must finish before restoring the runner pause.",
    )
    verify_install(profile)
    require(
        json.loads(
            (p["install"] / "runtime.json").read_text(), object_pairs_hook=_unique
        )
        == plan["before"],
        "Runner source was already published; preserve its missing-pause transaction.",
    )
    original = {name: (p["install"] / name).read_bytes() for name in PAYLOAD}
    _maintenance_sources(profile, original, dict(plan, after=plan["before"]))
    status = inspect_service(profile)
    require(
        not status["loaded"]
        or (
            status["fresh"]
            and set(status["pools"]) == set(profile["pools"])
            and all(
                value["state"]
                in ("idle", "waiting", "blocked", "drained", "unavailable")
                for value in status["pools"].values()
            )
        ),
        "The original runner controller is active or stale; its jobs were preserved.",
    )
    processes = native(
        ["/bin/ps", "-axo", "pid=,command="],
        "Check workers before restoring runner pause",
    )
    pattern = re.compile(
        re.escape(str(p["install"] / "runner_pool.py")) + r"\s+worker\b"
    )
    require(
        not any(pattern.search(line) for line in processes.stdout.splitlines()),
        "A runner worker is still active; its process and build environment were preserved.",
    )
    _repair_slot_records(profile)
    with control.file_lock(p["state"].parent / ".resources.lock"):
        drain = p["state"] / "drain"
        require(
            not drain.exists() and not drain.is_symlink(),
            "Runner pause changed during recovery; the existing pause was preserved.",
        )
        # Keep a resumable intent before restoring admission exclusion. Source
        # stays original until the ordinary provider checks and shutdown finish.
        plan = _maintenance_save(
            profile,
            dict(
                plan,
                after={
                    name: hashlib.sha256(raw).hexdigest()
                    for name, raw in contents.items()
                },
            ),
            "draining",
        )
        control.atomic_write(drain, (plan["token"] + "\n").encode(), mode=0o600)
    return plan


@serialized_setup
def begin_blocked_repair(profile, contents):
    """Quiesce a reviewed idle or blocked fleet; preserve exact interrupted publication."""
    require_no_image_upgrade(profile)
    p = paths(profile)
    require(
        os.geteuid() == protected(p["state"], directory=True).st_uid,
        "Runner recovery requires the existing protected host identity.",
    )
    private, public, drain = (
        p["state"] / "maintenance.json",
        p["install"] / "maintenance.json",
        p["state"] / "drain",
    )
    if private.exists() or private.is_symlink():
        plan = _maintenance_read(private, profile)
        if plan["stage"] == "stopped" and not drain.exists() and not drain.is_symlink():
            plan = _restart_lost_repair_pause(profile, contents, plan)
        candidate = {
            name: hashlib.sha256(content).hexdigest()
            for name, content in contents.items()
        }
        if candidate != plan["after"] and plan["stage"] == "restoring":
            # A fully published candidate whose controller never verifies
            # startup cannot finish. Its bytes are now the installed original:
            # drain again under the owned pause and update from them.
            require(
                set(candidate) == set(PAYLOAD),
                "A different runner update is pending; its original recovery transaction was preserved.",
            )
            protected(drain)
            require(
                drain.read_text() == plan["token"] + "\n",
                "Runner pause belongs to another operation; it was preserved.",
            )
            pending = p["state"] / "runtime-repair.json"
            require(
                not pending.exists() and not pending.is_symlink(),
                "Source publication journal changed; its original recovery candidate was preserved.",
            )
            require(
                json.loads(
                    (p["install"] / "runtime.json").read_text(),
                    object_pairs_hook=_unique,
                )
                == plan["after"],
                "Runner source update is incomplete; its original recovery candidate was preserved.",
            )
            installed = {name: (p["install"] / name).read_bytes() for name in PAYLOAD}
            _maintenance_sources(profile, installed, dict(plan, before=plan["after"]))
            plan = _maintenance_save(
                profile, dict(plan, before=plan["after"], after=candidate), "draining"
            )
        if candidate != plan["after"] and plan["stage"] == "draining":
            # Draining publishes nothing; it runs the installer's own provider
            # checks. A candidate whose checks fail would otherwise hold this
            # transaction before 'stopped', where a correction is accepted.
            require(
                set(candidate) == set(PAYLOAD),
                "A different runner update is pending; its original recovery transaction was preserved.",
            )
            if drain.exists() or drain.is_symlink():
                protected(drain)
                require(
                    drain.read_text() == plan["token"] + "\n",
                    "Runner pause belongs to another operation; it was preserved.",
                )
            pending = p["state"] / "runtime-repair.json"
            require(
                not pending.exists() and not pending.is_symlink(),
                "Source publication journal exists before shutdown; its original recovery candidate was preserved.",
            )
            require(
                json.loads(
                    (p["install"] / "runtime.json").read_text(),
                    object_pairs_hook=_unique,
                )
                == plan["before"],
                "Runner source was already published; its original recovery candidate was preserved.",
            )
            installed = {name: (p["install"] / name).read_bytes() for name in PAYLOAD}
            _maintenance_sources(profile, installed, dict(plan, after=plan["before"]))
            plan = _maintenance_save(profile, dict(plan, after=candidate), "draining")
        if candidate != plan["after"]:
            # A failed installer may need corrected code before any publication.
            # Never retarget a running, partly published or resumed transaction.
            require(
                plan["stage"] == "stopped" and set(candidate) == set(PAYLOAD),
                "A different runner update is pending; its original recovery transaction was preserved.",
            )
            protected(drain)
            require(
                drain.read_text() == plan["token"] + "\n",
                "Runner pause belongs to another operation; it was preserved.",
            )
            require(
                not inspect_service(profile)["loaded"],
                "A runner controller is active; its recovery candidate was preserved.",
            )
            label = service_spec(profile)["Label"]
            require(
                native(
                    ["/bin/launchctl", "print", "system/" + label],
                    "Verify stopped recovery before updating candidate",
                    allowed=(0, 113),
                    timeout=5,
                ).returncode
                == 113,
                "macOS still lists the controller; its recovery candidate was preserved.",
            )
            processes = native(
                ["/bin/ps", "-axo", "pid=,command="],
                "Check workers before updating recovery candidate",
            )
            pattern = re.compile(
                re.escape(str(p["install"] / "runner_pool.py")) + r"\s+worker\b"
            )
            require(
                not any(pattern.search(line) for line in processes.stdout.splitlines()),
                "A runner worker is still active; its recovery candidate was preserved.",
            )
            installed = {name: (p["install"] / name).read_bytes() for name in PAYLOAD}
            _maintenance_sources(profile, installed, dict(plan, after=plan["before"]))
            _repair_slot_records(profile)
            pending = p["state"] / "runtime-repair.json"
            if pending.exists() or pending.is_symlink():
                protected(pending)
                require(
                    json.loads(pending.read_text(), object_pairs_hook=_unique)
                    == {k: plan[k] for k in ("before", "after")},
                    "Source publication journal changed; its original recovery candidate was preserved.",
                )
                # Publication can stop after journaling but before copying a
                # byte. All original bytes were verified above: retire only
                # that zero-byte intent before saving the corrected candidate.
                pending.unlink()
            plan = _maintenance_save(profile, dict(plan, after=candidate), "stopped")
    elif public.exists() or public.is_symlink():
        plan = _maintenance_read(public, profile)
        require(
            plan["stage"] == "resuming",
            "Private runner recovery intent is missing; existing state was preserved.",
        )
        _maintenance_sources(profile, contents, plan)
        plan = _maintenance_save(profile, plan, "resuming")
    else:
        verify_install(profile)
        require(
            not drain.exists() and not drain.is_symlink(),
            "Runners were deliberately paused; automatic recovery will not undo that pause.",
        )
        require(
            not (p["state"] / "enrollment.json").exists()
            and not (p["install"] / "enrollment.json").exists(),
            "Repository enrollment must finish before replacing runner tools.",
        )
        status = inspect_service(profile)
        require(
            maintenance_update_required(profile, status),
            "The runner controller is unavailable; preserve its existing startup state.",
        )
        _repair_slot_records(profile)
        before = json.loads(
            (p["install"] / "runtime.json").read_text(), object_pairs_hook=_unique
        )
        plan = dict(
            schema_version=1,
            profile=profile,
            before=before,
            after={k: hashlib.sha256(v).hexdigest() for k, v in contents.items()},
            token=uuid.uuid4().hex,
            stage="draining",
        )
        _maintenance_sources(profile, contents, validate_maintenance(plan, profile))
        plan = _maintenance_save(profile, plan, "draining")
    _maintenance_sources(profile, contents, plan)
    if drain.exists() or drain.is_symlink():
        protected(drain)
        require(
            drain.read_text() == plan["token"] + "\n",
            "Runner pause belongs to another operation; it was preserved.",
        )
    else:
        require(
            plan["stage"] in ("draining", "resuming"),
            "Runner recovery lost its owned admission pause.",
        )
        if plan["stage"] == "draining":
            with control.file_lock(p["state"].parent / ".resources.lock"):
                # Ordinary manual drain shares this lock, not setup.lock.
                # It may have won after the earlier absence observation.
                if drain.exists() or drain.is_symlink():
                    protected(drain)
                    require(
                        drain.read_text() == plan["token"] + "\n",
                        "Runner pause belongs to another operation; it was preserved.",
                    )
                else:
                    control.atomic_write(
                        drain, (plan["token"] + "\n").encode(), mode=0o600
                    )
    if plan["stage"] in ("restoring", "resuming"):
        return plan
    status = inspect_service(profile)
    if status["loaded"]:
        require(
            plan["stage"] == "draining"
            and status["fresh"]
            and set(status["pools"]) == set(profile["pools"])
            and all(
                v["state"]
                in (
                    "idle",
                    "waiting",
                    "blocked",
                    "drained",
                    "unavailable",
                    "preparing",
                    "creating",
                    "starting",
                    "retrying",
                )
                for v in status["pools"].values()
            ),
            "A runner became active during recovery; its job was preserved.",
        )
    from pool_auth import GitHubApp
    from pool_runtime import Runtime
    import pool_policy as policy

    with ExitStack() as locks:
        for platform in sorted(profile["pools"]):
            # The owned pause is already written, so preparation stops at its
            # next safe point and releases this lock; a job never holds it.
            locks.enter_context(
                control.file_lock(
                    p["state"] / (platform + ".lock"), wait=PREPARATION_PAUSE_WAIT
                )
            )
        records = _repair_slot_records(profile)
        api = GitHubApp(profile, p["state"]).api
        runtime = Runtime(
            profile,
            p["state"],
            api,
            Worker(profile),
            storage_uid=protected(p["state"], directory=True).st_uid,
            health=lambda _: None,
        )

        def check_workers():
            processes = native(
                ["/bin/ps", "-axo", "pid=,command="],
                "Check runner workers before recovery",
            )
            pattern = re.compile(
                re.escape(str(p["install"] / "runner_pool.py")) + r"\s+worker\b"
            )
            require(
                not any(pattern.search(line) for line in processes.stdout.splitlines()),
                "A runner worker is still active; its process and build environment were preserved.",
            )

        check_workers()
        import runner_fleet as fleet

        groups = policy.inspect(profile, api, strict_selectors=False)["groups"]
        for platform, group in groups.items():
            require(
                isinstance(group, dict) and type(group.get("id")) is int,
                "A configured runner group is missing during recovery.",
            )
            rows = policy.pool_runners(profile, api, platform, group["id"])
            expected = {
                r["name"]
                for r in records
                if r["state"] != "idle" and r["platform"] == platform
            }
            for row in rows:
                parsed = fleet.parse_runner(row.get("name"), profile["id"], platform)
                require(
                    parsed is not None,
                    "GitHub reports an unrecognized runner; its job and build environment were preserved.",
                )
                if parsed["host_id"] not in (
                    None,
                    profile.get("fleet", {}).get("host_id"),
                ):
                    require(
                        "fleet" in profile,
                        "A fleet runner shares a non-fleet pool; its build environment was preserved.",
                    )
                    continue  # The other Mac owns this valid fleet generation.
                require(
                    row.get("busy") is False and row.get("name") in expected,
                    "GitHub reports an active or unjournaled runner; its job and build environment were preserved.",
                )
        for record in records:
            if record["state"] != "idle":
                runtime._unregister_idle(
                    record
                )  # Close scheduler admission before stopping the controller.
        check_workers()
        label = service_spec(profile)["Label"]
        if status["loaded"]:
            native(
                ["/bin/launchctl", "bootout", "system/" + label],
                "Stop the idle runner controller for its reviewed update",
            )
        # bootout may return before launchd removes the service definition.
        # Observe completion without repeating shutdown or killing any process.
        deadline = time.monotonic() + 30
        while (
            native(
                ["/bin/launchctl", "print", "system/" + label],
                "Verify runner controller stopped",
                allowed=(0, 113),
                timeout=5,
            ).returncode
            != 113
        ):
            require(
                time.monotonic() < deadline,
                "macOS still lists the runner controller after 30 seconds of shutdown. "
                "Runner tools were not replaced; the admission pause and recovery records are saved.",
            )
            time.sleep(1)
        check_workers()
        with control.file_lock(p["state"] / "controller.lock"):
            plan = _maintenance_save(profile, plan, "stopped")
            if p["plist"].exists() or p["plist"].is_symlink():
                protected(p["plist"])
                require(
                    plistlib.loads(p["plist"].read_bytes()) == service_spec(profile),
                    "The startup service changed during recovery.",
                )
                p["plist"].unlink()
            health = p["install"] / "health.json"
            if health.exists() or health.is_symlink():
                protected(health)
                require(
                    json.loads(health.read_text(), object_pairs_hook=_unique).get(
                        "profile"
                    )
                    == profile["id"],
                    "Controller health belongs to another organization; it was preserved.",
                )
                health.unlink()
    return plan


def _maintenance_preflight(profile, plan):
    try:
        return config.preflight_disk(profile)
    except config.DiskSpaceFailure as error:
        drain = paths(profile)["state"] / "drain"
        paused = False
        if drain.exists() or drain.is_symlink():
            protected(drain)
            require(
                drain.read_text() == plan["token"] + "\n",
                "Runner pause changed during recovery; it was preserved.",
            )
            paused = True
        raise config.DiskSpaceFailure(error.snapshot, recovery_paused=paused) from None


SUPPORT_FIELDS = {
    "time": int,
    "event": str,
    "platform": str,
    "tart_version": str,
    "image": str,
    "network": str,
    "free_bytes": int,
    "vm": str,
    "attempt": int,
    "outcome": str,
    "boot_tail": str,
    "tart_tail": str,
}


def publish_support(profile):
    """Republish each platform's private support ring for operators, revalidated and redacted.

    The worker writes the ring in the runner account's private home. Only
    known fields cross, guest and Tart text is redacted again, and the result
    is readable without administrator access.
    """
    import pool_vm

    p = paths(profile)
    uid = pwd.getpwnam(username(profile)).pw_uid
    platforms = {}
    for platform, pool in profile["pools"].items():
        root = p["home"] / "pool-vms" / platform
        if pool.get("image_revision"):
            root = root / "images" / pool["image_revision"]
        entries = []
        try:
            info = (root / "support.json").lstat()
            raw = []
            if (
                stat.S_ISREG(info.st_mode)
                and info.st_uid == uid
                and info.st_size <= 65536
            ):
                raw = json.loads(
                    (root / "support.json").read_text(), object_pairs_hook=_unique
                )
            for value in raw[-pool_vm.SUPPORT_LIMIT :] if isinstance(raw, list) else []:
                if not isinstance(value, dict):
                    continue
                entry = {}
                for key, kind in SUPPORT_FIELDS.items():
                    item = value.get(key)
                    if type(item) is not kind:
                        continue
                    if key in ("boot_tail", "tart_tail"):
                        item = pool_vm.support_redact(item)
                    elif kind is str:
                        item = (
                            item[:256]
                            if all(32 <= ord(ch) < 127 for ch in item)
                            else "?"
                        )
                    entry[key] = item
                entries.append(entry)
        except (OSError, ValueError):
            entries = []
        platforms[platform] = entries
    target = p["install"] / "support.json"
    content = (
        json.dumps({"profile": profile["id"], "platforms": platforms}, sort_keys=True)
        + "\n"
    ).encode()
    if target.exists() and not target.is_symlink() and target.read_bytes() == content:
        return False
    control.atomic_write(target, content, mode=0o644)
    return True


def recovery_converged(profile, receipt):
    """True when recovery has nothing to do, so a rerun writes nothing."""
    p = paths(profile)
    if any(
        path.exists() or path.is_symlink()
        for path in (
            p["state"] / "maintenance.json",
            p["install"] / "maintenance.json",
            p["state"] / "runtime-repair.json",
        )
    ):
        return False
    saved = p["install"] / "runtime.json"
    protected(saved)
    if json.loads(saved.read_text(), object_pairs_hook=_unique) != receipt:
        return False
    status = inspect_service(profile)
    return bool(
        status["loaded"]
        and status["fresh"]
        and set(status["pools"]) == set(profile["pools"])
        and all(
            v["state"] not in ("blocked", "cleanup-required")
            for v in status["pools"].values()
        )
    )


def rollback_unstarted_repair(profile):
    """Undo a refused update that changed nothing, so the account is as it was.

    Only a draining transaction qualifies: its own pause, a loaded controller,
    the original receipt and no publication journal. Anything else is kept
    for the next run to resume.
    """
    p = paths(profile)
    private, public, drain = (
        p["state"] / "maintenance.json",
        p["install"] / "maintenance.json",
        p["state"] / "drain",
    )
    try:
        if not private.exists():
            return False
        plan = _maintenance_read(private, profile)
        receipt = json.loads(
            (p["install"] / "runtime.json").read_text(), object_pairs_hook=_unique
        )
        journal = p["state"] / "runtime-repair.json"
        if (
            plan["stage"] != "draining"
            or receipt != plan["before"]
            or journal.exists()
            or journal.is_symlink()
            or not inspect_service(profile)["loaded"]
        ):
            return False
        with control.file_lock(p["state"].parent / ".resources.lock"):
            if drain.exists() or drain.is_symlink():
                protected(drain)
                if drain.read_text() != plan["token"] + "\n":
                    return False
                drain.unlink()
            # The public marker goes first: a private intent alone still resumes.
            for target in (public, private):
                if target.exists() or target.is_symlink():
                    _maintenance_read(target, profile)
                    target.unlink()
        return True
    except (Failure, OSError, ValueError):
        return False  # Never mask the refusal that is being reported.


# Seconds an update waits for idle preparation to release its pool. A
# controller with pause-aware preparation stops within seconds; an older one
# finishes its current attempt (three boots of up to 130 seconds each) first.
PREPARATION_PAUSE_WAIT = 1200
IMAGE_BUDGET = 20 * 1024**3  # One download of the macOS base image (18 GiB measured).
BOOT_BUDGET = 5 * 1024**3  # One account's base preparation and proof guest writes.


def retire_account_macos(profile):
    """Remove what the runner account kept for macOS guests; return the bytes freed.

    macOS guests now run in the owner's session, so the account's own macOS
    base, image download, guest journals and keychain are no longer used.
    Nothing is removed while the account's macOS slot holds a generation.
    """
    p = paths(profile)
    freed = 0
    for name in ("macos.keychain", "macos.boot-proof.json"):
        path = p["state"] / name
        if path.is_file() and not path.is_symlink():
            freed += _allocated(path.lstat())
            path.unlink()
    slot = p["state"] / "slots/macos.json"
    if slot.exists():
        try:
            if json.loads(slot.read_text()).get("state") != "idle":
                return freed
        except (OSError, ValueError):
            return freed
    try:
        user = pwd.getpwnam(username(profile))
        home = os.open(p["home"], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except (KeyError, FileNotFoundError):
        return freed
    descriptors = [home]
    try:
        if os.fstat(home).st_uid != user.pw_uid:
            return freed

        def child(parent, name):
            try:
                descriptor = os.open(
                    name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
                )
            except (FileNotFoundError, NotADirectoryError, OSError):
                return None
            descriptors.append(descriptor)
            return descriptor if os.fstat(descriptor).st_uid == user.pw_uid else None

        library = child(home, "Library")
        keychains = child(library, "Keychains") if library is not None else None
        if keychains is not None:
            freed += _discard_at(keychains, "login.keychain-db")
        vms_parent = child(home, ".tart")
        if vms_parent is not None:
            vms = child(vms_parent, "vms")
            if vms is not None:
                for name in os.listdir(vms):
                    if re.fullmatch(
                        re.escape(profile["id"]) + r"-macos-(?:base|seed|[0-9a-f]{32})",
                        name,
                    ):
                        freed += _discard_at(vms, name)
            source = profile["pools"].get("macos", {}).get("image_source", "")
            parts = source.split("@", 1)[0].split("/")
            cache = child(vms_parent, "cache")
            cache = child(cache, "OCIs") if cache is not None else None
            for part in parts[:-1]:
                if cache is None or part in ("", ".", ".."):
                    cache = None
                    break
                cache = child(cache, part)
            if cache is not None and parts[-1] not in ("", ".", ".."):
                freed += _discard_at(cache, parts[-1])
        pool_vms = child(home, "pool-vms")
        if pool_vms is not None:
            freed += _discard_at(pool_vms, "macos")
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    return freed


def macos_owner_session(profile, owner_home):
    """Hand this account's macOS guests to the owner's logged-in session.

    The owner is recorded, their private guest directory receives an APFS
    clone of the shared image, and the runner account's macOS leftovers are
    removed. The first macOS job's guest is the boot proof.
    """
    if "macos" not in profile["pools"]:
        return {}
    record_owner_session(profile, owner_home)
    session = owner_session(profile)
    reclaimed = retire_account_macos(profile)
    home = prepare_agent_home(profile, session)
    reserve = max(20, profile["min_free_gib"]) * 1024**3
    free = shutil.disk_usage(home).free
    shared = shared_image_bytes(profile, "macos") is not None
    required = reserve + BOOT_BUDGET + (0 if shared else IMAGE_BUDGET)
    result = {"reclaimed_bytes": reclaimed}
    if free < required:
        result["macos_boot_proof"] = {
            "result": "fail",
            "code": "disk_budget",
            "available_bytes": free,
            "required_bytes": required,
            "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        return result
    try:
        ensure_shared_image(
            profile,
            "macos",
            lambda argv, timeout: native(
                argv, "Prepare the shared macOS image", timeout=timeout
            ),
            home=home,
            account=SimpleNamespace(pw_uid=session["uid"], pw_gid=session["gid"]),
        )
    except (Failure, OSError):
        pass  # The controller prepares it before the first macOS job.
    return result


def reclaim_runner_storage(profile):
    """Prune the runner account's pulled image caches; never a VM or a record.

    The dedicated account's Tart caches hold only images this tool pulled by
    pinned digest, and every Tart call disables automatic pruning. A base or
    clone never depends on them, and a later preparation pulls again.
    """
    p = paths(profile)
    home, user = p["home"], username(profile)
    try:
        info = home.lstat()
    except FileNotFoundError:
        free = shutil.disk_usage(home.parent).free
        return {"reclaimed_bytes": 0, "available_bytes": free}
    try:
        owner = pwd.getpwnam(user).pw_uid
    except KeyError:
        owner = None
    require(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == owner
        and not info.st_mode & 0o077,
        "Runner storage belongs to an unexpected account; it was preserved.",
    )
    tart = p["install"] / "bin/tart.app"
    protected(tart, directory=True)
    before = shutil.disk_usage(home).free
    if not (home / ".tart").exists():
        # The account has never stored a Tart image, so nothing can be reclaimed.
        return {"reclaimed_bytes": 0, "available_bytes": before}
    native(
        [
            "/usr/bin/sudo",
            "-n",
            "-H",
            "-u",
            user,
            "--",
            "/usr/bin/env",
            "-i",
            "HOME=" + str(home),
            "USER=" + user,
            "LOGNAME=" + user,
            "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
            "TART_HOME=" + str(home / ".tart"),
            "TART_NO_AUTO_PRUNE=1",
            str(tart / "Contents/MacOS/tart"),
            "prune",
            "--entries",
            "caches",
            "--space-budget",
            "0",
        ],
        "Reclaim runner image caches",
        timeout=600,
    )
    after = shutil.disk_usage(home).free
    return {"reclaimed_bytes": max(0, after - before), "available_bytes": after}


BOOTSTRAP_STAGE = re.compile(r"\.bootstrap-[0-9a-f]{64}")
IMAGE_STORE = Path("/private/var/db/runner-pool-images")
INSTALL_ROOT = Path("/Library/Application Support/RunnerPools")
IMAGE_FILES = ("config.json", "disk.img", "nvram.bin")
SEED_MARKER = ".runner-pools-image"
SHARED_IMAGE = re.compile(
    r"[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9._/-]+@sha256:([a-f0-9]{64})"
)
_CLONE_NOFOLLOW, _CLONE_NOOWNERCOPY = 0x1, 0x2


class SharedImageBusy(Failure):
    """Another account is downloading the shared base image."""


def _allocated(info):
    return (
        info.st_blocks * 512 if stat.S_ISREG(info.st_mode) and info.st_nlink == 1 else 0
    )


def _remove_tree_at(parent, name):
    """Remove one directory tree through directory handles; return its freed bytes.

    Links are removed, never followed, so a replaced path cannot redirect the
    deletion outside the tree.
    """
    freed = 0
    descriptor = os.open(
        name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
    )
    try:
        for entry in os.listdir(descriptor):
            info = os.stat(entry, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                freed += _remove_tree_at(descriptor, entry)
            else:
                freed += _allocated(info)
                os.unlink(entry, dir_fd=descriptor)
    finally:
        os.close(descriptor)
    os.rmdir(name, dir_fd=parent)
    return freed


def prune_install_snapshots(profile, *, keep=None):
    """Remove superseded root install snapshots; return the bytes freed.

    Each snapshot holds the exact inputs of one install, which reads them only
    while it runs under the account's bootstrap lock. The caller holds that
    lock (the install itself) or has just taken it (the controller), so no
    snapshot it removes can be in use. `keep` names the running install's own.
    """
    install = paths(profile)["install"]
    freed = 0
    parent = os.open(install, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in os.listdir(parent):
            if not BOOTSTRAP_STAGE.fullmatch(name) or name == keep:
                continue
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077
            ):
                continue  # Not a snapshot this install made; leave it.
            freed += _remove_tree_at(parent, name)
    finally:
        os.close(parent)
    return freed


def sweep_install_snapshots(profile):
    """The controller's sweep: remove every snapshot when no install is running."""
    lock = paths(profile)["install"] / ".bootstrap.lock"
    if not lock.exists():
        return 0
    try:
        with control.file_lock(lock):
            return prune_install_snapshots(profile)
    except control.StateError:
        return 0  # An install holds the lock; it prunes its own predecessors.


def _store_tart(profile, *args):
    tart = paths(profile)["install"] / "bin/tart.app"
    verify_tart(tart)
    return [
        "/usr/bin/env",
        "-i",
        "HOME=" + str(IMAGE_STORE / "home"),
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
        "TART_HOME=" + str(IMAGE_STORE / "tart"),
        "TART_NO_AUTO_PRUNE=1",
        str(tart / "Contents/MacOS/tart"),
        *args,
    ]


def _image_name(source):
    return "image-" + SHARED_IMAGE.fullmatch(source)[1]


def _complete_image(directory):
    try:
        return all(
            stat.S_ISREG((directory / name).lstat().st_mode) for name in IMAGE_FILES
        )
    except FileNotFoundError:
        return False


def referenced_images(root=None):
    """Shared base images any installed account still uses, or None if unknown."""
    root = Path(root) if root is not None else INSTALL_ROOT
    names = set()
    try:
        for directory in root.iterdir():
            path = directory / "profile.json"
            if directory.is_symlink() or not path.exists():
                continue
            for pool in load(path)["pools"].values():
                if SHARED_IMAGE.fullmatch(pool.get("image_source", "")):
                    names.add(_image_name(pool["image_source"]))
    except (OSError, ValueError, KeyError, TypeError, Failure):
        return None
    return names


def shared_image_bytes(profile, platform):
    """Bytes the shared base holds for this pool, or None when it is not stored."""
    source = profile["pools"].get(platform, {}).get("image_source", "")
    if platform != "macos" or not SHARED_IMAGE.fullmatch(source):
        return None
    marker = IMAGE_STORE / (_image_name(source) + ".json")
    try:
        value = json.loads(marker.read_text(), object_pairs_hook=_unique)
    except (OSError, ValueError):
        return None
    if (
        not isinstance(value, dict)
        or value.get("image") != source
        or type(value.get("allocated_bytes")) is not int
        or not _complete_image(IMAGE_STORE / "tart/vms" / _image_name(source))
    ):
        return None
    return value["allocated_bytes"]


def ensure_shared_image(profile, platform, spawn, *, home=None, account=None):
    """Keep one root-owned macOS base on disk and give this account a clone of it.

    Root downloads the digest-pinned image once into its own store and never
    starts it. Each runner account receives an APFS clone, so the accounts
    share the image's blocks and each guest's writes stay in its own account.
    `spawn(argv, timeout)` runs one store command and lets its caller stop it.
    Returns None when this pool does not use a shared image.
    """
    source = profile["pools"][platform].get("image_source", "")
    if platform != "macos" or not SHARED_IMAGE.fullmatch(source):
        return None
    root_directory(IMAGE_STORE.parent)
    root_directory(IMAGE_STORE, 0o700)
    for name in ("tart", "home"):
        root_directory(IMAGE_STORE / name, 0o700)
    name = _image_name(source)
    try:
        with control.file_lock(IMAGE_STORE / ".lock"):
            canonical = IMAGE_STORE / "tart/vms" / name
            pulled = False
            allocated = shared_image_bytes(profile, platform)
            if allocated is None:
                spawn(_store_tart(profile, "pull", source), 3600)
                if canonical.exists() or canonical.is_symlink():
                    spawn(_store_tart(profile, "delete", name), 300)
                spawn(_store_tart(profile, "clone", source, name), 900)
                # The local image now holds every block; the download cache is
                # only a second name for them.
                spawn(
                    _store_tart(
                        profile, "prune", "--entries", "caches", "--space-budget", "0"
                    ),
                    600,
                )
                require(
                    _complete_image(canonical),
                    "The shared macOS image is incomplete after download.",
                )
                allocated = sum(
                    (canonical / item).lstat().st_blocks * 512 for item in IMAGE_FILES
                )
                control.atomic_write(
                    IMAGE_STORE / (name + ".json"),
                    json.dumps(
                        {"image": source, "allocated_bytes": allocated}, sort_keys=True
                    ).encode(),
                    mode=0o600,
                )
                pulled = True
            _retire_images(profile, spawn, keep={name})
            seeded = seed_account(
                profile, platform, canonical, source, home=home, account=account
            )
    except control.StateError:
        raise SharedImageBusy(
            "Another runner account is downloading the shared macOS image."
        ) from None
    return {"pulled": pulled, "seeded": seeded, "allocated_bytes": allocated}


def _retire_images(profile, spawn, *, keep=()):
    """Delete stored images no installed account uses; the caller holds the store lock."""
    referenced = referenced_images()
    vms = IMAGE_STORE / "tart/vms"
    if referenced is None or not vms.is_dir():
        return 0
    freed = 0
    for other in vms.iterdir():
        if not other.name.startswith("image-") or other.name in referenced | set(keep):
            continue
        marker = IMAGE_STORE / (other.name + ".json")
        try:
            freed += json.loads(marker.read_text()).get("allocated_bytes", 0)
        except (OSError, ValueError, AttributeError):
            pass
        spawn(_store_tart(profile, "delete", other.name), 300)
        if marker.exists():
            marker.unlink()
    return freed


def retire_shared_images(profile):
    """The controller's reclaim: drop superseded shared images when the store is free."""
    if not (IMAGE_STORE / ".lock").exists():
        return 0
    try:
        with control.file_lock(IMAGE_STORE / ".lock"):
            return _retire_images(
                profile,
                lambda argv, timeout: native(
                    argv, "Remove a superseded macOS image", timeout=timeout
                ),
            )
    except control.StateError:
        return 0


DIAGNOSIS_FIELDS = {
    "slot": {"status", "state"},
    "preparation": {"status", "stage", "identity_matches", "recipe_matches"},
    "base": {"status", "identity_matches"},
}


def _account_record(path, uid):
    """One small JSON record from the runner account's storage, never followed."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return "absent", None
    except OSError:
        return "unavailable", None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_size > 65536:
            return "invalid", None
        with os.fdopen(descriptor) as stream:
            descriptor = None
            return "valid", json.loads(stream.read(), object_pairs_hook=_unique)
    except (OSError, ValueError, UnicodeError):
        return "invalid", None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def diagnosis_facts(profile):
    """The recovery facts an update needs, without secrets or native output.

    Root reads its own slot records and the account's preparation and base
    records, then keeps only states and whether identities and recipes match.
    """
    import pool_guest

    p = paths(profile)
    uid = pwd.getpwnam(username(profile)).pw_uid
    pools = {}
    for platform, pool in profile["pools"].items():
        status, value = _account_record(p["state"] / "slots" / (platform + ".json"), 0)
        slot = {"status": status}
        if status == "valid":
            slot = (
                {"status": "valid", "state": value["state"]}
                if isinstance(value, dict) and isinstance(value.get("state"), str)
                else {"status": "invalid"}
            )
        name = profile["id"] + "-" + platform + "-base"
        storage, owner = p["home"], uid
        if platform == "macos":
            session = owner_session(profile)
            if session is not None:
                storage, owner = agent_home(session, profile), session["uid"]
        status, value = _account_record(
            storage / "pool-vms" / platform / "prepare.json", owner
        )
        preparation = {"status": status}
        if status == "valid" and isinstance(value, dict):
            recipe = hashlib.sha256(
                pool_guest.script(
                    platform,
                    "ssh-ed25519 AAAA",
                    pool["runner_version"],
                    pool["runner_digest"],
                    **(
                        {"toolchains": tuple(pool["toolchains"])}
                        if pool.get("toolchains")
                        else {}
                    ),
                ).encode()
            ).hexdigest()
            preparation = {
                "status": "valid",
                "stage": value.get("stage")
                if isinstance(value.get("stage"), str)
                else "unknown",
                "identity_matches": value.get("profile") == profile["id"]
                and value.get("owner") == profile["owner"]
                and value.get("platform") == platform
                and value.get("name") == name
                and value.get("pool") == pool,
                "recipe_matches": value.get("recipe") == recipe,
            }
        elif status == "valid":
            preparation = {"status": "invalid"}
        status, value = _account_record(
            storage / "pool-vms" / platform / "base.json", owner
        )
        base = {"status": status}
        if status == "valid":
            base = (
                {
                    "status": "valid",
                    "identity_matches": value.get("profile") == profile["id"]
                    and value.get("owner") == profile["owner"]
                    and value.get("platform") == platform
                    and value.get("name") == name
                    and value.get("image") == pool["image_source"],
                }
                if isinstance(value, dict)
                else {"status": "invalid"}
            )
        pools[platform] = {"slot": slot, "preparation": preparation, "base": base}
    return pools


def publish_diagnosis(profile, instance):
    """Leave the recovery facts where the owner's tools read them without a password."""
    control.atomic_write(
        paths(profile)["install"] / "diagnosis.json",
        (
            json.dumps(
                {
                    "schema_version": 1,
                    "profile": profile["id"],
                    "instance": instance,
                    "generated_at": int(time.time()),
                    "pools": diagnosis_facts(profile),
                },
                sort_keys=True,
            )
            + "\n"
        ).encode(),
        mode=0o644,
    )


def _clonefileat():
    import ctypes
    import ctypes.util

    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    function = libc.clonefileat
    function.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint32,
    )
    function.restype = ctypes.c_int

    def clone(source_directory, source, target_directory, target):
        if function(
            source_directory,
            source.encode(),
            target_directory,
            target.encode(),
            _CLONE_NOFOLLOW | _CLONE_NOOWNERCOPY,
        ):
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))

    return clone


def _owned_directory(parent, name, uid, gid, *, create=True):
    try:
        os.mkdir(name, 0o700, dir_fd=parent)
        os.chown(name, uid, gid, dir_fd=parent, follow_symlinks=False)
    except FileExistsError:
        pass
    descriptor = os.open(
        name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
    )
    info = os.fstat(descriptor)
    if info.st_uid != uid or stat.S_IMODE(info.st_mode) & 0o077:
        os.close(descriptor)
        raise Failure(
            "Runner image storage belongs to an unexpected account; it was preserved."
        )
    return descriptor


def seed_account(
    profile, platform, canonical, source, *, clone=None, account=None, home=None
):
    """Clone the shared image into the account's Tart storage as `<id>-<platform>-seed`.

    Every path is opened relative to directory handles verified as the
    account's own, so the account cannot redirect root's writes. The clone is
    populated while root still owns it and handed over only when complete.
    Returns True when a new seed was created.
    """
    clone = clone or _clonefileat()
    account = account or pwd.getpwnam(username(profile))
    uid, gid = account.pw_uid, account.pw_gid
    seed = profile["id"] + "-" + platform + "-seed"
    home = os.open(
        home or paths(profile)["home"], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    )
    descriptors = [home]
    try:
        info = os.fstat(home)
        require(
            info.st_uid == uid and not stat.S_IMODE(info.st_mode) & 0o077,
            "Runner storage belongs to an unexpected account; it was preserved.",
        )
        tart = _owned_directory(home, ".tart", uid, gid)
        descriptors.append(tart)
        vms = _owned_directory(tart, "vms", uid, gid)
        descriptors.append(vms)
        try:
            marker = os.open(
                SEED_MARKER,
                os.O_RDONLY | os.O_NOFOLLOW,
                dir_fd=_open_at(vms, seed, descriptors),
            )
            with os.fdopen(marker) as stream:
                if stream.read(4096) == source:
                    return False
        except OSError:
            pass  # No usable seed; a fresh one replaces whatever is there.
        staging = ".runner-pools-seed"
        _discard_at(tart, staging)
        os.mkdir(staging, 0o700, dir_fd=tart)
        target = os.open(
            staging, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=tart
        )
        descriptors.append(target)
        origin = os.open(canonical, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(origin)
        for name in IMAGE_FILES:
            clone(origin, name, target, name)
            os.chmod(name, 0o600, dir_fd=target, follow_symlinks=False)
            os.chown(name, uid, gid, dir_fd=target, follow_symlinks=False)
        marker = os.open(
            SEED_MARKER,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=target,
        )
        with os.fdopen(marker, "w") as stream:
            stream.write(source)
        os.chown(SEED_MARKER, uid, gid, dir_fd=target, follow_symlinks=False)
        _discard_at(vms, seed)
        os.chown(staging, uid, gid, dir_fd=tart, follow_symlinks=False)
        os.rename(staging, seed, src_dir_fd=tart, dst_dir_fd=vms)
        return True
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _discard_at(parent, name):
    """Remove one entry without following it; a directory goes with its contents."""
    try:
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return 0
    if stat.S_ISDIR(info.st_mode):
        return _remove_tree_at(parent, name)
    os.unlink(name, dir_fd=parent)
    return _allocated(info)


def _open_at(parent, name, descriptors):
    descriptor = os.open(
        name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
    )
    descriptors.append(descriptor)
    return descriptor


def recovery_capacity(profile, plan):
    """Reclaim only when the reserve check fails, never beside a loaded controller or worker.

    Above the reserve the caches stay: a base that still has to be prepared
    pulls its image from them.
    """
    try:
        _maintenance_preflight(profile, plan)
        return {"reclaimed_bytes": 0}
    except config.DiskSpaceFailure:
        pass
    reclaimed = 0
    if (
        plan["stage"] in ("stopped", "restoring")
        and not inspect_service(profile)["loaded"]
    ):
        processes = native(
            ["/bin/ps", "-axo", "pid=,command="], "Check runner workers before reclaim"
        )
        pattern = re.compile(
            re.escape(str(paths(profile)["install"] / "runner_pool.py"))
            + r"\s+worker\b"
        )
        if not any(pattern.search(line) for line in processes.stdout.splitlines()):
            reclaimed = reclaim_runner_storage(profile)["reclaimed_bytes"]
    try:
        _maintenance_preflight(profile, plan)
    except config.DiskSpaceFailure as error:
        error.snapshot["reclaimed_bytes"] = reclaimed
        raise
    return {"reclaimed_bytes": reclaimed}


@serialized_setup
def finish_blocked_repair(profile, contents):
    p = paths(profile)
    plan = _maintenance_read(p["state"] / "maintenance.json", profile)
    _maintenance_sources(profile, contents, plan)
    _maintenance_preflight(profile, plan)
    require(
        json.loads(
            (p["install"] / "runtime.json").read_text(), object_pairs_hook=_unique
        )
        == plan["after"],
        "Runner source update is incomplete; the saved transaction will continue before activation.",
    )
    verify_install(profile)
    if plan["stage"] != "resuming":
        plan = _maintenance_save(profile, plan, "restoring")
    activate(profile)
    deadline = time.monotonic() + 30
    while True:
        status = inspect_service(profile)
        states = status.get("pools", {})
        # When resuming after drain removal, an already verified replacement
        # may have accepted work. Do not demand that it become drained again.
        acceptable = (
            {"drained"}
            if plan["stage"] != "resuming"
            else {
                "starting",
                "idle",
                "waiting",
                "unavailable",
                "preparing",
                "creating",
                "registered",
                "busy",
                "retrying",
                "blocked",
                "drained",
                "cleanup-required",
            }
        )
        if (
            status["loaded"]
            and status["fresh"]
            and set(states) == set(profile["pools"])
            and all(value["state"] in acceptable for value in states.values())
        ):
            break
        require(
            time.monotonic() < deadline,
            "The replacement runner controller has not reported verified startup; its recovery intent and admission pause were retained.",
        )
        time.sleep(1)
    _maintenance_preflight(profile, plan)  # Capacity may have changed during startup.
    plan = _maintenance_save(profile, plan, "resuming")
    drain = p["state"] / "drain"
    if drain.exists() or drain.is_symlink():
        protected(drain)
        require(
            drain.read_text() == plan["token"] + "\n",
            "Runner pause changed during recovery; it was preserved.",
        )
        drain.unlink()
    # The controller can still publish its pre-removal drained heartbeat for
    # one polling interval. Keep the resuming receipt until it acknowledges
    # admission; an interruption must never look like an unrelated manual pause.
    deadline = time.monotonic() + 30
    while True:
        status = inspect_service(profile)
        states = status.get("pools", {})
        if (
            status["loaded"]
            and status["fresh"]
            and set(states) == set(profile["pools"])
            and all(value["state"] != "drained" for value in states.values())
        ):
            break
        require(
            time.monotonic() < deadline,
            "Runner recovery removed its owned pause, but the controller has not acknowledged it within 30 seconds. "
            "The resuming transaction is saved; existing jobs and admission were preserved.",
        )
        time.sleep(1)
    for target in (p["state"] / "maintenance.json", p["install"] / "maintenance.json"):
        _maintenance_read(target, profile)
        target.unlink()


def _publish_unactivated_runtime(profile, contents, *, allow_configured):
    p = paths(profile)
    require(
        set(contents) == set(PAYLOAD)
        and all(isinstance(v, bytes) for v in contents.values()),
        "Runtime repair requires the complete reviewed source snapshot.",
    )
    markers = (p["plist"], p["install"] / "health.json")
    if not allow_configured:
        markers += (p["state"] / "slots",)
    for marker in markers:
        require(
            not marker.exists() and not marker.is_symlink(),
            "Runtime repair is limited to initial setup before service or VM activation; preserve this installation.",
        )
    running = native(
        ["/bin/launchctl", "print", "system/" + service_spec(profile)["Label"]],
        "Inspect preactivation controller",
        allowed=(0, 113),
    )
    require(
        running.returncode == 113,
        "A controller is loaded; preserve it instead of repairing its runtime.",
    )
    # Older installed revisions did not take setup.lock around App finalization.
    # Repair requires that failed legacy invocation to have exited, as well as
    # an inactive controller. Never replace code under an existing legacy RPC.
    processes = native(
        ["/bin/ps", "-axo", "pid=,command="], "Inspect preactivation host operations"
    )
    pattern = re.compile(
        r"(?:^|\s)"
        + re.escape(str(p["install"] / "runner_pool.py"))
        + r"\s+(?:host-control|daemon|worker)\b"
    )
    for line in processes.stdout.splitlines():
        fields = line.strip().split(maxsplit=1)
        if len(fields) == 2 and pattern.search(fields[1]):
            require(
                fields[0].isdigit() and int(fields[0]) == os.getpid(),
                "An earlier installed host operation is still running; let that setup exit before repairing its runtime.",
            )
    saved, journal = p["install"] / "runtime.json", p["state"] / "runtime-repair.json"
    protected(saved)

    def digests(value):
        require(
            isinstance(value, dict)
            and set(value) == set(PAYLOAD)
            and all(
                isinstance(v, str) and re.fullmatch(r"[a-f0-9]{64}", v)
                for v in value.values()
            ),
            "Runtime repair receipt differs; preserve the installed source.",
        )
        return value

    actual = digests(json.loads(saved.read_text(), object_pairs_hook=_unique))
    after = {
        name: hashlib.sha256(content).hexdigest() for name, content in contents.items()
    }
    pending = journal.exists() or journal.is_symlink()
    if pending:
        protected(journal)
        plan = json.loads(journal.read_text(), object_pairs_hook=_unique)
        require(
            isinstance(plan, dict) and set(plan) == {"before", "after"},
            "Runtime repair journal differs; preserve it.",
        )
        before = digests(plan["before"])
        require(
            digests(plan["after"]) == after and actual in (before, after),
            "Another runtime repair is pending; resume its exact reviewed source.",
        )
    else:
        before, plan = actual, {"before": actual, "after": after}
    # Validate every old/new byte before writing any candidate or new journal.
    for name in PAYLOAD:
        target = p["install"] / name
        protected(target)
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        allowed = (before[name], after[name]) if pending else (before[name],)
        require(
            digest in allowed,
            "Installed source differs from its exact repair receipts; preserve it.",
        )
    if allow_configured:
        if pending:
            # Partial publication cannot execute a mixture of worker versions.
            _idle_repair_slots(profile)
        else:
            _recover_repair_slots(profile)
    if not pending:
        control.atomic_write(
            journal, json.dumps(plan, sort_keys=True).encode(), mode=0o600
        )
    for name, content in contents.items():
        target = p["install"] / name
        if hashlib.sha256(target.read_bytes()).hexdigest() != after[name]:
            control.atomic_write(target, content, mode=0o644)
    control.atomic_write(saved, json.dumps(after, sort_keys=True).encode(), mode=0o644)
    protected(journal)
    journal.unlink()


def extract_tart(raw, staging):
    """Extract the digest-pinned upstream app and its top-level license."""
    require(
        hashlib.sha256(raw).hexdigest() == TART_SHA256,
        "Pinned official Tart archive digest differs.",
    )
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as package:
        require(
            all(
                (Path(member.name).parts and Path(member.name).parts[0] == "tart.app")
                or (member.name == "LICENSE" and member.isfile())
                for member in package.getmembers()
            ),
            "Pinned Tart archive contains an unexpected root.",
        )
        package.extractall(staging, filter="data")
    # Implicit archive parents inherit the private bootstrap umask. The app is
    # public signed code; its dedicated unprivileged account must traverse it.
    for directory, _, files in os.walk(Path(staging) / "tart.app"):
        Path(directory).chmod(0o755)
        for name in files:
            path = Path(directory) / name
            require(not path.is_symlink(), "Pinned Tart app has an unexpected link.")
            path.chmod(stat.S_IMODE(path.stat().st_mode) & ~0o022)


def install(
    profile,
    source,
    tart_archive,
    owner_home,
    *,
    repair_runtime=False,
    recover_blocked=False,
):
    require_no_image_upgrade(profile)
    require(
        type(repair_runtime) is bool,
        "Runtime repair permission must be an explicit boolean.",
    )
    require(
        type(recover_blocked) is bool and (not recover_blocked or repair_runtime),
        "Blocked runner recovery requires the reviewed runtime repair transaction.",
    )
    require(
        os.geteuid() == 0
        and platform.system() == "Darwin"
        and platform.machine() == "arm64",
        "Host installation requires the reviewed Apple Silicon owner-admin handoff.",
    )
    profile = validate(profile)
    p = paths(profile)
    if repair_runtime:
        # Repair cannot become an unchecked first installation. Validate the
        # existing immutable identity before account or filesystem mutations.
        protected(p["profile"])
        protected(p["install"] / "runtime.json")
        require(
            load(p["profile"]) == profile,
            "Runtime repair requires the exact installed organization profile.",
        )
        verify_baseline(profile, required=False)
        if recover_blocked:
            protected(
                p["state"], directory=True
            )  # Recovery cannot create a replacement namespace.
    pool_python.verify(profile)
    root_directory(p["install"].parent)
    root_directory(p["install"])
    root_directory(p["state"].parent)
    root_directory(p["state"], 0o700)
    with setup_lock(profile):
        require_no_image_upgrade(profile)
        # Validate before admission pauses or account mutations, including a
        # stopped maintenance replay whose source receipt is still original.
        verify_baseline(profile, required=False)
        # This install runs from its own snapshot under the bootstrap lock;
        # every other snapshot belongs to a finished or abandoned install.
        running = Path(__file__).resolve().parent.name
        snapshots = prune_install_snapshots(
            profile, keep=running if BOOTSTRAP_STAGE.fullmatch(running) else None
        )
        source = Path(source).resolve(strict=True)
        contents = {name: (source / name).read_bytes() for name in PAYLOAD}
        receipt = {
            name: hashlib.sha256(content).hexdigest()
            for name, content in contents.items()
        }
        if recover_blocked:
            profile = complete_enrollment_for_repair(profile)
            p = paths(profile)
        if recover_blocked and recovery_converged(profile, receipt):
            return {"reclaimed_bytes": snapshots}
        if recover_blocked:
            try:
                plan = begin_blocked_repair(profile, contents)
            except (Failure, control.StateError):
                rollback_unstarted_repair(profile)
                raise
            # Quiescing and reclaim are safe below reserve; account/source/VM
            # work is not, so the reserve is checked after reclaim.
            capacity = recovery_capacity(profile, plan)
        user = prepare_account(profile, owner_home)
        baseline = p["install"] / "baseline-profile.json"
        if not baseline.exists() and not baseline.is_symlink():
            control.atomic_write(
                baseline,
                (json.dumps(profile, sort_keys=True, indent=2) + "\n").encode(),
                mode=0o644,
            )
        saved = p["install"] / "runtime.json"
        if p["profile"].exists() or p["profile"].is_symlink():
            protected(p["profile"])
            require(
                load(p["profile"]) == profile,
                "This profile namespace already has a different organization or policy; preserve it.",
            )
        if saved.exists():
            protected(saved)
            if (
                json.loads(saved.read_text()) != receipt
                or (p["state"] / "runtime-repair.json").exists()
            ):
                publish_unactivated_runtime(
                    profile, contents, allow_configured=repair_runtime
                )
            verify_install(profile)
        else:
            # An interrupted initial installation may replay only matching bytes.
            for name, content in contents.items():
                target = p["install"] / name
                if target.exists() or target.is_symlink():
                    protected(target)
                    require(
                        target.read_bytes() == content,
                        "Incomplete runtime contains a different source; preserve it.",
                    )
                else:
                    control.atomic_write(target, content, mode=0o644)
            control.atomic_write(
                p["profile"],
                (json.dumps(profile, sort_keys=True, indent=2) + "\n").encode(),
                mode=0o644,
            )
            control.atomic_write(
                saved, json.dumps(receipt, sort_keys=True).encode(), mode=0o644
            )
        binary = p["install"] / "bin"
        root_directory(binary)
        tart = binary / "tart.app"
        if not tart.exists():
            raw = Path(tart_archive).read_bytes()
            require(
                hashlib.sha256(raw).hexdigest() == TART_SHA256,
                "Pinned official Tart archive digest differs.",
            )
            # A cancelled extraction never publishes a partial executable. Stale
            # private staging directories are preserved, never traversed/deleted.
            with tempfile.TemporaryDirectory(
                prefix=".tart-install-", dir=binary
            ) as temporary:
                staging = Path(temporary)
                extract_tart(raw, staging)
                verify_tart(staging / "tart.app")
                os.rename(staging / "tart.app", tart)
        verify_tart(tart)
        # The account owns this subtree: perform all writes after dropping to
        # that account, never root chown/chmod through a replaceable pathname.
        create_storage = (
            "import os,pathlib,stat; os.umask(0o077); "
            "home=pathlib.Path.home(); "
            "[(home/name).mkdir(mode=0o700,exist_ok=True) for name in ('pool-vms','logs')]"
        )
        native(
            [
                "/usr/bin/sudo",
                "-n",
                "-H",
                "-u",
                user.pw_name,
                "--",
                "/usr/bin/env",
                "-i",
                "HOME=" + str(p["home"]),
                "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
                str(pool_python.python_path(profile)),
                "-I",
                "-B",
                "-c",
                create_storage,
            ],
            "Prepare isolated account storage",
        )
        for directory in (p["home"] / "pool-vms", p["home"] / "logs"):
            info = directory.lstat()
            require(
                stat.S_ISDIR(info.st_mode)
                and info.st_uid == user.pw_uid
                and stat.S_IMODE(info.st_mode) == 0o700,
                "Existing organization host storage differs; preserve it.",
            )
        verify_install(profile)
        _join_local_admission(profile, owner_home)
        proof = macos_owner_session(profile, owner_home)
        snapshots += proof.pop("reclaimed_bytes", 0)
        if recover_blocked:
            finish_blocked_repair(profile, contents)
            capacity = dict(
                capacity, reclaimed_bytes=capacity["reclaimed_bytes"] + snapshots
            )
            return dict(capacity, **proof)
        return dict(proof, reclaimed_bytes=snapshots)
    return {}


def verify_tart(tart):
    protected(tart, directory=True)
    native(
        ["/usr/bin/codesign", "--verify", "--deep", "--strict", str(tart)],
        "Verify official virtualization signature",
    )
    version = native(
        [str(tart / "Contents/MacOS/tart"), "--version"],
        "Verify pinned virtualization version",
    ).stdout.strip()
    require(
        version == TART_VERSION, "Virtualization version differs from the reviewed pin."
    )


def shared_controller_reference():
    """Public root-owned registration pin; never contains signing material."""
    from pool_auth import SHARED_PUBLIC

    if not SHARED_PUBLIC.exists() and not SHARED_PUBLIC.is_symlink():
        return None
    info = protected(SHARED_PUBLIC)
    require(info.st_size <= 4096, "Shared controller registration exceeds its bound.")
    return config.app_reference(
        json.loads(SHARED_PUBLIC.read_text(), object_pairs_hook=config._unique)
    )


def adopt_shared_controller(profile, reference, *, pem=None):
    """Adopt one host key without modifying any running account or old key."""
    import pool_auth as auth

    require(
        os.geteuid() == 0,
        "Shared controller adoption requires native administrator approval.",
    )
    reference = config.app_reference(reference)
    root_directory(auth.SHARED_STATE, 0o700)
    with control.file_lock(auth.SHARED_STATE / "setup.lock"):
        saved = shared_controller_reference()
        require(
            saved is None or saved == reference,
            "A different shared controller is already selected; preserve it.",
        )
        target = auth.SHARED_STATE / "app.pem"
        if not target.exists() and not target.is_symlink():
            if pem is None:
                require(
                    profile.get("github_app", {}).get("client_id")
                    == reference["client_id"]
                    and profile["owner"] == reference["owner"],
                    "This Mac needs its own key for the existing shared App; never create another App.",
                )
                old = auth.protected_key(paths(profile)["state"])
                pem = old.read_text()
            require(
                isinstance(pem, str)
                and len(pem) < 20000
                and pem.startswith(
                    ("-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----")
                ),
                "The shared controller key must be a private PEM from the selected existing App.",
            )
            staging = auth.SHARED_STATE / "pending"
            root_directory(staging, 0o700)
            control.atomic_write(staging / "app.pem", pem.encode(), mode=0o600)
            signing_state = staging
        else:
            protected(target)
            if pem is not None:
                require(
                    target.read_bytes() == pem.encode(),
                    "A different host key is already installed; use deliberate key rotation.",
                )
            signing_state = auth.SHARED_STATE
        candidate = dict(profile, controller_app=reference)
        candidate.pop("github_app", None)
        app = auth._request(
            "GET", "app", token=auth._sign_jwt(reference["client_id"], signing_state)
        )
        auth.app_identity(app, candidate, reference["client_id"])
        auth._permissions(app.get("permissions"), candidate)
        if signing_state != auth.SHARED_STATE:
            control.atomic_write(
                target, (signing_state / "app.pem").read_bytes(), mode=0o600
            )
        root_directory(auth.SHARED_PUBLIC.parent)
        control.atomic_write(
            auth.SHARED_PUBLIC,
            json.dumps(reference, sort_keys=True).encode(),
            mode=0o644,
        )
    return reference


@serialized_setup
def connect_shared_controller(profile):
    """Attach an inactive initial setup to the existing host registration."""
    require(
        os.geteuid() == 0,
        "Shared controller connection requires native administrator approval.",
    )
    verify_install(profile)
    reference = profile.get("controller_app") or shared_controller_reference()
    if reference is None:
        return profile
    require(
        shared_controller_reference() == reference,
        "This Mac needs a key for the existing shared App before setup can continue.",
    )
    if "github_app" in profile:
        require(
            profile.get("controller_app") == reference,
            "Migrate the existing controller before changing its credentials.",
        )
        return profile
    updated = validate(dict(profile, controller_app=reference))
    control.atomic_write(
        paths(profile)["profile"],
        json.dumps(updated, sort_keys=True).encode(),
        mode=0o644,
    )
    return updated


@serialized_setup
def finish_shared_controller(profile):
    import pool_auth as auth

    require(
        os.geteuid() == 0 and "controller_app" in profile,
        "Shared controller setup requires its protected registration.",
    )
    verify_install(profile)
    require(
        shared_controller_reference() == profile["controller_app"],
        "Shared controller registration changed; preserve setup.",
    )
    installation = auth.discover_installation(
        profile, paths(profile)["state"], profile["controller_app"]["client_id"]
    )
    if installation is None:
        return None
    updated = validate(dict(profile, github_app=installation))
    auth.GitHubApp(updated, paths(profile)["state"]).api(
        "GET", __import__("pool_policy").owner_path(updated)
    )
    reference = updated["controller_app"]
    control.atomic_write(
        paths(profile)["install"] / "app.json",
        json.dumps(
            {"client_id": reference["client_id"], "slug": reference["slug"]},
            sort_keys=True,
        ).encode(),
        mode=0o644,
    )
    control.atomic_write(
        paths(profile)["profile"],
        json.dumps(updated, sort_keys=True).encode(),
        mode=0o644,
    )
    return updated


@serialized_setup
def credential(profile, packet):
    require(
        os.geteuid() == 0,
        "Credential installation needs the normal owner-admin handoff.",
    )
    verify_install(profile)
    require(
        isinstance(packet, dict)
        and set(packet) == {"client_id", "installation_id", "pem"},
        "Native credential handoff shape differs.",
    )
    updated = dict(
        profile,
        github_app={
            "client_id": packet["client_id"],
            "installation_id": packet["installation_id"],
        },
    )
    validate(updated)
    require(
        isinstance(packet["pem"], str)
        and packet["pem"].startswith(
            ("-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----")
        )
        and len(packet["pem"]) < 20000,
        "GitHub did not provide the expected native App key.",
    )
    state = paths(profile)["state"]
    target = state / "app.pem"
    if target.exists() or target.is_symlink():
        protected(target)
        require(
            target.read_bytes() == packet["pem"].encode(),
            "A different App key is already installed; preserve it for explicit rotation.",
        )
    else:
        control.atomic_write(target, packet["pem"].encode(), mode=0o600)
    # Verify App + installation through the real native API before any service activation.
    from pool_auth import GitHubApp
    from pool_policy import owner_path

    GitHubApp(updated, state).api("GET", owner_path(updated))
    control.atomic_write(
        paths(profile)["profile"],
        (json.dumps(updated, sort_keys=True, indent=2) + "\n").encode(),
        mode=0o644,
    )
    return updated


@serialized_setup
def pending_credential(profile, packet=None):
    """Publish the manifest conversion durably before opening installation approval."""
    require(
        os.geteuid() == 0, "Native App handoff requires owner-admin authentication."
    )
    verify_install(profile)
    p = paths(profile)
    pending = p["state"] / "pending-app.json"
    if packet is not None:
        require(
            isinstance(packet, dict)
            and set(packet) == {"app_id", "client_id", "pem", "slug"},
            "GitHub manifest conversion handoff differs.",
        )
        require(
            type(packet["app_id"]) is int
            and packet["app_id"] > 0
            and re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", packet.get("client_id", ""))
            and re.fullmatch(r"[a-z0-9-]{1,100}", packet.get("slug", ""))
            and isinstance(packet["pem"], str)
            and packet["pem"].startswith(
                ("-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----")
            )
            and len(packet["pem"]) < 20000,
            "Native App metadata/key shape differs.",
        )
        if pending.exists() or pending.is_symlink():
            protected(pending)
            require(
                json.loads(pending.read_text()) == packet,
                "A different App setup is pending; preserve it.",
            )
        else:
            control.atomic_write(pending, json.dumps(packet).encode(), mode=0o600)
    if not pending.exists():
        return None
    protected(pending)
    packet = json.loads(pending.read_text())
    # Retry completes both publications from the private atomic packet.
    key = p["state"] / "app.pem"
    if key.exists() or key.is_symlink():
        protected(key)
        require(
            key.read_bytes() == packet["pem"].encode(),
            "Installed native App key differs; preserve it for explicit rotation.",
        )
    else:
        control.atomic_write(key, packet["pem"].encode(), mode=0o600)
    public = {name: packet[name] for name in ("app_id", "client_id", "slug")}
    control.atomic_write(
        p["install"] / "pending-app.json", json.dumps(public).encode(), mode=0o644
    )
    return public


@serialized_setup
def finish_credential(profile):
    from pool_auth import discover_installation

    pending = pending_credential(profile)
    if pending is None:
        require("github_app" in profile, "No native App setup is pending.")
        return profile
    app = discover_installation(profile, paths(profile)["state"], pending["client_id"])
    if app is None:
        return None
    secret = json.loads((paths(profile)["state"] / "pending-app.json").read_text())
    try:
        updated = credential(
            profile,
            {
                "client_id": pending["client_id"],
                "installation_id": app["installation_id"],
                "pem": secret["pem"],
            },
        )
    except Failure as error:
        if str(error) in (
            "GitHub API operation failed (HTTP 422); response suppressed.",
            "GitHub API operation failed (HTTP 403); response suppressed.",
        ):
            return None  # Installation exists but selected repository approval remains pending.
        raise
    control.atomic_write(
        paths(profile)["install"] / "app.json", json.dumps(pending).encode(), mode=0o644
    )
    for target in (
        paths(profile)["state"] / "pending-app.json",
        paths(profile)["install"] / "pending-app.json",
    ):
        protected(target)
        target.unlink()
    return updated


@serialized_setup
def activate(profile, *, migration_token=None):
    require(
        os.geteuid() == 0, "Service activation requires owner-admin authentication."
    )
    verify_install(profile)
    require(
        "github_app" in profile,
        "Complete the native GitHub App installation before activating pools.",
    )
    p = paths(profile)
    expected = service_spec(profile)
    if p["plist"].exists() or p["plist"].is_symlink():
        protected(p["plist"])
        require(
            plistlib.loads(p["plist"].read_bytes()) == expected,
            "Existing startup service differs; preserve it.",
        )
    else:
        control.atomic_write(p["plist"], plistlib.dumps(expected), mode=0o644)
    result = native(
        ["/bin/launchctl", "print", "system/" + expected["Label"]],
        "Inspect exact pool controller",
        allowed=(0, 113),
    )
    if result.returncode == 113:
        native(
            ["/bin/launchctl", "bootstrap", "system", str(p["plist"])],
            "Start organization pool controller",
        )


@serialized_setup
def prepare_images(profile):
    from pool_auth import GitHubApp
    from pool_runtime import Runtime

    p = paths(profile)
    transport = Worker(profile)
    runtime = Runtime(
        profile, p["state"], GitHubApp(profile, p["state"]).api, transport
    )
    inspected = None
    prepared, preserved = [], []
    for platform_name in profile["pools"]:
        with ExitStack() as stack:
            try:
                stack.enter_context(
                    control.file_lock(p["state"] / (platform_name + ".lock"))
                )
            except control.StateError:
                # Controller owns the platform operation. Do not contend with a
                # running preparation or healthy waiting/busy generation.
                preserved.append(platform_name)
                continue
            record = runtime._read(runtime._path(platform_name))
            if record is not None and record["state"] != "idle":
                preserved.append(platform_name)
                continue
            if inspected is None:
                import pool_policy as policy

                inspected = policy.inspect(profile, runtime.api, strict_selectors=False)
            group = inspected["groups"].get(platform_name)
            require(isinstance(group, dict), "Exact provisioning group is missing.")
            record = runtime._admit(platform_name, group["id"])
            try:
                transport("prepare", platform_name, record["generation"])
            except BaseException:
                try:
                    runtime._cleanup(platform_name, record)
                except (Failure, control.StateError, OSError):
                    pass  # Uncertain native cleanup retains the reservation.
                raise
            runtime._cleanup(platform_name, record)
            prepared.append(platform_name)
    return {"prepared": prepared, "preserved_active": preserved}


def _local_verification_maintenance(profile):
    p = paths(profile)
    return any(
        (directory / "maintenance.json").exists()
        or (directory / "maintenance.json").is_symlink()
        for directory in (p["state"], p["install"])
    )


@serialized_setup
def verify_local(profile, platforms):
    """Run fixed acceptance checks in disposable guests, without a GitHub job."""
    from pool_auth import GitHubApp
    from pool_runtime import (
        Runtime,
        GenerationFailure,
        CapacityWaiting,
        WorkerUncertain,
    )
    import pool_policy as policy

    require(
        os.geteuid() == 0,
        "Local guest verification requires the normal administrator handoff.",
    )
    require(
        isinstance(platforms, list)
        and platforms
        and len(set(platforms)) == len(platforms)
        and all(isinstance(v, str) and v in profile["pools"] for v in platforms),
        "Local verification needs unique configured platforms.",
    )
    verify_install(profile)
    require_no_shared_migration(profile)
    require_no_image_upgrade(profile)
    require(
        not _local_verification_maintenance(profile)
        and pending_enrollment(profile) is None,
        "Finish the saved maintenance or enrollment before local guest verification.",
    )
    p = paths(profile)
    app = GitHubApp(profile, p["state"])

    def read_only(method, path, *args):
        require(
            method == "GET" and not args,
            "Local verification cannot write GitHub runner or workflow state.",
        )
        return app.api(method, path)

    transport = Worker(profile)
    runtime = Runtime(profile, p["state"], read_only, transport)
    inspected = policy.inspect(profile, read_only, strict_selectors=False)
    results = {}
    for platform_name in platforms:
        with ExitStack() as stack:
            try:
                stack.enter_context(
                    control.file_lock(p["state"] / (platform_name + ".lock"))
                )
            except control.StateError:
                results[platform_name] = {"status": "waiting_active"}
                continue
            old = runtime._read(runtime._path(platform_name))
            if old is not None and old["state"] != "idle":
                results[platform_name] = {"status": "waiting_active"}
                continue
            available = runtime.availability(
                profile.get("fleet", {}).get("role", "desktop")
            )
            if available.get("available") is not True:
                results[platform_name] = {
                    "status": "waiting_capacity",
                    "reason": available.get("reason"),
                }
                continue
            group = inspected["groups"].get(platform_name)
            require(
                isinstance(group, dict)
                and type(group.get("id")) is int
                and group["id"] > 0,
                "Local verification requires the exact configured runner group.",
            )
            record = None
            try:
                record = runtime._admit(platform_name, group["id"])
                runtime._prepare(platform_name, record)
                if (
                    runtime.availability(
                        profile.get("fleet", {}).get("role", "desktop")
                    ).get("available")
                    is not True
                ):
                    raise CapacityWaiting("Host eligibility changed after preparation.")
                runtime._prepare(platform_name, record, operation="create")
                if (
                    runtime.availability(
                        profile.get("fleet", {}).get("role", "desktop")
                    ).get("available")
                    is not True
                ):
                    raise CapacityWaiting(
                        "Host eligibility changed before the manual check."
                    )
                report = transport("probe", platform_name, record["generation"])
                require(
                    isinstance(report, dict)
                    and report.get("profile") == profile["id"]
                    and report.get("platform") == platform_name
                    and report.get("generation") == record["generation"]
                    and report.get("account") == "ci-build"
                    and report.get("ci_checks") is True
                    and report.get("machine") in ("arm64", "aarch64"),
                    "The manual guest check did not establish its exact isolated ARM64 generation.",
                )
            except (GenerationFailure, CapacityWaiting) as error:
                if record is not None:
                    runtime._cleanup(platform_name, record)
                if isinstance(error, GenerationFailure) and (
                    not error.retryable or error.reason != "capacity_unavailable"
                ):
                    raise
                results[platform_name] = {"status": "waiting_capacity"}
                continue
            except WorkerUncertain:
                if record is not None:
                    runtime._phase(platform_name, record, "cleanup-required")
                raise  # A live or uncertain preparation thread must retain its guest and slot.
            except BaseException:
                if record is not None:
                    try:
                        runtime._cleanup(platform_name, record)
                    except (Failure, control.StateError, OSError):
                        pass  # Unconfirmed cleanup retains the owned generation and reservation.
                raise
            runtime._cleanup(platform_name, record)
            results[platform_name] = {"status": "passed", "guest": report}
    return {
        "profile": profile["id"],
        "pools": results,
        "github_registration": False,
        "provider_writes": False,
        "claims": "Fixed isolation and native ARM64 checks only; no GitHub Actions execution or product build established.",
    }


def enrollment_access(profile):
    from pool_auth import GitHubApp

    verify_install(profile)
    target = paths(profile)["state"] / "enrollment.json"
    protected(target)
    plan = json.loads(target.read_text())
    import pool_policy as policy

    policy._extension(plan["before"], plan["after"])
    require(
        profile in (plan["before"], plan["after"]),
        "Pending enrollment profile differs.",
    )
    try:
        from pool_policy import owner_path

        GitHubApp(plan["after"], paths(profile)["state"]).api(
            "GET", owner_path(plan["after"])
        )
    except Failure as error:
        # A missing selected repository rejects installation-token minting. Only
        # these controlled permission failures mean approval is still pending.
        if str(error) in (
            "GitHub API operation failed (HTTP 422); response suppressed.",
            "GitHub API operation failed (HTTP 403); response suppressed.",
        ):
            return False
        raise
    return True


def enrollment_idle(profile):
    from pool_runtime import Runtime
    from pool_auth import GitHubApp

    verify_install(profile)
    p = paths(profile)
    require((p["state"] / "drain").exists(), "Enrollment requires drained admission.")
    runtime = Runtime(
        profile, p["state"], GitHubApp(profile, p["state"]).api, Worker(profile)
    )
    with runtime._resources():
        return all(
            (record is None or record["state"] == "idle")
            for record in (runtime._read(runtime._path(v)) for v in profile["pools"])
        )


def enrollment(profile, proposed=None, *, commit=False):
    """Durable consumer-only transition; no active VM or controller is replaced."""
    require_no_image_upgrade(profile)
    from pool_auth import GitHubApp
    import pool_policy as policy

    require(os.geteuid() == 0, "Enrollment needs the normal administrator handoff.")
    verify_install(profile)
    p = paths(profile)
    target = p["state"] / "enrollment.json"
    public = p["install"] / "enrollment.json"
    with setup_lock(profile):
        require_no_image_upgrade(profile)
        require(
            not any(
                (directory / "maintenance.json").exists()
                or (directory / "maintenance.json").is_symlink()
                for directory in (p["state"], p["install"])
            ),
            "Finish the existing runner maintenance transaction before staging or resuming repository enrollment.",
        )
        if (
            not target.exists()
            and not target.is_symlink()
            and (public.exists() or public.is_symlink())
        ):
            # Finalization removes the public marker last. If interruption
            # already removed the private tail, replay the same protected
            # before/after intent; never invent an empty current==current plan.
            retained = _public_enrollment_plan(profile)
            require(
                proposed is None or proposed == retained["after"],
                "Another enrollment is pending; resume its exact public plan first.",
            )
            control.atomic_write(
                target,
                json.dumps({k: retained[k] for k in ("before", "after")}).encode(),
                mode=0o600,
            )
        if target.exists() or target.is_symlink():
            protected(target)
            plan = json.loads(target.read_text())
            require(
                set(plan) == {"before", "after"}
                and profile in (plan["before"], plan["after"]),
                "Pending enrollment belongs to another policy; preserve it.",
            )
            policy._extension(plan["before"], plan["after"])
            if proposed is not None:
                require(
                    proposed == plan["after"],
                    "Another enrollment is pending; resume its exact plan first.",
                )
        elif proposed is None:
            return None
        else:
            before, after = policy._extension(profile, proposed)
            policy.inspect(
                before, GitHubApp(before, p["state"]).api, strict_selectors=False
            )
            plan = {"before": before, "after": after}
            with control.file_lock(p["state"].parent / ".resources.lock"):
                control.atomic_write(p["state"] / "drain", b"drain\n")
            # Publish intent before waiting: retries retain the exact proposal.
            control.atomic_write(target, json.dumps(plan).encode(), mode=0o600)
        control.atomic_write(public, json.dumps(plan).encode(), mode=0o644)
        if not commit:
            with control.file_lock(p["state"].parent / ".resources.lock"):
                control.atomic_write(p["state"] / "drain", b"drain\n")
            return plan
        if profile == plan["after"] and plan["before"] != plan["after"]:
            policy.inspect(
                profile, GitHubApp(profile, p["state"]).api, strict_selectors=False
            )
            activate(profile)
            finish_enrollment(profile, plan)
            return plan
        require(
            (p["state"] / "drain").exists(), "Enrollment requires drained admission."
        )
        from pool_runtime import Runtime

        runtime = Runtime(
            profile, p["state"], GitHubApp(profile, p["state"]).api, Worker(profile)
        )
        for platform_name in profile["pools"]:
            record = runtime._read(runtime._path(platform_name))
            require(
                record is None or record["state"] == "idle",
                "Jobs or uncertain generations remain; preserve drain and retry after they finish.",
            )
        # New short-lived token creation proves installation repository access.
        policy.inspect(
            plan["after"],
            GitHubApp(plan["after"], p["state"]).api,
            strict_selectors=False,
        )
        label = service_spec(profile)["Label"]
        present = native(
            ["/bin/launchctl", "print", "system/" + label],
            "Inspect drained controller",
            allowed=(0, 113),
        )
        if present.returncode == 0:
            native(
                ["/bin/launchctl", "bootout", "system/" + label],
                "Unload idle controller",
            )
        control.atomic_write(
            p["profile"],
            (json.dumps(plan["after"], sort_keys=True, indent=2) + "\n").encode(),
            mode=0o644,
        )
        # Activation remains drained until the matching source and provider policy
        # have been read back. A crash at any point resumes this same transition.
        activate(plan["after"])
        finish_enrollment(plan["after"], plan)
        return plan


@serialized_setup
def complete_enrollment_for_repair(profile):
    """Finish saved, idle enrollment with candidate validation before runtime repair.

    An older installed validator may reject an owner-approved organization-wide
    App grant. Reuse the canonical commit and all its identity, policy and idle
    checks; never remove a pending plan to make maintenance eligible.
    """
    p = paths(profile)
    if not any(
        path.exists() or path.is_symlink()
        for path in (p["state"] / "enrollment.json", p["install"] / "enrollment.json")
    ):
        return profile
    plan = enrollment(profile, commit=True)
    actual = load(paths(profile)["profile"])
    require(
        actual == plan["after"],
        "Saved enrollment did not commit its exact reviewed profile.",
    )
    deadline = time.monotonic() + 30
    while True:
        status = inspect_service(actual)
        states = status.get("pools", {})
        if (
            status.get("loaded")
            and status.get("fresh")
            and set(states) == set(actual["pools"])
            and all(
                value.get("state") not in ("drained", "starting")
                for value in states.values()
            )
        ):
            return actual
        require(
            time.monotonic() < deadline,
            "The enrolled controller has not published fresh status. Its saved profile is preserved; resume the runtime repair.",
        )
        time.sleep(1)


def finish_enrollment(profile, plan):
    p = paths(profile)
    # This public tombstone permits the original source command to resolve the
    # deliberately installed extended policy after an interrupted final handoff.
    control.atomic_write(
        p["install"] / "last-enrollment.json", json.dumps(plan).encode(), mode=0o644
    )
    for target in (
        p["state"] / "drain",
        p["state"] / "enrollment.json",
        p["install"] / "enrollment.json",
    ):
        if target.exists() or target.is_symlink():
            protected(target)
            target.unlink()


def worker_command(
    profile, platform_name, operation, generation, *, input_present=False
):
    require(
        platform_name in profile["pools"]
        and operation
        in (
            "prepare",
            "create",
            "inspect",
            "probe",
            "execute",
            "cleanup",
        ),
        "Unsupported worker operation/platform.",
    )
    require(
        re.fullmatch(r"[a-f0-9]{32}", generation) is not None,
        "Worker generation must be a complete UUID.",
    )
    p = paths(profile)
    user = username(profile)
    return [
        "/usr/bin/sudo",
        "-n",
        "-H",
        "-u",
        user,
        "--",
        "/usr/bin/env",
        "-i",
        "HOME=" + str(p["home"]),
        "USER=" + user,
        "LOGNAME=" + user,
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
        str(pool_python.python_path(profile)),
        "-I",
        "-B",
        str(p["install"] / "runner_pool.py"),
        "worker",
        "--profile",
        str(p["profile"]),
        "--platform",
        platform_name,
        "--operation",
        operation,
        "--generation",
        generation,
    ] + (["--input-present"] if input_present else [])


OWNER_SESSION = "owner-session.json"
AGENT_LABEL = "studio.hypertext.runner-guests."
AGENT_OPERATIONS = frozenset({"prepare", "create", "inspect", "execute", "cleanup"})
AGENT_REPLY_LIMIT = 4 * 1024 * 1024


class OwnerSessionUnavailable(Failure):
    """The owner is logged out, or this account's macOS guest agent is not running."""


def owner_session(profile):
    """The owner whose logged-in session runs this account's macOS guests, or None."""
    path = paths(profile)["install"] / OWNER_SESSION
    if not path.exists() and not path.is_symlink():
        return None
    info = protected(path)
    require(
        info.st_size <= 4096, "The owner session record is too large; it was preserved."
    )
    value = json.loads(path.read_text(), object_pairs_hook=_unique)
    require(
        isinstance(value, dict)
        and set(value) == {"uid", "gid", "home"}
        and type(value["uid"]) is int
        and 0 < value["uid"] < 2**31
        and type(value["gid"]) is int
        and 0 <= value["gid"] < 2**31
        and isinstance(value["home"], str)
        and Path(value["home"]).is_absolute()
        and ".." not in Path(value["home"]).parts,
        "The owner session record is invalid; it was preserved.",
    )
    return value


def agent_home(session, profile):
    """This account's guest directory inside the owner's home: Tart, journals and socket."""
    return (
        Path(session["home"])
        / "Library/Application Support/hypertext-studio/runner-guests"
        / ("ci-pools-" + profile["id"])
    )


def agent_socket(session, profile):
    """A bounded socket address, separate from durable guest images and journals."""
    name = hashlib.sha256(profile["id"].encode()).hexdigest()[:32]
    return Path(session["home"]) / "Library/Caches/ht-runners" / name / "s"


def prepare_agent_socket(session, profile):
    """Create private socket directories without following owner-controlled links."""
    path = agent_socket(session, profile)
    require(
        len(os.fsencode(path)) <= 103,
        "The home folder path is too long for the macOS guest connection.",
    )
    base = Path(session["home"]) / "Library"
    parent = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptors = [parent]
    try:
        require(
            os.fstat(parent).st_uid == session["uid"],
            "The owner's Library folder belongs to another account; it was preserved.",
        )
        try:
            os.mkdir("Caches", 0o700, dir_fd=parent)
        except FileExistsError:
            pass
        parent = os.open(
            "Caches", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
        )
        descriptors.append(parent)
        require(
            os.fstat(parent).st_uid == session["uid"],
            "The owner's cache folder belongs to another account; it was preserved.",
        )
        for name in ("ht-runners", path.parent.name):
            parent = _owned_directory(parent, name, session["uid"], session["gid"])
            descriptors.append(parent)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    return path


def record_owner_session(profile, owner_home):
    """Remember the administrator who approved setup as the owner of macOS guests."""
    info = Path(owner_home).stat()
    require(
        info.st_uid != 0 and stat.S_ISDIR(info.st_mode),
        "macOS guests run in the owner's own session, not as the system administrator.",
    )
    control.atomic_write(
        paths(profile)["install"] / OWNER_SESSION,
        json.dumps(
            {"uid": info.st_uid, "gid": info.st_gid, "home": str(Path(owner_home))},
            sort_keys=True,
        ).encode(),
        mode=0o644,
    )


def prepare_agent_home(profile, session):
    """Create the owner's guest directory, owned by the owner and private to them."""
    base = Path(session["home"]) / "Library/Application Support"
    parent = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptors = [parent]
    try:
        require(
            os.fstat(parent).st_uid == session["uid"],
            "The owner's Application Support folder belongs to another account; it was preserved.",
        )
        for name in ("hypertext-studio", "runner-guests", "ci-pools-" + profile["id"]):
            parent = _owned_directory(parent, name, session["uid"], session["gid"])
            descriptors.append(parent)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    return agent_home(session, profile)


def peer_uid(connection):
    """The effective user of the process at the other end of a local socket."""
    import ctypes
    import ctypes.util

    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    uid, gid = ctypes.c_uint32(), ctypes.c_uint32()
    if libc.getpeereid(connection.fileno(), ctypes.byref(uid), ctypes.byref(gid)):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return uid.value


def agent_exchange(path, expected_uid, request, *, timeout):
    """Send one request to a guest agent and return its reply.

    The socket must belong to the expected owner, and so must the process
    that answers; nothing else may stand in for the agent.
    """
    import socket

    try:
        info = os.lstat(path)
    except FileNotFoundError:
        raise OwnerSessionUnavailable("The macOS guest agent is not running.") from None
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != expected_uid:
        raise OwnerSessionUnavailable(
            "The macOS guest agent's socket is not the owner's."
        )
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        connection.settimeout(10)
        try:
            connection.connect(str(path))
        except OSError:
            raise OwnerSessionUnavailable(
                "The macOS guest agent is not running."
            ) from None
        require(
            peer_uid(connection) == expected_uid,
            "The macOS guest agent is not running as the owner; nothing was sent.",
        )
        connection.settimeout(timeout)
        chunks, size = [], 0
        try:
            connection.sendall((json.dumps(request, sort_keys=True) + "\n").encode())
            while True:
                chunk = connection.recv(65536)
                if not chunk:
                    break
                size += len(chunk)
                require(
                    size <= AGENT_REPLY_LIMIT,
                    "The macOS guest agent's reply is too large.",
                )
                chunks.append(chunk)
        except (BrokenPipeError, ConnectionResetError):
            raise OwnerSessionUnavailable(
                "The macOS guest agent closed the connection without answering."
            ) from None
    finally:
        connection.close()
    try:
        reply = json.loads(b"".join(chunks), object_pairs_hook=_unique)
    except (ValueError, UnicodeError):
        raise OwnerSessionUnavailable(
            "The macOS guest agent stopped before it replied."
        ) from None
    require(
        isinstance(reply, dict)
        and set(reply) == {"returncode", "stdout"}
        and type(reply["returncode"]) is int
        and isinstance(reply["stdout"], str),
        "The macOS guest agent's reply is malformed.",
    )
    return reply


class OwnerSessionWorker:
    """macOS guest work, done by the account's agent in the owner's logged-in session."""

    def __init__(self, profile):
        self.profile = validate(profile)

    def _target(self):
        session = owner_session(self.profile)
        if session is None:
            raise OwnerSessionUnavailable(
                "No owner session is recorded for macOS guests."
            )
        return session, agent_socket(session, self.profile)

    def available(self):
        try:
            session, path = self._target()
            agent_exchange(path, session["uid"], {"operation": "ping"}, timeout=10)
            return True
        except (Failure, OSError):
            return False

    def __call__(self, operation, platform_name, generation, jit_config=None, **_):
        require(
            platform_name == "macos" and operation in AGENT_OPERATIONS,
            "Unsupported macOS guest operation.",
        )
        require(
            re.fullmatch(r"[a-f0-9]{32}", generation) is not None,
            "Worker generation must be a complete UUID.",
        )
        session, path = self._target()
        request = {"operation": operation, "generation": generation}
        if jit_config is not None:
            request["jit"] = jit_config
        reply = agent_exchange(
            path,
            session["uid"],
            request,
            timeout=86400 if operation == "execute" else 3600,
        )
        return worker_result(operation, reply["returncode"], reply["stdout"])

    def cancel(self, platform_name):
        try:
            session, path = self._target()
            agent_exchange(path, session["uid"], {"operation": "cancel"}, timeout=30)
        except (Failure, OSError):
            pass  # Nothing is running there, or the agent already stopped.


class Workers:
    """Linux guests run in the runner account; macOS guests in the owner's session."""

    def __init__(self, profile):
        self.profile = validate(profile)
        self.linux = Worker(profile)
        self.macos = OwnerSessionWorker(profile)

    def _for(self, platform_name):
        return self.macos if platform_name == "macos" else self.linux

    def __call__(self, operation, platform_name, generation, jit_config=None, **kwargs):
        return self._for(platform_name)(
            operation, platform_name, generation, jit_config, **kwargs
        )

    def cancel(self, platform_name):
        try:
            # The root worker owns shared-image downloads on both platforms.
            self.linux.cancel(platform_name)
        finally:
            if platform_name == "macos":
                self.macos.cancel(platform_name)

    def session_available(self, platform_name):
        return platform_name != "macos" or self.macos.available()

    def _owner_target(self):
        session = owner_session(self.profile)
        if session is None:
            raise OwnerSessionUnavailable(
                "No owner session is recorded for macOS guests."
            )
        return agent_home(session, self.profile), SimpleNamespace(
            pw_uid=session["uid"], pw_gid=session["gid"]
        )

    def shared_image(self, platform_name):
        if platform_name != "macos":
            return self.linux.shared_image(platform_name)
        home, account = self._owner_target()
        return self.linux.shared_image(platform_name, home=home, account=account)

    def shared_image_state(self, platform_name):
        if platform_name != "macos":
            return self.linux.shared_image_state(platform_name)
        try:
            home, _ = self._owner_target()
        except Failure:
            return "absent"
        return self.linux.shared_image_state(platform_name, home=home)


def worker_result(operation, returncode, stdout):
    """Interpret one worker's exit and output; only controlled metadata crosses."""
    if returncode != 0:
        errors = [line for line in stdout.splitlines() if line.startswith("ERROR ")]
        packets = [
            line.removeprefix("DIAGNOSTIC ")
            for line in stdout.splitlines()
            if line.startswith("DIAGNOSTIC ")
        ]
        diagnostics = []
        if not packets and len(errors) == 1:
            check = config.diagnostic_check(errors[0][6:])
            if check:
                diagnostics = [
                    {"operation": operation, "kind": "Failure", "check": check}
                ]
        if packets:
            require(
                len(packets) == 1 and len(packets[0]) <= 2048,
                "Worker diagnostic metadata is ambiguous or too large; native values suppressed.",
            )
            try:
                diagnostics = config.validate_diagnostics(
                    [json.loads(packets[0], object_pairs_hook=_unique)]
                )
            except (ValueError, TypeError):
                raise Failure(
                    "Worker diagnostic metadata is invalid; native values suppressed."
                ) from None
            require(
                diagnostics[0]["operation"] == operation,
                "Worker diagnostic operation differs; native values suppressed.",
            )
        # The protected worker suppresses native values. Only its exact
        # known unavailable/timeout diagnostic crosses as retryable,
        # only before execution. Runtime still requires confirmed
        # generation cleanup before acting on this classification.
        native_timeout = errors == [
            "ERROR Pool native operation unavailable or timed out; preserve VM state for recovery."
        ]
        if len(errors) == 1 and re.fullmatch(
            r"ERROR Native pool operation failed \[worker; TimeoutExpired(?:; [a-z_]+\.py:[0-9]+)?\]\. Values suppressed\.",
            errors[0],
        ):
            native_timeout = True
        if returncode == 1 and operation in ("prepare", "create") and native_timeout:
            from pool_runtime import GenerationFailure

            raise GenerationFailure("native_unavailable", True, diagnostics=diagnostics)
        error = Failure(
            "Isolated worker "
            + operation
            + " failed; inspect its controlled diagnostic codes.",
            diagnostics=diagnostics,
        )
        if not diagnostics and type(returncode) is int and -255 <= returncode <= 255:
            error.exit_code = returncode
        raise error
    try:
        result = json.loads(stdout)
    except (ValueError, TypeError):
        raise Failure(
            "Worker returned invalid controlled metadata; preserve the generation."
        ) from None
    require(isinstance(result, dict), "Worker metadata is not an object.")
    return result


class Worker:
    """Only transient JIT input crosses root-to-private-host-worker stdin."""

    def __init__(self, profile):
        self.profile = validate(profile)
        self.processes = {}
        self.lock = threading.Lock()

    def command(self, platform_name, operation, generation, *, input_present=False):
        return worker_command(
            self.profile,
            platform_name,
            operation,
            generation,
            input_present=input_present,
        )

    def __call__(self, operation, platform_name, generation, jit_config=None):
        packet = {"jit": jit_config} if jit_config is not None else {}
        argv = self.command(platform_name, operation, generation)
        data = json.dumps(packet) if packet else None
        process, pending = None, []
        try:
            # Keep a handle even when a signal lands immediately after fork.
            with control.handlers(lambda signum, frame: pending.append(signum)):
                with self.lock:
                    require(
                        platform_name not in self.processes,
                        "A worker operation for this platform is already active.",
                    )
                    process = subprocess.Popen(
                        argv,
                        text=True,
                        stdin=subprocess.PIPE if data else subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        process_group=0,
                        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
                    )
                    self.processes[platform_name] = process
            if pending:
                control.stop(process, True, 10)
                raise control.Cancelled(pending[0])
            try:
                stdout, _ = process.communicate(
                    input=data, timeout=86400 if operation == "execute" else 3600
                )
            except BaseException:
                control.stop(process, True, 10)
                raise
            return worker_result(operation, process.returncode, stdout)
        finally:
            with self.lock:
                if self.processes.get(platform_name) is process:
                    self.processes.pop(platform_name, None)

    def shared_image(self, platform_name, *, home=None, account=None):
        """Give this account its clone of the shared base; `cancel` stops a download."""

        def spawn(argv, timeout):
            process, pending = None, []
            try:
                with control.handlers(lambda signum, frame: pending.append(signum)):
                    with self.lock:
                        require(
                            platform_name not in self.processes,
                            "A worker operation for this platform is already active.",
                        )
                        process = subprocess.Popen(
                            argv,
                            text=True,
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE,
                            process_group=0,
                            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
                        )
                        self.processes[platform_name] = process
                if pending:
                    control.stop(process, True, 10)
                    raise control.Cancelled(pending[0])
                try:
                    _, stderr = process.communicate(timeout=timeout)
                except BaseException:
                    control.stop(process, True, 10)
                    raise
                if process.returncode != 0:
                    error = Failure(
                        "The shared macOS image operation failed; native output suppressed."
                    )
                    error.native_operation = "native"
                    if (
                        type(process.returncode) is int
                        and -255 <= process.returncode <= 255
                    ):
                        error.exit_code = process.returncode
                    raise error
            finally:
                with self.lock:
                    if (
                        process is not None
                        and self.processes.get(platform_name) is process
                    ):
                        self.processes.pop(platform_name, None)

        return ensure_shared_image(
            self.profile, platform_name, spawn, home=home, account=account
        )

    def shared_image_state(self, platform_name, *, home=None):
        """`seeded`, `stored` (in the store, not yet in this account) or `absent`."""
        if shared_image_bytes(self.profile, platform_name) is None:
            return "absent"
        source = self.profile["pools"][platform_name]["image_source"]
        marker = (
            (home or paths(self.profile)["home"])
            / ".tart/vms"
            / (self.profile["id"] + "-" + platform_name + "-seed")
            / SEED_MARKER
        )
        try:
            descriptor = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(descriptor) as stream:
                return "seeded" if stream.read(4096) == source else "stored"
        except (OSError, UnicodeError):
            return "stored"

    def cancel(self, platform_name):
        with self.lock:
            process = self.processes.get(platform_name)
            if process is not None and process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)


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
