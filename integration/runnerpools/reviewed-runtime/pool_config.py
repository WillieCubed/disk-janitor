"""Strict, credential-free configuration for organization-scoped runner pools."""

import ast
import copy
from functools import lru_cache
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat


class Failure(Exception):
    """The root controlled runner error; every runner Failure class derives from it.

    ``code`` names an entry in the operator's registry (runner_errors.py). Installed
    runtime modules pass it here, and it crosses process boundaries in diagnostics.
    """

    def __init__(self, message, *, diagnostics=(), code=None, params=None):
        super().__init__(message)
        require_code(code, params)
        self.code = code
        self.params = dict(params or {})
        self.diagnostics = validate_diagnostics(list(diagnostics))


ERROR_CODE = re.compile(r"[a-z]+(?:\.[a-z_]+)+")
PARAM_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}")


def require_code(code, params):
    """Codes and integer parameters only: no text crosses with a code."""
    valid = (
        code is None
        and not params
        or (
            isinstance(code, str)
            and len(code) <= 64
            and ERROR_CODE.fullmatch(code) is not None
            and (
                params is None
                or type(params) is dict
                and len(params) <= 6
                and all(
                    isinstance(name, str)
                    and PARAM_NAME.fullmatch(name)
                    and type(value) is int
                    and 0 <= value < 2**63
                    for name, value in params.items()
                )
            )
        )
    )
    if not valid:
        raise ValueError("Runner error code or parameters are invalid.")


def require(condition, message):
    if not condition:
        raise Failure(message)


# Reviewed guest image additions a pool may opt into. A pool without `toolchains`
# keeps its exact existing image recipe, so enabling one is a deliberate rebuild.
#   browser (linux): Chromium runtime libraries and reserved .localhost NSS resolution.
#   docker  (linux): rootless Docker + Buildx with QEMU amd64 emulation, no daemon access beyond the build account.
#   android (macos): Temurin JDK and an Android SDK owned by the build account.
TOOLCHAINS = {"linux": ("browser", "docker"), "macos": ("android",)}

DIAGNOSTIC_OPERATIONS = {
    "prepare",
    "create",
    "inspect",
    "probe",
    "cleanup",
    "execute",
    "recover",
    "register",
    "controller",
    "keychain",
    "boot-proof",
}
NATIVE_OPERATIONS = {
    "native",
    "ssh",
    "ssh-keygen",
    "tart",
    "tart-pull",
    "tart-clone",
    "tart-set",
    "tart-run",
    "tart-stop",
    "tart-delete",
    "tart-list",
    "tart-ip",
    "tart-exec",
    "tart-version",
}
NATIVE_REASONS = {
    "permission_denied": "The operating system denied access.",
    "disk_full": "The filesystem has no free space.",
    "host_identity_changed": "The guest SSH host identity could not be verified.",
    "authorization_denied": "The download service rejected authorization.",
    "source_unavailable": "The pinned download or image was not found.",
    "transport_unavailable": "The guest or download service could not be reached.",
    "capacity_unavailable": "The virtual machine could not allocate its configured resources.",
    "keychain_unavailable": "macOS could not create the virtual machine's identity: the runner account has no unlocked keychain.",
}
DIAGNOSTIC_KINDS = {
    "Failure",
    "StateError",
    "PermissionError",
    "FileNotFoundError",
    "OSError",
    "ValueError",
    "TypeError",
    "KeyError",
    "TimeoutExpired",
    "CalledProcessError",
    "SubprocessError",
    "Exception",
}
DIAGNOSTIC_FILES = {
    "runner_pool.py",
    "runner_fleet.py",
    "runner_recovery.py",
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
}


def validate_disk_capacity(value):
    """A measured lower bound, never a virtual disk size or an image-fit claim."""
    fields = {
        "start_free_bytes",
        "minimum_free_bytes",
        "reserve_bytes",
        "required_free_bytes",
    }
    require(
        type(value) is dict
        and set(value) == fields
        and all(
            type(number) is int and 0 <= number < 2**63 for number in value.values()
        ),
        "Saved preparation disk measurements are invalid; preserve the slot.",
    )
    start, minimum, reserve, required = (
        value[key]
        for key in (
            "start_free_bytes",
            "minimum_free_bytes",
            "reserve_bytes",
            "required_free_bytes",
        )
    )
    require(
        reserve >= 20 * 1024**3
        and minimum <= start
        and minimum < reserve
        and required == max(reserve, start + reserve - minimum),
        "Saved preparation disk measurements are inconsistent; preserve the slot.",
    )
    return dict(value)


def preparation_required_free(capacity, reserve):
    capacity = validate_disk_capacity(capacity)
    require(
        type(reserve) is int and 20 * 1024**3 <= reserve < 2**63,
        "Current preparation disk reserve is invalid; preserve the slot.",
    )
    required = reserve + capacity["start_free_bytes"] - capacity["minimum_free_bytes"]
    require(
        required < 2**63, "Preparation disk requirement exceeds the supported range."
    )
    return required


def validate_diagnostics(values):
    """Only bounded code locations, fixed operation names and numeric status cross IPC."""
    if not (type(values) is list and len(values) <= 2):
        raise Failure(
            "Worker diagnostic metadata is invalid; native values suppressed."
        )
    result = []
    for value in values:
        valid = (
            isinstance(value, dict)
            and {"operation", "kind"} <= set(value)
            and set(value)
            <= {
                "operation",
                "kind",
                "file",
                "line",
                "errno",
                "native_operation",
                "native_kind",
                "native_reason",
                "exit_code",
                "http_status",
                "check",
                "source",
                "disk_capacity",
                "current_reserve_bytes",
                "recovery_capacity",
                "code",
                "params",
            }
        )
        if valid:
            valid = (
                isinstance(value["operation"], str)
                and value["operation"] in DIAGNOSTIC_OPERATIONS
                and isinstance(value["kind"], str)
                and value["kind"] in DIAGNOSTIC_KINDS
                and (("file" in value) == ("line" in value))
            )
        if valid and "file" in value:
            valid = (
                isinstance(value["file"], str)
                and value["file"] in DIAGNOSTIC_FILES
                and type(value["line"]) is int
                and 0 < value["line"] < 1000000
            )
        if valid and "errno" in value:
            valid = type(value["errno"]) is int and 0 <= value["errno"] <= 65535
        if valid and "native_operation" in value:
            valid = (
                isinstance(value["native_operation"], str)
                and value["native_operation"] in NATIVE_OPERATIONS
            )
        if valid and "native_kind" in value:
            valid = isinstance(value["native_kind"], str) and value["native_kind"] in {
                "FileNotFoundError",
                "PermissionError",
                "OSError",
                "TimeoutExpired",
            }
        if valid and "native_reason" in value:
            valid = (
                isinstance(value["native_reason"], str)
                and value["native_reason"] in NATIVE_REASONS
            )
        if valid and "exit_code" in value:
            valid = (
                type(value["exit_code"]) is int and -255 <= value["exit_code"] <= 255
            )
        if valid and "http_status" in value:
            valid = (
                type(value["http_status"]) is int and 100 <= value["http_status"] <= 599
            )
        if valid and "check" in value:
            valid = (
                isinstance(value["check"], str)
                and re.fullmatch("[a-f0-9]{64}", value["check"]) is not None
            )
        if valid and "source" in value:
            valid = (
                isinstance(value["source"], str)
                and re.fullmatch("[a-f0-9]{64}", value["source"]) is not None
            )
        if valid and ("code" in value or "params" in value):
            try:
                require_code(value.get("code"), value.get("params"))
                valid = "code" in value
            except ValueError:
                valid = False
        if valid and "disk_capacity" in value:
            validate_disk_capacity(value["disk_capacity"])
        if valid and "current_reserve_bytes" in value:
            valid = "disk_capacity" in value
            if valid:
                preparation_required_free(
                    value["disk_capacity"], value["current_reserve_bytes"]
                )
        if valid and "recovery_capacity" in value:
            capacity = value["recovery_capacity"]
            valid = (
                value["operation"] == "recover"
                and value["kind"] == "Failure"
                and type(capacity) is dict
                and set(capacity) == {"available_bytes", "reserve_bytes"}
                and all(type(number) is int for number in capacity.values())
                and 0 <= capacity["available_bytes"] < capacity["reserve_bytes"] < 2**63
                and capacity["reserve_bytes"] >= 20 * 1024**3
            )
        if not valid:
            raise Failure(
                "Worker diagnostic metadata is invalid; native values suppressed."
            )
        clean = dict(value)
        if "disk_capacity" in clean:
            clean["disk_capacity"] = validate_disk_capacity(clean["disk_capacity"])
        if "recovery_capacity" in clean:
            clean["recovery_capacity"] = dict(clean["recovery_capacity"])
        if "params" in clean:
            clean["params"] = dict(clean["params"])
        result.append(clean)
    return result


@lru_cache(maxsize=1)
def diagnostic_checks():
    """Only authored literal checks can become public explanations, never error values."""
    # Retained failure journals can outlive the source that authored their check.
    # Keep reviewed historical wording readable without accepting arbitrary text.
    historical = ("Stop the blocked runner controller",)
    checks = {
        hashlib.sha256(message.encode()).hexdigest(): message for message in historical
    }
    for filename in DIAGNOSTIC_FILES:
        path = Path(__file__).resolve().parent / filename
        try:
            if not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
                continue
            tree = ast.parse(path.read_text())
        except (OSError, UnicodeError, SyntaxError):
            continue  # A secondary source read must not replace the original failure code.
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = (
                node.func.id
                if isinstance(node.func, ast.Name)
                else getattr(node.func, "attr", None)
            )
            index = (
                1
                if name in ("require", "native", "_native")
                else 0
                if name in ("Failure", "StateError")
                else None
            )
            if index is None or len(node.args) <= index:
                continue
            literal = node.args[index]
            if (
                isinstance(literal, ast.Constant)
                and isinstance(literal.value, str)
                and len(literal.value) <= 1000
            ):
                checks[hashlib.sha256(literal.value.encode()).hexdigest()] = (
                    literal.value
                )
    return checks


def diagnostic_check(message):
    code = hashlib.sha256(message.encode()).hexdigest()
    return code if code in diagnostic_checks() else None


def describe_diagnostic(value):
    value = validate_diagnostics([value])[0]
    if "recovery_capacity" in value:
        capacity = value["recovery_capacity"]
        return (
            "Runners are paused for recovery. "
            f"{capacity['available_bytes'] / 1024**3:.2f} GiB available; "
            f"{capacity['reserve_bytes'] / 1024**3:g} GiB required before updating or resuming."
        )
    if "disk_capacity" in value:
        capacity = value["disk_capacity"]
        reserve = value.get("current_reserve_bytes", capacity["reserve_bytes"])
        required = preparation_required_free(capacity, reserve)
        return (
            "Preparation exhausted available disk headroom. "
            f"At least {required / 1024**3:.2f} GiB free is needed for another guarded attempt "
            f"while preserving the {reserve / 1024**3:g} GiB reserve."
        )
    explanation = NATIVE_REASONS.get(
        value.get("native_reason")
    ) or diagnostic_checks().get(value.get("check"))
    if explanation:
        if "native_operation" in value:
            operation = value["native_operation"]
            text = (
                operation.replace("-", " ") + ": " if operation != "native" else ""
            ) + explanation
            if "native_kind" in value:
                text += " " + value["native_kind"] + "."
            if "errno" in value:
                text += " OS error " + str(value["errno"]) + "."
            if "exit_code" in value:
                text += " Exit " + str(value["exit_code"]) + "."
            return text
        return explanation
    action = value.get("native_operation", value["operation"]).replace("-", " ")
    reason = value.get("native_kind", value["kind"])
    details = [action + ": " + reason]
    for field, label in (
        ("errno", "OS error"),
        ("exit_code", "exit"),
        ("http_status", "HTTP"),
    ):
        if field in value:
            details.append(label + " " + str(value[field]))
    if "file" in value:
        details.append(value["file"] + ":" + str(value["line"]))
    return "; ".join(details) + "."


def source_diagnostic(error, operation):
    """Support-bundle record only; the owner-facing renderer never reads file or line.

    Never copy exception messages, source lines, paths, argv or native streams.
    """
    kind = type(error).__name__
    value = {
        "operation": operation,
        "kind": "Failure"
        if isinstance(error, Failure)
        else kind
        if kind in DIAGNOSTIC_KINDS
        else "Exception",
    }
    trace = error.__traceback__
    while trace is not None:
        path = Path(trace.tb_frame.f_code.co_filename)
        if (
            path.parent.resolve() == Path(__file__).resolve().parent
            and path.name in DIAGNOSTIC_FILES
            and trace.tb_frame.f_code.co_name != "require"
        ):
            value.update(file=path.name, line=trace.tb_lineno)
            try:
                value["source"] = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError:
                pass
        trace = trace.tb_next
    if (
        isinstance(error, OSError)
        and type(error.errno) is int
        and 0 <= error.errno <= 65535
    ):
        value["errno"] = error.errno
    for key in ("native_operation", "native_kind", "native_reason", "exit_code"):
        if hasattr(error, key):
            value[key] = getattr(error, key)
    number = getattr(error, "native_errno", None)
    if type(number) is int and 0 <= number <= 65535:
        value["errno"] = number
    if isinstance(error, Failure):
        code, params = getattr(error, "code", None), getattr(error, "params", None)
        if code is not None:
            value["code"] = code
            if params:
                value["params"] = dict(params)
        check = getattr(error, "check", None)
        check = check if check in diagnostic_checks() else diagnostic_check(str(error))
        if check:
            value["check"] = check
        status = re.fullmatch(
            r"GitHub API operation failed \(HTTP ([1-5][0-9]{2})\); response suppressed\.",
            str(error),
        )
        if status:
            value["http_status"] = int(status[1])
    return validate_diagnostics([value])[0]


def failure_diagnostics(error, operation):
    values = getattr(error, "diagnostics", ())
    return (
        validate_diagnostics(list(values))
        if values
        else [source_diagnostic(error, operation)]
    )


def remember_diagnostics(state, uid, profile_id, scope, diagnostics):
    """A separate private record survives controller heartbeat replacement."""
    import process_control

    require(
        scope in ("linux", "macos", "controller")
        and re.fullmatch("[a-z][a-z0-9-]{0,19}", profile_id),
        "Failure record scope is invalid.",
    )
    state = Path(state)
    info = state.lstat()
    require(
        stat.S_ISDIR(info.st_mode)
        and not state.is_symlink()
        and info.st_uid == uid
        and not info.st_mode & 0o077
        and os.geteuid() == uid,
        "Failure record directory has unsafe metadata.",
    )
    target = state / (scope + ".failure.json")
    if target.exists() or target.is_symlink():
        info = target.lstat()
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == uid
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600,
            "Saved runner failure has unsafe metadata; preserve it.",
        )
    value = dict(
        schema_version=1,
        profile_id=profile_id,
        platform=scope,
        diagnostics=validate_diagnostics(diagnostics),
    )
    process_control.atomic_write(
        target, (json.dumps(value, sort_keys=True) + "\n").encode(), mode=0o600
    )


def _object(value, required, optional=(), context="Profile"):
    require(isinstance(value, dict), context + " must be an object.")
    require(
        set(required) <= set(value) and set(value) <= set(required) | set(optional),
        context + " contains missing or unknown fields.",
    )


def _integer(value, minimum=1):
    return type(value) is int and value >= minimum


def _match(pattern, value):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def consumer_events(consumer):
    """Reviewed event pairs; omission preserves legacy profile receipts."""
    events = consumer.get("events", ["push", "workflow_dispatch"])
    require(
        type(events) is list
        and events
        in (
            ["push", "workflow_dispatch"],
            ["schedule", "workflow_dispatch"],
            ["workflow_run", "workflow_dispatch"],
        ),
        "Consumer events must be exactly push/manual, schedule/manual or reviewed recovery/manual in that order.",
    )
    return list(events)


TAG_PREFIX = r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"


def consumer_tag_prefix(consumer):
    """Reviewed tag releases use one literal prefix; omission means trusted main."""
    prefix = consumer.get("tag_prefix")
    require(
        prefix is None
        or (
            _match(TAG_PREFIX, prefix)
            and consumer_events(consumer) == ["push", "workflow_dispatch"]
        ),
        "Tag releases need one literal tag prefix with push/manual events.",
    )
    return prefix


def app_reference(value):
    _object(value, ("owner", "client_id", "slug"), context="Shared App identity")
    owner = value["owner"]
    _object(owner, ("login", "id", "type"), context="Shared App owner")
    require(
        _match(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", owner["login"])
        and _integer(owner["id"])
        and owner["type"] in ("Organization", "User")
        and _match(r"[A-Za-z0-9_.-]{1,100}", value["client_id"])
        and _match(r"[a-z0-9][a-z0-9-]{0,99}", value["slug"]),
        "Shared App identity must pin its immutable owner, client and slug.",
    )
    return copy.deepcopy(value)


def profile_identity(data):
    """Validate the protected account identity without interpreting its workflow schema."""
    _object(
        data,
        ("schema_version", "id", "owner", "pools", "consumers"),
        (
            "min_free_gib",
            "max_active_vms",
            "github_app",
            "fleet",
            "trust",
            "controller_app",
            "recovery_app",
        ),
    )
    require(
        type(data["schema_version"]) is int and data["schema_version"] == 1,
        "Unsupported profile schema version.",
    )
    require(
        _match(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", data["id"]) and len(data["id"]) <= 20,
        "Profile id must be a lowercase slug of at most 20 characters.",
    )
    owner = data["owner"]
    _object(owner, ("login", "id", "type"), context="Owner")
    require(
        _match(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", owner["login"])
        and _integer(owner["id"])
        and owner["type"] in ("Organization", "User"),
        "Owner must be an explicitly identified GitHub organization or personal account.",
    )
    return {"id": data["id"], "owner": copy.deepcopy(owner)}


def validate(data):
    identity = profile_identity(data)
    owner = identity["owner"]
    if owner["type"] == "User":
        require(
            data.get("trust") == "repository-administrators" and "fleet" in data,
            "Personal runners require explicit repository-administrator trust and host admission.",
        )
    else:
        require(
            "trust" not in data,
            "Organization runners retain their server-enforced workflow boundary.",
        )
    if "fleet" in data:
        fleet = data["fleet"]
        _object(fleet, ("host_id", "role"), context="Fleet host")
        require(
            _match(r"[a-f0-9]{12}", fleet["host_id"])
            and fleet["role"] in ("desktop", "laptop"),
            "Fleet host needs a stable identity and desktop/laptop role.",
        )
    pools = data["pools"]
    require(
        isinstance(pools, dict) and bool(pools) and set(pools) <= {"linux", "macos"},
        "Pools must select linux and/or macos.",
    )
    for platform_name, pool in pools.items():
        _object(
            pool,
            (
                "capacity",
                "image_source",
                "cpus",
                "memory_gib",
                "disk_gib",
                "runner_version",
                "runner_digest",
            ),
            ("image_revision", "guest_os_major", "toolchains"),
            context="Pool",
        )
        if "toolchains" in pool:
            names = pool["toolchains"]
            require(
                isinstance(names, list)
                and bool(names)
                and names == sorted(set(names))
                and all(isinstance(name, str) for name in names)
                and set(names) <= set(TOOLCHAINS.get(platform_name, ())),
                "Pool toolchains must be a sorted list of reviewed names for this platform: "
                + ", ".join(TOOLCHAINS.get(platform_name, ()))
                + ".",
            )
        if "image_revision" in pool or "guest_os_major" in pool:
            require(
                platform_name == "macos"
                and _match(r"[a-f0-9]{64}", pool.get("image_revision"))
                and type(pool.get("guest_os_major")) is int
                and pool["guest_os_major"] >= 26
                and pool["image_source"].endswith("@sha256:" + pool["image_revision"]),
                "Versioned images require an exact macOS digest and guest OS verification.",
            )
        require(
            type(pool["capacity"]) is int and pool["capacity"] == 1,
            "Initial pool capacity must be exactly one.",
        )
        require(
            _match(
                r"ghcr\.io/[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+@sha256:[a-f0-9]{64}",
                pool["image_source"],
            ),
            "Pool image source must be an immutable ghcr.io OCI digest.",
        )
        require(
            all(_integer(pool[k]) for k in ("cpus", "memory_gib", "disk_gib")),
            "Pool resources must be positive integers.",
        )
        require(
            _match(r"[0-9]+\.[0-9]+\.[0-9]+", pool["runner_version"])
            and _match(r"[a-f0-9]{64}", pool["runner_digest"]),
            "Pool runner must pin an exact release version and SHA256 digest.",
        )
    consumers = data["consumers"]
    require(
        isinstance(consumers, list) and bool(consumers),
        "Profile must contain consumers.",
    )
    names, ids, workflows = {}, {}, set()
    used = set()
    for consumer in consumers:
        _object(
            consumer,
            ("repo", "id", "workflow", "pools"),
            ("events", "visibility", "credentials", "tag_prefix"),
            context="Consumer",
        )
        require(
            consumer.get("credentials", True) is True,
            "Credential-bearing workflows are recorded only as an explicit reviewed choice.",
        )
        require(
            "tag_prefix" not in consumer or owner["type"] == "User",
            "Organization runner groups admit exact workflow refs only; tag releases need repository-scoped runners.",
        )
        require(
            consumer.get("visibility", "private") in ("private", "public")
            and (consumer.get("visibility") != "public" or "fleet" in data),
            "Public consumers require explicit fleet admission and visibility.",
        )
        repo = consumer["repo"]
        require(
            _match(re.escape(owner["login"]) + r"/[A-Za-z0-9_.-]+", repo)
            and repo.rsplit("/", 1)[1] not in (".", "..")
            and _integer(consumer["id"]),
            "Consumer must pin an owner-matching repository and immutable ID.",
        )
        require(
            names.get(repo.lower(), (repo, consumer["id"])) == (repo, consumer["id"])
            and ids.get(consumer["id"], repo) == repo,
            "Consumer repository identities must remain consistent across workflows.",
        )
        names[repo.lower()] = (repo, consumer["id"])
        ids[consumer["id"]] = repo
        require(
            _match(
                r"\.github/workflows/[A-Za-z0-9_][A-Za-z0-9_.-]*\.ya?ml",
                consumer["workflow"],
            )
            and ".." not in consumer["workflow"],
            "Consumer workflow must be a literal direct .github/workflows YAML file.",
        )
        key = (repo, consumer["workflow"])
        require(key not in workflows, "Duplicate consumer repository/workflow pair.")
        workflows.add(key)
        consumer_events(consumer)
        consumer_tag_prefix(consumer)
        selected = consumer["pools"]
        require(
            isinstance(selected, list)
            and bool(selected)
            and all(isinstance(item, str) for item in selected)
            and len(selected) == len(set(selected))
            and set(selected) <= set(pools),
            "Consumer pools must be unique configured platforms.",
        )
        used.update(selected)
    require(used == set(pools), "Every configured pool must have an enrolled consumer.")
    result = copy.deepcopy(data)
    result.setdefault("min_free_gib", 20)
    result.setdefault("max_active_vms", 2)
    require(
        _integer(result["min_free_gib"], 12),
        "Disk reserve must be an integer of at least 12 GiB.",
    )
    require(
        _integer(result["max_active_vms"])
        and result["max_active_vms"] <= 4
        and result["max_active_vms"] >= sum(p["capacity"] for p in pools.values()),
        "Maximum active VMs must cover every configured slot and cannot exceed four.",
    )
    for name in ("controller_app", "recovery_app"):
        if name in result:
            reference = app_reference(result[name])
            if name == "controller_app" and "github_app" in result:
                require(
                    reference["client_id"] == result["github_app"]["client_id"],
                    "Shared controller identity differs from the installation client.",
                )
    if "github_app" in result:
        app = result["github_app"]
        _object(app, ("client_id", "installation_id"), context="GitHub App")
        require(
            _match(r"[A-Za-z0-9_.-]{1,100}", app["client_id"])
            and _integer(app["installation_id"]),
            "GitHub App requires a public client ID and positive installation ID.",
        )
    return result


def _unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key in profile.")
        result[key] = value
    return result


def load(path):
    try:
        data = json.loads(
            Path(path).read_text(encoding="utf-8"), object_pairs_hook=_unique
        )
    except (OSError, ValueError, UnicodeError):
        raise Failure("Profile cannot be read as strict UTF-8 JSON.") from None
    return validate(data)


def username(profile):
    return "ci-pools-" + validate(profile)["id"]


def group_name(profile, platform):
    p = validate(profile)
    require(platform in p["pools"], "Unknown pool platform.")
    return p["id"] + "-" + platform


def labels(profile, platform):
    name = group_name(profile, platform)
    return [
        "self-hosted",
        {"linux": "Linux", "macos": "macOS"}[platform],
        "ARM64",
        name,
    ]


def paths(profile):
    p = validate(profile)
    install = Path("/Library/Application Support/RunnerPools") / p["id"]
    return dict(
        install=install,
        state=Path("/private/var/db/runner-pools") / p["id"],
        home=Path("/Users") / username(p),
        plist=Path("/Library/LaunchDaemons")
        / ("com.github.runner-pools." + p["id"] + ".plist"),
        profile=install / "profile.json",
    )


def disk_available_label(snapshot):
    """Keep a below-reserve observation visibly below that reserve."""
    available = f"{snapshot['available_gib']:.1f}"
    if snapshot["shortfall_gib"] > 0 and float(available) >= snapshot["required_gib"]:
        available = f"{snapshot['available_bytes'] * 1000 // 1024**3 / 1000:.3f}"
    return available


def disk_shortfall_label(snapshot):
    """Round a real deficit upward; never ask someone to free zero bytes."""
    gib = snapshot["shortfall_gib"]
    if gib < 1:
        return f"{max(1, math.ceil(gib * 1024))} MiB"
    return f"{math.ceil(gib * 10) / 10:.1f} GiB"


class DiskSpaceFailure(Failure):
    """Measured shortage safe for either terminal or guided presentation."""

    def __init__(self, snapshot, *, recovery_paused=False):
        require(
            type(recovery_paused) is bool, "Recovery pause must be an explicit boolean."
        )
        self.snapshot = dict(snapshot)
        self.recovery_paused = recovery_paused
        diagnostics = (
            [
                dict(
                    operation="recover",
                    kind="Failure",
                    recovery_capacity={
                        "available_bytes": snapshot["available_bytes"],
                        "reserve_bytes": snapshot["required_bytes"],
                    },
                )
            ]
            if recovery_paused
            else []
        )
        super().__init__(
            f"Physical disk reserve is unavailable on {snapshot['filesystem_path']}: "
            f"{disk_available_label(snapshot)} GiB available; "
            f"{snapshot['required_gib']:.2f} GiB required; "
            f"{disk_shortfall_label(snapshot)} short. "
            + (
                "Recovery is paused in its saved transaction; restore capacity before continuing."
                if recovery_paused
                else "Setup stopped; preserve installed state and resolve the shortage before resuming."
            ),
            diagnostics=diagnostics,
        )


def recovery_capacity_failure(profile, diagnostics):
    values = [
        value["recovery_capacity"]
        for value in validate_diagnostics(list(diagnostics))
        if "recovery_capacity" in value
    ]
    require(len(values) <= 1, "Runner recovery returned ambiguous capacity metadata.")
    if not values:
        return None
    capacity = values[0]
    require(
        capacity["reserve_bytes"] == max(20, profile["min_free_gib"]) * 1024**3,
        "Runner recovery capacity belongs to a different reserve; preserve it.",
    )
    observed_path, _ = disk_observation(profile)
    snapshot = disk_readiness(
        profile, observe=lambda _: (observed_path, capacity["available_bytes"])
    )
    return DiskSpaceFailure(snapshot, recovery_paused=True)


def disk_observation(profile):
    """Sample the selected home volume and return the actual path sampled."""
    return disk_observation_path(paths(profile)["home"])


def disk_observation_path(path):
    """Sample a known account path before a full enrollment profile exists."""
    path = Path(path)
    while True:
        try:
            available = shutil.disk_usage(path).free
            return path.resolve(), available
        except FileNotFoundError:
            if path == path.parent:
                raise
            path = path.parent


def disk_readiness(profile, *, observe=None):
    """Read-only physical reserve snapshot; image and job capacity is separate."""
    try:
        path, available = (observe or disk_observation)(profile)
    except OSError:
        raise Failure(
            "Cannot observe the physical disk reserve. Setup stopped; preserve installed state and inspect the selected home filesystem."
        ) from None
    required = max(20, profile["min_free_gib"]) * 1024**3
    shortfall = max(0, required - available)
    return {
        "filesystem_path": str(path),
        "available_bytes": available,
        "required_bytes": required,
        "shortfall_bytes": shortfall,
        "available_gib": available / 1024**3,
        "required_gib": required / 1024**3,
        "shortfall_gib": shortfall / 1024**3,
        "ready": not shortfall,
    }


def preflight_disk(profile, *, observe=None):
    """Reject a shortage before a setup or native authentication boundary."""
    snapshot = disk_readiness(profile, observe=observe)
    if not snapshot["ready"]:
        raise DiskSpaceFailure(snapshot)
    return snapshot
