"""Root broker for fresh one-job guests; credentials never enter worker journals."""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import threading
import time
import uuid

import pool_config as config
from pool_config import Failure, require, validate
import pool_policy as policy
import runner_fleet as fleet
import process_control as control
runnerpools_bridge = control

GIB = 1024**3
ACTIVE = {"creating", "registered", "busy", "cleanup", "cleanup-required"}
_RESOURCE_MUTEX = threading.RLock()


EXECUTION_MARGIN = 2 * 1024**3
# Expected writes of a workflow no job has measured yet.
INITIAL_JOB_DISK = {"linux": 15 * 1024**3, "macos": 40 * 1024**3}
UNATTRIBUTED = "*"
DISK_STOP_NOTICE = 6 * 3600  # How long an idle pool reports a job it stopped for disk.


class PreparationPaused(Failure):
    """An owned pause arrived during pre-job preparation, which stopped at a safe point."""


class CapacityWaiting(Failure):
    """An occupied host is ordinary waiting, not a failed provisioning attempt."""


class ProviderBusy(Failure):
    """The provider retains a busy registration; its guest must be preserved."""


class WorkerUncertain(Failure):
    """The execution thread is still active; cleanup must not race it."""


class GenerationFailure(Failure):
    def __init__(self, reason, retryable, *, diagnostics=()):
        super().__init__(
            "Generation stopped; its controlled health and private journal describe recovery.",
            diagnostics=diagnostics,
        )
        self.reason, self.retryable = reason, retryable


def recovery_reason(error):
    """Classify only known transient failures; never expose exception values."""
    if isinstance(error, fleet.ProviderObservationUnavailable):
        return "provider_unavailable", True
    if isinstance(error, GenerationFailure):
        return error.reason, error.retryable
    if isinstance(error, (subprocess.TimeoutExpired, ConnectionError, TimeoutError)):
        return "native_unavailable", True
    # Native causes travel as validated diagnostic fields, not prose. A guest
    # that got no address, or a transport or capacity failure, is transient.
    for value in getattr(error, "diagnostics", None) or []:
        if not isinstance(value, dict):
            continue
        # Nothing outside the system will make the keychain available.
        if value.get("native_reason") == "keychain_unavailable":
            return "native_unavailable", False
        if value.get("native_reason") in ("capacity_unavailable", "disk_full"):
            return "capacity_unavailable", True
        if (
            value.get("native_operation") == "tart-ip"
            or value.get("native_reason") == "transport_unavailable"
        ):
            return "native_unavailable", True
    if getattr(error, "native_operation", None) == "tart-ip":
        return "native_unavailable", True
    message = str(error) if isinstance(error, Failure) else ""
    if (
        re.fullmatch(
            r"GitHub API operation failed \(HTTP (?:429|5[0-9]{2})\); response suppressed\.",
            message,
        )
        or message
        == "GitHub HTTPS operation unavailable; credentials and response suppressed."
    ):
        return "provider_unavailable", True
    if message.startswith(
        (
            "Managed VM capacity is reserved;",
            "Managed pools would exceed half",
            "Physical free disk is below the managed reserve;",
        )
    ):
        return "capacity_unavailable", True
    return (
        "unsafe_state"
        if isinstance(error, (Failure, control.StateError))
        else "operation_failed"
    ), False


def _memory():
    if sys.platform != "darwin":
        return os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
    try:
        result = subprocess.run(
            ["/usr/sbin/sysctl", "-n", "hw.memsize"],
            capture_output=True,
            text=True,
            timeout=10,
            env={"PATH": "/usr/bin:/bin"},
        )
        require(result.returncode == 0, "Host physical memory is unavailable.")
        return int(result.stdout.strip())
    except (OSError, ValueError, subprocess.SubprocessError):
        raise Failure("Host physical memory is unavailable.") from None


def _value(source):
    return source() if callable(source) else source


def _slug(value):
    return (
        isinstance(value, str)
        and len(value) <= 20
        and re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", value)
    )


class ImageUpgradePending(Failure):
    """Only the exact native image transaction may recover this slot."""


class Runtime:
    def __init__(
        self,
        profile,
        state,
        api,
        worker,
        *,
        global_root=None,
        free_bytes=None,
        cpu_count=None,
        memory_bytes=None,
        storage_uid=0,
        health=None,
        poll_interval=15,
        backoff=15,
        max_retries=3,
        retry_probe_interval=300,
        demand=None,
        availability=None,
        allow_image_upgrade=False,
        reclaim=None,
        resource_bridge=None,
    ):
        self.profile, self.state = validate(profile), Path(state)
        self.global_root = (
            Path(global_root) if global_root is not None else self.state.parent
        )
        require(
            self.state == self.global_root / self.profile["id"]
            and self.state.is_absolute()
            and ".." not in self.state.parts,
            "Controller state must use its own absolute profile namespace.",
        )
        require(
            os.geteuid() == storage_uid,
            "Pool broker requires its protected operating-system account.",
        )
        self.uid, self.api, self.worker, self.health = storage_uid, api, worker, health
        require(
            type(allow_image_upgrade) is bool,
            "Image recovery permission must be explicit.",
        )
        self.allow_image_upgrade = allow_image_upgrade
        self.free_bytes = (
            free_bytes
            if free_bytes is not None
            else lambda: shutil.disk_usage(self.global_root).free
        )
        self.cpu_count = cpu_count if cpu_count is not None else os.cpu_count
        self.memory_bytes = memory_bytes if memory_bytes is not None else _memory
        self.poll_interval, self.backoff = poll_interval, backoff
        require(
            type(max_retries) is int and 1 <= max_retries <= 3,
            "Recovery attempts must be bounded by three.",
        )
        self.max_retries = max_retries
        self.preparation_poll_interval = 1
        self.preparation_join_timeout = 5
        require(
            retry_probe_interval >= 300,
            "Dependency recovery probes must be at least five minutes apart.",
        )
        self.retry_probe_interval = retry_probe_interval
        require(
            poll_interval > 0 and backoff > 0,
            "Controller polling intervals must be positive.",
        )
        self.demand = demand or fleet.demand
        self.reclaim = reclaim
        self.resource_bridge = resource_bridge or runnerpools_bridge.BrokerBridge()
        self._shared_bridge = None
        self._last_repository = {}
        self.availability = availability or (
            lambda role: fleet.admission(role, fleet.observe())
        )
        self._stop = threading.Event()
        if storage_uid == 0:
            for ancestor in reversed(self.global_root.parents):
                self._directory(ancestor, create=False)
        for directory in (self.global_root, self.state, self.state / "slots"):
            self._directory(directory)

    def _directory(self, path, *, create=True):
        if create:
            try:
                path.mkdir(mode=0o700)
            except FileExistsError:
                pass
        info = path.lstat()
        require(
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == self.uid
            and not info.st_mode & 0o022,
            "Managed state directory has unsafe metadata; preserve it and inspect.",
        )

    @contextmanager
    def _resources(self):
        try:
            with (
                _RESOURCE_MUTEX,
                control.file_lock(self.global_root / ".resources.lock"),
            ):
                with self.resource_bridge.transaction(self.global_root) as bridge:
                    self._shared_bridge = bridge
                    try:
                        if bridge:
                            bridge.publish(self._scan(), self.global_root.stat().st_dev)
                        yield
                    finally:
                        try:
                            if bridge:
                                bridge.publish(self._scan(), self.global_root.stat().st_dev)
                        finally:
                            self._shared_bridge = None
        except runnerpools_bridge.BridgeUnavailable:
            raise CapacityWaiting("Shared local/CI admission is unavailable; existing work is preserved.") from None
        except control.StateError:
            raise Failure(
                "Pool resource state is locked or unsafe; preserve it and retry after inspection."
            ) from None

    def _path(self, platform):
        require(platform in self.profile["pools"], "Unknown pool platform.")
        return self.state / "slots" / (platform + ".json")

    def _remember_failure(self, platform, diagnostics):
        """Retain the cause independently of heartbeat and authoritative slot state."""
        self._path(platform)
        config.remember_diagnostics(
            self.state, self.uid, self.profile["id"], platform, diagnostics
        )

    def _read(self, path):
        if not path.exists() and not path.is_symlink():
            return None
        info = path.lstat()
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == self.uid
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600,
            "Managed slot journal has unsafe metadata.",
        )
        try:
            require(info.st_size <= 65536, "Managed slot journal is too large.")
            record = json.loads(path.read_text(), object_pairs_hook=config._unique)
        except (OSError, ValueError, UnicodeError):
            raise Failure(
                "Managed slot journal is malformed; preserve it and inspect."
            ) from None
        basic = {"schema_version", "profile_id", "platform", "state"}
        require(
            isinstance(record, dict)
            and basic <= set(record)
            and type(record["schema_version"]) is int
            and record["schema_version"] == 1
            and _slug(record["profile_id"])
            and record["profile_id"] == path.parent.parent.name
            and record["platform"] in ("linux", "macos")
            and path.name == record["platform"] + ".json",
            "Managed slot identity is inconsistent; replacement is blocked.",
        )
        if "disk_capacity" in record:
            config.validate_disk_capacity(record["disk_capacity"])
        if "preparation_start_free_bytes" in record:
            require(
                type(record["preparation_start_free_bytes"]) is int
                and 0 <= record["preparation_start_free_bytes"] < 2**63,
                "Saved preparation starting capacity is invalid; preserve the slot.",
            )
        fields = set(record) - {"disk_capacity"}
        if record["state"] == "idle":
            require(
                fields == basic,
                "Idle slot retains unknown state; inspect it before replacement.",
            )
            return record
        require(
            record["state"] in ACTIVE
            and fields - {"preparation_start_free_bytes"}
            == basic | {"generation", "name", "group_id", "runner_id", "resources"},
            "Managed slot state is unknown.",
        )
        require(
            isinstance(record["generation"], str)
            and re.fullmatch(r"[a-f0-9]{32}", record["generation"])
            and fleet.parse_runner(
                record["name"], record["profile_id"], record["platform"]
            )
            is not None
            and fleet.parse_runner(
                record["name"], record["profile_id"], record["platform"]
            )["generation"]
            == record["generation"]
            and type(record["group_id"]) is int
            and record["group_id"] > 0
            and (
                record["runner_id"] is None
                or type(record["runner_id"]) is int
                and record["runner_id"] > 0
            ),
            "Managed generation identity is inconsistent; replacement is blocked.",
        )
        resources = record["resources"]
        require(
            isinstance(resources, dict)
            and set(resources)
            == {"cpus", "memory_bytes", "disk_bytes", "reserve_bytes"}
            and all(type(value) is int and value > 0 for value in resources.values())
            and resources["reserve_bytes"] >= 20 * GIB,
            "Managed resource reservation is invalid.",
        )
        if "preparation_start_free_bytes" in record:
            require(
                record["preparation_start_free_bytes"] >= resources["reserve_bytes"],
                "Saved preparation starting capacity is below its admission reserve; preserve the slot.",
            )
        return record

    def _scan(self):
        result = []
        for namespace in self.global_root.iterdir():
            if namespace.name in (".resources.lock", ".fairness.json"):
                continue
            require(
                _slug(namespace.name),
                "Unknown entry in the managed pool hierarchy; admission is blocked.",
            )
            self._directory(namespace, create=False)
            slots = namespace / "slots"
            if not slots.exists() and not slots.is_symlink():
                continue
            self._directory(slots, create=False)
            for path in slots.iterdir():
                if re.fullmatch(r"\.(?:linux|macos)\.json\.[a-zA-Z0-9_]+", path.name):
                    info = path.lstat()
                    require(
                        stat.S_ISREG(info.st_mode)
                        and info.st_uid == self.uid
                        and info.st_nlink == 1,
                        "Interrupted journal staging metadata is unsafe.",
                    )
                    continue
                require(
                    path.name in ("linux.json", "macos.json"),
                    "Unknown managed slot file; admission is blocked.",
                )
                record = self._read(path)
                if record["state"] != "idle":
                    result.append(record)
        return result

    def _write(self, platform, record):
        if self._shared_bridge and record["state"] in ACTIVE:
            # Export the claim durably before the authoritative journal can
            # admit VM work. An interrupted commit remains conservative.
            records = [r for r in self._scan() if
                       (r["profile_id"], r["platform"]) != (record["profile_id"], platform)]
            self._shared_bridge.publish(records + [record], self.global_root.stat().st_dev)
        control.atomic_write(
            self._path(platform),
            (json.dumps(record, sort_keys=True) + "\n").encode(),
            mode=0o600,
        )

    def _phase(self, platform, record, state):
        record = dict(record, state=state)
        with self._resources():
            self._write(platform, record)
        self._health(platform, state, generation=record["generation"])
        return record

    def _health(self, platform, state, **details):
        value = dict(
            profile_id=self.profile["id"], platform=platform, state=state, **details
        )
        # Proof that a guest built from the current base registered a runner.
        # It persists through idle periods and ends when the pool blocks.
        if state == "blocked":
            self._clear_proof(platform)
        proof = self._current_proof(platform)
        if proof is not None:
            value["proof"] = proof
        if state == "blocked":
            self._clear_prepared(platform)
        elif state == "idle" and self._prepared_current(platform):
            value["prepared"] = True
        stopped = self._disk_stopped().get(platform)
        if (
            state == "idle"
            and "reason" not in value
            and stopped is not None
            and time.time() - stopped < DISK_STOP_NOTICE
        ):
            value["reason"] = "job_disk_exceeded"
        if self.health:
            try:
                self.health(value)
            except Exception:
                print(
                    "Pool health publication unavailable; runtime state remains journaled.",
                    flush=True,
                )
        else:
            print("PHASE " + platform + " " + state, flush=True)

    def _proof_path(self, platform):
        return self.state / (platform + ".proof.json")

    def _identity(self, platform):
        """The current base recipe: pool settings and the installed guest recipe code."""
        runtime = {}
        try:
            receipt = json.loads(
                (config.paths(self.profile)["install"] / "runtime.json").read_text()
            )
            runtime = {
                name: receipt.get(name) for name in ("pool_guest.py", "pool_vm.py")
            }
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            pass
        source = json.dumps(
            {"pool": self.profile["pools"][platform], "runtime": runtime},
            sort_keys=True,
        )
        return hashlib.sha256(source.encode()).hexdigest()[:32]

    def _record_proof(self, platform):
        value = {
            "generation": self._identity(platform),
            "registered_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        try:
            control.atomic_write(
                self._proof_path(platform),
                json.dumps(value, sort_keys=True).encode(),
                mode=0o600,
            )
        except OSError:
            pass  # Proof only adds confidence; without it the pool reports unproven.

    def _current_proof(self, platform):
        try:
            value = json.loads(self._proof_path(platform).read_text())
        except (OSError, ValueError):
            return None
        if not (
            isinstance(value, dict)
            and set(value) == {"generation", "registered_at"}
            and value["generation"] == self._identity(platform)
            and isinstance(value["registered_at"], str)
            and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value["registered_at"])
        ):
            return None
        return value

    def _prepared_path(self, platform):
        return self.state / (platform + ".prepared.json")

    def _record_prepared(self, platform):
        try:
            control.atomic_write(
                self._prepared_path(platform),
                json.dumps({"generation": self._identity(platform)}).encode(),
                mode=0o600,
            )
        except OSError:
            pass  # Without it the pool is reported as not yet prepared.

    def _prepared_current(self, platform):
        try:
            value = json.loads(self._prepared_path(platform).read_text())
        except (OSError, ValueError):
            return False
        return isinstance(value, dict) and value.get("generation") == self._identity(
            platform
        )

    def _clear_prepared(self, platform):
        try:
            self._prepared_path(platform).unlink()
        except FileNotFoundError:
            pass

    def _clear_proof(self, platform):
        try:
            self._proof_path(platform).unlink()
        except FileNotFoundError:
            pass

    def _draining(self):
        marker = self.state / "drain"
        return self._stop.is_set() or marker.exists() or marker.is_symlink()

    def _offer(self, platform, count):
        require(type(count) is int and count >= 0, "Invalid queued demand.")
        control.atomic_write(
            self.state / ("demand-" + platform + ".json"),
            json.dumps({"count": count, "updated_at": time.time()}).encode(),
            mode=0o600,
        )

    def _turn(self, platform):
        """Host-local fairness across accounts; stale demand never blocks work."""
        with self._resources():
            pending = {}
            for namespace in self.global_root.iterdir():
                if not _slug(namespace.name):
                    continue
                self._directory(namespace, create=False)
                for selected in ("linux", "macos"):
                    path = namespace / ("demand-" + selected + ".json")
                    if not path.exists():
                        continue
                    info = path.lstat()
                    require(
                        stat.S_ISREG(info.st_mode)
                        and info.st_uid == self.uid
                        and info.st_nlink == 1
                        and stat.S_IMODE(info.st_mode) == 0o600
                        and info.st_size < 1024,
                        "Demand record is unsafe; admission stopped.",
                    )
                    value = json.loads(
                        path.read_text(), object_pairs_hook=config._unique
                    )
                    require(
                        set(value) == {"count", "updated_at"}
                        and type(value["count"]) is int
                        and value["count"] >= 0
                        and type(value["updated_at"]) in (int, float),
                        "Demand record is invalid.",
                    )
                    if 0 <= time.time() - value["updated_at"] <= 60:
                        pending[namespace.name + "/" + selected] = value["count"]
            path = self.global_root / ".fairness.json"
            last = None
            if path.exists() or path.is_symlink():
                info = path.lstat()
                require(
                    stat.S_ISREG(info.st_mode)
                    and info.st_uid == self.uid
                    and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o600
                    and info.st_size < 1024,
                    "Fairness record is unsafe; admission stopped.",
                )
                value = json.loads(path.read_text(), object_pairs_hook=config._unique)
                require(
                    isinstance(value, dict)
                    and set(value) == {"last"}
                    and isinstance(value["last"], str),
                    "Invalid fairness record.",
                )
                last = value["last"]
            selected = fleet.choose(pending, last=last)
            if selected != self.profile["id"] + "/" + platform:
                return False
            control.atomic_write(
                path, json.dumps({"last": selected}).encode(), mode=0o600
            )
            return True

    def _admit(self, platform, group_id):
        self._require_image_available(platform)
        require(not self._draining(), "Pool is draining; no new generation admitted.")
        pool = self.profile["pools"][platform]
        resources = dict(
            cpus=pool["cpus"],
            memory_bytes=pool["memory_gib"] * GIB,
            # What a job of this pool is expected to write, never its whole
            # virtual disk: guest clones are sparse.
            disk_bytes=self._disk_budget(platform),
            reserve_bytes=max(20, self.profile["min_free_gib"]) * GIB,
        )
        with self._resources():
            require(
                not self._draining(),
                "Pool began draining while waiting for resources; no generation admitted.",
            )
            active = self._scan()
            local = self._shared_bridge.local_claims() if self._shared_bridge else []
            device = self.global_root.stat().st_dev
            local_disk = sum(max((v["budget"] for v in item["volumes"] if v["device"] == device), default=0) for item in local)
            local_reserve = max([0] + [v["reserve"] for item in local for v in item["volumes"] if v["device"] == device])
            if self.profile.get("fleet") and len(active) >= 2:
                raise CapacityWaiting(
                    "Managed VM capacity is reserved; waiting for a job to finish."
                )
            require(
                len(active) < 2
                and sum(r["profile_id"] == self.profile["id"] for r in active)
                < self.profile["max_active_vms"],
                "Managed VM capacity is reserved; finish or recover existing generations.",
            )
            cpus, memory, free = (
                _value(self.cpu_count),
                _value(self.memory_bytes),
                _value(self.free_bytes),
            )
            require(
                all(
                    type(value) is int and 0 < value < 2**63
                    for value in (cpus, memory, free)
                ),
                "Host resource readings are unavailable.",
            )
            if (
                self.profile.get("fleet")
                and active
                and (
                    sum(r["resources"]["cpus"] for r in active) + resources["cpus"]
                    > cpus // 2
                    or sum(r["resources"]["memory_bytes"] for r in active)
                    + resources["memory_bytes"]
                    > memory // 2
                )
            ):
                raise CapacityWaiting(
                    "Managed host compute is occupied; waiting for a job to finish."
                )
            require(
                sum(r["resources"]["cpus"] for r in active) + resources["cpus"]
                <= cpus // 2,
                "Managed pools would exceed half the host logical CPUs.",
            )
            require(
                sum(r["resources"]["memory_bytes"] for r in active)
                + resources["memory_bytes"]
                <= memory // 2,
                "Managed pools would exceed half the host physical memory.",
            )
            if sum(r["resources"]["memory_bytes"] for r in active) + resources["memory_bytes"] + sum(item["memory"] for item in local) > memory:
                raise CapacityWaiting("Shared local/CI memory commitments are occupied; waiting for completion.")
            reserve = max(
                [resources["reserve_bytes"], local_reserve]
                + [r["resources"]["reserve_bytes"] for r in active]
            )
            require(
                free >= reserve,
                "Physical free disk is below the managed reserve; no cleanup of unrelated data attempted.",
            )
            # Admit a job only when what it and every running job are
            # expected to write fits beside the reserve. The execution
            # watchdog stops any job that writes more than expected.
            budget = resources["disk_bytes"] + local_disk + sum(
                r["resources"]["disk_bytes"] for r in active
            )
            if free < reserve + budget:
                raise CapacityWaiting(
                    "Free disk space cannot hold what this job is expected to write beside the reserve; waiting for space or a running job to finish."
                )
            previous = self._read(self._path(platform))
            capacity = previous.get("disk_capacity") if previous else None
            state = getattr(self.worker, "shared_image_state", None)
            if capacity and state is not None and state(platform) == "stored":
                # Measured while this account still downloaded its own image;
                # the shared image is now on disk, so that cost is gone.
                capacity = None
            if capacity and free < config.preparation_required_free(capacity, reserve):
                raise GenerationFailure(
                    "capacity_unavailable",
                    True,
                    diagnostics=[
                        dict(
                            operation="prepare",
                            kind="Failure",
                            disk_capacity=capacity,
                            current_reserve_bytes=reserve,
                        )
                    ],
                )
            generation = uuid.uuid4().hex
            record = dict(
                schema_version=1,
                profile_id=self.profile["id"],
                platform=platform,
                state="creating",
                generation=generation,
                name=fleet.runner_name(
                    self.profile["id"],
                    platform,
                    generation,
                    self.profile.get("fleet", {}).get("host_id"),
                ),
                group_id=group_id,
                runner_id=None,
                resources=resources,
                preparation_start_free_bytes=free,
            )
            if capacity:
                record["disk_capacity"] = capacity
            self._write(platform, record)
        self._health(platform, "creating", generation=record["generation"])
        return record

    def _owned(self, record):
        if self.profile["owner"]["type"] == "User":
            root = policy.runner_root(self.profile, record["group_id"])
            consumer = next(
                c for c in self.profile["consumers"] if c["id"] == record["group_id"]
            )
            policy._repo(
                self.api("GET", "repos/" + consumer["repo"]), consumer, self.profile
            )
            rows = policy._pages(self.api, root, "runners")
        else:
            rows = self._group_runners(record)
        return self._owned_row(record, rows)

    def _group_runners(self, record):
        root = (
            "orgs/"
            + self.profile["owner"]["login"]
            + "/actions/runner-groups/"
            + str(record["group_id"])
        )
        group = self.api("GET", root)
        require(
            isinstance(group, dict)
            and group.get("id") == record["group_id"]
            and group.get("name")
            == config.group_name(self.profile, record["platform"]),
            "Saved runner group identity changed; preserve the generation.",
        )
        return policy._pages(self.api, root + "/runners", "runners")

    def _owned_row(self, record, rows):
        require(
            all(
                type(row.get("id")) is int
                and row["id"] > 0
                and isinstance(row.get("name"), str)
                for row in rows
            )
            and len({row["id"] for row in rows}) == len(rows),
            "Runner roster identities are malformed.",
        )
        matches = [row for row in rows if row["name"] == record["name"]]
        require(len(matches) <= 1, "Generation registration is ambiguous; preserve it.")
        if not matches:
            return None
        row = matches[0]
        require(
            (record["runner_id"] is None or row["id"] == record["runner_id"])
            and type(row.get("busy")) is bool
            and row.get("status") in ("online", "offline"),
            "Generation registration state changed; preserve it.",
        )
        return row

    def _unregister_idle(self, record):
        row = self._owned(record)
        if row and row["busy"]:
            raise ProviderBusy(
                "Provider reports the generation busy; preserve its VM and reservation."
            )
        if row:
            # Removing the idle registration closes scheduler admission before
            # native shutdown. A busy-removal rejection preserves the guest.
            self.api(
                "DELETE",
                policy.runner_root(self.profile, record["group_id"])
                + "/"
                + str(row["id"]),
            )
            require(
                self._owned(record) is None,
                "Runner removal is not confirmed; preserve its VM and reservation.",
            )

    def _cleanup(self, platform, record):
        record = self._phase(platform, record, "cleanup-required")
        self._unregister_idle(record)
        result = self.worker("cleanup", platform, record["generation"])
        require(
            isinstance(result, dict) and result.get("clean") is True,
            "Native VM cleanup is unconfirmed; its slot remains reserved.",
        )
        row = self._owned(record)
        require(
            row is None or row["busy"] is False,
            "Provider still reports the generation busy; its reservation is preserved.",
        )
        require(
            row is None,
            "Generation registration reappeared; its reservation is preserved.",
        )
        idle = dict(
            schema_version=1,
            profile_id=self.profile["id"],
            platform=platform,
            state="idle",
        )
        if "disk_capacity" in record:
            idle["disk_capacity"] = record["disk_capacity"]
        with self._resources():
            self._write(platform, idle)
        self._health(platform, "idle")
        return idle

    def _image_upgrade_pending(self, platform):
        if self.allow_image_upgrade:
            return False
        path = self.state / "image-upgrade.json"
        if not path.exists() and not path.is_symlink():
            return False
        info = path.lstat()
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == self.uid
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_size <= 262144,
            "Image replacement journal is unsafe; preserve the macOS reservation.",
        )
        value = json.loads(path.read_text(), object_pairs_hook=config._unique)
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
            "Image replacement journal is invalid; preserve its reservation.",
        )
        before, after = validate(value["before"]), validate(value["after"])
        require(
            all(
                p["id"] == self.profile["id"] and p["owner"] == self.profile["owner"]
                for p in (before, after)
            ),
            "Image replacement belongs to another account; preserve its reservation.",
        )
        changed = [
            name
            for name in before["pools"]
            if before["pools"][name] != after["pools"].get(name)
        ]
        require(len(changed) <= 1, "Image replacement must identify at most one pool.")
        target = (
            changed[0] if changed else "macos"
        )  # Legacy macOS journals may repeat the installed profile.
        if platform != target or value["stage"] == "complete":
            return False
        require(
            self.profile in (before, after),
            "Image replacement belongs to another profile; preserve its reservation.",
        )
        return True

    def _require_image_available(self, platform):
        """Reject reservations while their exact pool image is under maintenance."""
        if self._image_upgrade_pending(platform):
            raise ImageUpgradePending(
                "A build image replacement is pending; preserve its reservation and resume its maintenance command."
            )

    def _recover(self, platform):
        self._require_image_available(platform)
        record = self._read(self._path(platform))
        if record is None or record["state"] == "idle":
            return dict(state="idle")
        row = self._owned(record)
        if row and row["busy"]:
            return self._phase(platform, record, "busy")
        return self._cleanup(platform, record)

    def recover(self, platform):
        self._path(platform)
        try:
            with control.file_lock(self.state / (platform + ".lock")):
                return self._recover(platform)
        except control.StateError:
            raise Failure(
                "Pool slot is already controlled or has unsafe lock metadata."
            ) from None

    def _execute(self, platform, record, jit):
        registered_at = time.monotonic()
        done, output = threading.Event(), {}
        start_free = lowest_free = _value(self.free_bytes)
        workflow, looked_up, disk_stopped = None, False, False

        def execute():
            try:
                output["result"] = self.worker(
                    "execute",
                    platform,
                    record["generation"],
                    jit_config=jit,
                )
            except BaseException as error:
                output["error"] = error
            finally:
                done.set()

        thread = threading.Thread(target=execute, name="pool-execute-" + platform)
        thread.start()
        cancelled = False
        try:
            while not done.wait(self.poll_interval):
                try:
                    row = self._owned(record)
                except Failure:
                    # A provider outage does not establish that an active job
                    # may be killed. Preserve execution and its reservation.
                    row = None
                    self._health(platform, "blocked")
                if row and row["busy"] and record["state"] != "busy":
                    record = self._phase(platform, record, "busy")
                if row and row["busy"] and not looked_up:
                    looked_up = True
                    workflow = self._job_workflow(platform, record)
                with self._resources():
                    active = self._scan()
                    reserve = max(
                        [record["resources"]["reserve_bytes"]]
                        + [r["resources"]["reserve_bytes"] for r in active]
                    )
                # Stop the guest before free space reaches the reserve, allowing
                # for the writes one polling interval can add.
                free = _value(self.free_bytes)
                if type(free) is int:
                    lowest_free = min(lowest_free, free)
                low_disk = free < reserve + EXECUTION_MARGIN
                if not cancelled:
                    if low_disk:
                        self.worker.cancel(platform)  # Explicit host-reserve emergency.
                        cancelled = disk_stopped = True
                    elif (
                        row is not None
                        and not row["busy"]
                        and (
                            self._draining()
                            or self.profile.get("fleet")
                            and (
                                not self.availability(self.profile["fleet"]["role"])[
                                    "available"
                                ]
                                or time.monotonic() - registered_at >= 120
                            )
                        )
                    ):
                        try:
                            self._unregister_idle(record)
                        except Failure:
                            self._health(platform, "blocked")
                        else:
                            self.worker.cancel(platform)
                            cancelled = True
            self._record_job_disk(
                platform,
                workflow,
                start_free - lowest_free
                if type(start_free) is int and type(lowest_free) is int
                else 0,
                stopped=disk_stopped,
            )
            if "error" in output:
                raise output["error"]
            result = output.get("result")
            require(
                isinstance(result, dict) and type(result.get("exit_code")) is int,
                "Worker execution did not return a native process result.",
            )
            return result
        except BaseException as error:
            if not done.is_set():
                # An ordinary shutdown/cancellation cannot race scheduler
                # admission. Unknown/busy state leaves the tracked guest alive.
                try:
                    self._unregister_idle(record)
                except Failure:
                    raise WorkerUncertain(
                        "Worker may still own a job; preserve its generation for recovery."
                    ) from None
                self.worker.cancel(platform)
            thread.join(timeout=5)
            if thread.is_alive():
                raise WorkerUncertain(
                    "Worker termination is unconfirmed; preserve the generation for recovery."
                ) from None
            raise

    def _budget_path(self, platform):
        return self.state / (platform + ".disk-budget.json")

    def _budget_record(self, platform):
        path = self._budget_path(platform)
        try:
            info = path.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != self.uid
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size > 65536
            ):
                return {}
            value = json.loads(path.read_text(), object_pairs_hook=config._unique)
        except (OSError, ValueError):
            return {}
        if not isinstance(value, dict) or not all(
            isinstance(k, str) and type(v) is int and v >= 0 for k, v in value.items()
        ):
            return {}
        return value

    def _workflows(self, platform):
        return [
            consumer["repo"] + ":" + consumer["workflow"]
            for consumer in self.profile["consumers"]
            if platform in consumer["pools"]
        ]

    def _disk_budget(self, platform):
        """What the next job here is expected to write: the largest measured
        peak of any workflow this pool serves, plus a quarter, or the starting
        estimate for a workflow not yet measured. The assigned job is unknown
        until GitHub hands it over, so the largest estimate applies."""
        record = self._budget_record(platform)
        initial = INITIAL_JOB_DISK[platform]
        keys = self._workflows(platform) + (
            [UNATTRIBUTED] if UNATTRIBUTED in record else []
        )
        estimates = [
            record[key] + record[key] // 4 if key in record else initial for key in keys
        ] or [initial]
        ceiling = self.profile["pools"][platform]["disk_gib"] * GIB
        return max(1, min(max(estimates), ceiling))

    def _job_workflow(self, platform, record):
        """The consumer workflow GitHub assigned this runner's job to, if it can be read."""
        try:
            for consumer in self.profile["consumers"]:
                if platform not in consumer["pools"]:
                    continue
                runs = fleet.pages(
                    self.api,
                    f"repos/{consumer['repo']}/actions/runs?status=in_progress",
                    "workflow_runs",
                )
                for run in runs:
                    if not fleet.trusted_run(run, consumer):
                        continue
                    jobs = fleet.pages(
                        self.api,
                        f"repos/{consumer['repo']}/actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs",
                        "jobs",
                    )
                    if any(job.get("runner_name") == record["name"] for job in jobs):
                        return consumer["repo"] + ":" + consumer["workflow"]
        except Exception:
            return None
        return None

    def _record_job_disk(self, platform, workflow, written, *, stopped):
        """Keep each workflow's highest measured disk use for the next admission.

        The measure is the free space the Mac lost while the job ran, so it
        never under-counts the job. A stopped job's peak is kept even when it
        is below the estimate, because that job needed more than it was given.
        """
        if type(written) is not int or written < 0:
            written = 0
        key = workflow or UNATTRIBUTED
        try:
            with self._resources():
                record = self._budget_record(platform)
                peak = max(record.get(key, 0), written)
                if stopped:
                    peak = max(peak, self._disk_budget(platform))
                    self._disk_stopped()[platform] = time.time()
                if peak != record.get(key):
                    record[key] = peak
                    control.atomic_write(
                        self._budget_path(platform),
                        json.dumps(record, sort_keys=True).encode(),
                        mode=0o600,
                    )
        except Exception:
            pass  # The estimate stays as it was; the watchdog still guards the reserve.

    def _disk_stopped(self):
        if "_stopped_for_disk" not in self.__dict__:
            self._stopped_for_disk = {}
        return self._stopped_for_disk

    def _shared(self):
        """Bytes of a shared image each pool's current attempt downloaded."""
        if "_shared_bytes" not in self.__dict__:
            self._shared_bytes = {}
        return self._shared_bytes

    def _share_image(self, platform, record, cancelled):
        """Clone the shared macOS image into this account before preparing its base."""
        self._shared().pop(platform, None)
        share = getattr(self.worker, "shared_image", None)
        if share is None or platform != "macos":
            return
        try:
            result = share(platform)
        except Failure as error:
            if type(error).__name__ == "SharedImageBusy":
                raise CapacityWaiting(str(error)) from None
            if cancelled.is_set():
                raise
            # The account then downloads its own copy under the same reserve.
            print(
                "Shared macOS image unavailable; this account downloads its own copy.",
                flush=True,
            )
            return
        if result and result.get("pulled"):
            self._shared()[platform] = result["allocated_bytes"]

    def _prepare(self, platform, record, *, operation="prepare"):
        """Preparation has no job; enforce reserve through its owned worker only."""
        require(
            operation in ("prepare", "create"),
            "Only pre-job work can use preparation reserve cancellation.",
        )
        current_free = _value(self.free_bytes)
        require(
            type(current_free) is int and current_free >= 0,
            "Physical disk observation unavailable.",
        )
        # Admission covers the whole prepare+create sequence, including space
        # consumed by an earlier successful stage. Never reset it at clone creation.
        start_free = record.get("preparation_start_free_bytes", current_free)

        def observe(free=None):
            free = _value(self.free_bytes) if free is None else free
            require(
                type(free) is int and free >= 0,
                "Physical disk observation unavailable.",
            )
            with self._resources():
                active = self._scan()
                reserve = max(
                    [record["resources"]["reserve_bytes"]]
                    + [value["resources"]["reserve_bytes"] for value in active]
                )
                if free < reserve:
                    # Retain the failed starting capacity plus its measured shortfall.
                    # Cleanup restoring that same starting capacity is not recovery.
                    # A shared image this attempt finished downloading stays on
                    # disk for every account, so it is not a cost to repeat.
                    shared = self._shared().get(platform, 0)
                    lowest = min(start_free, free + shared)
                    capacity = config.validate_disk_capacity(
                        dict(
                            start_free_bytes=start_free,
                            minimum_free_bytes=lowest,
                            reserve_bytes=reserve,
                            required_free_bytes=max(
                                reserve, start_free + reserve - lowest
                            ),
                        )
                    )
                    previous = record.get("disk_capacity")
                    if (
                        previous
                        and config.preparation_required_free(previous, reserve)
                        > capacity["required_free_bytes"]
                    ):
                        capacity = previous
                    record["disk_capacity"] = capacity
                    self._write(platform, record)
                    return GenerationFailure(
                        "capacity_unavailable",
                        True,
                        diagnostics=[
                            dict(
                                operation=operation,
                                kind="Failure",
                                disk_capacity=capacity,
                                current_reserve_bytes=reserve,
                            )
                        ],
                    )
            return None

        shortage = observe(current_free)
        if shortage is not None:
            raise shortage  # Never start a worker below its observed admission requirement.
        done, output, cancelled = threading.Event(), {}, threading.Event()

        def prepare():
            try:
                if operation == "prepare":
                    self._share_image(platform, record, cancelled)
                require(not cancelled.is_set(), "Preparation was stopped.")
                output["result"] = self.worker(
                    operation,
                    platform,
                    record["generation"],
                )
            except BaseException as error:
                output["error"] = error
            finally:
                done.set()

        thread = threading.Thread(target=prepare, name="pool-prepare-" + platform)
        thread.start()
        stopped = None

        def stop_owned():
            cancel_error = None
            cancelled.set()
            try:
                self.worker.cancel(platform)
            except BaseException as error:
                cancel_error = error
            thread.join(timeout=getattr(self, "preparation_join_timeout", 5))
            if thread.is_alive():
                raise WorkerUncertain(
                    "Pre-job worker termination is unconfirmed; preserve its journal."
                )
            if cancel_error is not None and not isinstance(cancel_error, OSError):
                raise cancel_error

        try:
            while not done.wait(self.preparation_poll_interval):
                try:
                    stopped = observe()
                except (OSError, Failure) as error:
                    stopped = GenerationFailure(
                        "native_unavailable",
                        False,
                        diagnostics=config.failure_diagnostics(error, operation),
                    )
                if self._stop.is_set():
                    stopped = GenerationFailure("native_unavailable", False)
                elif stopped is None and self._draining():
                    # Preparation is idle work: an update or a manual pause
                    # always takes precedence over it.
                    stopped = PreparationPaused(
                        "Preparation stopped for a runner pause."
                    )
                if stopped is not None:
                    stop_owned()
                    break
            thread.join(timeout=getattr(self, "preparation_join_timeout", 5))
            if thread.is_alive():
                raise WorkerUncertain(
                    "Preparation termination is unconfirmed; preserve its journal."
                )
            if stopped is not None:
                raise stopped
            if "error" in output:
                raise output["error"]
            shortage = observe()  # A fast worker can finish between reserve samples.
            if shortage is not None:
                raise shortage
            return output.get("result")
        except BaseException as error:
            if isinstance(error, WorkerUncertain):
                raise
            if not done.is_set():
                stop_owned()
            raise

    def run_once(self, platform):
        if self.resource_bridge.binding() is not None:
            with self._resources():
                pass  # Refresh joined admission for idle/unavailable/drained pools.
        self._path(platform)
        self._require_image_available(platform)
        available = getattr(self.worker, "session_available", None)
        if available is not None and not available(platform):
            # macOS guests run only while the owner is logged in. Admit nothing
            # and touch no journal until the session returns.
            self._health(platform, "waiting", reason="owner_logged_out")
            return dict(state="waiting")
        try:
            with control.file_lock(self.state / (platform + ".lock")):
                recovered = self._recover(platform)
                if recovered["state"] == "busy":
                    return recovered
                if self._draining():
                    self._health(platform, "drained")
                    return dict(state="drained")
                if self.profile.get("fleet"):
                    available = self.availability(self.profile["fleet"]["role"])
                    count = (
                        self.demand(self.profile, platform, self.api)
                        if available["available"]
                        else 0
                    )
                    self._offer(platform, count)
                    if not available["available"]:
                        self._health(
                            platform, "unavailable", reason=available["reason"]
                        )
                        return dict(state="unavailable")
                    if not count:
                        self._health(platform, "idle")
                        return dict(state="idle")
                    if not self._turn(platform):
                        self._health(platform, "waiting", reason="account_turn")
                        return dict(state="waiting")
                inspected = policy.inspect(
                    self.profile, self.api, strict_selectors=False
                )
                group = inspected["groups"].get(platform)
                require(
                    isinstance(group, dict)
                    and type(group.get("id")) is int
                    and group["id"] > 0,
                    "Exact runner group is not ready; complete admission policy setup.",
                )
                if self.profile["owner"]["type"] == "User":
                    waiting = fleet.repository_demand(self.profile, platform, self.api)
                    selected = fleet.choose(
                        {str(key): count for key, count in waiting.items()},
                        last=self._last_repository.get(platform),
                    )
                    if selected is None:
                        self._health(platform, "idle")
                        return dict(state="idle")
                    group = dict(group, id=int(selected))
                record = self._admit(platform, group["id"])
                if self.profile["owner"]["type"] == "User":
                    self._last_repository[platform] = str(group["id"])
                cleaning = False
                operation = "prepare"
                try:
                    self._health(platform, "preparing", generation=record["generation"])
                    self._prepare(platform, record)
                    self._record_prepared(platform)
                    self._health(platform, "creating", generation=record["generation"])
                    operation = "create"
                    self._prepare(platform, record, operation="create")
                    if "disk_capacity" in record:
                        del record["disk_capacity"]
                        with self._resources():
                            self._write(platform, record)
                    require(
                        not self._draining(),
                        "Pool drained during creation; registration was not started.",
                    )
                    if self.profile.get("fleet"):
                        # Preparation can outlive a laptop's AC/availability
                        # observation. Recheck at the last pre-registration
                        # boundary; provider assignment after this sample is
                        # guarded by the existing idle/busy execution handling.
                        available = self.availability(self.profile["fleet"]["role"])
                        if not available["available"]:
                            self._offer(platform, 0)
                            cleaning = True
                            self._cleanup(platform, record)
                            self._health(
                                platform, "unavailable", reason=available["reason"]
                            )
                            return dict(state="unavailable")
                    operation = "register"
                    response = self.api(
                        "POST",
                        policy.runner_root(self.profile, record["group_id"])
                        + "/generate-jitconfig",
                        dict(
                            name=record["name"],
                            runner_group_id=1
                            if self.profile["owner"]["type"] == "User"
                            else record["group_id"],
                            labels=config.labels(self.profile, platform),
                            work_folder="_work",
                        ),
                    )
                    runner = (
                        response.get("runner") if isinstance(response, dict) else None
                    )
                    jit = (
                        response.get("encoded_jit_config")
                        if isinstance(response, dict)
                        else None
                    )
                    require(
                        isinstance(runner, dict)
                        and type(runner.get("id")) is int
                        and runner["id"] > 0
                        and runner.get("name") == record["name"]
                        and isinstance(jit, str)
                        and bool(jit)
                        and len(jit) <= 2 * 1024 * 1024
                        and not any(c.isspace() for c in jit),
                        "GitHub returned malformed one-job registration; response suppressed.",
                    )
                    record["runner_id"] = runner["id"]
                    record = self._phase(platform, record, "registered")
                    self._record_proof(platform)
                    operation = "execute"
                    result = self._execute(platform, record, jit)
                    jit = None
                    cleaning = True
                    self._cleanup(platform, record)
                    return dict(
                        state="idle",
                        exit_code=result["exit_code"],
                        generation=record["generation"],
                    )
                except BaseException as error:
                    # Do not mask cancellation, disclose worker output, release
                    # unknown capacity, or attempt a workflow retry.
                    if isinstance(error, ProviderBusy):
                        raise
                    uncertain = cleaning or isinstance(error, WorkerUncertain)
                    diagnostics = config.failure_diagnostics(
                        error, "cleanup" if cleaning else operation
                    )
                    if isinstance(error, WorkerUncertain):
                        self._phase(platform, record, "cleanup-required")
                    elif not cleaning:
                        try:
                            self._cleanup(platform, record)
                        except ProviderBusy as cleanup_error:
                            if isinstance(
                                error,
                                (KeyboardInterrupt, control.Cancelled, SystemExit),
                            ):
                                raise error
                            raise ProviderBusy(
                                str(cleanup_error), diagnostics=diagnostics
                            ) from None
                        except Exception as cleanup_error:
                            uncertain = True
                            diagnostics = (
                                diagnostics[:1]
                                + config.failure_diagnostics(cleanup_error, "cleanup")[
                                    :1
                                ]
                            )
                            self._health(platform, "cleanup-required")
                    if isinstance(
                        error, (KeyboardInterrupt, control.Cancelled, SystemExit)
                    ):
                        raise
                    if (
                        isinstance(error, (PreparationPaused, CapacityWaiting))
                        and not uncertain
                    ):
                        raise
                    reason, retryable = recovery_reason(error)
                    raise GenerationFailure(
                        "unsafe_state" if uncertain else reason,
                        retryable and not uncertain,
                        diagnostics=diagnostics,
                    ) from None
        except control.StateError:
            raise Failure(
                "Pool slot is already controlled or has unsafe lock metadata."
            ) from None

    def _dependency_ready(self, reason, platform):
        """Read-only observation; run_once still proves journal safety before any admission."""
        try:
            if reason == "provider_unavailable":
                inspected = policy.inspect(
                    self.profile, self.api, strict_selectors=False
                )
                return not inspected["missing"]
            if reason in ("capacity_unavailable", "native_unavailable"):
                active = self._scan()
                record = self._read(self._path(platform))
                capacity = record.get("disk_capacity") if record else None
                reserve = max(
                    [max(20, self.profile["min_free_gib"]) * GIB]
                    + [r["resources"]["reserve_bytes"] for r in active]
                )
                required = (
                    config.preparation_required_free(capacity, reserve)
                    if capacity
                    else reserve
                )
                pool = self.profile["pools"][platform]
                cpus, memory, free = (
                    _value(self.cpu_count),
                    _value(self.memory_bytes),
                    _value(self.free_bytes),
                )
                return (
                    all(
                        type(value) is int and value > 0
                        for value in (cpus, memory, free)
                    )
                    and len(active) < 2
                    and sum(r["profile_id"] == self.profile["id"] for r in active)
                    < self.profile["max_active_vms"]
                    and sum(r["resources"]["cpus"] for r in active) + pool["cpus"]
                    <= cpus // 2
                    and sum(r["resources"]["memory_bytes"] for r in active)
                    + pool["memory_gib"] * GIB
                    <= memory // 2
                    and free >= required
                )
        except Exception:
            pass  # Unknown observations never authorize another mutating attempt.
        return False

    def _reclaim(self, platform):
        """Free storage only the runner system owns; return the bytes freed."""
        if getattr(self, "reclaim", None) is None:
            return 0
        try:
            # Holding the resource lock keeps any pool from being admitted
            # meanwhile; image caches go only while no other pool of this
            # account can be downloading into them.
            with self._resources():
                busy = [
                    r
                    for r in self._scan()
                    if r["profile_id"] == self.profile["id"]
                    and r["platform"] != platform
                ]
                freed = self.reclaim(caches=not busy)
        except Exception:
            return 0
        return freed if type(freed) is int and freed > 0 else 0

    def _serve_platform(self, platform, stop_event):
        failures = 0
        reclaimed = False
        while not stop_event.is_set():
            try:
                self.run_once(platform)
                failures = 0
                reclaimed = False
            except Exception as error:
                if isinstance(error, ImageUpgradePending):
                    self._health(
                        platform, "blocked", reason="image_upgrade", retrying=False
                    )
                    stop_event.wait(self.poll_interval)
                    continue
                if isinstance(error, ProviderBusy):
                    self._health(platform, "busy", reason="provider_finishing")
                    stop_event.wait(self.poll_interval)
                    continue
                if isinstance(error, PreparationPaused):
                    self._health(platform, "drained")
                    stop_event.wait(self.poll_interval)
                    continue
                if isinstance(error, CapacityWaiting):
                    self._health(platform, "waiting", reason="host_capacity")
                    stop_event.wait(self.poll_interval)
                    continue
                failures = min(failures + 1, self.max_retries)
                reason, retryable = recovery_reason(error)
                diagnostics = config.failure_diagnostics(error, "controller")
                try:
                    self._remember_failure(platform, diagnostics)
                except Exception as storage_error:
                    # Keep the primary cause and exact storage failure visible;
                    # never let a failed diagnostic write silently kill a pool thread.
                    self._health(
                        platform,
                        "blocked",
                        reason="unsafe_state",
                        attempt=failures,
                        diagnostics=diagnostics[:1]
                        + config.failure_diagnostics(storage_error, "controller")[:1],
                        retrying=False,
                    )
                    stop_event.wait()
                    return
                disk_shortage = any("disk_capacity" in value for value in diagnostics)
                if disk_shortage and not reclaimed and self._reclaim(platform) > 0:
                    # Runner-owned storage was freed: try again before anyone
                    # hears about a shortage.
                    reclaimed = True
                    self._health(platform, "retrying", reason=reason, attempt=failures)
                    stop_event.wait(self.backoff)
                    continue
                if not retryable or failures >= self.max_retries or disk_shortage:
                    probing = retryable and reason in (
                        "provider_unavailable",
                        "capacity_unavailable",
                        "native_unavailable",
                    )
                    self._health(
                        platform,
                        "blocked",
                        reason=reason,
                        attempt=failures,
                        diagnostics=diagnostics,
                        retrying=probing,
                    )
                    if probing:
                        # At most one read-only probe per five minutes. No VM
                        # creation/cleanup occurs until the dependency returns.
                        # Capacity recovery permits one guarded attempt, not a
                        # fresh mutation burst on cleanup-restored headroom. A
                        # guest that got no address is retried every 30 minutes.
                        interval = self.retry_probe_interval * (
                            6 if reason == "native_unavailable" else 1
                        )
                        while not stop_event.wait(interval):
                            if self._dependency_ready(reason, platform):
                                if reason == "provider_unavailable":
                                    failures = 0
                                break
                        if stop_event.is_set():
                            return
                        continue
                    stop_event.wait()  # Unsafe/native ambiguity requires deliberate maintenance.
                    return
                delay = min(self.backoff * 2 ** (failures - 1), 300)
                self._health(
                    platform,
                    "retrying",
                    reason=reason,
                    attempt=failures,
                    retry_at=time.time() + delay,
                    diagnostics=diagnostics,
                )
                stop_event.wait(delay)
                continue
            stop_event.wait(self.backoff)

    def serve(self, stop_event):
        self._stop = stop_event
        threads = [
            threading.Thread(
                target=self._serve_platform,
                args=(platform, stop_event),
                name="pool-" + platform,
            )
            for platform in self.profile["pools"]
        ]
        for thread in threads:
            thread.start()
        try:
            while not stop_event.wait(0.2):
                pass
        except BaseException:
            stop_event.set()
            raise
        finally:
            for thread in threads:
                thread.join()
