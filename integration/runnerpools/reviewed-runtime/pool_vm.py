"""Organization-scoped disposable Tart VMs. Native output never reaches the console."""

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid

from pool_config import Failure
import pool_guest

TART_VERSION = "2.41.1"
SEED_MARKER = ".runner-pools-image"  # Written by root beside each shared-image clone.
TART_ARCHIVE_SHA256 = "e680a734febccfce7d4e910c1f7f13fc3b00f19a181c945e2d746de3214c32c2"


def _native_operation(argv):
    if argv and str(argv[0]) in ("/usr/bin/ssh", "/usr/bin/ssh-keygen"):
        return Path(argv[0]).name
    for index, item in enumerate(argv[:-1]):
        if Path(str(item)).name == "tart":
            from pool_config import NATIVE_OPERATIONS

            value = "tart-" + (
                "version" if argv[index + 1] == "--version" else str(argv[index + 1])
            )
            return value if value in NATIVE_OPERATIONS else "tart"
    return "native"


_REASONS = (
    (
        "keychain_unavailable",
        (
            "failed to generate keypair",
            "interaction is not allowed with the security server",
            "encountered a security error",
            "unable to access security information",
        ),
    ),
    (
        "host_identity_changed",
        ("host key verification failed", "remote host identification has changed"),
    ),
    ("disk_full", ("no space left on device", "not enough disk space")),
    ("permission_denied", ("permission denied", "operation not permitted")),
    (
        "authorization_denied",
        ("unauthorized", "authentication required", "forbidden", "returned error: 403"),
    ),
    ("source_unavailable", ("manifest unknown", "not found", "returned error: 404")),
    (
        "transport_unavailable",
        (
            "connection refused",
            "connection timed out",
            "could not resolve host",
            "network is unreachable",
        ),
    ),
    (
        "capacity_unavailable",
        ("cannot allocate memory", "not enough memory", "insufficient memory"),
    ),
)


SUPPORT_LIMIT = 8
_SECRET = re.compile(
    r"-----BEGIN [^-]+-----.*?-----END [^-]+-----|gh[pousr]_[A-Za-z0-9]{16,}|[A-Za-z0-9+/=_-]{40,}",
    re.S,
)


def support_redact(text):
    """Bounded printable text with keys, tokens and long opaque strings removed."""
    text = "".join(ch if ch == "\n" or 32 <= ord(ch) < 127 else "?" for ch in str(text))
    return _SECRET.sub("[redacted]", text)[-2048:]


def _native_reason(output):
    return next(
        (
            reason
            for reason, patterns in _REASONS
            if any(pattern in output for pattern in patterns)
        ),
        None,
    )


def require(condition, message):
    if not condition:
        raise Failure(message)


# macOS 15 and later need an unlocked login keychain while a macOS guest runs:
# Virtualization creates the virtual machine's host identity in it. macOS
# guests therefore run in the owner's logged-in session, never in a runner
# account; a refusal is still named `keychain_unavailable`.


def _private_directory(path):
    require(not path.is_symlink(), "Pool storage cannot be a symlink.")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    require(
        info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0,
        "Pool storage must be private and owned by the isolated runtime account.",
    )


def _write(path, value):
    require(not path.is_symlink(), "Pool record cannot be a symlink.")
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex)
    with temporary.open("x", encoding="utf-8") as stream:
        os.chmod(temporary, 0o600)
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


class Tart:
    def __init__(self, profile, platform, run, home, *, tool=None, user=None):
        self.profile, self.platform, self.run, self.home = (
            profile,
            platform,
            run,
            Path(home),
        )
        self.user = user
        ident = profile.get("id", "")
        require(
            re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", ident) and len(ident) <= 20,
            "Pool VM namespace requires a validated organization ID.",
        )
        require(
            platform in ("linux", "macos") and platform in profile.get("pools", {}),
            "Unknown pool platform.",
        )
        self.pool = profile["pools"][platform]
        require(
            re.fullmatch(
                r"ghcr\.io/[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}",
                self.pool.get("image_source", ""),
            ),
            "VM source must be an immutable reviewed GHCR digest.",
        )
        require(
            re.fullmatch(r"\d+\.\d+\.\d+", self.pool.get("runner_version", ""))
            and re.fullmatch(r"[0-9a-f]{64}", self.pool.get("runner_digest", "")),
            "Runner version and SHA256 must be pinned.",
        )
        require(
            self.home.is_absolute()
            and ".." not in self.home.parts
            and self.home.name == "ci-pools-" + ident,
            "VM state requires the isolated organization account home.",
        )
        for key in ("cpus", "memory_gib", "disk_gib"):
            require(
                type(self.pool.get(key)) is int and self.pool[key] > 0,
                "VM resources must be explicit positive integers.",
            )
        self.tool = (
            Path(tool)
            if tool
            else Path("/Library/Application Support/RunnerPools")
            / ident
            / "bin/tart.app/Contents/MacOS/tart"
        )
        require(
            self.tool.is_absolute() and ".." not in self.tool.parts,
            "Tart executable path must be absolute.",
        )
        self.root = self.home / "pool-vms" / platform
        revision = self.pool.get("image_revision")
        if revision is not None:
            require(
                platform == "macos" and re.fullmatch(r"[a-f0-9]{64}", revision),
                "Image revision requires an exact macOS image identity.",
            )
            self.root = self.root / "images" / revision
        self.key = self.root / "management_ed25519"
        self.ready = self.root / "base.json"
        self.intent = self.root / "prepare.json"
        self.instances = self.root / "instances"
        self.base_name = ident + "-" + platform + "-base"
        if revision is not None:
            self.base_name = ident + "-" + platform + "-" + revision[:12] + "-base"

    def _invoke(self, argv, *, data=None, timeout=60, check=True):
        try:
            result = self.run([str(a) for a in argv], input=data, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as original:
            error = Failure(
                "Pool native operation unavailable or timed out; preserve VM state for recovery."
            )
            error.native_operation = _native_operation(argv)
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
        if check and result.returncode != 0:
            error = Failure(
                "Pool native operation failed; native output suppressed. Preserve state for recovery."
            )
            error.native_operation = _native_operation(argv)
            output = (
                (result.stdout or "")[-32768:] + "\n" + (result.stderr or "")[-32768:]
            ).lower()
            reason = _native_reason(output)
            if reason:
                error.native_reason = reason
            error.native_tail = support_redact(
                (result.stdout or "")[-4096:] + "\n" + (result.stderr or "")[-4096:]
            )
            if type(result.returncode) is int and -255 <= result.returncode <= 255:
                error.exit_code = result.returncode
            raise error
        return result

    def _tart_argv(self, *args):
        return [
            "/usr/bin/env",
            "-i",
            # In the owner's session Tart runs as the owner, whose keychain
            # macOS needs; in a runner account, as that account.
            "HOME=" + (self.user.pw_dir if self.user else str(self.home)),
            "USER=" + (self.user.pw_name if self.user else self.home.name),
            "LOGNAME=" + (self.user.pw_name if self.user else self.home.name),
            "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
            "TART_HOME=" + str(self.home / ".tart"),
            "TART_NO_AUTO_PRUNE=1",
            str(self.tool),
            *args,
        ]

    def _tart(self, *args, **kwargs):
        return self._invoke(self._tart_argv(*args), **kwargs)

    def _storage(self):
        _private_directory(self.home)
        _private_directory(self.home / ".tart")
        _private_directory(self.home / "pool-vms")
        _private_directory(self.root)
        _private_directory(self.instances)

    def _record(self, path):
        require(
            path.is_file()
            and not path.is_symlink()
            and path.stat().st_uid == os.geteuid()
            and path.stat().st_mode & 0o077 == 0,
            "Pool lifecycle record missing or unsafe; recover before continuing.",
        )
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            raise Failure(
                "Pool lifecycle record unreadable; preserve VM state."
            ) from None
        require(isinstance(data, dict), "Pool lifecycle record malformed.")
        return data

    def _native_state(self, name):
        result = self._tart("list", "--source", "local", "--format", "json")
        try:
            rows = json.loads(result.stdout)
        except (ValueError, TypeError):
            raise Failure(
                "Tart returned ambiguous VM state; preserve the instance."
            ) from None
        require(
            isinstance(rows, list) and all(isinstance(r, dict) for r in rows),
            "Tart returned ambiguous VM state.",
        )
        matches = [r for r in rows if r.get("Name") == name]
        require(len(matches) <= 1, "Tart returned duplicate VM state.")
        if not matches:
            return "absent"
        row = matches[0]
        require(
            row.get("State") in ("running", "stopped")
            and type(row.get("Running")) is bool
            and row["Running"] == (row["State"] == "running"),
            "Tart VM is in an unknown or suspended state; preserve it.",
        )
        return row["State"]

    def _start(self, name):
        log = self.root / (name + ".boot.log")
        # Tart's foreground VM process survives this short supervised launcher. The controller
        # owns its unique generation and stops it with Tart before deleting any files.
        launcher = (
            "import os,subprocess,sys; os.umask(0o077); "
            'f=open(sys.argv[1],"ab",buffering=0); '
            "subprocess.Popen(sys.argv[2:],stdin=subprocess.DEVNULL,stdout=f,stderr=f,start_new_session=True,close_fds=True)"
        )
        self._invoke(
            [
                sys.executable,
                "-c",
                launcher,
                str(log),
                *self._tart_argv(
                    "run",
                    "--no-graphics",
                    "--no-audio",
                    "--no-clipboard",
                    "--no-usb-accessories",
                    name,
                ),
            ]
        )

    def _start_reachable(self, name, attempts=3):
        """Boot a VM until the guest has an address; stop it before each retry.

        A guest that boots under disk or memory pressure can fail to obtain a
        DHCP lease. The last failure carries the reason found in its boot log.
        """
        for attempt in range(attempts):
            self._start(name)
            try:
                address = self._ip(name)
            except Failure as error:
                if getattr(error, "native_operation", None) != "tart-ip":
                    raise
                if self._native_state(name) == "running":
                    self._tart("stop", name, timeout=120)
                self._support(
                    "boot",
                    vm=name,
                    attempt=attempt + 1,
                    outcome="no_address",
                    boot_tail=support_redact(self._boot_tail(name)),
                    tart_tail=getattr(error, "native_tail", ""),
                )
                reason = self._boot_reason(name)
                # Another boot cannot help a guest whose identity macOS refused.
                if attempt == attempts - 1 or reason == "keychain_unavailable":
                    if reason:
                        error.native_reason = reason
                    raise
            else:
                self._support("boot", vm=name, attempt=attempt + 1, outcome="address")
                return address

    def _support(self, event, **fields):
        """Append to this platform's bounded, private support ring."""
        path = self.root / "support.json"
        try:
            entries = (
                json.loads(path.read_text())
                if path.exists() and not path.is_symlink()
                else []
            )
        except (OSError, ValueError):
            entries = []
        entry = {
            "time": int(time.time()),
            "event": event,
            "platform": self.platform,
            "tart_version": TART_VERSION,
            "image": self.pool["image_source"],
            "network": "shared",
            **fields,
        }
        try:
            # Free space beside each attempt shows whether retries grow storage.
            entry["free_bytes"] = shutil.disk_usage(self.home).free
        except OSError:
            pass
        previous = (
            [e for e in entries if isinstance(e, dict)]
            if isinstance(entries, list)
            else []
        )
        try:
            _write(path, (previous + [entry])[-SUPPORT_LIMIT:])
        except OSError:
            pass  # The ring explains failures; it never causes one.

    def _boot_tail(self, name):
        log = self.root / (name + ".boot.log")
        try:
            info = log.lstat()
            if (
                not os.path.isfile(log)
                or log.is_symlink()
                or info.st_uid != os.geteuid()
            ):
                return ""
            with open(log, "rb") as handle:
                handle.seek(max(0, info.st_size - 65536))
                return handle.read().decode(errors="replace")
        except OSError:
            return ""

    def _boot_reason(self, name):
        return _native_reason(self._boot_tail(name).lower())

    def _ip(self, name):
        result = self._tart("ip", "--wait", "120", name, timeout=130)
        try:
            value = str(ipaddress.ip_address((result.stdout or "").strip()))
        except ValueError:
            raise Failure("Tart did not return a valid guest address.") from None
        return value

    def _pin_host_key(self, base):
        result = self._tart(
            "exec", self.base_name, "/bin/cat", "/etc/ssh/ssh_host_ed25519_key.pub"
        )
        value = (result.stdout or "").strip()
        require(
            re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\r\n]*)?", value),
            "Trusted guest channel returned an invalid SSH host key.",
        )
        base["host_key"] = " ".join(value.split()[:2])
        return base

    def _known_hosts(self, instance):
        value = instance.get("host_key", "")
        require(
            re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]+", value),
            "Pinned guest host key is missing.",
        )
        path = Path(instance["known_hosts"])
        require(
            path.parent == self.root and not path.is_symlink(),
            "Guest known-hosts path is unsafe.",
        )
        content = self.base_name + " " + value + "\n"
        if path.exists():
            require(
                path.is_file()
                and path.stat().st_uid == os.geteuid()
                and path.stat().st_mode & 0o077 == 0
                and path.read_text() == content,
                "Pinned guest SSH identity changed; preserve the VM.",
            )
        else:
            fd = os.open(
                path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
            )
            with os.fdopen(fd, "w") as stream:
                stream.write(content)

    def _ssh(self, instance, command, *, data=None, timeout=60, check=True):
        self._known_hosts(instance)
        return self._invoke(
            [
                "/usr/bin/ssh",
                "-F",
                "/dev/null",
                "-T",
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "IdentityAgent=none",
                "-o",
                "ForwardAgent=no",
                "-o",
                "ClearAllForwardings=yes",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "HostKeyAlias=" + self.base_name,
                "-o",
                "UserKnownHostsFile=" + instance["known_hosts"],
                "-i",
                str(self.key),
                "ci-manager@" + instance["ip"],
                "sudo",
                "-n",
                command,
            ],
            data=data,
            timeout=timeout,
            check=check,
        )

    def _wait(self, instance):
        for attempt in range(30):
            result = self._ssh(
                instance, "/usr/local/libexec/runner-pool-check", check=False
            )
            if result.returncode == 0 and (result.stdout or "").strip() == "POOL_READY":
                return
            if attempt != 29:
                time.sleep(2)
        raise Failure(
            "Guest hardening/readiness check failed; preserve the generation for recovery."
        )

    def _wait_management(self, instance):
        # A reviewed pre-job upgrade repairs the root-owned readiness helpers.
        # Reachability must therefore depend only on the pinned management transport.
        for attempt in range(30):
            result = self._ssh(instance, "/usr/bin/true", check=False)
            if result.returncode == 0:
                return
            if attempt != 29:
                time.sleep(2)
        raise Failure(
            "Pinned guest management transport unavailable; preserve the base for recovery."
        )

    def _bootstrap_fingerprint(self):
        return hashlib.sha256(
            json.dumps(
                {
                    "pool": self.pool,
                    "bootstrap": pool_guest.script(
                        self.platform,
                        self.key.with_suffix(".pub").read_text().strip(),
                        self.pool["runner_version"],
                        self.pool["runner_digest"],
                        **self._toolchains(),
                    ),
                },
                sort_keys=True,
            ).encode()
        ).hexdigest()

    def _toolchains(self):
        """Pass reviewed image additions only when the pool opts in, so other recipes stay byte-identical."""
        return (
            {"toolchains": tuple(self.pool["toolchains"])}
            if self.pool.get("toolchains")
            else {}
        )

    def _fingerprint(self):
        return hashlib.sha256(
            (
                self._bootstrap_fingerprint()
                + pool_guest.finalize(self.platform, **self._toolchains())
            ).encode()
        ).hexdigest()

    def _finalize_base(self, base):
        self._ssh(
            base,
            "/bin/bash",
            data=pool_guest.finalize(self.platform, **self._toolchains()),
            timeout=120,
        )
        self._wait(base)
        if "guest_os_major" in self.pool:
            require(
                self.platform == "macos" and type(self.pool["guest_os_major"]) is int,
                "Guest OS verification requires an explicit macOS release.",
            )
            version = self._ssh(base, "/usr/bin/sw_vers -productVersion").stdout.strip()
            require(
                re.fullmatch(
                    str(self.pool["guest_os_major"]) + r"(?:\.[0-9]+){0,2}", version
                ),
                "Guest macOS version does not match the reviewed image requirement; preserve the base.",
            )
            base["guest_os_version"] = version
        self._ssh(base, "/bin/sync", timeout=120)
        self._tart("stop", self.base_name, timeout=120)
        require(
            self._native_state(self.base_name) == "stopped",
            "Prepared base did not stop; preserve it.",
        )
        base["bootstrap_fingerprint"] = self._bootstrap_fingerprint()
        base["fingerprint"] = self._fingerprint()
        _write(self.ready, base)
        return base

    def _ownership(self):
        recipe = hashlib.sha256(
            pool_guest.script(
                self.platform,
                "ssh-ed25519 AAAA",
                self.pool["runner_version"],
                self.pool["runner_digest"],
                **self._toolchains(),
            ).encode()
        ).hexdigest()
        return {
            "profile": self.profile["id"],
            "owner": self.profile.get("owner"),
            "platform": self.platform,
            "name": self.base_name,
            "pool": self.pool,
            "recipe": recipe,
        }

    def _retire_stale_base(self):
        """Hand a stopped base built from an older recipe to the interrupted-preparation path."""
        ownership = self._ownership()
        if self.intent.exists():
            previous = self._record(self.intent)
            keys = ("profile", "owner", "platform", "name")
            require(
                {k: previous.get(k) for k in keys} == {k: ownership[k] for k in keys}
                and (
                    previous.get("stage") == "ready"
                    or previous == {**ownership, "stage": "intended"}
                ),
                "Prepared base has a different owner or an unfinished preparation; preserve it for review.",
            )
        # The new intent precedes removing the old record, so an interruption
        # resumes this rebuild rather than leaving an unowned base.
        _write(self.intent, {**ownership, "stage": "intended"})
        self.ready.unlink()

    def prepare(self):
        self._storage()
        version = self._tart("--version").stdout.strip()
        require(
            version == TART_VERSION,
            "Installed Tart version differs from the reviewed pin.",
        )
        if self.ready.exists():
            base = self._record(self.ready)
            require(
                base.get("name") == self.base_name,
                "Prepared base identity changed; preserve it for recovery.",
            )
            if self._native_state(self.base_name) == "running":
                # Jobs run only in clones, so an owned base left running by an
                # interrupted replay is stopped rather than refused.
                self._tart("stop", self.base_name, timeout=120)
            require(
                self._native_state(self.base_name) == "stopped",
                "Prepared base identity changed or is running; preserve it for recovery.",
            )
            if base.get("fingerprint") == self._fingerprint():
                return base
            if (
                base.get("bootstrap_fingerprint", base.get("fingerprint"))
                != self._bootstrap_fingerprint()
            ):
                # macOS keeps its base for a staged, reversible image upgrade.
                # A Linux base has no such path; rebuild it from the reviewed recipe.
                require(
                    self.platform == "linux" and "image_revision" not in self.pool,
                    "Prepared bootstrap changed; preserve it for reviewed image upgrade.",
                )
                self._retire_stale_base()
                return self.prepare()
            # A finalization-only recipe change can replay idempotently over SSH.
            try:
                base["ip"] = self._start_reachable(self.base_name)
                if not base.get("host_key"):
                    base = self._pin_host_key(base)
                self._wait_management(base)
                return self._finalize_base(base)
            except BaseException:
                if self._native_state(self.base_name) == "running":
                    self._tart("stop", self.base_name, timeout=120)
                raise
        ownership = self._ownership()
        if self.intent.exists():
            previous = self._record(self.intent)
            # The partial base and its keys are discarded below, so a Linux
            # preparation may restart under a newer recipe; macOS keeps its own.
            keys = ("profile", "owner", "platform", "name")
            rebuilds = self.platform == "linux" and "image_revision" not in self.pool
            require(
                {k: v for k, v in previous.items() if k != "stage"} == ownership
                or rebuilds
                and {k: previous.get(k) for k in keys}
                == {k: ownership[k] for k in keys},
                "Incomplete preparation has a different owner or recipe; preserve it for review.",
            )
            self._discard_prejob_base()
            for path in (
                self.key,
                self.key.with_suffix(".pub"),
                self.root / "base.known_hosts",
            ):
                if path.exists() or path.is_symlink():
                    require(
                        path.is_file()
                        and not path.is_symlink()
                        and path.stat().st_uid == os.geteuid(),
                        "Incomplete preparation contains unsafe authentication paths; preserve them.",
                    )
                    path.unlink()
        else:
            require(
                self._native_state(self.base_name) == "absent",
                "A base without a matching ownership intent exists; preserve it.",
            )
            require(
                not self.key.exists() and not self.key.with_suffix(".pub").exists(),
                "Management authentication without an ownership intent exists; preserve it.",
            )
        # This durable ownership receipt precedes every key and VM creation.
        _write(self.intent, {**ownership, "stage": "intended"})
        try:
            self._invoke(
                [
                    "/usr/bin/ssh-keygen",
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-C",
                    "pool-management",
                    "-f",
                    str(self.key),
                ]
            )
            os.chmod(self.key, 0o600)
            seed = self._seed()
            if seed is None:
                _write(self.intent, {**ownership, "stage": "pulling"})
                self._tart("pull", self.pool["image_source"], timeout=3600)
                self._support("pull")
            _write(self.intent, {**ownership, "stage": "cloning"})
            self._tart(
                "clone", seed or self.pool["image_source"], self.base_name, timeout=180
            )
            if seed is not None:
                self._drop_superseded_cache()
            self._tart(
                "set",
                self.base_name,
                "--cpu",
                str(self.pool["cpus"]),
                "--memory",
                str(self.pool["memory_gib"] * 1024),
                "--disk-size",
                str(self.pool["disk_gib"]),
            )
            _write(self.intent, {**ownership, "stage": "bootstrapping"})
            self._start_reachable(self.base_name)
            # Only immutable public images with a guest agent are supported. Credentials never
            # cross this boundary: the initial upstream admin agent executes trusted stdin.
            bootstrap = pool_guest.script(
                self.platform,
                self.key.with_suffix(".pub").read_text().strip(),
                self.pool["runner_version"],
                self.pool["runner_digest"],
                **self._toolchains(),
            )
            for attempt in range(30):
                ready = self._tart("exec", self.base_name, "/usr/bin/true", check=False)
                if ready.returncode == 0:
                    break
                require(
                    attempt < 29, "Trusted upstream guest agent did not become ready."
                )
                time.sleep(2)
            self._tart(
                "exec",
                "-i",
                self.base_name,
                "/usr/bin/sudo",
                "-n",
                "/bin/bash",
                data=bootstrap,
                timeout=3600,
            )
            base = {
                "name": self.base_name,
                "profile": self.profile["id"],
                "owner": self.profile.get("owner"),
                "platform": self.platform,
                "image": self.pool["image_source"],
                "key": str(self.key),
                "known_hosts": str(self.root / "base.known_hosts"),
                "ip": self._ip(self.base_name),
                "fingerprint": self._fingerprint(),
            }
            base = self._pin_host_key(base)
            self._wait(base)
            base = self._finalize_base(base)
            _write(self.intent, {**ownership, "stage": "ready"})
            return base
        except BaseException:
            # No provider registration is possible during base preparation. An owned
            # interrupted base may be stopped; ambiguous state is retained for recovery.
            try:
                if self._native_state(self.base_name) == "running":
                    self._tart("stop", self.base_name, timeout=120)
            except (Failure, OSError):
                pass
            raise

    def _seed(self):
        """The account's clone of the shared image, when it carries this exact image."""
        if self.platform != "macos":
            return None
        name = self.profile["id"] + "-macos-seed"
        marker = self.home / ".tart/vms" / name / SEED_MARKER
        try:
            info = marker.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_size > 4096
                or marker.read_text() != self.pool["image_source"]
            ):
                return None
        except (OSError, UnicodeError):
            return None
        return name if self._native_state(name) == "stopped" else None

    def _drop_superseded_cache(self):
        """Remove this account's own download of an image it now clones from the shared copy."""
        reference = self.pool["image_source"].split("@", 1)[0]
        parts = reference.split("/")
        cache = self.home / ".tart/cache/OCIs"
        target = cache.joinpath(*parts)
        try:
            if (
                len(parts) >= 2
                and all(part not in ("", ".", "..") for part in parts)
                and target.is_dir()
                and not any(
                    p.is_symlink()
                    for p in [target, *target.parents]
                    if p.is_relative_to(cache)
                )
            ):
                shutil.rmtree(target)
        except OSError:
            pass  # Only space is lost; the controller reclaims caches on a shortage.

    def _discard_prejob_base(self):
        state = self._native_state(self.base_name)
        if state == "running":
            self._tart("stop", self.base_name, timeout=120)
            state = self._native_state(self.base_name)
        if state == "stopped":
            self._tart("delete", self.base_name, timeout=120)
        require(
            self._native_state(self.base_name) == "absent",
            "Owned incomplete base cleanup is ambiguous; preserve it and rerun recovery.",
        )

    def create(self, generation):
        require(
            isinstance(generation, str) and re.fullmatch(r"[0-9a-f]{32}", generation),
            "Generation ID is unsafe.",
        )
        base = self._record(self.ready)
        require(
            base.get("fingerprint") == self._fingerprint()
            and self._native_state(self.base_name) == "stopped",
            "Prepared base missing, changed or running.",
        )
        name = self.profile["id"] + "-" + self.platform + "-" + uuid.uuid4().hex
        instance = {
            "name": name,
            "generation": generation,
            "platform": self.platform,
            "image": base["image"],
            "key": str(self.key),
            "known_hosts": str(self.root / (name + ".known_hosts")),
            "host_key": base["host_key"],
        }
        # Journal the intended name before native clone: interruption never loses ownership.
        _write(
            self.instances / (name + ".json"),
            {"instance": instance, "phase": "provisioning"},
        )
        self._tart("clone", self.base_name, name, timeout=180)
        instance["ip"] = self._start_reachable(name)
        _write(
            self.instances / (name + ".json"),
            {"instance": instance, "phase": "provisioning"},
        )
        self._wait(instance)
        self._ssh(
            instance,
            "/usr/local/libexec/runner-pool-generation",
            data=json.dumps(
                {
                    "profile": self.profile["id"],
                    "platform": self.platform,
                    "generation": generation,
                }
            )
            + "\n",
        )
        self._wait(instance)
        _write(
            self.instances / (name + ".json"), {"instance": instance, "phase": "ready"}
        )
        return instance

    def _owned(self, instance):
        require(
            isinstance(instance, dict)
            and re.fullmatch(
                re.escape(self.profile["id"] + "-" + self.platform + "-")
                + r"[0-9a-f]{32}",
                instance.get("name", ""),
            ),
            "Refuse operation on a VM outside this organization generation namespace.",
        )
        path = self.instances / (instance["name"] + ".json")
        record = self._record(path)
        require(
            record.get("instance") == instance,
            "VM identity differs from its owned generation journal; preserve it.",
        )
        return path, record

    def execute(self, instance, jit_config):
        path, record = self._owned(instance)
        require(
            record["phase"] == "ready"
            and self._native_state(instance["name"]) == "running",
            "A generation can execute one JIT runner only.",
        )
        require(
            isinstance(jit_config, str)
            and re.fullmatch(r"[A-Za-z0-9+/=_-]{1,1048576}", jit_config),
            "JIT configuration is malformed.",
        )
        _write(path, {"instance": instance, "phase": "executing"})
        # Official runner receives its JIT argument inside the disposable guest only.
        result = self._ssh(
            instance,
            "/usr/local/libexec/runner-pool-job",
            data=jit_config + "\n",
            timeout=86400,
            check=False,
        )
        if result.returncode == 255:
            _write(path, {"instance": instance, "phase": "execution-unknown"})
            raise Failure(
                "Guest execution transport disconnected; preserve registration and inspect provider busy state before cleanup."
            )
        _write(
            path,
            {"instance": instance, "phase": "executed", "exit_code": result.returncode},
        )
        return result.returncode

    def probe(self, instance):
        """Verify a fresh unregistered guest, returning only a strict public status report."""
        _, record = self._owned(instance)
        require(
            record["phase"] == "ready"
            and self._native_state(instance["name"]) == "running",
            "Native acceptance probes require a fresh, unregistered running generation.",
        )
        expected = {
            "profile": self.profile["id"],
            "platform": self.platform,
            "generation": instance["generation"],
        }
        source = (
            "expected = "
            + repr(expected)
            + "\n"
            + r"""import json, os, pathlib, pwd, stat, subprocess
subprocess.run(['/usr/local/libexec/runner-pool-check'], check=True, capture_output=True)
marker = pathlib.Path('/etc/runner-pool-generation.json')
info = marker.lstat()
assert stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022 and info.st_size < 4096
assert json.loads(marker.read_text()) == expected
user = pwd.getpwnam('ci-build')
home = pathlib.Path(user.pw_dir)
info = home.lstat()
assert user.pw_uid != 0 and stat.S_ISDIR(info.st_mode) and info.st_uid == user.pw_uid and stat.S_IMODE(info.st_mode) == 0o700
assert subprocess.check_output(['sudo','-n','-u','ci-build','id','-un'], text=True).strip() == 'ci-build'
management = '/home/ci-manager' if expected['platform'] == 'linux' else '/Users/ci-manager'
private = subprocess.run(['sudo','-n','-u','ci-build','test','-x',management], capture_output=True).returncode != 0
if expected['platform'] == 'linux':
    locked = subprocess.check_output(['passwd','-S','ci-build'],text=True).split()[1] == 'L'
else:
    locked = 'DisabledUser' in subprocess.check_output(['dscl','.','-read','/Users/ci-build','AuthenticationAuthority'],text=True)
processes = subprocess.run(['pgrep','-u','ci-build'],capture_output=True)
assert processes.returncode in (0,1)
report = dict(expected, account='ci-build',uid=user.pw_uid,home=str(home),locked=locked,nonsudo=True,
    no_host_mounts=True,management_private=private,clean_processes=processes.returncode==1,
    marker_absent=not (home/'.runner-pool-probe-marker').exists())
print(json.dumps(report,sort_keys=True))
"""
        )
        result = self._ssh(
            instance, "/opt/runner-pool/python/bin/python3", data=source, timeout=60
        )
        try:
            report = json.loads(result.stdout)
        except (ValueError, TypeError):
            raise Failure(
                "Guest acceptance returned invalid status; native output suppressed."
            ) from None
        checks = (
            "locked",
            "nonsudo",
            "no_host_mounts",
            "management_private",
            "clean_processes",
            "marker_absent",
        )
        require(
            isinstance(report, dict)
            and set(report) == set(expected) | {"account", "uid", "home", *checks}
            and all(report.get(k) == v for k, v in expected.items())
            and report.get("account") == "ci-build"
            and type(report.get("uid")) is int
            and report["uid"] > 0
            and report.get("home")
            == ("/home/ci-build" if self.platform == "linux" else "/Users/ci-build")
            and all(report.get(k) is True for k in checks),
            "Guest acceptance did not establish the isolated fresh-generation boundary.",
        )
        return report

    def verify_acceptance(self, instance):
        """Execute the fixed fleet pilot checks as ci-build, without registering."""
        self.probe(instance)
        expected = {
            "profile": self.profile["id"],
            "platform": self.platform,
            "generation": instance["generation"],
        }
        payload = (
            "expected = "
            + repr(expected)
            + "\n"
            + r"""import json, os, pathlib, platform, pwd, stat, sys
assert pwd.getpwuid(os.getuid()).pw_name == 'ci-build' and os.getuid() != 0
assert sys.platform == ('linux' if expected['platform'] == 'linux' else 'darwin')
marker = pathlib.Path('/etc/runner-pool-generation.json')
info = marker.lstat()
assert stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
assert json.loads(marker.read_text()) == expected
assert not any(os.environ.get(k) for k in ('GH_TOKEN','GITHUB_TOKEN','SSH_AUTH_SOCK'))
assert platform.machine() in ('arm64','aarch64')
print(json.dumps(dict(expected,machine=platform.machine(),account='ci-build',ci_checks=True),sort_keys=True))
"""
        )
        home = "/home/ci-build" if self.platform == "linux" else "/Users/ci-build"
        source = (
            "CI_ACCEPTANCE_PAYLOAD = "
            + repr(payload)
            + "\n"
            + r"""import subprocess
result = subprocess.run(['sudo','-n','-u','ci-build','/usr/bin/env','-i',
    'HOME=' + """
            + repr(home)
            + r""", 'PATH=/usr/bin:/bin',
    '/opt/runner-pool/python/bin/python3','-I','-c',CI_ACCEPTANCE_PAYLOAD],
    capture_output=True,text=True,check=True,timeout=30)
print(result.stdout,end='')
"""
        )
        result = self._ssh(
            instance, "/opt/runner-pool/python/bin/python3", data=source, timeout=60
        )
        try:
            report = json.loads(result.stdout)
        except (ValueError, TypeError):
            raise Failure(
                "Manual guest acceptance returned invalid controlled metadata."
            ) from None
        require(
            isinstance(report, dict)
            and set(report) == set(expected) | {"machine", "account", "ci_checks"}
            and all(report.get(k) == v for k, v in expected.items())
            and report["machine"] in ("arm64", "aarch64")
            and report["account"] == "ci-build"
            and report["ci_checks"] is True,
            "Manual guest acceptance did not establish isolated ARM64 execution.",
        )
        return report

    def settle_preparation(self):
        """Stop only a provably owned pre-job base; retain images, keys and receipts."""
        if self.intent.exists():
            receipt = self._record(self.intent)
            require(
                receipt.get("profile") == self.profile["id"]
                and receipt.get("owner") == self.profile.get("owner")
                and receipt.get("platform") == self.platform
                and receipt.get("name") == self.base_name
                and receipt.get("pool") == self.pool,
                "Preparation ownership differs; preserve native base state.",
            )
        elif self.ready.exists():
            receipt = self._record(self.ready)
            require(
                receipt.get("profile") == self.profile["id"]
                and receipt.get("owner") == self.profile.get("owner")
                and receipt.get("platform") == self.platform
                and receipt.get("name") == self.base_name
                and receipt.get("image") == self.pool["image_source"],
                "Prepared base ownership is unconfirmed; preserve it.",
            )
        else:
            require(
                self._native_state(self.base_name) == "absent",
                "Unreceipted native base exists; preserve it.",
            )
            return
        state = self._native_state(self.base_name)
        if state == "running":
            self._tart("stop", self.base_name, timeout=120)
            state = self._native_state(self.base_name)
        require(
            state in ("absent", "stopped"),
            "Base shutdown is unconfirmed; retain its resource reservation.",
        )

    def interrupt(self, instance):
        """Stop an exact owned generation while retaining disk and registration for recovery."""
        path, record = self._owned(instance)
        state = self._native_state(instance["name"])
        require(
            state in ("running", "stopped"),
            "Interrupted guest state is unknown; preserve it.",
        )
        if state == "running":
            self._tart("stop", instance["name"], timeout=120)
        require(
            self._native_state(instance["name"]) == "stopped",
            "Guest stop is unconfirmed; preserve it.",
        )
        _write(
            path,
            {
                "instance": instance,
                "phase": "interrupted",
                "exit_code": record.get("exit_code"),
            },
        )

    def destroy(self, instance):
        path, record = self._owned(instance)
        state = self._native_state(instance["name"])
        if state == "absent":
            require(
                record.get("phase") in ("cleanup-required", "destroyed"),
                "Owned VM disappeared outside cleanup; preserve its journal for recovery.",
            )
            _write(
                path,
                {
                    "instance": instance,
                    "phase": "destroyed",
                    "exit_code": record.get("exit_code"),
                },
            )
            return
        _write(path, {"instance": instance, "phase": "cleanup-required"})
        if state == "running":
            self._tart("stop", instance["name"], timeout=120)
        require(
            self._native_state(instance["name"]) == "stopped",
            "VM shutdown is ambiguous; preserve it instead of deleting.",
        )
        self._tart("delete", instance["name"], timeout=120)
        require(
            self._native_state(instance["name"]) == "absent",
            "VM removal is ambiguous; preserve lifecycle journal.",
        )
        _write(
            path,
            {
                "instance": instance,
                "phase": "destroyed",
                "exit_code": record.get("exit_code"),
            },
        )

    def inspect(self, instance):
        _, record = self._owned(instance)
        return {
            "name": instance["name"],
            "generation": instance["generation"],
            "platform": self.platform,
            "state": self._native_state(instance["name"]),
            "phase": record["phase"],
        }
