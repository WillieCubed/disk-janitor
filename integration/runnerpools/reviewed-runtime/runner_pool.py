#!/usr/bin/env python3
"""Turnkey, organization-scoped pools of disposable Linux and macOS runners."""

import argparse
from contextlib import contextmanager, redirect_stdout
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid

# `-I` intentionally excludes the source directory. Only this selected bundle
# supplies imports; privileged runtime verifies its protected installed copy.
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import pool_config as config
from pool_config import Failure, require
import pool_auth as auth
import pool_host as host
import runner_fleet as fleet
import pool_python
import pool_policy as policy
import process_control as control
from runner_console import Console, Outcome, current_session


# Compatibility name for installed callers; there is one renderer implementation.
PoolConsole = Console
UI = Console()


class AuthorityRequired(Failure):
    """Native administrator approval is missing; never substitute credentials."""


def current_profile(path):
    profile = config.load(path)
    installed = config.paths(profile)["profile"]
    if installed.exists() and Path(path).resolve() != installed:
        other = config.load(installed)
        if {k: v for k, v in other.items() if k != "github_app"} != {
            k: v for k, v in profile.items() if k != "github_app"
        }:
            baseline_path = config.paths(profile)["install"] / "baseline-profile.json"
            if baseline_path.exists():
                host.protected(baseline_path)
                baseline = config.load(baseline_path)
                if (
                    "fleet" not in profile
                    and baseline.get("fleet") is not None
                    and baseline["fleet"] == other.get("fleet")
                ):
                    # Legacy source profiles omit this host-derived default.
                    # Explicit identities are never replaced, and source was
                    # validated before this normalization.
                    host.protected(installed)
                    profile = dict(profile, fleet=baseline["fleet"])
                if (
                    profile.get("github_app") is not None
                    and profile["github_app"] != other.get("github_app")
                    and other.get("controller_app")
                ):
                    marker = installed.parent / "shared-controller-migration.json"
                    info = host.protected(marker)
                    require(
                        info.st_nlink == 1 and info.st_size <= 131072,
                        "Shared migration source receipt is unsafe.",
                    )
                    receipt = json.loads(
                        marker.read_text(), object_pairs_hook=config._unique
                    )
                    require(
                        isinstance(receipt, dict)
                        and {"before", "after"} <= set(receipt)
                        and receipt.get("schema_version") == 1
                        and receipt.get("profile") == profile["id"]
                        and receipt.get("stage") == "complete",
                        "Finish the exact shared migration before reusing its original source profile.",
                    )
                    from runner_migration import transition

                    before, after = transition(receipt["before"], receipt["after"])
                    require(
                        before["id"] == profile["id"]
                        and profile["github_app"] == before.get("github_app")
                        and after.get("fleet") == other.get("fleet")
                        and all(
                            after.get(field) == other.get(field)
                            for field in (
                                "github_app",
                                "controller_app",
                                "recovery_app",
                            )
                        ),
                        "Source App identity differs from its protected migration receipt.",
                    )
                    policy._extension(after, other)
                    profile = dict(profile, github_app=other["github_app"])
                require(
                    {k: v for k, v in profile.items() if k != "github_app"}
                    == {k: v for k, v in baseline.items() if k != "github_app"},
                    "Source profile differs from this installation baseline; use its installed profile.",
                )
                for field in ("github_app", "controller_app", "recovery_app"):
                    if field in other:
                        require(
                            field not in profile or profile[field] == other[field],
                            "Source App identity conflicts with the protected installation.",
                        )
                        baseline = dict(baseline, **{field: other[field]})
                policy._extension(baseline, other)
            else:
                pending = config.paths(profile)["install"] / "enrollment.json"
                if not pending.exists():
                    pending = config.paths(profile)["install"] / "last-enrollment.json"
                require(
                    pending.exists(),
                    "Installed policy differs from this source profile; inspect its intended enrollment/upgrade first.",
                )
                host.protected(pending)
                transition = json.loads(pending.read_text())
                policy._extension(transition["before"], transition["after"])
                require(
                    other in (transition["before"], transition["after"])
                    and {k: v for k, v in profile.items() if k != "github_app"}
                    == {
                        k: v
                        for k, v in transition["before"].items()
                        if k != "github_app"
                    },
                    "Installed policy differs from the exact pending enrollment; preserve it.",
                )
        require(
            "github_app" not in profile
            or profile.get("github_app") == other.get("github_app"),
            "Source GitHub App identity conflicts with this installed organization; preserve the installation.",
        )
        if "github_app" in other:
            profile = other
    return profile


def _public(result):
    # Native child protocols emit only explicitly selected controlled metadata.
    print(json.dumps(result, sort_keys=True), flush=True)


def readiness_message(result, *, organization=None):
    """Compatibility adapter for the native lifecycle explanation."""
    from runner_console import readiness_message as message

    return message(result, organization=organization)


def print_readiness(result, *, human=False, organization=None):
    """Format controlled readiness only; automation retains its JSON contract."""
    if not human:
        _public(result)
        return
    if result.get("status") in ("authority_required", "runtime_update_blocked"):
        message = readiness_message(result, organization=organization)
        recovery = result.get("recovery") or {}
        if result["status"] == "authority_required" and recovery.get("command"):
            message += " Run " + recovery["command"] + "."
        print(message, flush=True)
        if recovery.get("detail"):
            print(recovery["detail"], flush=True)
    elif not result.get("diagnostics"):
        print(readiness_message(result, organization=organization), flush=True)
    if result.get("diagnostics"):
        print(
            "\n".join(
                config.describe_diagnostic(value) for value in result["diagnostics"]
            ),
            flush=True,
        )


def _stdin():
    raw = sys.stdin.read(2 * 1024 * 1024 + 1)
    require(len(raw) <= 2 * 1024 * 1024, "Native handoff is too large.")
    try:
        value = json.loads(raw, object_pairs_hook=config._unique)
    except (ValueError, UnicodeError):
        raise Failure("Native handoff is malformed; values suppressed.") from None
    require(isinstance(value, dict), "Native handoff must be an object.")
    return value


def native_failure(error, mode, operation=None):
    """Expose static code context, never exception values, paths or command data."""
    categories = (
        PermissionError,
        FileNotFoundError,
        subprocess.TimeoutExpired,
        subprocess.CalledProcessError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        subprocess.SubprocessError,
    )
    category = next(
        (kind.__name__ for kind in categories if isinstance(error, kind)), "Exception"
    )
    known_operations = (
        "install",
        "pending",
        "finish",
        "prepare",
        "activate",
        "recover",
        "drain",
        "resume",
        "enrollment",
        "enrollment-access",
        "enrollment-idle",
        "create",
        "inspect",
        "probe",
        "local-verify",
        "cleanup",
        "execute",
    )
    context = mode + ("/" + operation if operation in known_operations else "")
    details = [context, category]
    if (
        isinstance(error, OSError)
        and type(error.errno) is int
        and 0 <= error.errno <= 65535
    ):
        details.append("errno=" + str(error.errno))
    location = None
    trace = error.__traceback__
    while trace is not None:
        name = Path(trace.tb_frame.f_code.co_filename).name
        if (
            name in host.PAYLOAD
            and type(trace.tb_lineno) is int
            and 0 < trace.tb_lineno < 1000000
        ):
            location = name + ":" + str(trace.tb_lineno)
        trace = trace.tb_next
    if location:
        details.append(location)
    return (
        "Native pool operation failed [" + "; ".join(details) + "]. Values suppressed."
    )


def privileged(
    profile,
    operation,
    *,
    packet=None,
    source=None,
    archive=None,
    python_archive=None,
    repair_runtime=False,
    recover_blocked=False,
):
    p = config.paths(profile)

    def execute(argv):
        data = json.dumps(packet) if packet is not None else None
        try:
            result = control.run(
                argv,
                input=data,
                timeout=3600
                if operation in ("prepare", "install", "local-verify")
                else 180,
                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise Failure(native_failure(error, "host-control", operation)) from None
        if result.returncode:
            lines = [
                line for line in result.stdout.splitlines() if line.startswith("ERROR ")
            ]
            detail = (
                lines[0][6:]
                if len(lines) == 1 and len(lines[0]) < 1000
                else "Native host operation failed; inspect exact private state."
            )
            packets = [
                line.removeprefix("DIAGNOSTICS ")
                for line in result.stdout.splitlines()
                if line.startswith("DIAGNOSTICS ")
            ]
            diagnostics = []
            if packets:
                require(
                    len(packets) == 1 and len(packets[0]) <= 4096,
                    "Native failure diagnostic packet is ambiguous or too large.",
                )
                diagnostics = config.validate_diagnostics(
                    json.loads(packets[0], object_pairs_hook=config._unique)
                )
            raise Failure(detail, diagnostics=diagnostics)
        try:
            answer = json.loads(result.stdout)
        except (ValueError, TypeError):
            raise Failure("Native host returned invalid controlled metadata.") from None
        require(isinstance(answer, dict), "Native host metadata is not an object.")
        return answer

    if operation == "install":
        require(
            packet is None
            and source is not None
            and archive is not None
            and python_archive is not None,
            "Installation requires verified public source and runtime archives.",
        )
        with pool_python.bootstrap(
            profile,
            HERE,
            source,
            archive,
            python_archive,
            Path.home(),
            host.PAYLOAD,
            repair_runtime=repair_runtime,
            recover_blocked=recover_blocked,
        ) as argv:
            return execute(argv)
    pool_python.verify(profile)
    argv = [
        "/usr/bin/sudo",
        "-n",
        str(pool_python.python_path(profile)),
        "-I",
        "-B",
        str(p["install"] / "runner_pool.py"),
        "host-control",
        "--profile",
        str(p["profile"]),
        "--operation",
        operation,
    ]
    if packet is not None:
        argv += ["--input-present"]
    return execute(argv)


SUDO = "/usr/bin/sudo"


def sudo_prompt():
    """Ask for the Mac password on the owner's terminal, with no time limit.

    sudo writes its prompt and "Sorry, try again." to the terminal device itself;
    only its error lines use stderr, which is captured so the summary can explain
    them. A person typing, or approving with Touch ID, is never stopped by a timer:
    stopping sudo makes it print "a password is required".
    """
    with UI.prompting():
        result = control.run(
            # On a terminal the prompt sits in the same two-space margin as the
            # lines around it (docs/cli.md#layout).
            [SUDO, "-v", *(["-p", "  Password:"] if sys.stderr.isatty() else [])],
            interactive=True,
            capture_output=True,
            timeout=None,
        )
    if result.returncode == 0:
        return
    errors = result.stderr or ""
    if "incorrect password attempt" in errors:
        raise Failure(
            "The Mac password was not accepted.", code="approval.mac_password_rejected"
        )
    if "timed out reading password" in errors:
        raise Failure(
            "The administrator prompt closed before a password was entered.",
            code="approval.mac_password_timeout",
        )
    raise Failure(
        "Native administrator authentication was not completed.",
        code="approval.mac_password_timeout",
    )


def sudo_authorize(*, purpose=None, terminal_command=None):
    cached = control.run([SUDO, "-n", "-v"], timeout=10)
    if cached.returncode == 0:
        return
    session = current_session()
    if session is not None and session.machine:
        raise AuthorityRequired(
            "Administrator authentication is required. Run hypertext runners in your normal Terminal; no setup changes have started."
        )
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        if purpose is not None and terminal_command is not None:
            raise AuthorityRequired(
                purpose + " Run in your normal Terminal: " + terminal_command
            )
        raise AuthorityRequired(
            "Continue the same command in your normal visible Terminal for native administrator authentication."
        )
    if purpose is None:
        UI.administrator_prompt()
    else:
        UI.authorization(purpose)
    sudo_prompt()


def authorize_setup(profile, *, recover_blocked=False):
    if recover_blocked:
        sudo_authorize(
            purpose="Mac administrator access is needed to pause the blocked runners and recover their saved setup.",
            terminal_command="hypertext runners",
        )
        return
    snapshot = config.preflight_disk(profile)
    if UI.environ.get("RUNNER_POOLS_GUIDED") != "1":
        UI.note(
            f"Storage check: {snapshot['available_gib']:.1f} GiB available · {snapshot['required_gib']:g} GiB minimum free reserve"
        )
        UI.note("Runner storage: " + snapshot["filesystem_path"])
    sudo_authorize()


def installation_guidance(profile):
    """Explain the one-time App grant separately from allowed workflow execution."""
    if profile["owner"]["type"] == "Organization":
        return (
            "Choose All repositories for this organization to avoid approving each new repository. "
            "Only configured, validated workflows can run on this Mac. "
            "Only select repositories remains available if you prefer a restricted App grant."
        )
    return "Choose Only select repositories and keep the personal repositories you want to run selected."


def show_in_chrome(url, browser):
    if current_session() is not None and current_session().machine:
        raise AuthorityRequired(
            "GitHub approval is required. Continue with hypertext runners in your normal Terminal."
        )
    from pool_setup import open_chrome

    with UI.attending():  # The owner must see where to approve, even in quiet runs.
        UI.note("Approval address (open in your browser signed in to GitHub):")
        # Keep long nonce-bearing URLs intact for terminal links and copy/paste.
        UI.write(url)
        if os.environ.get("SSH_CONNECTION"):
            UI.note(
                "Open the address above on the Mac running SSH; keep the forwarded connection open."
            )
            return
        if sys.stdin.isatty():
            answer = UI.prompt("Open in Chrome? [Y/n]").strip().lower()
            if answer not in ("", "y", "yes"):
                UI.note(
                    "Open the address above when ready. Setup will continue after approval."
                )
                return
        try:
            opened = open_chrome(url, browser)
        except (Failure, OSError, subprocess.SubprocessError):
            opened = False
        if not opened:
            UI.note(
                "Open the address above in your intended GitHub browser profile. Setup is waiting for approval."
            )


@contextmanager
def administrator_session():
    """Refresh only this supervised invocation's normal sudo timestamp."""
    done = threading.Event()

    def refresh():
        while not done.wait(45):
            try:
                subprocess.run(
                    [SUDO, "-n", "-v"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
                )
            except (OSError, subprocess.SubprocessError):
                pass  # A later native handoff fails visibly; no password fallback.

    thread = threading.Thread(target=refresh, daemon=True)
    thread.start()
    try:
        yield
    finally:
        done.set()
        thread.join(timeout=11)


def archive_path(args, *, allow_download=True):
    if args.tart_archive:
        target = args.tart_archive
    else:
        directory = Path.home() / ".cache/runner-pools/tools" / host.TART_VERSION
        if allow_download:
            directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        target = directory / "tart.tar.gz"
        if not target.exists():
            require(
                allow_download,
                "Pinned virtualization recovery archive is not cached; no tools were downloaded or installed.",
            )
            with tempfile.TemporaryDirectory(
                prefix="download-", dir=directory
            ) as temporary:
                result = control.run(
                    [
                        "gh",
                        "release",
                        "download",
                        host.TART_VERSION,
                        "--repo",
                        "cirruslabs/tart",
                        "--pattern",
                        "tart.tar.gz",
                        "--dir",
                        temporary,
                    ],
                    timeout=300,
                )
                require(
                    result.returncode == 0,
                    "Official virtualization download failed; native output suppressed.",
                )
                raw = (Path(temporary) / "tart.tar.gz").read_bytes()
                require(
                    hashlib.sha256(raw).hexdigest() == host.TART_SHA256,
                    "Official virtualization archive digest differs.",
                )
                control.atomic_write(target, raw, mode=0o600)
    require(
        target.is_file()
        and not target.is_symlink()
        and hashlib.sha256(target.read_bytes()).hexdigest() == host.TART_SHA256,
        "Pinned official virtualization archive is missing or differs.",
    )
    return target


def read_controller_key(path):
    path = Path(path).expanduser().absolute()
    require(
        ".." not in path.parts
        and all(not item.is_symlink() for item in (path, *path.parents)),
        "Controller key input must not traverse links.",
    )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.geteuid()
            and info.st_nlink == 1
            and info.st_size < 20000,
            "Controller key must be a small regular file owned by you.",
        )
        os.fchmod(fd, 0o600)
        raw = os.read(fd, 20001)
        require(
            len(raw) < 20000
            and raw.startswith(
                (b"-----BEGIN RSA PRIVATE KEY-----", b"-----BEGIN PRIVATE KEY-----")
            ),
            "Choose the private key downloaded from the existing controller App; values are suppressed.",
        )
        return raw.decode("ascii")
    finally:
        os.close(fd)


def prepare_shared_host_key(args, profile):
    reference = profile.get("controller_app")
    if reference is None or host.shared_controller_reference() is not None:
        return
    path = getattr(args, "controller_key", None)
    if path is None:
        require(
            sys.stdin.isatty(),
            "This Mac needs a key for the existing shared controller App. Resume setup in your normal Terminal; do not create another App.",
        )
        UI.note(
            "Add this Mac to "
            + reference["slug"]
            + ". Generate a separate private key in the existing App so this device can be revoked independently. No new App is created; account installation approval follows only if needed."
        )
        owner = reference["owner"]
        base = (
            "https://github.com/organizations/" + owner["login"] + "/settings/apps/"
            if owner["type"] == "Organization"
            else "https://github.com/settings/apps/"
        )
        show_in_chrome(base + reference["slug"], args.chrome_profile or owner["login"])
        path = UI.prompt(
            "Path to the downloaded private key (never paste its contents):"
        ).strip()
        require(
            bool(path),
            "No key selected. Resume the same setup; no new App was created.",
        )
    pem = read_controller_key(path)
    try:
        privileged(profile, "shared-key", packet={"reference": reference, "pem": pem})
    finally:
        pem = None


FACT_KEYS = {"result", "code", "available_bytes", "required_bytes", "checked_at"}


def _facts(answer):
    """Hand the operator the native install's facts on the quiet protocol.

    Only the bounded macOS proof and reclaimed-storage facts cross; any other
    answer content stays inside the native boundary.
    """
    if os.environ.get("RUNNER_POOLS_PROTOCOL") != "1" or not isinstance(answer, dict):
        return
    facts = {}
    proof = answer.get("macos_boot_proof")
    if isinstance(proof, dict):
        facts["macos_boot_proof"] = {k: v for k, v in proof.items() if k in FACT_KEYS}
    if type(answer.get("reclaimed_bytes")) is int and answer["reclaimed_bytes"] >= 0:
        facts["reclaimed_bytes"] = answer["reclaimed_bytes"]
    line = "FACTS " + json.dumps(facts, sort_keys=True)
    if facts and len(line) <= 4096:
        print(line, flush=True)


def setup(args, profile):
    require(
        os.geteuid() != 0
        and platform.system() == "Darwin"
        and platform.machine() == "arm64",
        "Run setup as the Apple Silicon Mac operator, not as root.",
    )
    UI.banner(profile, "setup")
    if getattr(args, "repair_runtime", False):
        # Repair reconciles interrupted generations before publication. Changes
        # to repository access and activation resume after source is consistent.
        guided = UI.environ.get("RUNNER_POOLS_GUIDED") == "1"
        if not guided:
            UI.phase(1, 1, "Update installed runner tools")
            UI.note(
                "Existing GitHub access, repository permissions and build environments are kept."
            )
        recovery = getattr(args, "recover_blocked", False)
        allow_download = not recovery or config.disk_readiness(profile)["ready"]
        if recovery:
            # Source may be an exact interrupted before/after publication.
            # The native transaction validates that mixture before any worker
            # or replacement; only the immutable interpreter is needed here.
            pool_python.verify(profile)
        archive = archive_path(args, allow_download=allow_download)
        python_archive = pool_python.archive(allow_download=allow_download)
        authorize_setup(profile, recover_blocked=recovery)
        with tempfile.TemporaryDirectory(prefix="runner-profile-") as directory:
            snapshot = Path(directory) / "profile.json"
            snapshot.write_text(json.dumps(profile))
            with administrator_session(), UI.operation("Update runner tools"):
                answer = privileged(
                    profile,
                    "install",
                    source=snapshot,
                    archive=archive,
                    python_archive=python_archive,
                    repair_runtime=True,
                    recover_blocked=getattr(args, "recover_blocked", False),
                )
        _facts(answer)
        from runner_operator import ensure_guest_agent

        profile = host.read_profile(config.paths(profile)["profile"], installed=True)
        ensure_guest_agent(profile, restart=True)
        if not guided:
            UI.finish("Runner tools updated", "Continue setup with hypertext runners.")
        return
    UI.phase(1, 4, "Check GitHub access")
    policy.reconcile(profile, auth.gh_api, apply=False)
    require(
        shutil.disk_usage(Path.home()).free >= profile["min_free_gib"] * 1024**3,
        "The configured physical disk reserve is unavailable; preserve unrelated data and free space before setup.",
    )
    archive = archive_path(args)
    python_archive = pool_python.archive()
    UI.phase(2, 4, "Prepare this Mac")
    authorize_setup(profile)
    # Native group writes occur only after all read-only checks and archive verification.
    policy.reconcile(profile, auth.gh_api, apply=True)
    # Install from a private temporary public-profile snapshot so source config
    # does not need GitHub App metadata written back into a repository.
    with tempfile.TemporaryDirectory(prefix="runner-profile-") as directory:
        snapshot = Path(directory) / "profile.json"
        snapshot.write_text(json.dumps(profile))
        _facts(
            privileged(
                profile,
                "install",
                source=snapshot,
                archive=archive,
                python_archive=python_archive,
                repair_runtime=getattr(args, "repair_runtime", False),
            )
        )
    p = config.paths(profile)
    UI.phase(3, 4, "Connect GitHub")
    UI.note(installation_guidance(profile))
    prepare_shared_host_key(args, profile)
    if profile.get("controller_app") or host.shared_controller_reference():
        profile = privileged(profile, "shared-connect")["profile"]
    if profile.get("controller_app"):
        ready = privileged(profile, "shared-finish").get("ready") is True
        if not ready:
            reference = profile["controller_app"]
            UI.note(
                "Reuse "
                + reference["slug"]
                + " for "
                + profile["owner"]["login"]
                + ". Approve this account installation once; adding another Mac does not create another App."
            )
            show_in_chrome(
                "https://github.com/apps/"
                + reference["slug"]
                + "/installations/new?target_id="
                + str(profile["owner"]["id"]),
                args.chrome_profile or profile["owner"]["login"],
            )
            deadline = time.monotonic() + 900
            while not ready:
                require(
                    time.monotonic() < deadline,
                    "Shared App installation approval is pending. Resume the same setup; no new App is needed.",
                )
                time.sleep(5)
                ready = privileged(profile, "shared-finish").get("ready") is True
        profile = config.load(p["profile"])
    else:
        pending = privileged(profile, "pending")["pending"]
    if not profile.get("controller_app") and (
        "github_app" not in profile or pending is not None
    ):
        from pool_setup import ManifestFlow

        browser = args.chrome_profile or profile["owner"]["login"]
        if pending is None:
            UI.note(
                "Connect "
                + profile["owner"]["login"]
                + " on this Mac: create its controller App once. Continue to GitHub and approve the displayed permissions. Future setup reuses the saved App."
            )
            with ManifestFlow(profile) as flow:
                show_in_chrome(flow.start_url, browser)
                code = flow.wait()
                packet = auth.exchange_manifest(code, profile)
                code = None
                pending = privileged(profile, "pending", packet=packet)["pending"]
                packet = None
        # A rerun after approval finishes without reopening the installation page.
        ready = privileged(profile, "finish").get("ready") is True
        if not ready:
            UI.note(
                "Install the saved controller App "
                + pending["slug"]
                + " for "
                + profile["owner"]["login"]
                + ". Select the intended account and enrolled repositories. Setup continues after approval; this does not create another App."
            )
            show_in_chrome(
                "https://github.com/apps/"
                + pending["slug"]
                + "/installations/new?target_id="
                + str(profile["owner"]["id"]),
                browser,
            )
            deadline = time.monotonic() + 900
            while not ready:
                if time.monotonic() >= deadline:
                    raise Failure(
                        "GitHub installation approval is still pending. Rerun the same command; the native App/key is preserved."
                    )
                time.sleep(5)
                ready = privileged(profile, "finish").get("ready") is True
        profile = config.load(p["profile"])
    # Hosted recovery is a separate explicit operation. Local startup must not
    # depend on billing, recovery credentials or another App consent flow.
    UI.phase(4, 4, "Enable automatic CI")
    from runner_operator import ensure_guest_agent

    ensure_guest_agent(profile, restart=True)
    result = ensure(profile, apply=True, timeout=0)
    outcome = Outcome.from_readiness(result, account=profile["owner"]["login"])
    require(
        outcome.code == 0,
        readiness_message(result, organization=profile["owner"]["login"]),
    )
    return result


def requested_platforms(profile, platforms=None):
    """Select readiness only; never derive a different installed profile."""
    selected = list(profile["pools"]) if platforms is None else platforms
    require(
        isinstance(selected, (list, tuple))
        and bool(selected)
        and all(isinstance(name, str) for name in selected)
        and len(selected) == len(set(selected))
        and set(selected) <= set(profile["pools"]),
        "Readiness platforms must be unique configured pool names.",
    )
    return sorted(selected)


def _demand_idle(profile, pool):
    """Recognize demand-driven configured slots without promising current capacity."""
    return bool(profile.get("fleet")) and pool["state"] in (
        "idle",
        "waiting",
        "unavailable",
    )


def registration_ready(profile, inspected, controller, platforms=None):
    """Bind online registration to each live controller's exact current generation."""
    selected = requested_platforms(profile, platforms)
    complete_policy = (
        inspected["ready"]
        if platforms is None
        else (
            set(inspected["pools"]) == set(profile["pools"])
            and all(
                type(v.get("group_id")) is int and v["group_id"] > 0
                for v in inspected["pools"].values()
            )
        )
    )
    if not (
        controller["fresh"]
        and complete_policy
        and set(controller["pools"]) == set(profile["pools"])
    ):
        return False
    for platform in selected:
        value = controller["pools"][platform]
        if _demand_idle(profile, value):
            continue  # A demand-driven host can be configured without a parked VM.
        if value["state"] not in ("registered", "busy") or not isinstance(
            value.get("generation"), str
        ):
            return False
        if not any(
            (parsed := fleet.parse_runner(row.get("name"), profile["id"], platform))
            and parsed["generation"] == value["generation"]
            and (
                not profile.get("fleet")
                or parsed["host_id"] == profile["fleet"]["host_id"]
            )
            for row in inspected["pools"].get(platform, {}).get("runners", [])
        ):
            return False
    return True


def ensure(profile, *, apply=False, timeout=180, platforms=None, wait=False):
    """Restore exact controller persistence only; policy/enrollment/upgrades stay explicit."""
    require(
        type(timeout) in (int, float) and 0 <= timeout <= 3600,
        "Readiness timeout must be between 0 and 3600 seconds.",
    )
    require(
        type(wait) is bool
        and not (wait and apply)
        and (not wait or platforms is not None),
        "Read-only waiting requires requested platforms and cannot apply runner changes.",
    )
    if apply:
        host.require_no_shared_migration(profile)
    selected = requested_platforms(profile, platforms)
    result = {
        "profile": profile["id"],
        "ready": False,
        "status": "setup_required",
        "pools": {},
        "controller": {},
        "consumers": profile["consumers"],
        "pending_enrollment": None,
        "claims": "Controller health and online registration only; real CI outcomes require actual jobs.",
    }
    if platforms is not None:
        result.update(
            requested_platforms=selected,
            all_platforms_ready=False,
            claims="Controller health and online registration for requested platforms only; actual CI requires real jobs.",
        )
    if "github_app" not in profile:
        return result
    host.verify_install(profile)

    def transaction_pending():
        if host.shared_migration_pending(profile):
            result.update(status="shared_migration_pending")
            return True
        pending = host.pending_enrollment(profile)
        if pending is not None:
            # The durable enrollment transaction owns any old/new policy tail.
            result.update(status="enrollment_pending", pending_enrollment=pending)
            return True
        maintenance = config.paths(profile)["install"] / "maintenance.json"
        if platforms is not None and (maintenance.exists() or maintenance.is_symlink()):
            host._maintenance_read(maintenance, profile)
            result["status"] = "recovery_pending"
            return True
        return False

    deadline = time.monotonic() + timeout
    activated = False
    inspected = None
    while True:
        if transaction_pending():
            return result
        controller = host.inspect_service(profile)
        candidate = (
            controller["fresh"]
            and set(controller["pools"]) == set(profile["pools"])
            and all(
                controller["pools"][name]["state"] in ("registered", "busy")
                or _demand_idle(profile, controller["pools"][name])
                for name in selected
            )
        )
        # Validate complete policy initially and again before any acceptance.
        # During transitional heartbeats, wait on cheap local health instead of
        # repeatedly reading every GitHub policy and roster.
        if inspected is None or not (wait or apply) or candidate:
            inspected = doctor(profile, output=False)
            if platforms is not None or candidate:
                # Provider reads can outlive a health snapshot or a policy
                # transition. Recheck local trust before accepting that roster.
                host.verify_install(profile)
                if transaction_pending():
                    return result
                controller = host.inspect_service(profile)
        result.update(
            controller=controller,
            pools=inspected["pools"],
            policy_ready=inspected["ready"],
        )
        states = (
            [value["state"] for value in controller["pools"].values()]
            if controller["fresh"]
            else []
        )
        selected_states = (
            [
                value["state"]
                for name, value in controller["pools"].items()
                if name in selected
            ]
            if controller["fresh"]
            else []
        )
        if platforms is not None:
            result["all_platforms_ready"] = registration_ready(
                profile, inspected, controller
            )
        if controller["fresh"] and "drained" in states:
            result["status"] = "drained"  # An observed pause remains profile-wide.
        elif platforms is not None and (
            set(inspected["pools"]) != set(profile["pools"])
            or any(
                type(value.get("group_id")) is not int or value["group_id"] <= 0
                for value in inspected["pools"].values()
            )
        ):
            result["status"] = "policy_required"
        elif controller["fresh"] and "blocked" in selected_states:
            result["status"] = "blocked"
        elif registration_ready(profile, inspected, controller, platforms):
            result.update(ready=True, status="ready")
            return result
        elif controller["loaded"]:
            result["status"] = (
                "preparing" if controller["fresh"] else "controller_starting"
            )
        else:
            result["status"] = "controller_missing"
            if apply and not activated:
                config.preflight_disk(profile)
                try:
                    sudo_authorize()
                except AuthorityRequired:
                    result["status"] = "authority_required"
                    return result
                privileged(profile, "activate")
                inspected = None
                activated = True
                result["activation_started"] = True
                continue
        stop = (
            ("blocked", "policy_required")
            if wait
            else ("drained", "blocked", "policy_required")
        )
        if (
            (not apply and not wait)
            or result["status"] in stop
            or time.monotonic() >= deadline
        ):
            return result
        time.sleep(min(5 if wait else 2, max(0, deadline - time.monotonic())))


def doctor(profile, *, strict=True, output=True):
    inspected = policy.inspect(profile, auth.gh_api, strict_selectors=strict)
    pools = {}
    for platform_name, group in inspected["groups"].items():
        rows = []
        if group:
            rows = policy.pool_runners(profile, auth.gh_api, platform_name, group["id"])
        expected = set(config.labels(profile, platform_name))
        online = [
            r
            for r in rows
            if isinstance(r, dict)
            and r.get("status") == "online"
            and fleet.parse_runner(r.get("name"), profile["id"], platform_name)
            is not None
            and expected
            <= {v.get("name") for v in r.get("labels", []) if isinstance(v, dict)}
        ]
        pools[platform_name] = {
            "group_id": group["id"] if group else None,
            "online": len(online),
            "runners": [
                {"id": r["id"], "name": r["name"], "busy": r.get("busy")}
                for r in online
            ],
        }
    result = {
        "profile": profile["id"],
        "ready": all(
            p["group_id"] is not None
            and (bool(profile.get("fleet")) or p["online"] >= 1)
            for p in pools.values()
        ),
        "pools": pools,
        "claims": "Server policy and online registration only; real CI, WIF/cache and browser outcomes require actual jobs.",
    }
    if output:
        _public(result)
    return result


def _instance(backend, generation):
    matches = []
    if backend.instances.exists():
        for file in backend.instances.glob("*.json"):
            record = backend._record(file)
            candidate = record.get("instance")
            require(
                isinstance(candidate, dict), "Worker instance journal is malformed."
            )
            if candidate.get("generation") == generation:
                backend._owned(candidate)
                matches.append(candidate)
    require(
        len(matches) <= 1,
        "Worker generation has ambiguous instance journals; preserve them.",
    )
    return matches[0] if matches else None


def worker(args, profile):
    from pool_vm import Tart

    p = config.paths(profile)
    require(
        os.geteuid() != 0 and Path(args.profile).resolve() == p["profile"],
        "Worker must execute only as its isolated organization host account with the installed profile.",
    )
    if getattr(args, "owner_session", False):
        # macOS guests run in the owner's logged-in session, in their own
        # guest directory; Linux guests never do.
        session = host.owner_session(profile)
        require(
            args.platform == "macos"
            and session is not None
            and os.geteuid() == session["uid"],
            "Only the recorded owner runs macOS guests, and only macOS guests.",
        )
        home_path = host.agent_home(session, profile)
    else:
        account = pwd.getpwuid(os.geteuid())
        require(
            account.pw_name == config.username(profile)
            and Path(account.pw_dir) == p["home"],
            "Worker must execute only as its isolated organization host account with the installed profile.",
        )
        home_path = p["home"]
    for name in host.PAYLOAD:
        host.protected(p["install"] / name)
    home = home_path.lstat()
    require(
        stat.S_ISDIR(home.st_mode)
        and home.st_uid == os.geteuid()
        and stat.S_IMODE(home.st_mode) == 0o700,
        "Worker home has unsafe metadata.",
    )

    def run(argv, input=None, timeout=60):
        return control.run(
            argv,
            input=input,
            timeout=timeout,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(home_path)},
        )

    # One stdin packet: the one-job registration for execute. It is never written down.
    packet = _stdin() if args.operation == "execute" or args.input_present else {}
    require(
        set(packet) <= {"jit"}
        and (args.operation != "execute" or isinstance(packet.get("jit"), str)),
        "Worker input is malformed; values suppressed.",
    )
    backend = Tart(
        profile,
        args.platform,
        run,
        home_path,
        user=pwd.getpwuid(os.geteuid())
        if getattr(args, "owner_session", False)
        else None,
    )
    directory = home_path / "pool-vms"
    with control.file_lock(directory / ("." + args.platform + ".lock")):
        if args.operation == "prepare":
            backend.prepare()
            return {"prepared": True}
        if args.operation == "create":
            backend.create(args.generation)
            return {"created": True}
        instance = _instance(backend, args.generation)
        if instance is None:
            require(
                args.operation in ("cleanup", "inspect"),
                "Requested generation is missing; preserve runtime state.",
            )
            if args.operation == "cleanup":
                backend.settle_preparation()
                return {"clean": True}
            return {"state": "absent"}
        if args.operation == "inspect":
            return backend.inspect(instance)
        if args.operation == "probe":
            return backend.verify_acceptance(instance)
        if args.operation == "cleanup":
            backend.destroy(instance)
            return {"clean": True}
        try:
            result = backend.execute(instance, packet["jit"])
        except (control.Cancelled, KeyboardInterrupt):
            # The broker first removes an idle registration before requesting
            # ordinary drain cancellation. Stop-only leaves exact disks and
            # journals for provider-aware recovery; transport failures do not
            # enter this explicit cancellation path.
            with control.handlers(signal.SIG_IGN):
                backend.interrupt(instance)
            raise
        finally:
            packet = None
        return {"exit_code": result}


def host_control(args, profile):
    require(
        os.geteuid() == 0 and args.operation is not None,
        "Host operations require the normal administrator handoff.",
    )
    operation = args.operation
    if operation == "install":
        result = host.install(
            profile,
            HERE,
            args.tart_archive,
            args.owner_home,
            repair_runtime=getattr(args, "repair_runtime", False),
            recover_blocked=getattr(args, "recover_blocked", False),
        )
        return {"installed": True, **(result or {})}
    host.verify_install(profile)
    if operation == "local-verify":
        packet = _stdin()
        require(
            set(packet) == {"platforms"},
            "Local verification accepts configured platforms only.",
        )
        return host.verify_local(profile, packet["platforms"])
    if operation == "shared-key":
        packet = _stdin()
        require(
            set(packet) == {"reference", "pem"}
            and profile.get("controller_app") == packet["reference"],
            "Host key input must match the selected shared registration.",
        )
        host.adopt_shared_controller(profile, packet["reference"], pem=packet["pem"])
        return {"configured": True}
    if operation == "shared-connect":
        return {"profile": host.connect_shared_controller(profile)}
    if operation == "shared-finish":
        return {"ready": host.finish_shared_controller(profile) is not None}
    if operation == "pending":
        return {
            "pending": host.pending_credential(
                profile, _stdin() if args.input_present else None
            )
        }
    if operation == "finish":
        result = host.finish_credential(profile)
        return {"ready": result is not None}
    if operation == "enrollment":
        packet = _stdin() if args.input_present else {}
        require(
            set(packet) <= {"proposed", "commit"}, "Enrollment handoff shape differs."
        )
        return {
            "plan": host.enrollment(
                profile, packet.get("proposed"), commit=packet.get("commit") is True
            )
        }
    if operation == "enrollment-access":
        return {"ready": host.enrollment_access(profile)}
    if operation == "enrollment-idle":
        return {"idle": host.enrollment_idle(profile)}
    if operation == "prepare":
        return host.prepare_images(profile)
    if operation in ("activate", "recover"):
        host.activate(profile)
        return {"active": True}
    target = config.paths(profile)["state"] / "drain"
    require(operation in ("drain", "resume"), "Unsupported host control operation.")
    if operation == "resume":
        require(
            not (config.paths(profile)["state"] / "enrollment.json").exists(),
            "Resume the pending enrollment before ordinary admission; its drain is required.",
        )
    with control.file_lock(config.paths(profile)["state"].parent / ".resources.lock"):
        if operation == "resume":
            require(
                not (config.paths(profile)["state"] / "enrollment.json").exists(),
                "Resume the pending enrollment before ordinary admission; its drain is required.",
            )
            image = config.paths(profile)["state"] / "image-upgrade.json"
            if image.exists() or image.is_symlink():
                host.protected(image)
                require(
                    json.loads(image.read_text(), object_pairs_hook=config._unique).get(
                        "stage"
                    )
                    == "complete",
                    "Resume the pending image replacement before ordinary admission.",
                )
        if target.exists() or target.is_symlink():
            host.protected(target)
            require(
                target.read_text() == "drain\n",
                "Admission pause belongs to a native transaction; preserve it and resume that operation.",
            )
        if operation == "drain":
            control.atomic_write(target, b"drain\n")
        elif target.exists():
            target.unlink()
    return {"draining": operation == "drain"}


def enroll(args, profile):
    require(
        args.repo and args.workflow and args.platforms,
        "Enrollment needs --repo, --workflow and --platforms.",
    )
    saved = config.paths(profile)["install"] / "enrollment.json"
    if saved.exists():
        host.protected(saved)
        plan = json.loads(saved.read_text())
        policy._extension(plan["before"], plan["after"])
        consumer = next(
            (
                c
                for c in plan["after"]["consumers"]
                if (c["repo"], c["workflow"]) == (args.repo, args.workflow)
            ),
            None,
        )
        require(
            consumer is not None
            and consumer["workflow"] == args.workflow
            and set(args.platforms) <= set(consumer["pools"])
            and (
                getattr(args, "events", None) is None
                or config.consumer_events(consumer) == args.events
            )
            and bool(consumer.get("credentials"))
            == bool(getattr(args, "credentials", False))
            and consumer.get("tag_prefix") == getattr(args, "tag_prefix", None),
            "A different enrollment is pending. Resume its exact repository/workflow/platform request.",
        )
    else:
        proposal = policy.plan_enrollment(
            profile,
            args.repo,
            args.workflow,
            args.platforms,
            auth.gh_api,
            events=getattr(args, "events", None),
            credentials=bool(getattr(args, "credentials", False)),
            tag_prefix=getattr(args, "tag_prefix", None),
        )
        plan = {"before": profile, "after": proposal["profile"]}
    if plan["before"] == plan["after"]:
        UI.note(
            "This repository already has the exact requested enrollment. No writes performed."
        )
        return {
            "profile": profile["id"],
            "status": "already_enrolled",
            "applied": False,
        }
    if not args.apply:
        return {
            "profile": plan["after"],
            "changes": policy._changes(plan["before"], plan["after"]),
            "applied": False,
        }
    authorize_setup(profile)
    plan = privileged(profile, "enrollment", packet={"proposed": plan["after"]})["plan"]
    if profile == plan["after"]:
        privileged(profile, "enrollment", packet={"commit": True})
        UI.finish(
            "Enrollment resumed",
            "Installed policy and admission handoff completed without replacing active generations.",
        )
        return
    UI.note(
        "Admission is drained. Existing jobs finish before any access policy changes."
    )
    deadline = time.monotonic() + 180
    while not privileged(profile, "enrollment-idle")["idle"]:
        require(
            time.monotonic() < deadline,
            "Jobs or uncertain generations remain. Drain is preserved; rerun enrollment after they finish.",
        )
        time.sleep(5)
    policy.apply_enrollment(plan["before"], plan["after"], auth.gh_api)
    app_file = config.paths(profile)["install"] / "app.json"
    host.protected(app_file)
    json.loads(
        app_file.read_text()
    )  # Verify controlled public metadata remains readable.
    ready = privileged(profile, "enrollment-access")["ready"]
    if ready:
        UI.note("Runner App access verified; continuing without browser approval.")
    else:
        UI.attention(
            "Give the existing runner App access to this repository in GitHub."
        )
        UI.note(installation_guidance(profile))
        show_in_chrome(
            (
                "https://github.com/settings/installations/"
                if profile["owner"]["type"] == "User"
                else "https://github.com/organizations/"
                + profile["owner"]["login"]
                + "/settings/installations/"
            )
            + str(profile["github_app"]["installation_id"]),
            args.chrome_profile or profile["owner"]["login"],
        )
    # The same command resumes the durable old/new plan if approval is pending.
    deadline = time.monotonic() + 900
    while not ready:
        require(
            time.monotonic() < deadline,
            "Enrollment remains drained pending verified App access. Resume the same command after approval.",
        )
        time.sleep(5)
        ready = privileged(profile, "enrollment-access")["ready"]
    authorize_setup(profile)
    privileged(profile, "enrollment", packet={"commit": True})
    UI.finish(
        "Repository enrolled",
        "Exact server policy and App access were read back. Run its real main CI for operational acceptance.",
    )


def daemon(profile):
    from pool_runtime import Runtime

    require(os.geteuid() == 0, "Controller requires its protected host identity.")
    host.verify_install(profile)
    stop = threading.Event()

    def shutdown(signum, frame):
        stop.set()  # Runtime drains idle slots and preserves active jobs.

    previous = {
        s: signal.signal(s, shutdown)
        for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
    }
    state = config.paths(profile)["state"]
    health_lock = threading.Lock()
    health = {name: {"state": "starting"} for name in profile["pools"]}
    instance = uuid.uuid4().hex

    def snapshot():
        control.atomic_write(
            config.paths(profile)["install"] / "health.json",
            json.dumps(
                {
                    "profile": profile["id"],
                    "controller": {
                        "pid": os.getpid(),
                        "instance": instance,
                        "updated_at": time.time(),
                    },
                    "pools": health,
                }
            ).encode(),
            mode=0o644,
        )

    def support():
        try:
            host.publish_support(profile)
        except (OSError, ValueError, KeyError, Failure):
            pass  # Health stays authoritative; the support summary only explains it.

    def publish(value):
        support()
        if value.get("state") == "blocked":
            try:
                host.publish_diagnosis(profile, instance)
            except (OSError, ValueError, KeyError, TypeError, Failure):
                pass  # The owner's tools then read the protected records instead.
        with health_lock:
            health[value["platform"]] = {
                k: v for k, v in value.items() if k not in ("platform", "profile_id")
            }
            snapshot()

    heartbeat_stop = threading.Event()

    def reclaim(*, caches):
        """Free storage the runner system owns: snapshots, old images, image caches."""
        freed = host.sweep_install_snapshots(profile) + host.retire_shared_images(
            profile
        )
        if caches:
            freed += host.reclaim_runner_storage(profile)["reclaimed_bytes"]
        return freed

    def heartbeat():
        ticks = 0
        while not heartbeat_stop.wait(5):
            try:
                with health_lock:
                    snapshot()
            except OSError:
                pass  # Missing fresh health prevents readiness; private journals remain authoritative.
            ticks += 1
            if ticks % 360 == 1:
                # Every 30 minutes: remove install snapshots no install is using.
                try:
                    host.sweep_install_snapshots(profile)
                except (OSError, Failure, control.StateError):
                    pass

    try:
        with control.file_lock(state / "controller.lock"):
            with health_lock:
                snapshot()
            thread = threading.Thread(target=heartbeat, name="pool-health")
            thread.start()
            try:
                Runtime(
                    profile,
                    state,
                    auth.GitHubApp(profile, state).api,
                    host.Workers(profile),
                    health=publish,
                    reclaim=reclaim,
                ).serve(stop)
            finally:
                heartbeat_stop.set()
                thread.join()
    finally:
        for s, handler in previous.items():
            signal.signal(s, handler)


class _Parser(argparse.ArgumentParser):
    """Argument errors become a controlled failure, never usage text on stderr."""

    def error(self, message):
        raise Failure("Unsupported runner tool arguments: " + message + ".")


AGENT_REQUEST_LIMIT = 4 * 1024 * 1024


class GuestAgent:
    """Runs this account's macOS guests in the owner's logged-in session.

    The only caller it answers is root, the account's controller. Each
    request names one fixed guest operation, which runs as this worker's
    own code; nothing else can be asked of it.
    """

    def __init__(self, profile, profile_path, home, *, caller=0, spawn=None):
        self.profile, self.profile_path, self.home = profile, profile_path, home
        self.caller = caller
        self.spawn = spawn or self._spawn
        self.lock = threading.Lock()
        self.current = None

    def _spawn(self, request):
        argv = [
            sys.executable,
            "-I",
            "-B",
            str(HERE / "runner_pool.py"),
            "worker",
            "--profile",
            str(self.profile_path),
            "--platform",
            "macos",
            "--operation",
            request["operation"],
            "--generation",
            request["generation"],
            "--owner-session",
        ]
        data = None
        if "jit" in request:
            argv.append("--input-present")
            data = json.dumps({"jit": request["jit"]})
        return subprocess.Popen(
            argv,
            text=True,
            stdin=subprocess.PIPE if data else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            process_group=0,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(self.home)},
        ), data

    def handle(self, connection):
        try:
            if host.peer_uid(connection) != self.caller:
                return  # Only the account's controller may ask for guests.
            raw = b""
            while not raw.endswith(b"\n"):
                chunk = connection.recv(65536)
                if not chunk:
                    return
                raw += chunk
                if len(raw) > AGENT_REQUEST_LIMIT:
                    return
            reply = self.answer(json.loads(raw, object_pairs_hook=config._unique))
            connection.sendall(json.dumps(reply).encode())
        except (OSError, ValueError, UnicodeError):
            pass
        finally:
            connection.close()

    def answer(self, request):
        if not isinstance(request, dict):
            return {"returncode": 2, "stdout": ""}
        operation = request.get("operation")
        if operation == "ping" and set(request) == {"operation"}:
            return {"returncode": 0, "stdout": "{}"}
        if operation == "cancel" and set(request) == {"operation"}:
            with self.lock:
                process = self.current
            if process is not None and process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
            return {"returncode": 0, "stdout": "{}"}
        if not (
            operation in host.AGENT_OPERATIONS
            and set(request) <= {"operation", "generation", "jit"}
            and isinstance(request.get("generation"), str)
            and re.fullmatch(r"[a-f0-9]{32}", request["generation"])
            and (
                "jit" not in request
                or operation == "execute"
                and isinstance(request["jit"], str)
            )
            and (operation != "execute" or "jit" in request)
        ):
            return {"returncode": 2, "stdout": ""}
        try:
            process, data = self.spawn(request)
        except (OSError, Failure):
            return {"returncode": 1, "stdout": ""}
        with self.lock:
            self.current = process
        try:
            stdout, _ = process.communicate(input=data)
        finally:
            with self.lock:
                if self.current is process:
                    self.current = None
        return {"returncode": process.returncode, "stdout": stdout[-1024 * 1024 :]}

    def serve(self, server, stop):
        server.settimeout(1)
        while not stop.is_set():
            try:
                connection, _ = server.accept()
            except TimeoutError:
                continue
            threading.Thread(
                target=self.handle, args=(connection,), daemon=True
            ).start()


def guest_agent(profile, profile_path):
    """The owner-session LaunchAgent: serve this account's macOS guest operations."""
    import socket

    session = host.owner_session(profile)
    require(
        session is not None and os.geteuid() == session["uid"],
        "macOS guests run only in the recorded owner's session.",
    )
    home = host.agent_home(session, profile)
    for directory in (home, home / "pool-vms", home / "logs"):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        require(
            not directory.is_symlink()
            and directory.stat().st_uid == os.geteuid()
            and stat.S_IMODE(directory.stat().st_mode) == 0o700,
            "The macOS guest directory is not private to the owner; it was preserved.",
        )
    path = host.prepare_agent_socket(session, profile)
    if path.is_socket():
        path.unlink()
    previous = os.umask(0o177)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(path))
    finally:
        os.umask(previous)
    server.listen(8)
    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, lambda *_: stop.set())
    try:
        GuestAgent(profile, profile_path, home).serve(server, stop)
    finally:
        server.close()
        if path.is_socket():
            path.unlink()


def arguments(argv=None):
    parser = _Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument(
        "mode",
        choices=(
            "plan",
            "setup",
            "ensure",
            "doctor",
            "drain",
            "resume",
            "recover",
            "verify",
            "enroll",
            "worker",
            "host-control",
            "daemon",
            "guest-agent",
        ),
    )
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument(
        "--repair-runtime",
        action="store_true",
        help="Explicitly repair a stopped preactivation runtime while preserving its configured App",
    )
    parser.add_argument("--chrome-profile")
    parser.add_argument(
        "--controller-key",
        type=Path,
        help="Private key downloaded from the existing shared App for this Mac",
    )
    parser.add_argument("--tart-archive", type=Path)
    parser.add_argument(
        "--recover-blocked", action="store_true", help=argparse.SUPPRESS
    )
    parser.add_argument("--owner-home", type=Path)
    parser.add_argument("--platform", choices=("linux", "macos"))
    parser.add_argument("--operation")
    parser.add_argument("--generation")
    parser.add_argument("--input-present", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--owner-session", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--dispatch", action="store_true")
    parser.add_argument("--repo")
    parser.add_argument("--workflow")
    parser.add_argument("--platforms", nargs="+", choices=("linux", "macos"))
    parser.add_argument(
        "--events",
        nargs="+",
        choices=("push", "schedule", "workflow_run", "workflow_dispatch"),
    )
    parser.add_argument(
        "--credentials",
        action="store_true",
        help="Explicitly reviewed deploy/release workflow that keeps its existing secrets or WIF",
    )
    parser.add_argument(
        "--tag-prefix",
        help="Reviewed literal tag prefix for repository-scoped tag releases",
    )
    parser.add_argument(
        "--wait",
        action="store_true",
        help="Read-only requested-platform readiness wait",
    )
    parser.add_argument(
        "--human",
        action="store_true",
        help="Readable ensure outcome instead of final JSON",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="Bounded readiness wait in seconds (0–3600)",
    )
    return parser.parse_args(argv)


def main(argv=None):
    try:
        args = arguments(argv)
    except Failure as error:
        # The supervising operator reads only the controlled prefix.
        print("ERROR " + str(error), flush=True)
        return 2
    try:
        require(
            not args.wait
            or (args.mode == "ensure" and args.platforms and not args.apply),
            "Read-only waiting requires ensure --platforms and cannot use --apply.",
        )
        require(
            not args.human or args.mode == "ensure",
            "--human is only supported for ensure.",
        )
        require(
            not args.repair_runtime
            or (args.mode == "setup" and args.apply)
            or (args.mode == "host-control" and args.operation == "install"),
            "Runtime repair requires applied setup or the native install handoff.",
        )
        require(
            not args.recover_blocked or args.repair_runtime,
            "Blocked setup recovery requires the reviewed runtime repair transaction.",
        )
        profile = (
            config.load(args.profile)
            if args.mode in ("worker", "host-control", "daemon", "guest-agent")
            else current_profile(args.profile)
        )
        with control.cancellation_signals():
            if args.mode in ("worker", "host-control"):
                # Keep native progress outside the single-object JSON protocol.
                with redirect_stdout(sys.stderr):
                    result = (
                        worker(args, profile)
                        if args.mode == "worker"
                        else host_control(args, profile)
                    )
                _public(result)
            elif args.mode == "daemon":
                daemon(profile)
            elif args.mode == "guest-agent":
                guest_agent(profile, Path(args.profile))
            elif args.mode == "doctor":
                require(
                    doctor(profile)["ready"],
                    "One or more pools are not online. Inspect the organization controller and its private diagnostics.",
                )
            elif args.mode == "ensure":
                result = ensure(
                    profile,
                    apply=args.apply,
                    timeout=args.timeout,
                    platforms=args.platforms,
                    wait=args.wait,
                )
                print_readiness(
                    result, human=args.human, organization=profile["owner"]["login"]
                )
                return 0 if result["ready"] else 1
            elif args.mode == "setup" and args.apply:
                with administrator_session():
                    setup(args, profile)
            elif args.mode in ("drain", "resume", "recover") and args.apply:
                sudo_authorize()
                _public(privileged(profile, args.mode))
            elif args.mode == "enroll":
                with administrator_session():
                    result = enroll(args, profile)
                if result is not None:
                    _public(result)
            elif args.mode == "verify":
                result = doctor(profile)
                require(
                    result["ready"],
                    "Complete pool readiness before real CI acceptance.",
                )
                if args.dispatch:
                    require(args.apply, "Dispatching real CI requires --apply.")
                    for consumer in profile["consumers"]:
                        auth.gh_api(
                            "POST",
                            "repos/"
                            + consumer["repo"]
                            + "/actions/workflows/"
                            + consumer["workflow"].rsplit("/", 1)[1]
                            + "/dispatches",
                            {"ref": "main"},
                        )
                    UI.note(
                        "Real main workflows dispatched. Inspect their actual runner/group and completed check results before claiming acceptance."
                    )
            else:
                planned = policy.reconcile(profile, auth.gh_api, apply=False)
                UI.banner(profile, "plan")
                UI.note(
                    "Selected private repositories and exact main-workflow allowlists verified. No host, provider, credential or service writes performed."
                )
                UI.note("Missing groups: " + ", ".join(planned["missing"]))
                UI.note(
                    "One disposable VM and one-job registration per configured platform. Other organizations remain separate profiles."
                )
        return 0
    except (KeyboardInterrupt, control.Cancelled) as error:
        if os.environ.get("RUNNER_POOLS_GUIDED") != "1":
            message = "Existing generations and ambiguous state are preserved; rerun the same command."
            if args.mode in ("worker", "host-control", "daemon"):
                print("INTERRUPTED Pool operation stopped. " + message, flush=True)
            else:
                UI.failure(
                    args.mode.capitalize(),
                    message,
                    interrupted=True,
                    task="Runner operation",
                )
        return 128 + (error.signum if isinstance(error, control.Cancelled) else 2)
    except Exception as error:
        detail = (
            str(error)
            if isinstance(error, (Failure, control.StateError))
            else native_failure(error, args.mode, args.operation)
        )
        if args.mode == "worker" and args.operation in config.DIAGNOSTIC_OPERATIONS:
            print(
                "DIAGNOSTIC "
                + json.dumps(
                    config.source_diagnostic(error, args.operation), sort_keys=True
                ),
                flush=True,
            )
        elif args.mode in ("host-control", "daemon"):
            diagnostics = config.failure_diagnostics(
                error, "recover" if args.recover_blocked else "controller"
            )
            print("DIAGNOSTICS " + json.dumps(diagnostics, sort_keys=True), flush=True)
            if os.geteuid() == 0 and "profile" in locals():
                try:
                    config.remember_diagnostics(
                        config.paths(profile)["state"],
                        0,
                        profile["id"],
                        "controller",
                        diagnostics,
                    )
                except (Failure, OSError, control.StateError):
                    pass  # The original diagnostic packet still crosses the supervised native boundary.
        elif os.environ.get("RUNNER_POOLS_PROTOCOL") == "1":
            print(
                "DIAGNOSTICS "
                + json.dumps(
                    config.failure_diagnostics(error, "recover"), sort_keys=True
                ),
                flush=True,
            )
        if getattr(error, "diagnostics", ()) and args.mode not in (
            "worker",
            "host-control",
            "daemon",
        ):
            detail = "\n".join(
                config.describe_diagnostic(value) for value in error.diagnostics
            )
        if (
            args.mode not in ("worker", "host-control", "daemon")
            and os.environ.get("RUNNER_POOLS_GUIDED") != "1"
        ):
            UI.failure(args.mode.capitalize(), detail, task="Runner operation")
        else:
            # Native callers require the exact controlled prefix; the guided
            # parent owns headings, cancellation and recovery instructions.
            print("ERROR " + detail, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
