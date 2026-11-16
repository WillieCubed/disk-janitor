#!/usr/bin/env python3
"""Explicit administrator handoff for an isolated Studio macOS runner account/service."""

import argparse
import grp
import json
import os
from pathlib import Path
import platform
import plistlib
import pwd
import re
import shutil
import stat
import subprocess
import uuid
import process_control as control
import pool_config


class Failure(pool_config.Failure):
    """A host helper failure; also caught as the root runner Failure."""


def require(condition, message):
    if not condition:
        raise Failure(message)


def native(argv, context, *, allowed=(0,)):
    try:
        result = control.run(
            argv,
            text=True,
            capture_output=True,
            timeout=60,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
    except (OSError, subprocess.TimeoutExpired):
        raise Failure(context + " unavailable or timed out.") from None
    require(
        result.returncode in allowed,
        context
        + f" failed (exit {result.returncode}); inspect native system state locally (output suppressed).",
    )
    return result.stdout, result.returncode


def paths(args):
    home = Path("/Users") / args.user
    return (
        home,
        home / "actions-runner",
        Path("/Library/LaunchDaemons") / (args.label + ".plist"),
    )


def account_identity(args):
    home, _, _ = paths(args)
    try:
        user = pwd.getpwnam(args.user)
        group = grp.getgrnam(args.user)
    except KeyError:
        raise Failure(
            "Dedicated account/private group is missing; run reviewed prepare first."
        ) from None
    require(
        user.pw_uid >= 500
        and user.pw_gid == group.gr_gid
        and user.pw_uid == group.gr_gid
        and user.pw_dir == str(home)
        and user.pw_shell == "/usr/bin/false",
        "Existing account differs from the dedicated locked Studio account; preserve it and stop.",
    )
    groups, _ = native(["/usr/bin/id", "-Gn", args.user], "Inspect account membership")
    # macOS nests everyone/localaccounts into printing and file-sharing groups.
    # Preserve those system memberships; private HOME plus kernel access checks
    # protect the operator. Never accept administrative/developer/staff access.
    require(
        args.user in groups.split()
        and all(
            item in {args.user, "everyone", "localaccounts", "_lpoperator"}
            or re.fullmatch(r"com\.apple\.sharepoint\.group\.\d+", item)
            for item in groups.split()
        ),
        "Dedicated runner has unexpected or privileged group membership.",
    )
    return user


def account(args):
    user = account_identity(args)
    home, _, _ = paths(args)
    authority, _ = native(
        [
            "/usr/bin/dscl",
            ".",
            "-read",
            "/Users/" + args.user,
            "AuthenticationAuthority",
        ],
        "Inspect disabled login",
    )
    require(
        " ".join(authority.split()) == "AuthenticationAuthority: ;DisabledUser;",
        "Existing account login is not locked; no automatic modification permitted.",
    )
    require(
        home.is_dir()
        and not home.is_symlink()
        and home.stat().st_uid == user.pw_uid
        and stat.S_IMODE(home.stat().st_mode) == 0o700,
        "Dedicated home ownership/mode must be uid/0700.",
    )
    owner = Path(args.owner_home).resolve()
    require(
        owner.is_dir() and owner != home and owner.stat().st_uid != user.pw_uid,
        "Select the actual separate operator home.",
    )
    # Test kernel access as the runner, including ACLs; no credential contents are read.
    for flag in ("-r", "-x"):
        _, code = native(
            [
                "/usr/bin/sudo",
                "-n",
                "-H",
                "-u",
                args.user,
                "--",
                "/bin/test",
                flag,
                str(owner),
            ],
            "Verify operator-home isolation",
            allowed=(0, 1),
        )
        require(
            code == 1,
            "Runner can access the operator home; owner-admin must fix host permissions before activation.",
        )
    return user


def finish_account(args):
    """Resume only our exact nonlogin identity, never replace an existing user."""
    user = account_identity(args)
    home, _, plist = paths(args)
    marker, _ = native(
        ["/usr/bin/dscl", ".", "-read", "/Users/" + args.user, "RealName"],
        "Inspect Studio account marker",
    )
    require(
        " ".join(marker.split())
        == "RealName: " + getattr(args, "marker", "Hypertext Studio isolated CI"),
        "Partial account lacks the exact Studio installer marker; preserve it and stop.",
    )
    authority, _ = native(
        [
            "/usr/bin/dscl",
            ".",
            "-read",
            "/Users/" + args.user,
            "AuthenticationAuthority",
        ],
        "Inspect partial account login",
    )
    # Native dscl succeeds with empty stdout for an absent attribute.
    require(
        not authority.strip()
        or " ".join(authority.split()) == "AuthenticationAuthority: ;DisabledUser;",
        "Partial account has an unexpected authentication configuration; preserve it and stop.",
    )
    require(
        not home.exists()
        and not home.is_symlink()
        and not plist.exists()
        and not plist.is_symlink(),
        "Partial account recovery requires absent home and service; preserve existing data.",
    )
    native(
        [
            "/usr/bin/dscl",
            ".",
            "-create",
            "/Users/" + args.user,
            "AuthenticationAuthority",
            ";DisabledUser;",
        ],
        "Disable dedicated account login",
    )
    native(
        ["/usr/bin/dscl", ".", "-create", "/Users/" + args.user, "IsHidden", "1"],
        "Hide dedicated account",
    )
    home.mkdir(mode=0o700)
    os.chown(home, user.pw_uid, user.pw_gid)
    return account(args)


def source_tree(source):
    require(
        source.is_dir() and not source.is_symlink(),
        "Select the helper-prepared runner directory.",
    )
    try:
        provenance = json.loads((source / ".studio-package.json").read_text())
    except (OSError, ValueError):
        raise Failure(
            "Runner source lacks the verified official-package receipt; use self_hosted_runner.py prepare."
        ) from None
    require(
        isinstance(provenance, dict)
        and provenance.get("repository") == "actions/runner"
        and re.fullmatch(r"[0-9a-f]{64}", provenance.get("sha256", "")),
        "Official package receipt is invalid.",
    )
    require(
        (source / "config.sh").is_file() and (source / "bin/runsvc.sh").is_file(),
        "Official runner entrypoints are missing.",
    )
    require(
        not any(
            (source / name).exists()
            for name in (".runner", ".credentials", ".credentials_rsaparams")
        ),
        "Prepare copies unregistered packages only; never copy an existing runner credential.",
    )
    for path in source.rglob("*"):
        if path.is_symlink():
            require(
                not Path(os.readlink(path)).is_absolute()
                and path.resolve(strict=True).is_relative_to(source.resolve()),
                "Runner source link must resolve within the verified package.",
            )
        else:
            require(
                path.is_dir() or path.is_file(),
                "Runner source contains a special file.",
            )


def prepare_account(args):
    """Create/reuse a locked host account without copying a runner or activating it."""
    home, _, _ = paths(args)
    try:
        pwd.getpwnam(args.user)
        existing = True
    except KeyError:
        existing = False
    if existing:
        return account(args) if home.exists() else finish_account(args)
    require(
        not home.exists(),
        "Account home already exists; preserve it and reconcile manually.",
    )
    users, _ = native(
        ["/usr/bin/dscl", ".", "-list", "/Users", "UniqueID"],
        "Inspect allocated user IDs",
    )
    groups, _ = native(
        ["/usr/bin/dscl", ".", "-list", "/Groups", "PrimaryGroupID"],
        "Inspect allocated group IDs",
    )
    require(
        not any(
            line.split()[0] == args.user for line in groups.splitlines() if line.split()
        ),
        "Group name already exists; preserve it and stop.",
    )
    occupied = {
        int(line.split()[-1])
        for line in (users + "\n" + groups).splitlines()
        if line.split() and line.split()[-1].isdigit()
    }
    available = [number for number in range(550, 1000) if number not in occupied]
    require(bool(available), "No free reviewed local UID/GID range remains.")
    uid = available[0]
    records = [
        ("/Groups/" + args.user, "PrimaryGroupID", str(uid)),
        ("/Groups/" + args.user, "Password", "*"),
        ("/Users/" + args.user, "UniqueID", str(uid)),
        ("/Users/" + args.user, "PrimaryGroupID", str(uid)),
        ("/Users/" + args.user, "NFSHomeDirectory", str(home)),
        ("/Users/" + args.user, "UserShell", "/usr/bin/false"),
        (
            "/Users/" + args.user,
            "RealName",
            getattr(args, "marker", "Hypertext Studio isolated CI"),
        ),
        ("/Users/" + args.user, "GeneratedUID", str(uuid.uuid4()).upper()),
    ]
    for record, key, value in records:
        native(
            ["/usr/bin/dscl", ".", "-create", record, key, value],
            "Create dedicated account " + key,
        )
    user = finish_account(args)
    return user


def prepare(args):
    home, directory, _ = paths(args)
    require(
        args.source is not None,
        "Prepare needs --source from the verified official package helper.",
    )
    source_tree(args.source)
    user = prepare_account(args)
    if directory.exists():
        require(
            not directory.is_symlink() and directory.stat().st_uid == user.pw_uid,
            "Existing runner directory ownership differs; preserve it and stop.",
        )
        require(
            (directory / ".studio-package.json").read_bytes()
            == (args.source / ".studio-package.json").read_bytes(),
            "Existing runner package differs; use deliberate native upgrade/removal, never overwrite.",
        )
        print(
            "OK Existing dedicated runner package preserved; no account or runner files changed."
        )
        return
    shutil.copytree(args.source, directory, symlinks=True)
    for path in [directory, *directory.rglob("*")]:
        os.lchown(path, user.pw_uid, user.pw_gid)
        if not path.is_symlink():
            os.chmod(path, stat.S_IMODE(path.stat().st_mode) & 0o700)
    print(
        "OK Locked private account and verified unregistered runner prepared; no service started."
    )


def service_spec(args):
    home, directory, _ = paths(args)
    return {
        "Label": args.label,
        "UserName": args.user,
        "GroupName": args.user,
        "ProgramArguments": [str(directory / "bin/runsvc.sh")],
        "WorkingDirectory": str(directory),
        "EnvironmentVariables": {
            "HOME": str(home),
            "USER": args.user,
            "LOGNAME": args.user,
            "PATH": "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
            "RUNNER_TOOL_CACHE": str(home / "tool-cache"),
        },
        "RunAtLoad": True,
        "KeepAlive": True,
        "SessionCreate": True,
        "StandardOutPath": str(home / "logs/runner.stdout.log"),
        "StandardErrorPath": str(home / "logs/runner.stderr.log"),
    }


def install_service(args):
    user = account(args)
    home, directory, plist = paths(args)
    try:
        # GitHub's IOUtil.SaveObject writes Encoding.UTF8, including its BOM.
        registration = json.loads(
            (directory / ".runner").read_text(encoding="utf-8-sig")
        )
    except FileNotFoundError:
        raise Failure(
            "Native runner must be registered in its restricted Studio group first."
        ) from None
    except OSError:
        raise Failure(
            "Cannot read native .runner metadata; check the dedicated home permissions."
        ) from None
    except (UnicodeError, ValueError):
        raise Failure(
            "Native .runner metadata is not valid UTF-8 JSON; preserve it and inspect native configuration."
        ) from None
    require(
        isinstance(registration, dict)
        and registration.get("poolId") == args.group_id
        and registration.get("agentName") == args.name
        and isinstance(registration.get("gitHubUrl"), str)
        and registration["gitHubUrl"].rstrip("/")
        == "https://github.com/TheHypertextStudio",
        "Registration metadata does not match the reviewed Studio group/name.",
    )
    require(
        (directory / "bin/runsvc.sh").is_file()
        and not (directory / "bin/runsvc.sh").is_symlink(),
        "Official runsvc.sh missing.",
    )
    expected = service_spec(args)
    if plist.exists():
        require(
            not plist.is_symlink() and plist.stat().st_uid == 0,
            "Existing service ownership is unsafe; preserve it and stop.",
        )
        try:
            current = plistlib.loads(plist.read_bytes())
        except (ValueError, plistlib.InvalidFileException):
            raise Failure(
                "Existing service is unreadable; preserve it and stop."
            ) from None
        require(
            current == expected,
            "Existing service differs; preserve it and review a deliberate change.",
        )
    else:
        for child in ("logs", "tool-cache"):
            path = home / child
            path.mkdir(mode=0o700, exist_ok=True)
            require(
                not path.is_symlink(),
                "Account-local cache/log directory must not be a symlink.",
            )
            os.chown(path, user.pw_uid, user.pw_gid)
        with plist.open("xb") as output:
            plistlib.dump(expected, output)
        os.chmod(plist, 0o644)
    _, loaded = native(
        ["/bin/launchctl", "print", "system/" + args.label],
        "Inspect Studio service",
        allowed=(0, 3, 113),
    )
    if loaded != 0:
        native(
            ["/bin/launchctl", "bootstrap", "system", str(plist)],
            "Bootstrap isolated Studio service",
        )
    print(
        "OK Isolated Studio launchd service loaded; verify online status and an intended main workflow next."
    )


def execute(args):
    require(platform.system() == "Darwin", "This administrator helper is macOS only.")
    if not args.apply:
        print(
            "PLAN "
            + args.mode
            + ": dedicated account "
            + args.user
            + "; service "
            + args.label
            + ". No writes. Review runbook, then invoke through sudo with --apply."
        )
        return
    require(
        os.geteuid() == 0,
        "Host mutation requires an explicit owner-admin sudo invocation; no privilege workaround.",
    )
    if args.mode == "prepare":
        prepare(args)
    elif args.mode == "install-service":
        install_service(args)
    else:
        account(args)
        _, _, plist = paths(args)
        require(
            plist.exists()
            and not plist.is_symlink()
            and plist.stat().st_uid == 0
            and stat.S_IMODE(plist.stat().st_mode) == 0o644
            and plistlib.loads(plist.read_bytes()) == service_spec(args),
            "Only the exact owned Studio service may be stopped.",
        )
        _, loaded = native(
            ["/bin/launchctl", "print", "system/" + args.label],
            "Inspect exact Studio service before stopping",
            allowed=(0, 113),
        )
        if loaded == 113:
            print(
                "OK Matching Studio service already stopped; account, files and plist preserved. Remove registration separately."
            )
            return
        native(
            ["/bin/launchctl", "bootout", "system/" + args.label],
            "Stop isolated Studio service",
        )
        print(
            "OK Studio service stopped; account, files and plist preserved. Remove registration separately."
        )


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "install-service", "stop-service"))
    parser.add_argument("--user", required=True)
    parser.add_argument("--owner-home", required=True)
    parser.add_argument(
        "--source", type=lambda value: Path(value).expanduser().absolute()
    )
    parser.add_argument(
        "--group-id",
        type=int,
        help="Required positive group ID for service installation/stopping",
    )
    parser.add_argument("--name", default="studio-product-admin")
    parser.add_argument("--label", default="com.hypertextstudio.actions.product-admin")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    require(re.fullmatch(r"ci-[a-z0-9-]+", args.user), "Use a dedicated ci-* account.")
    require(
        re.fullmatch(r"com\.hypertextstudio\.actions\.[a-z0-9-]+", args.label),
        "Only owned Studio runner services are supported.",
    )
    require(
        re.fullmatch(r"[A-Za-z0-9_-]+", args.name)
        and (
            args.mode == "prepare"
            and args.group_id is None
            or isinstance(args.group_id, int)
            and args.group_id > 0
        ),
        "Select the reviewed runner name and positive group ID for service modes.",
    )
    require(Path(args.owner_home).is_absolute(), "Use an absolute operator home path.")
    return args


def main():
    try:
        with control.cancellation_signals():
            execute(arguments())
        return 0
    except (control.Cancelled, KeyboardInterrupt) as error:
        print(
            "INTERRUPTED Host operation stopped; preserve partial native state and inspect before retrying."
        )
        return 128 + (error.signum if isinstance(error, control.Cancelled) else 2)
    except (Failure, OSError, ValueError, TypeError) as error:
        print(
            "ERROR "
            + (
                str(error)
                if isinstance(error, (Failure, control.StateError))
                else "Local host setup failed; preserve partial state and inspect native paths/permissions."
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
