#!/usr/bin/env python3
"""Inspect and operate a narrowly restricted Studio runner using native tools."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import posixpath
import pwd
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import process_control as control
import pool_config

ORG = "TheHypertextStudio"
ORG_ID = 170363390
GUARD = "github.ref=='refs/heads/main'&&(github.event_name=='push'||github.event_name=='workflow_dispatch')"


class Failure(pool_config.Failure):
    """A host helper failure; also caught as the root runner Failure."""


def require(condition, message):
    if not condition:
        raise Failure(message)


def command(argv, context, *, env=None, cwd=None, timeout=60):
    helper = str(Path(__file__).with_name("macos_host.py"))
    try:
        result = control.run(
            argv,
            env=env,
            cwd=cwd,
            text=True,
            capture_output=True,
            timeout=timeout,
            cleanup_grace=6 if helper in argv else 1,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise Failure(
            f"{context} unavailable or timed out; check the native tool and explicit operator access."
        ) from None
    if result.returncode != 0:
        # Only our host helper's controlled ERROR line is safe to cross this boundary.
        # Never forward config.sh, GitHub, sudo or arbitrary subprocess output.
        helper = str(Path(__file__).with_name("macos_host.py"))
        detail = ""
        if helper in argv:
            errors = [
                line for line in result.stdout.splitlines() if line.startswith("ERROR ")
            ]
            if len(errors) == 1 and len(errors[0]) < 500:
                detail = " " + errors[0]
        raise Failure(
            f"{context} failed (exit {result.returncode}).{detail} Native output suppressed to protect credentials."
        )
    return result.stdout


def api(endpoint, method="GET"):
    context = "GitHub " + ("read " if method == "GET" else "request ") + endpoint
    raw = command(
        ["gh", "api", "--hostname", "github.com", "--method", method, endpoint], context
    )
    try:
        value = json.loads(raw)
    except ValueError:
        raise Failure(
            f"{context} returned invalid JSON (response suppressed)."
        ) from None
    require(isinstance(value, dict), f"{context} returned an unexpected JSON shape.")
    return value


def validate_repo(repo, requested):
    require(isinstance(repo, dict), "Repository metadata must be an object.")
    owner = repo.get("owner")
    require(
        isinstance(owner, dict)
        and owner.get("id") == ORG_ID
        and owner.get("login") == ORG,
        "Repository does not belong to Hypertext Studio; no changes permitted.",
    )
    require(
        repo.get("full_name") == requested and isinstance(repo.get("id"), int),
        "Repository identity does not match the request.",
    )
    require(
        repo.get("private") is True
        and repo.get("fork") is False
        and repo.get("archived") is False,
        "Runner consumer must be an active private Studio repository, never a fork or public repository.",
    )
    require(
        repo.get("default_branch") == "main",
        "This runner workflow requires default branch main.",
    )


def validate_group(group, selected, repo, workflow_ref):
    require(
        isinstance(group, dict) and isinstance(selected, dict),
        "Runner group metadata must be objects.",
    )
    require(
        group.get("visibility") == "selected"
        and group.get("allows_public_repositories") is False
        and group.get("default") is False
        and group.get("inherited") is False,
        "Runner group must be nondefault, Studio-owned, selected repositories only and deny public repositories.",
    )
    require(
        group.get("restricted_to_workflows") is True
        and group.get("selected_workflows") == [workflow_ref],
        "Server runner group must restrict access to exactly the requested workflow@refs/heads/main; YAML alone is insufficient.",
    )
    repos = selected.get("repositories")
    require(
        isinstance(repos, list)
        and selected.get("total_count") == 1
        and len(repos) == 1
        and isinstance(repos[0], dict)
        and repos[0].get("id") == repo["id"],
        "Server runner group must allow exactly the requested repository ID.",
    )


def preflight(args):
    repo = api("repos/" + args.repo)
    validate_repo(repo, args.repo)
    path = f"orgs/{ORG}/actions/runner-groups/{args.group_id}"
    group = api(path)
    require(
        group.get("id") == args.group_id and isinstance(group.get("name"), str),
        "Runner group identity mismatch.",
    )
    selected = api(path + "/repositories?per_page=100")
    ref = args.repo + "/" + args.workflow + "@refs/heads/main"
    validate_group(group, selected, repo, ref)
    # Fail closed rather than claiming a general YAML parser or treating YAML as isolation.
    content = api(f"repos/{args.repo}/contents/{args.workflow}?ref=main")
    try:
        source = base64.b64decode(content["content"], validate=False).decode("utf-8")
    except (KeyError, ValueError, UnicodeError, TypeError):
        raise Failure("Cannot read the committed main workflow source.") from None
    validate_workflow(source, args.repo, ref, group["name"])
    print(
        "OK Studio private repository and exact server group workflow/repository restrictions."
    )
    print(
        "OK Main workflow contains the canonical event/ref guard; review every runner job before activation."
    )
    return repo, group


def literal_name(value):
    match = re.fullmatch(
        r"(?:'([A-Za-z0-9_.-]+)'|\"([A-Za-z0-9_.-]+)\"|([A-Za-z0-9_.-]+))", value
    )
    require(
        match is not None,
        "Runner selectors require literal names; unsupported YAML must be reviewed.",
    )
    return next(part for part in match.groups() if part is not None)


def workflow_jobs(source):
    """Classify every job in the supported literal YAML subset, never skip a selector."""
    lines = source.splitlines()
    starts = [index for index, line in enumerate(lines) if re.match(r"^jobs:", line)]
    require(
        len(starts) == 1 and lines[starts[0]].rstrip() == "jobs:",
        "Main workflow needs exactly one canonical jobs mapping.",
    )
    # Multiline quoted/flow top-level values can contain text resembling jobs.
    # They are outside this deliberately small parser rather than safe to ignore.
    for index, line in enumerate(lines):
        if not line.strip() or line.lstrip().startswith("#") or line.startswith(" "):
            continue
        if index == 0 and line == "---":
            continue
        top = re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*: *(.*)", line)
        require(
            top is not None,
            "Top-level workflow keys must be literal; quoted keys and YAML merges require review.",
        )
        if top:
            value = top.group(1).strip()
            require(
                not value
                or value[0] not in "'\"[{"
                or (value[0] in "'\"" and len(value) > 1 and value[-1] == value[0])
                or (value[0] == "[" and value.endswith("]"))
                or (value[0] == "{" and value.endswith("}")),
                "Multiline quoted/flow workflow values require manual YAML review.",
            )
    jobs = []
    current = None
    for line in lines[starts[0] + 1 :]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            break
        require(
            "\t" not in line[: len(line) - len(line.lstrip())],
            "Tabs in workflow indentation are unsupported.",
        )
        if not line.startswith("   "):
            match = re.fullmatch(r"  ([A-Za-z_][A-Za-z0-9_-]*): *", line)
            require(
                match is not None
                and all(job["name"] != match.group(1) for job in jobs),
                "Every job must have a unique literal block mapping; aliases, merges and flow jobs require review.",
            )
            current = {"name": match.group(1), "lines": []}
            jobs.append(current)
        else:
            require(
                current is not None and line.startswith("    "),
                "Unsupported jobs mapping indentation.",
            )
            current["lines"].append(line)
    require(bool(jobs), "Main workflow has no canonical jobs.")
    for job in jobs:
        fields = {}
        field = None
        for line in job["lines"]:
            if not line.startswith("     "):
                match = re.fullmatch(r"    ([A-Za-z_][A-Za-z0-9_-]*): *(.*)", line)
                require(
                    match is not None and match.group(1) not in fields,
                    "Job fields must be unique literal keys; quoted keys, aliases and merges require review.",
                )
                field = match.group(1)
                fields[field] = [match.group(2), []]
            else:
                require(
                    field is not None and line.startswith("      "),
                    "Unsupported job field indentation.",
                )
                fields[field][1].append(line)
        require(
            "runs-on" in fields,
            "Every job requires an explicit supported runner selector; reusable jobs require review.",
        )
        value, nested = fields["runs-on"]
        job["fields"] = fields
        if value:
            label = literal_name(value)
            require(
                not nested
                and re.fullmatch(
                    r"(?:ubuntu|macos|windows)-(?:latest|[0-9]+(?:\.[0-9]+)*(?:-(?:arm|arm64|intel|large|xlarge))?)",
                    label,
                ),
                "Only literal GitHub-hosted labels or canonical self-hosted group mappings are supported.",
            )
            job["group"] = None
            continue
        require(
            len(nested) == 2
            and re.fullmatch(r"      group: +.+", nested[0])
            and nested[1].startswith("      labels:"),
            "Self-hosted jobs require the canonical group followed by inline literal labels; unsupported YAML must be reviewed.",
        )
        group = literal_name(nested[0][len("      group:") :].strip())
        match = re.fullmatch(r"      labels: *\[([^\[\]]+)\] *", nested[1])
        require(
            match is not None,
            "Self-hosted jobs require inline literal labels; expressions and block lists require review.",
        )
        labels = [literal_name(value.strip()) for value in match.group(1).split(",")]
        require(
            len(labels) == len(set(labels)) and "self-hosted" in labels,
            "Self-hosted labels must be unique and include self-hosted.",
        )
        job.update(group=group, labels=set(labels))
    return jobs


def validate_workflow(source, repo, ref, group_name):
    expected = (
        "github.repository=='"
        + repo
        + "'&&"
        + GUARD
        + "&&github.workflow_ref=='"
        + ref
        + "'"
    )
    selected = []
    for job in workflow_jobs(source):
        if job["group"] is None:
            continue
        condition = job["fields"].get("if", ["", []])
        match = re.fullmatch(r"\$\{\{(.*?)\}\} *", condition[0])
        require(
            not condition[1]
            and match is not None
            and re.sub(r"\s+", "", match.group(1)) == expected,
            "Every self-hosted runner job needs the canonical main push/manual guard at job level; step conditions do not count.",
        )
        if job["group"] == group_name:
            selected.append(job)
    require(
        bool(selected),
        "Main workflow must select the reviewed runner group explicitly at job level.",
    )
    return selected


def host(args):
    require(
        platform.system() in ("Darwin", "Linux"),
        "Host preparation supports macOS and Linux only.",
    )
    try:
        account = pwd.getpwnam(args.runner_user)
    except KeyError:
        raise Failure(
            f"Dedicated account {args.runner_user} is missing; owner-admin must provision it first."
        ) from None
    require(
        account.pw_uid != 0 and args.runner_user.startswith("ci-"),
        "Use a dedicated nonroot ci-* operating-system account.",
    )
    groups = command(
        ["id", "-Gn", args.runner_user], "Inspect dedicated account groups"
    ).split()
    require(
        not set(groups) & {"admin", "sudo", "wheel", "staff"},
        "Runner account must not inherit admin, sudo, wheel or shared staff access.",
    )
    home = Path(account.pw_dir)
    require(
        home.is_dir()
        and home.stat().st_uid == account.pw_uid
        and not home.is_symlink(),
        "Dedicated home is missing or has incorrect ownership.",
    )
    require(
        stat.S_IMODE(home.stat().st_mode) & 0o077 == 0,
        "Dedicated home must deny group/other access (mode 0700).",
    )
    directory = args.runner_dir
    require(
        directory.is_relative_to(home) and ".." not in directory.parts,
        "Configured runner must live inside its dedicated home.",
    )
    flags = ["-f", "%u:%HT"] if platform.system() == "Darwin" else ["-c", "%u:%F"]
    metadata = command(
        as_user(args, ["/usr/bin/stat", *flags, str(directory)]),
        "Inspect private runner directory",
    ).strip()
    require(
        metadata
        == str(account.pw_uid)
        + (":Directory" if platform.system() == "Darwin" else ":directory"),
        "Owner-admin must copy the verified runner into the dedicated home and assign ownership; links are rejected.",
    )
    print(
        "OK Dedicated nonadmin account and private runner home; account separation is not a VM sandbox."
    )
    return account


def as_user(args, argv, *, preserve_token=False):
    if os.geteuid() == pwd.getpwnam(args.runner_user).pw_uid:
        return argv
    return [
        "sudo",
        "-n",
        "-H",
        "-u",
        args.runner_user,
        *(["--preserve-env=ACTIONS_RUNNER_INPUT_TOKEN"] if preserve_token else []),
        "--",
        *argv,
    ]


def release(version, operating_system, architecture):
    metadata = api("repos/actions/runner/releases/tags/v" + version)
    require(
        metadata.get("tag_name") == "v" + version
        and metadata.get("draft") is False
        and metadata.get("prerelease") is False,
        "Choose an explicitly reviewed stable official runner release.",
    )
    name = f"actions-runner-{operating_system}-{architecture}-{version}.tar.gz"
    assets = metadata.get("assets", [])
    require(isinstance(assets, list), "Official release assets must be a list.")
    matches = [
        asset
        for asset in assets
        if isinstance(asset, dict) and asset.get("name") == name
    ]
    require(
        len(matches) == 1, "Official release lacks the exact host architecture asset."
    )
    asset = matches[0]
    require(
        asset.get("browser_download_url")
        == f"https://github.com/actions/runner/releases/download/v{version}/{name}",
        "Runner archive must come from the official actions/runner release.",
    )
    digest = asset.get("digest")
    require(
        isinstance(digest, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", digest),
        "Official runner asset needs a published SHA256 digest.",
    )
    return name, digest.split(":")[1]


def extract(archive, target):
    with tarfile.open(archive, "r:gz") as package:
        members = package.getmembers()
        names = {}
        for member in members:
            path = Path(member.name)
            require(
                not path.is_absolute()
                and ".." not in path.parts
                and (
                    member.isfile()
                    or member.isdir()
                    or member.issym()
                    or member.islnk()
                ),
                "Runner archive contains an unsafe path or special file.",
            )
            name = posixpath.normpath(member.name)
            require(
                name not in names or member.isdir() and names[name].isdir(),
                "Runner archive contains duplicate file paths.",
            )
            names[name] = member
        for name, member in names.items():
            parents = Path(name).parents
            require(
                not any(
                    str(parent) in names
                    and (names[str(parent)].issym() or names[str(parent)].islnk())
                    for parent in parents
                ),
                "Runner archive would extract through a link parent.",
            )
            if member.issym() or member.islnk():
                require(
                    not posixpath.isabs(member.linkname),
                    "Runner archive link target is absolute.",
                )
                destination = posixpath.normpath(
                    posixpath.join(
                        posixpath.dirname(name) if member.issym() else "",
                        member.linkname,
                    )
                )
                require(
                    destination != ".." and not destination.startswith("../"),
                    "Runner archive link escapes the extraction directory.",
                )
                seen = {name}
                while destination in names and (
                    names[destination].issym() or names[destination].islnk()
                ):
                    require(
                        destination not in seen, "Runner archive contains a link cycle."
                    )
                    seen.add(destination)
                    linked = names[destination]
                    require(
                        not posixpath.isabs(linked.linkname),
                        "Runner archive link target is absolute.",
                    )
                    destination = posixpath.normpath(
                        posixpath.join(
                            posixpath.dirname(destination) if linked.issym() else "",
                            linked.linkname,
                        )
                    )
                    require(
                        destination != ".." and not destination.startswith("../"),
                        "Runner archive link chain escapes the extraction directory.",
                    )
                if member.islnk():
                    require(
                        destination in names and names[destination].isfile(),
                        "Runner archive hardlink must name an included regular file.",
                    )
        require(
            not target.exists(),
            "Prepare destination already exists; preserve it and choose an empty staging path.",
        )
        target.mkdir(mode=0o700)
        for member in members:
            member.mode &= 0o777
            if hasattr(tarfile, "data_filter"):
                package.extract(member, target, filter="data")
            else:
                package.extract(member, target)


def prepare(args):
    require(
        args.version is not None,
        "Prepare requires --version with an explicitly reviewed official version.",
    )
    operating_system = "osx" if platform.system() == "Darwin" else "linux"
    architecture = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x64"}.get(
        platform.machine()
    )
    require(
        architecture is not None and platform.system() in ("Darwin", "Linux"),
        "Unsupported host platform/architecture.",
    )
    name, digest = release(args.version, operating_system, architecture)
    require(
        not args.runner_dir.exists(),
        "Prepare destination must not exist; never overwrite a runner or its credentials.",
    )
    with tempfile.TemporaryDirectory(prefix="studio-runner-") as temporary:
        command(
            [
                "gh",
                "release",
                "download",
                "v" + args.version,
                "--repo",
                "actions/runner",
                "--pattern",
                name,
                "--dir",
                temporary,
            ],
            "Download official runner release",
            timeout=300,
        )
        archive = Path(temporary) / name
        with archive.open("rb") as stream:
            actual = (
                hashlib.file_digest(stream, "sha256").hexdigest()
                if hasattr(hashlib, "file_digest")
                else hash_stream(stream)
            )
        require(actual == digest, "Runner archive SHA256 mismatch; nothing extracted.")
        extract(archive, args.runner_dir)
    (args.runner_dir / ".studio-package.json").write_text(
        json.dumps(
            {
                "version": args.version,
                "sha256": digest,
                "asset": name,
                "repository": "actions/runner",
            }
        )
        + "\n"
    )
    print(
        "OK Official runner archive verified and extracted; unregistered, no host service activated."
    )


def hash_stream(stream):
    digest = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(block)
    return digest.hexdigest()


def configured(args, group):
    try:
        raw = command(
            as_user(args, ["/bin/cat", str(args.runner_dir / ".runner")]),
            "Read native registration metadata",
        )
        data = json.loads(raw.removeprefix("\ufeff"))
    except (OSError, ValueError):
        raise Failure(
            "Native .runner registration metadata is missing or invalid; no credentials were read."
        ) from None
    require(
        isinstance(data, dict)
        and data.get("poolId") == group["id"]
        and isinstance(data.get("gitHubUrl"), str)
        and data["gitHubUrl"].rstrip("/") == f"https://github.com/{ORG}"
        and data.get("agentName") == args.name,
        "Native runner registration does not match the selected Studio group/name.",
    )
    return data


def configure(args, group, account):
    command(
        as_user(args, ["/bin/test", "-f", str(args.runner_dir / "config.sh")]),
        "Inspect official config.sh",
    )
    if args.mode == "register":
        command(
            as_user(args, ["/bin/test", "!", "-e", str(args.runner_dir / ".runner")]),
            "Require unregistered runner (existing registration is preserved)",
        )
        kind = "registration-token"
        native = [
            "./config.sh",
            "--unattended",
            "--url",
            f"https://github.com/{ORG}",
            "--runnergroup",
            group["name"],
            "--name",
            args.name,
            "--labels",
            args.name,
            "--work",
            "_work",
        ]
    else:
        data = configured(args, group)
        roster = api(
            f"orgs/{ORG}/actions/runner-groups/{group['id']}/runners?per_page=100"
        ).get("runners")
        require(isinstance(roster, list), "Runner roster returned an invalid shape.")
        found = [
            row
            for row in roster
            if isinstance(row, dict) and row.get("id") == data.get("agentId")
        ]
        require(
            len(found) == 1
            and found[0].get("busy") is False
            and found[0].get("status") == "offline",
            "Stop the exact Studio service and wait for this runner to be offline and idle before removing registration.",
        )
        kind = "remove-token"
        native = ["./config.sh", "remove", "--unattended"]
    token = api(f"orgs/{ORG}/actions/runners/{kind}", "POST").get("token")
    require(
        isinstance(token, str) and token,
        "GitHub did not return a short-lived runner token (response suppressed).",
    )
    env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": account.pw_dir,
        "USER": account.pw_name,
        "LOGNAME": account.pw_name,
        "ACTIONS_RUNNER_INPUT_TOKEN": token,
    }
    # The operator cannot traverse HOME0700. Change directory only after sudo switches user.
    argv = as_user(
        args,
        [
            "/bin/bash",
            "-c",
            'cd -- "$1" && shift && exec "$@"',
            "studio-runner",
            str(args.runner_dir),
            *native,
        ],
        preserve_token=True,
    )
    try:
        command(argv, "Native runner " + args.mode, env=env, timeout=120)
    finally:
        env.pop("ACTIONS_RUNNER_INPUT_TOKEN", None)
        token = None
    print(
        f"OK Native runner {args.mode} completed; no service activation or directory deletion performed."
    )


def verify(args, group):
    data = configured(args, group)
    roster = api(f"orgs/{ORG}/actions/runner-groups/{group['id']}/runners?per_page=100")
    runners = roster.get("runners")
    require(isinstance(runners, list), "Runner roster returned an invalid shape.")
    found = [
        row
        for row in runners
        if isinstance(row, dict) and row.get("id") == data.get("agentId")
    ]
    require(
        len(found) == 1 and found[0].get("name") == args.name,
        "Registered runner is not present in the restricted group.",
    )
    require(
        found[0].get("status") == "online",
        "Runner is registered but offline; owner-admin must inspect its isolated native service.",
    )
    print(
        "OK Matching registered runner is online in the restricted group. A successful intended workflow run is still required."
    )


def setup(args, group):
    require(
        platform.system() == "Darwin" and os.geteuid() != 0,
        "Setup runs as the macOS operator, never as root.",
    )
    require(
        sys.stdin.isatty() and sys.stdout.isatty(),
        "Setup needs one visible interactive operator terminal for the normal macOS administrator prompt.",
    )
    require(
        args.source is not None,
        "Setup requires --source with the verified unregistered official package.",
    )
    require(
        args.runner_dir == Path("/Users") / args.runner_user / "actions-runner",
        "macOS setup uses the dedicated account-local actions-runner directory.",
    )
    # Inherit the TTY for this single normal password prompt; no password is captured or stored.
    try:
        # No time limit: a stopped sudo prints "a password is required". Its prompt
        # uses the terminal device; its error lines go to captured stderr.
        result = control.run(
            ["sudo", "-v"], timeout=None, interactive=True, capture_output=True
        )
    except (OSError, subprocess.SubprocessError):
        raise Failure(
            "Native administrator authorization unavailable or timed out."
        ) from None
    require(
        result.returncode == 0,
        "Owner-admin authorization was not completed; no host changes started.",
    )
    helper = Path(__file__).with_name("macos_host.py")
    common = [
        "--user",
        args.runner_user,
        "--owner-home",
        str(Path.home()),
        "--group-id",
        str(args.group_id),
        "--name",
        args.name,
        "--label",
        args.service_label,
        "--apply",
    ]
    command(
        [
            "sudo",
            "-n",
            sys.executable,
            str(helper),
            "prepare",
            "--source",
            str(args.source),
            *common,
        ],
        "Prepare dedicated macOS account",
        timeout=180,
    )
    account = host(args)
    exists = command(
        as_user(
            args,
            [
                "/bin/bash",
                "-c",
                'if test -e "$1"; then printf yes; else printf no; fi',
                "studio-runner",
                str(args.runner_dir / ".runner"),
            ],
        ),
        "Inspect registration presence",
    )
    if exists == "yes":
        configured(args, group)
    else:
        mode = args.mode
        args.mode = "register"
        try:
            configure(args, group, account)
        finally:
            args.mode = mode
    preflight(args)
    command(
        ["sudo", "-n", sys.executable, str(helper), "install-service", *common],
        "Install isolated Studio service",
        timeout=180,
    )
    print(
        "OK Setup completed. Run verify after GitHub reports online, then execute the intended main workflow."
    )


def execute(args):
    if args.mode == "prepare":
        if args.apply:
            prepare(args)
        else:
            print(
                "PLAN prepare: verify/download an official archive only. No account, registration or service writes; add --version and --apply to execute."
            )
        return
    _, group = preflight(args)
    if args.mode in ("setup", "register", "remove") and not args.apply:
        print(
            f"PLAN {args.mode}: rerun with --apply after reviewing the runbook. No host/provider writes performed."
        )
        return
    if args.mode == "setup":
        setup(args, group)
        return
    account = host(args)
    if args.mode == "inspect":
        print(
            "OK Read-only inspection complete; registration/service/workflow execution not asserted."
        )
    elif args.mode == "verify":
        verify(args, group)
    else:
        configure(args, group, account)


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "mode",
        nargs="?",
        choices=("inspect", "prepare", "setup", "register", "verify", "remove"),
        default="inspect",
    )
    parser.add_argument(
        "--repo", required=True, help="Exact private TheHypertextStudio/repository"
    )
    parser.add_argument("--workflow", default=".github/workflows/checks.yml")
    parser.add_argument(
        "--group-id",
        type=int,
        help="Required positive server group ID except for archive prepare",
    )
    parser.add_argument(
        "--runner-dir",
        required=True,
        type=lambda value: Path(value).expanduser().absolute(),
    )
    parser.add_argument("--runner-user", required=True)
    parser.add_argument(
        "--name",
        default="studio-product-admin",
        help="Unique runner name and custom label",
    )
    parser.add_argument(
        "--version", help="Explicit reviewed runner version, e.g. 2.337.0"
    )
    parser.add_argument(
        "--source",
        type=lambda value: Path(value).expanduser().absolute(),
        help="Verified unregistered staging package for macOS setup",
    )
    parser.add_argument(
        "--service-label", default="com.hypertextstudio.actions.product-admin"
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Allow only the selected lifecycle mutation",
    )
    args = parser.parse_args(argv)
    require(
        re.fullmatch(ORG + r"/[A-Za-z0-9_.-]+", args.repo),
        "Select an exact Hypertext Studio repository.",
    )
    require(
        re.fullmatch(r"\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml", args.workflow),
        "Select one native workflow path.",
    )
    require(
        (
            args.mode == "prepare"
            and args.group_id is None
            or isinstance(args.group_id, int)
            and args.group_id > 0
        )
        and re.fullmatch(r"[A-Za-z0-9_-]+", args.name),
        "Select a positive server runner group ID (not needed for archive prepare) and valid name.",
    )
    require(
        re.fullmatch(r"ci-[a-z0-9-]+", args.runner_user),
        "Select a dedicated ci-* account.",
    )
    require(
        args.version is None or re.fullmatch(r"\d+\.\d+\.\d+", args.version),
        "Use a numeric stable runner version.",
    )
    require(
        re.fullmatch(r"com\.hypertextstudio\.actions\.[a-z0-9-]+", args.service_label),
        "Use an owned Studio service label.",
    )
    return args


def main():
    try:
        with control.cancellation_signals():
            execute(arguments())
        return 0
    except (control.Cancelled, KeyboardInterrupt) as error:
        print(
            "INTERRUPTED Runner operation stopped; native/provider state may have changed. Preserve it and inspect before retrying."
        )
        return 128 + (error.signum if isinstance(error, control.Cancelled) else 2)
    except (Failure, OSError, ValueError, TypeError) as error:
        # Only controlled Failure messages contain useful context; native/JSON payloads stay private.
        print(
            "ERROR "
            + (
                str(error)
                if isinstance(error, (Failure, control.StateError))
                else "Local runner inspection failed; check paths and permissions without sharing credential files."
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
