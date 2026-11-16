"""Host-local admission and provider demand; no network listener or shared secrets."""

import hashlib
import os
import re
import subprocess
import sys
import uuid

from pool_config import Failure, require
import runner_recovery


class ProviderObservationUnavailable(Failure):
    """Inventory changed or was incomplete; retry without reserving capacity."""


def pages(api, path, key):
    """A failed read of GitHub's queue is transient unless GitHub refused access."""
    try:
        return runner_recovery.pages(api, path, key)
    except runner_recovery.Failure:
        raise ProviderObservationUnavailable(
            "GitHub inventory observation unavailable; no demand inferred."
        ) from None
    except Failure as error:
        if re.search(r"\(HTTP (?:401|403|404)\)", str(error)):
            raise
        raise ProviderObservationUnavailable(
            "GitHub inventory observation unavailable; no demand inferred."
        ) from None
    except (AttributeError, KeyError, TypeError, ValueError):
        # Malformed provider data, such as a run whose repository is null.
        raise ProviderObservationUnavailable(
            "GitHub inventory observation unavailable; no demand inferred."
        ) from None


def host_id():
    """Stable pseudonymous identity; never publish the hardware serial or UUID."""
    if sys.platform == "darwin":
        code, text = _run(["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"])
        match = (
            re.search(r'"IOPlatformUUID"\s*=\s*"([A-Fa-f0-9-]+)"', text)
            if code == 0
            else None
        )
        require(match is not None, "Cannot identify this Mac; host admission stopped.")
        source = match.group(1)
    else:
        source = str(uuid.getnode())
    return hashlib.sha256(source.encode()).hexdigest()[:12]


def runner_name(profile, platform, generation, host=None):
    return "-".join(v for v in (profile, platform, host, generation) if v)


def parse_runner(name, profile, platform):
    match = re.fullmatch(
        re.escape(profile + "-" + platform + "-")
        + r"(?:(?P<host>[a-f0-9]{12})-)?(?P<generation>[a-f0-9]{32})",
        name or "",
    )
    return (
        {"host_id": match["host"], "generation": match["generation"]} if match else None
    )


def _run(argv):
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=10,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
        return result.returncode, result.stdout
    except (OSError, subprocess.SubprocessError):
        return 1, ""


def observe(run=_run):
    result = {"power": "unknown", "thermal": "unknown", "memory": "unknown"}
    code, text = run(["/usr/bin/pmset", "-g", "batt"])
    if code == 0:
        if "'AC Power'" in text:
            result["power"] = "ac"
        elif "'Battery Power'" in text:
            result["power"] = "battery"
    code, text = run(["/usr/bin/pmset", "-g", "therm"])
    if code == 0:
        if re.search(
            r"(?:CPU_Speed_Limit|CPU_Scheduler_Limit)\s*=\s*(?:[0-9]?\d)\b", text
        ):
            result["thermal"] = "serious"
        elif "No thermal warning level" in text or re.search(
            r"CPU_Speed_Limit\s*=\s*100\b", text
        ):
            result["thermal"] = "nominal"
    code, text = run(["/usr/sbin/sysctl", "-n", "kern.memorystatus_vm_pressure_level"])
    if code == 0:
        result["memory"] = {"1": "normal", "2": "warning", "4": "critical"}.get(
            text.strip(), "unknown"
        )
    return result


def role(run=_run):
    code, text = run(["/usr/bin/pmset", "-g", "batt"])
    require(code == 0, "Cannot observe this Mac power policy; setup stopped.")
    return "laptop" if re.search(r"InternalBattery|Battery-\d", text) else "desktop"


def admission(role, sample):
    require(role in ("desktop", "laptop"), "Unknown host role.")
    reason = None
    if role == "laptop" and sample.get("power") != "ac":
        reason = "power_unavailable"
    elif sample.get("thermal") != "nominal":
        reason = "thermal_unavailable"
    elif sample.get("memory") != "normal":
        reason = "memory_unavailable"
    return {"available": reason is None, "reason": reason, "role": role}


def choose(demand, *, last=None):
    names = sorted(name for name, count in demand.items() if count > 0)
    if not names:
        return None
    return next((name for name in names if last is None or name > last), names[0])


def trusted_run(run, consumer):
    return (
        run.get("head_branch") == "main"
        and run.get("event") in consumer.get("events", ["push", "workflow_dispatch"])
        and run.get("path") == consumer["workflow"]
        and type(run.get("run_attempt")) is int
        and run["run_attempt"] >= 1
        and (
            consumer.get("events") != ["workflow_run", "workflow_dispatch"]
            or (run.get("event") == "workflow_run" and run["run_attempt"] == 1)
        )
        and (run.get("repository") or {}).get("id") == consumer["id"]
        and (run.get("head_repository") or {}).get("id") == consumer["id"]
    )


def job_admitted(job, expected):
    """The job half of the demand rule; labels match exactly, as the runner does."""
    return job.get("status") == "queued" and expected <= set(job.get("labels") or [])


def admits(profile, platform, consumer, run, job, expected=None):
    """The controller's exact demand rule for one job on one pool."""
    if expected is None:
        from pool_config import labels

        expected = set(labels(profile, platform))
    return (
        platform in consumer["pools"]
        and trusted_run(run, consumer)
        and job_admitted(job, expected)
    )


def active_runs(api, repo, listing=None):
    """Queued and in-progress runs once each; runs with executing jobs may still queue work."""
    listing = listing or pages
    runs = {}
    for state in ("queued", "in_progress"):
        for row in listing(
            api, f"repos/{repo}/actions/runs?status={state}", "workflow_runs"
        ):
            runs.setdefault(row["id"], row)
    return [runs[identity] for identity in sorted(runs)]


def run_jobs(api, repo, run, listing=None):
    return (listing or pages)(
        api,
        f"repos/{repo}/actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs",
        "jobs",
    )


def repository_demand(profile, platform, api):
    """Only queued jobs with exact trusted identities and local labels reserve a VM."""
    from pool_config import labels

    expected = set(labels(profile, platform))
    counts = {}
    for consumer in profile["consumers"]:
        if platform not in consumer["pools"]:
            continue
        for row in active_runs(api, consumer["repo"]):
            if not trusted_run(row, consumer):
                continue
            jobs = run_jobs(api, consumer["repo"], row)
            # The run and consumer already passed; only the job half remains.
            counts[consumer["id"]] = counts.get(consumer["id"], 0) + sum(
                job_admitted(j, expected) for j in jobs
            )
    return counts


def demand(profile, platform, api):
    return sum(repository_demand(profile, platform, api).values())
