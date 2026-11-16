"""Small terminal presentation for Studio operations; no native payload rendering."""

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import argparse
import json
import os
import re
import shutil
import sys
import textwrap
import threading
import time

_SESSION = ContextVar("runner_output_session", default=None)
# Set while another program (sudo) owns the terminal; spinners stop drawing.
_PROMPTING = threading.Event()


class UsageError(ValueError):
    """A controlled public input error, rendered by the orchestrator."""


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        if _SESSION.get() is not None:
            raise UsageError(
                message + ". Use hypertext runners --help for supported options."
            )
        super().error(message)


def current_session():
    return _SESSION.get()


@dataclass
class Outcome:
    """The public operation result, independent of terminal or native protocol."""

    status: str
    summary: str
    detail: str = ""
    next_action: str | None = None
    payload: dict | None = None
    code: int = 0
    # Account name -> classified failures (runner_errors.Finding).
    findings: dict | None = None
    # {"columns": [...], "align": ["left"|"right", ...], "rows": [[...], ...]}
    table: dict | None = None
    # "success" renders the summary as "✓ <bold summary>" with dim detail lines.
    style: str | None = None
    # One tone per summary line when lines differ in meaning: "ready" is green,
    # "waiting" yellow and "needs_you" red, whatever the run's overall status.
    tones: tuple | None = None

    def document(self):
        value = dict(
            self.payload or {},
            schema_version=1,
            status=self.status,
            summary=self.summary,
            detail=self.detail,
            next_action=self.next_action,
        )
        if self.findings:
            value["codes"] = {
                account: [item.code for item in items]
                for account, items in self.findings.items()
            }
        return value

    @classmethod
    def from_readiness(cls, result, *, account):
        """Use the public account model; native transports keep the bounded fallback."""
        active = current_session()
        renderer = getattr(getattr(active, "backend", None), "readiness", None)
        if renderer is not None:
            return renderer(result, account=account)
        return cls.native_readiness(result, account=account)

    @classmethod
    def native_readiness(cls, result, *, account):
        """Present native lifecycle facts without importing the public CLI package."""
        controller = result.get("controller", {})
        pools = controller.get("pools", {})
        unsafe = any(
            value.get("state") in ("blocked", "cleanup-required")
            for value in pools.values()
        )
        observed = controller.get("fresh") is True and controller.get("loaded") is True
        policy_ready = result.get("policy_ready") is True
        starting = (
            result.get("status") == "controller_starting"
            and controller.get("loaded") is True
            and result.get("activation_started") is True
            and policy_ready
        )
        background = (
            result.get("status") == "preparing"
            and observed
            and policy_ready
            and bool(pools)
            and all(
                value.get("state")
                in (
                    "starting",
                    "idle",
                    "creating",
                    "preparing",
                    "registered",
                    "busy",
                    "waiting",
                    "unavailable",
                )
                for value in pools.values()
            )
        )
        payload = dict(result, background=background or starting)
        reasons = {
            "power_unavailable": "Paused on battery. Resumes automatically on external power.",
            "thermal_unavailable": "Waiting for this Mac to cool down.",
            "memory_unavailable": "Waiting for available memory.",
            "capacity_unavailable": "Waiting for enough local resources; the disk reserve is preserved.",
        }
        lines = []
        for name, value in pools.items():
            label = "macOS" if name == "macos" else "Linux"
            state = value.get("state")
            cleanup_failed = any(
                item.get("operation") == "cleanup"
                for item in value.get("diagnostics", [])
            )
            description = (
                "Preparation failed and cleanup is unconfirmed. Review the failure with hypertext runners doctor before resuming."
                if state in ("blocked", "cleanup-required") and cleanup_failed
                else "Runner preparation is paused. Review the failure with hypertext runners doctor."
                if state in ("blocked", "cleanup-required")
                else reasons.get(value.get("reason"))
            )
            if not description:
                description = {
                    "preparing": "Preparing the build environment in the background.",
                    "creating": "Preparing a clean build environment.",
                    "idle": "Ready for CI jobs from selected repositories.",
                    "waiting": "Waiting for CI jobs from selected repositories.",
                    "registered": "Ready for CI jobs from selected repositories.",
                    "busy": "Running a job.",
                }.get(state, "Checking availability.")
            lines.append(label + ": " + description)
        if unsafe or not (result.get("ready") is True or background or starting):
            connected = observed and policy_ready
            summary = (
                "This Mac is connected; some runners need hypertext runners to repair them."
                if unsafe and connected
                else "Runner connection is not confirmed."
            )
            detail = (
                "\n".join(lines)
                if connected
                else readiness_message(result, organization=account)
            )
            return cls(
                "action_required",
                summary,
                detail + "\nExisting jobs and saved enrollment are preserved.",
                payload=payload,
                code=1,
            )
        if starting:
            lines.append(
                "The background runner service is starting. Availability is not confirmed yet."
            )
        if background or starting:
            lines.append(
                "You can close this Terminal. Preparation resumes automatically when this Mac is available."
            )
        return cls(
            "connected",
            "This Mac is connected to " + account + ".",
            "\n".join(lines),
            payload=payload,
        )


def readiness_message(result, *, organization=None):
    """Explain the observed phase; never recommend repeating an unsafe failure."""
    from pool_config import describe_diagnostic

    if result.get("status") == "blocked":
        observed = result.get("controller", {}).get("pools", {})
        pools = {
            name: value
            for name, value in observed.items()
            if name in result.get("requested_platforms", observed)
        }
        blocked = [
            label
            for name, label in (("linux", "Linux"), ("macos", "macOS"))
            if pools.get(name, {}).get("state") == "blocked"
        ]
        target = (" and ".join(blocked) or "Job") + (
            " runners" if len(blocked) > 1 else " runner"
        )
        causes = [
            label + ": " + describe_diagnostic(diagnostic)
            for name, label in (("linux", "Linux"), ("macos", "macOS"))
            for diagnostic in pools.get(name, {}).get("diagnostics", [])
        ]
        if causes:
            return "\n".join(causes)
        return (
            target
            + " need interrupted setup recovery. The guided runner command checks and repairs this state automatically."
        )
    if result.get("status") == "ready" and result.get("requested_platforms"):
        names = [
            ("macOS" if name == "macos" else "Linux")
            for name in result["requested_platforms"]
        ]
        return (
            " and ".join(names)
            + " runners are online. Actual builds still need verification."
        )
    messages = {
        "policy_required": "Configured runner group policy is incomplete. Finish the shared pool setup before readiness can be established.",
        "shared_migration_pending": "Finish the shared controller migration with hypertext runners migrate --org "
        + (organization or "ORGANIZATION")
        + " --shared-app --apply.",
        "recovery_pending": "Runner recovery is still being finalized. Its saved transaction must finish before readiness can be established.",
        "ready": "Job runner is online. Actual builds still need verification.",
        "setup_required": "No runner installation is ready. Choose repositories in hypertext runners to set up this Mac.",
        "runtime_update_required": "The installed runner tools need an update before setup can continue.",
        "runtime_update_blocked": "The runner tools could not be updated safely. The reported safety check must be resolved before updating.",
        "authority_required": "Mac administrator access is needed to change the runner startup service. Complete this step in your normal Terminal.",
        "controller_missing": "The runner startup service is not running. Setup needs to start that service before it can prepare builds.",
        "controller_starting": "The runner startup service is starting. No additional setup or password is needed while it starts.",
        "preparing": "This Mac is connected. Build environments prepare in the background when the Mac is available; no setup retry or password is needed.",
        "drained": "Runners are paused for maintenance. Setup will not undo that pause; resume runners after the maintenance is complete.",
        "enrollment_pending": "A repository connection is incomplete. Setup must finish that connection before adding another repository.",
    }
    return messages.get(
        result.get("status"),
        "Setup could not identify the runner state. A diagnostic is needed before another setup attempt.",
    )


TITLE = "GitHub Actions on this Mac"
ASK_AGAIN = (
    "This one approval covers the rest of this run. A later run asks again only if it "
    "has to repair or update the runners."
)
SUDO_LOCAL = "/etc/pam.d/sudo_local"


def touch_id_sudo(path=SUDO_LOCAL):
    """True when macOS lets sudo accept Touch ID (pam_tid.so in sudo_local)."""
    try:
        with open(path, encoding="utf-8") as stream:
            lines = stream.read(65536).splitlines()
    except (OSError, UnicodeError):
        return False
    return any(
        "pam_tid.so" in line and not line.lstrip().startswith("#") for line in lines
    )


class Session:
    """One orchestrator-owned header, progress stream and final outcome."""

    def __init__(
        self,
        action,
        *,
        machine=False,
        console=None,
        publish=None,
        fallback=None,
        backend=None,
        quiet=False,
    ):
        self.action, self.machine = action, machine
        # The operator's Studio CLI backend: results to stdout, everything else to
        # stderr, the shared progress line and tables. Installed code has none.
        self.backend = backend
        # Step notes become --verbose detail; the result says what changed.
        self.quiet_notes = quiet
        self.console = console or Console()
        # The operator supplies the failure renderer; installed runtime code has none.
        self.publish = publish
        self.fallback = fallback  # Lines to show if rendering itself fails.
        self.finished = False
        self.token = None
        self.failure = None
        self.outcome = None
        self._account = None
        self.accounts = []  # Every account this session worked on, in order.
        # Collapsed progress shows only failed steps, then one line for the run.
        self.collapse = False
        self.started = self.console.clock()

    @property
    def account(self):
        """The account whose work is running in a multi-account operation."""
        return self._account

    @account.setter
    def account(self, value):
        self._account = value
        if value is not None and value not in self.accounts:
            self.accounts.append(value)

    def __enter__(self):
        self.token = _SESSION.set(self)
        if self.backend is not None:
            if not self.machine:
                self.backend.header(TITLE, None if self.quiet_notes else self.action)
        elif not self.machine:
            self.console.heading(TITLE, code="1;36")
            self.console.note(self.action)
        return self

    def progress_line(self):
        """One line for a collapsed run: the accounts checked and the total time."""
        names = self.accounts
        if not names:
            return None
        joined = (
            names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]
        )
        return (
            "Checked " + joined + " · " + duration(self.console.clock() - self.started)
        )

    def __exit__(self, *error):
        _SESSION.reset(self.token)

    def finish(self, outcome):
        if self.finished:
            raise RuntimeError("A runner session may publish only one final outcome.")
        self.finished = True
        try:
            if self.publish is not None:
                outcome = self.publish(outcome)
            self._render(outcome)
        except Exception as error:
            # The renderer itself failed: still end with one plain result.
            lines = (
                self.fallback(error)
                if self.fallback is not None
                else [
                    "Runner setup stopped because its result could not be displayed.",
                    "Completion is unconfirmed. Review the support record before changing runner state.",
                ]
            )
            if self.backend is not None:
                self.backend.fallback(lines)
            else:
                self.console.heading(lines[0], code="1;31")
                for line in lines[1:]:
                    self.console.note(line)
            return 70 if self.backend is not None else outcome.code or 1
        return outcome.code

    def _render(self, outcome):
        if self.backend is not None:
            self.backend.render(
                outcome,
                machine=self.machine,
                progress=self.progress_line() if self.collapse else None,
            )
            return
        if self.machine:
            print(
                json.dumps(outcome.document(), sort_keys=True),
                file=self.console.stream,
                flush=True,
            )
        else:
            waiting = outcome.status in (
                "connected",
                "preparing",
                "controller_starting",
                "review_required",
                "drained",
                "waiting",
            )
            color = "1;32" if outcome.code == 0 else "1;33" if waiting else "1;31"
            progress = self.progress_line() if self.collapse else None
            if progress:
                self.console.note(progress, dim=True)
            for index, line in enumerate(outcome.summary.split("\n")):
                self.console.heading(line, code=color, blank=index == 0)
            if outcome.table:
                self.console.write()
                self.console.table(outcome.table)
                if outcome.detail:
                    self.console.write()
            for line in outcome.detail.splitlines():
                self.console.note(line)
            if outcome.next_action:
                self.console.heading("Next step")
                if outcome.next_action.startswith("hypertext "):
                    self.console.write("    " + outcome.next_action)
                else:
                    self.console.note(outcome.next_action)


def present(outcome, *, action, machine=False):
    active = _SESSION.get()
    if active is not None:
        return active.finish(outcome)
    with Session(action, machine=machine) as session:
        return session.finish(outcome)


def duration(seconds):
    seconds = max(0, int(seconds))
    minutes, seconds = divmod(seconds, 60)
    return f"{minutes}m {seconds:02d}s" if minutes else f"{seconds}s"


class Console:
    def __init__(self, stream=None, environ=None, clock=time.monotonic):
        self._stream = stream
        self.environ = os.environ if environ is None else environ
        self.clock = clock

    @property
    def stream(self):
        return sys.stdout if self._stream is None else self._stream

    @property
    def terminal(self):
        return self.stream.isatty() and self.environ.get("TERM") != "dumb"

    def ink(self, text, code):
        if self.terminal and "NO_COLOR" not in self.environ:
            return f"\033[{code}m{text}\033[0m"
        return text

    def write(self, text=""):
        active = _SESSION.get()
        if active is not None:
            if active.machine:
                return
            if active.backend is not None:
                active.backend.write(text, verbose=active.quiet_notes)
                return
            print(text, file=active.console.stream, flush=True)
        else:
            print(text, file=self.stream, flush=True)

    CELL_COLORS = {"Ready": "32", "Waiting": "33", "Blocked": "31"}

    def table(self, table):
        """A table the way gh, kubectl and docker print one.

        On a terminal: a header row, columns two spaces apart, text left-aligned and
        numbers right-aligned, fitted to $COLUMNS (80 if unknown) by shortening the
        first column with an ellipsis; colour only when allowed. Piped: one
        tab-separated line per row, without the header or colour.
        """
        rows = [[str(value) for value in row] for row in table["rows"]]
        if not self.stream.isatty():
            for row in rows:
                self.write("\t".join(row))
            return
        columns, align = list(table["columns"]), table["align"]
        indent = 4
        width = shutil.get_terminal_size((80, 24)).columns
        widths = [
            max(len(row[i]) for row in [columns, *rows]) for i in range(len(columns))
        ]
        spare = width - indent - (sum(widths) + 2 * (len(widths) - 1))
        if spare < 0:
            widths[0] = max(len(columns[0]), widths[0] + spare)

        def fit(text, size):
            return text if len(text) <= size else text[: max(1, size - 1)] + "…"

        def line(row, *, header=False):
            cells = []
            for index, value in enumerate(row):
                value = fit(value, widths[index])
                padded = (
                    value.rjust(widths[index])
                    if align[index] == "right"
                    else value.ljust(widths[index])
                )
                if header:
                    padded = self.ink(padded, "1")
                elif value in self.CELL_COLORS:
                    padded = self.ink(padded, self.CELL_COLORS[value])
                cells.append(padded)
            return (" " * indent + "  ".join(cells)).rstrip()

        self.write(line(columns, header=True))
        for row in rows:
            self.write(line(row))

    def heading(self, title, *, code="1", blank=True):
        active = _SESSION.get()
        if active is not None and active.backend is not None:
            if not active.machine:
                active.backend.heading(title, verbose=active.quiet_notes)
            return
        if blank:
            self.write()
        width = max(20, min(88, shutil.get_terminal_size((88, 24)).columns) - 2)
        for line in textwrap.wrap(title, width=width):
            self.write("  " + self.ink(line, code))

    def banner(self, mode, legacy_mode=None, *, context=None):
        if legacy_mode is not None:
            context, mode = mode["owner"]["login"], legacy_mode
        if _SESSION.get() is not None or self.environ.get("RUNNER_POOLS_GUIDED") == "1":
            return
        self.heading(TITLE, code="1;36")
        self.note((context + " · " if context else "") + mode.capitalize())

    def administrator_prompt(self):
        self.authorization(
            "Hypertext needs administrator access to manage the dedicated runner account "
            "and configure automatic startup."
        )

    def gap(self):
        """A blank line between groups, on the operator's terminal only."""
        active = _SESSION.get()
        if active is not None and active.backend is not None and not active.machine:
            active.backend.gap()

    @contextmanager
    def prompting(self):
        """Hand the terminal to an interactive prompt; no spinner draws over it."""
        _PROMPTING.set()
        try:
            active = _SESSION.get()
            if active is not None and active.backend is not None:
                active.backend.clear_progress()
            elif self.terminal:
                self.stream.write("\r\033[2K")
                self.stream.flush()
            yield
        finally:
            _PROMPTING.clear()
        self.gap()  # The steps after an answered prompt start a new group.

    def authorization(self, purpose):
        """Why the owner is asked, whether they will be asked again, and how to approve."""
        self.gap()
        self.attention(purpose)
        self.attention(ASK_AGAIN)
        self.attention(
            "Approve with Touch ID to continue."
            if touch_id_sudo()
            else "Enter your Mac password to continue."
        )

    def phase(self, number, total, title):
        if _SESSION.get() is not None or self.environ.get("RUNNER_POOLS_GUIDED") == "1":
            self.heading(title)
            return
        self.write()
        self.write(
            "  "
            + self.ink(f"{number:02d}/{total:02d}", "36")
            + " "
            + self.ink(title, "1")
        )

    @contextmanager
    def attending(self):
        """Output the owner must read to continue: quiet runs still show it."""
        active = _SESSION.get()
        if active is None:
            yield
            return
        quiet, active.quiet_notes = active.quiet_notes, False
        try:
            yield
        finally:
            active.quiet_notes = quiet

    def attention(self, message):
        with self.attending():
            self.note(message)

    def note(self, message, *, dim=False):
        active = _SESSION.get()
        if active is not None and active.backend is not None:
            if not active.machine:
                active.backend.note(message, dim=dim, verbose=active.quiet_notes)
            return
        width = max(30, min(88, shutil.get_terminal_size((88, 24)).columns) - 4)
        for paragraph in message.split("\n"):
            if not paragraph:
                self.write()
                continue
            # Give addresses their own intact line; ordinary prose and long
            # repository names still wrap within the terminal width.
            for part in re.split(r"(https?://\S+|~/\S+)", paragraph):
                lines = (
                    [part]
                    if re.fullmatch(r"https?://\S+|~/\S+", part)
                    else textwrap.wrap(part, width=width)
                )
                for line in lines:
                    self.write("    " + (self.ink(line, "2") if dim else line))

    def prompt(self, message):
        active = _SESSION.get()
        if active is not None and active.machine:
            raise UsageError(
                "This approval requires your normal Terminal; JSON operations do not prompt."
            )
        with self.prompting():
            if active is not None and active.backend is not None:
                return active.backend.prompt(message)
            self.note(message)
            return input("  > ")

    @contextmanager
    def operation(self, title):
        # Only caller-owned labels enter the renderer. Never render command
        # arguments, stdin, provider output or native stderr here.
        started = self.clock()
        done = threading.Event()
        ticker = None
        active = _SESSION.get()
        if active is not None and active.machine:
            yield
            return
        if active is not None and getattr(active, "account", None):
            title = active.account + ": " + title
        if active is not None and active.backend is not None:
            with active.backend.operation(title):
                yield
            return
        quiet = active is not None and getattr(active, "collapse", False)
        if self.terminal:

            def tick():
                frames = ("·", "•", "●", "•")
                index = 0
                while not done.is_set():
                    if _PROMPTING.is_set():
                        done.wait(0.15)
                        continue
                    elapsed = duration(self.clock() - started)
                    width = max(20, shutil.get_terminal_size((88, 24)).columns - 18)
                    label = textwrap.shorten(title, width=width, placeholder="…")
                    self.stream.write(
                        "\r\033[2K    "
                        + self.ink(frames[index % 4], "36")
                        + " "
                        + label
                        + " "
                        + self.ink(elapsed, "2")
                    )
                    self.stream.flush()
                    index += 1
                    done.wait(0.15)

            ticker = threading.Thread(target=tick, daemon=True)
            ticker.start()
        elif not quiet:
            self.note(title) if active is not None else self.write("RUN " + title)
        succeeded = False
        try:
            yield
            succeeded = True
        finally:
            done.set()
            if ticker is not None:
                ticker.join()
                self.stream.write("\r\033[2K")
            elapsed = duration(self.clock() - started)
            mark = (
                ("✓" if succeeded else "×")
                if self.terminal or active is not None
                else ("OK" if succeeded else "STOP")
            )
            if not (quiet and succeeded):
                self.write(
                    "    "
                    + self.ink(mark, "32" if succeeded else "31")
                    + " "
                    + title
                    + " "
                    + self.ink(elapsed, "2")
                )

    def finish(self, title, message):
        active = _SESSION.get()
        if active is not None:
            if active.outcome is None:
                active.outcome = Outcome("complete", title, message)
            return
        if self.environ.get("RUNNER_POOLS_GUIDED") == "1":
            return  # The orchestrator publishes the single final result.
        self.heading(title, code="1;32")
        self.note(message)

    def failure(self, phase, message, command=None, interrupted=False, *, task="Setup"):
        active = _SESSION.get()
        if active is not None:
            active.failure = Outcome(
                "interrupted" if interrupted else "action_required",
                "Stopped. Finished steps are kept."
                if interrupted
                else "Runner operation needs attention.",
                message,
                next_action=command,
                code=130 if interrupted else 1,
            )
            return
        label = (
            "Stopped. Finished steps are kept." if interrupted else task + " stopped"
        )
        self.heading(label, code="1;33" if interrupted else "1;31")
        self.note("Step: " + phase)
        # Keep the controlled ERROR prefix for privileged helper propagation.
        self.write(("INTERRUPTED " if interrupted else "ERROR ") + message)
        if command:
            self.note("Resume with the same command in this Terminal:")
            self.write("    " + command)
