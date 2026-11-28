# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versioning is [SemVer](https://semver.org/).

## Unreleased

### Fixed
- `rustc` and `swiftc` are no longer shimmed, and an install removes their old shims. Cargo and
  swift run a compiler once per crate or module, so a `cargo build` started from a terminal (which
  runs unmanaged) turned every compile into its own job, about 11,000 a day on one machine.
- The hourly maintenance pass prunes finished jobs older than three days and retention caches
  older than an hour. Both used to pile up forever, reaching 43,000 job folders and 129,000
  cache files.
- A build tool started anywhere inside a running job now runs in that job's slot. Coverage follows
  real parent pids from the job's controller, so a turbo task in its own process group and a Gradle
  daemon in its own session are covered; an unrelated process or an orphan reparented to launchd is
  not. Jobs that spawned children through the shims used to queue them behind their own slots and
  deadlock once every slot held a parent.
- The reservation record is rewritten in place at a fixed size, so a reader never sees it empty.

### Changed
- A job waits only for a free slot. Slots follow the machine's cores and memory, the queue is
  first come, first served, and `status` shows each waiting job's position. Disk is decided when
  the slot is held: above the floor the job starts, below it one short recovery runs and the job
  starts or fails with the numbers. Reservation records, retention measurement, a running
  recovery and busy locks no longer delay a start.
- Commands that run no build tool start at once without a slot.
- Recovery no longer waits for running jobs or for the admission lock, and a watchdog keeps free
  space above a low-water mark every minute.

### Added
- Short checks have their own lane. A version probe or a test runner the interpreter provides
  (`pytest`, `python -m pytest`, `python -m unittest`, `node --test`) waits for one of three fast
  slots (`FAST_SLOTS`) instead of queueing behind builds. The lane follows from the command and its
  recorded disk use, never from a flag, and a fast job keeps the build disk floor and reserve.
  `status` shows each job's lane.
- A shared admission protocol (`docs/admission-protocol.md`): an external broker such as a CI
  runner pool or VM host publishes its commitments, which take admission slots, and can count
  running jobs under the same admission lock. Work it starts, marked by `DISK_JANITOR_BROKER`, is
  not admitted twice.
- Recovery of Gradle `build` outputs in idle git checkouts.
- Retirement of reservation records whose guardian is gone.
- Every hour, finished linked worktrees are retired and launchd service logs over the cap are
  emptied in place after keeping their tail, whatever the free space. Run
  `disk-janitor reclaim --schedule` again to update an existing hourly schedule.
- `disk-janitor space` reports worktrees by state and folder, build caches and service logs.

### Fixed
- The command-line tool selects a Python 3.10+ interpreter instead of failing in the middle of a
  scheduled run under the system interpreter.
- The runtime installer upgrades a release whose set of components differs from its own.
- The hourly pass and the watchdog no longer run as launchd Background jobs with low-priority IO,
  which stretched each git inspection past its timeout so a pass examined nothing.
- Removing a finished worktree is no longer cut short by the 10-second git timeout, which left a
  large checkout half-deleted.

## [0.1.4] - 2026-06-25

### Fixed
- Scheduled (cron) runs were logged with a `[dry-run]` label even though they performed real
  work, because `DRY` defaulted to `0` (non-empty) and tripped `${DRY:+…}`. `DRY` now defaults
  to empty. No behavior change — only the misleading log label.

## [0.1.3] - 2026-06-25

### Fixed
- Scheduled runs inherit a minimal PATH (launchd/systemd/cron), so `cargo-sweep` and `pnpm`
  were not found and the sweep silently skipped. `run` now prepends `~/.cargo/bin`,
  `/opt/homebrew/bin`, and `/usr/local/bin` to PATH.

## [0.1.2] - 2026-06-25

### Fixed
- The scheduled job ran `/bin/bash <script>`, so macOS attributed background activity to
  "bash" ("'bash' can run in the background"). The launchd/systemd/cron entries now invoke the
  `disk-janitor` script directly so it is named correctly.
- `install` could not refresh its on-disk copy when the source binary was read-only (e.g. a
  Homebrew Cellar path), so `brew upgrade` left the scheduler running the old version. It now
  removes the old copy first and marks the new one writable.

## [0.1.1] - 2026-06-25

### Fixed
- `status` reported the scheduled job as "not active" even when it was loaded: `launchctl
  list | grep -q` aborts the producer early and, under `set -o pipefail`, surfaced as SIGPIPE
  (141). Capture-then-match instead.
- The agent-guidance writer used `mv`, which replaced a config file that is a symlink (e.g.
  `~/.claude/CLAUDE.md` → `~/.codex/AGENTS.md`) with a regular file. It now writes through symlinks.

## [0.1.0] - 2026-06-25

Initial public release.

### Added
- Shared Cargo `target-dir` configuration so dependencies compile once across git worktrees.
- pnpm `package-import-method` dedup (`clone` on macOS/APFS, `hardlink` on Linux).
- Weekly scheduled sweep: `cargo-sweep`, stale `node_modules`, dangling worktree metadata, and idle
  `**/.claude/worktrees/agent-*` checkouts.
- Cross-platform scheduler: launchd (macOS), systemd user timer / crontab (Linux).
- `install` / `uninstall` / `run` / `status` / `logs` / `config` subcommands.
- `--dry-run` for `run`, opt-in `--with-agent-guidance`, and `--purge` uninstall.
- Clean, tracked install/uninstall (backs up and restores pre-existing config files).
- Safety guard against operating on `$HOME` or `/`.
- Shell completions for bash, zsh, and fish.
- A `disk-janitor(1)` man page.
- Homebrew formula (`WillieCubed/tap/disk-janitor`).
