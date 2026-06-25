# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versioning is [SemVer](https://semver.org/).

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
