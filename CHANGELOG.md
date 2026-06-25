# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versioning is [SemVer](https://semver.org/).

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
