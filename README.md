# disk-janitor

[![CI](https://github.com/WillieCubed/disk-janitor/actions/workflows/ci.yml/badge.svg)](https://github.com/WillieCubed/disk-janitor/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)

Keeps git worktrees from quietly filling your disk. Every worktree builds its own Rust
`target/` and installs its own `node_modules`, so a handful of them can waste hundreds of
gigabytes on copies of the same files. disk-janitor sets up dependency sharing so that stops
happening, and runs a weekly cleanup of the build junk that does pile up.

It never touches your source code or your coding agent's chat history.

```sh
brew install WillieCubed/tap/disk-janitor
disk-janitor install        # set up sharing and schedule the weekly cleanup
disk-janitor status         # show what's configured and how much space is free
disk-janitor run --dry-run  # show what a cleanup would remove, without removing it
```

## The problem

Tools like Claude Code and Codex do their work in git worktrees. Worktrees share git history
but not build output, so every worktree compiles its own copy of your dependencies into
`target/` and installs its own `node_modules`. You don't notice until the disk is full.

disk-janitor fixes the cause instead of only cleaning up after it:

- Points every project at one shared Cargo target directory, so dependencies compile once
  instead of once per worktree.
- Turns on pnpm's store linking, so a worktree's `node_modules` reuses files from the store
  instead of copying them (`clone` on macOS/APFS, `hardlink` on Linux).
- Schedules a weekly job that runs `cargo-sweep`, removes stale `node_modules`, prunes dead
  git worktrees, and clears abandoned agent worktrees.

Other tools clean build artifacts after the fact ([kondo](https://github.com/tbillington/kondo),
[cargo-sweep](https://github.com/holmgr/cargo-sweep),
[npkill](https://github.com/voidcosmos/npkill)). disk-janitor uses them, but its main job is to
stop the duplication in the first place.

## Install

```sh
brew install WillieCubed/tap/disk-janitor
```

Or from source:

```sh
git clone https://github.com/WillieCubed/disk-janitor
cd disk-janitor
./install.sh
```

`install.sh` copies the script to `~/.local/bin` and runs `disk-janitor install`. Make sure
`~/.local/bin` is on your `PATH`.

To also drop a short note into your agent config files (`~/.codex/AGENTS.md`,
`~/.claude/CLAUDE.md`) telling agents not to undo the shared setup:

```sh
disk-janitor install --with-agent-guidance
```

## Commands

| Command | What it does |
| --- | --- |
| `install` | set up sharing and schedule the weekly cleanup |
| `run` | run a cleanup now (`--dry-run` to preview) |
| `status` | show configuration and free space |
| `uninstall` | undo everything (`--purge` also removes cargo-sweep and saved state) |
| `logs` | show the run log (`-f` to follow) |
| `config` | print the config file path and contents |

`install` also takes `--with-agent-guidance` and `--dry-run`.

## Configuration

`install` writes `~/.disk-janitor/config.env`. Edit it and run `install` again to apply.

```sh
TARGET_DIR="$HOME/.cache/cargo-target"   # shared Cargo target directory
PROJECT_DIRS=("$HOME/Projects")          # where to look for worktrees and builds
NPM_IMPORT_METHOD="clone"                # clone (APFS), hardlink (Linux), or copy
SWEEP_DAYS=10                            # remove cargo artifacts older than this
NM_DAYS=30                               # remove node_modules untouched this long
WORKTREE_DAYS=14                         # remove idle agent worktrees after this
RUN_WEEKDAY=0; RUN_HOUR=3; RUN_MINUTE=0  # weekly schedule (0 is Sunday)
```

It refuses to run if `PROJECT_DIRS` points at your home directory or `/`.

## Completions and man page

Homebrew installs bash, zsh, and fish completions and a man page. After that:

```sh
man disk-janitor
disk-janitor <Tab>
```

The `install.sh` script sets these up too, on a best-effort basis, under `~/.local/share`.

## What it never removes

Your source code, and your agent chat history: `~/.claude/projects`, `~/.codex/sessions`, and
the like. Only build artifacts and abandoned worktree checkouts get cleaned.

## Platforms

Built and tested on macOS (Apple Silicon). Linux support (a systemd user timer or cron, plus
hardlink dedup) is in place but less tested; reports and patches are welcome. Needs bash 3.2 or
newer, git, and optionally cargo/cargo-sweep and pnpm.

## Troubleshooting

After `brew upgrade disk-janitor`, run `disk-janitor install` once. The scheduled job runs a copy
of the script under `~/.disk-janitor`, and re-running install refreshes that copy.

If Login Items lists a leftover "bash" entry, it's from an older version that scheduled the job as
`/bin/bash`. Current versions run the script directly, so you can remove the old entry.

## How the schedule works

macOS uses a launchd agent at `~/Library/LaunchAgents/disk-janitor.plist`. Linux uses a systemd
user timer, or a crontab entry if systemd isn't available.

## License

[MIT](LICENSE).
