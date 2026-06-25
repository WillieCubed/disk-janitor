# disk-janitor

**AI coding agents spin up git worktrees — and each one silently re-duplicates your Rust
`target/` and `node_modules`.** Five agent worktrees of one monorepo can quietly eat hundreds of
gigabytes. `disk-janitor` stops the duplication *at the source* and sweeps the regenerable rest on a
schedule. It never touches your source code or your agent chat history.

A single, dependency-free bash script. macOS and Linux. Installs and uninstalls cleanly.

```
disk-janitor install      # configure dedup + schedule a weekly sweep
disk-janitor run --dry-run # see exactly what would be cleaned (deletes nothing)
disk-janitor status        # what's configured + current free space
disk-janitor uninstall     # reverse everything, cleanly
```

## The problem

Tools like Claude Code and Codex isolate work in **git worktrees**. Worktrees share git history but
**not** build outputs — so every worktree gets its own `target/` (often tens of GB of identical
compiled dependencies) and its own `node_modules`. The artifact churn is invisible until your disk
is at 95%.

Plenty of tools *clean* build artifacts after the fact ([kondo](https://github.com/tbillington/kondo),
[`cargo-sweep`](https://github.com/holmgr/cargo-sweep), [`npkill`](https://github.com/voidcosmos/npkill),
`cargo-cache`). disk-janitor's angle is **prevention plus agent-awareness**:

- **Shared Cargo target dir** — point every project/worktree at one `target-dir` so dependencies
  compile *once*, not per worktree.
- **pnpm store dedup** — set `package-import-method` to `clone` (APFS reflinks) on macOS or
  `hardlink` on Linux, so a worktree's `node_modules` is ~free instead of a multi-GB copy.
- **Scheduled sweep that knows about agents** — a weekly job runs `cargo-sweep`, prunes stale
  `node_modules`, prunes dangling git worktree metadata, and removes idle
  `**/.claude/worktrees/agent-*` checkouts.

## What it never touches

Source code, and **agent chat history / transcripts**: `~/.claude/projects`, `~/.codex/sessions`,
and friends. Only regenerable build artifacts and abandoned worktree *checkouts* are removed.

## Install

```sh
git clone https://github.com/REPLACE-ME/disk-janitor
cd disk-janitor
./install.sh           # copies bin/disk-janitor to ~/.local/bin and runs `install`
```

Or run the script directly: `bin/disk-janitor install`. Make sure `~/.local/bin` is on your `PATH`.

Opt into the agent-config guidance block (writes a short "don't override the shared target dir" note
into `~/.codex/AGENTS.md` / `~/.claude/CLAUDE.md` if present):

```sh
disk-janitor install --with-agent-guidance
```

## Usage

| Command | Description |
|---|---|
| `install [--with-agent-guidance] [--dry-run]` | configure dedup + schedule the weekly sweep |
| `run [--dry-run\|-n]` | run the cleanup now; `--dry-run` reports candidates and deletes nothing |
| `status` | show configuration + free space |
| `uninstall [--purge]` | revert everything; `--purge` also removes `cargo-sweep` and app state |
| `logs [-f]` | show / follow the run log |
| `config` | print the config file path and contents |

## Configuration

`install` writes `~/.disk-janitor/config.env`. Edit it and re-run `install` to apply:

```sh
TARGET_DIR="$HOME/.cache/cargo-target"   # shared Cargo target dir
PROJECT_DIRS=("$HOME/Projects")          # roots scanned for worktrees/builds
NPM_IMPORT_METHOD="clone"                # clone (APFS) | hardlink (Linux) | copy
SWEEP_DAYS=10                            # cargo artifacts older than this are swept
NM_DAYS=30                               # node_modules untouched this long are removed
WORKTREE_DAYS=14                         # idle agent worktree checkouts removed after this
RUN_WEEKDAY=0; RUN_HOUR=3; RUN_MINUTE=0  # weekly schedule (0=Sunday)
AGENT_GUIDANCE=0                         # 1 = manage the guidance block
```

disk-janitor refuses to operate if `PROJECT_DIRS` points at `$HOME` or `/`.

## Shell completions & man page

Installing via Homebrew sets up `bash`, `zsh`, and `fish` completions and a man page
automatically. With the `install.sh` bootstrap they're placed under `~/.local/share` (and
`~/.config/fish`) on a best-effort basis. Then:

```sh
man disk-janitor
disk-janitor <TAB>     # complete subcommands and flags
```

For zsh, ensure the completion dir is on your `fpath` (Homebrew's is by default).

## How it schedules

- **macOS** — a `launchd` user agent (`~/Library/LaunchAgents/disk-janitor.plist`).
- **Linux** — a `systemd` **user** timer, falling back to a `crontab` entry if systemd isn't available.

## Platform support

Developed and tested on macOS (Apple Silicon). Linux support (systemd/cron, hardlink dedup) is
implemented but less battle-tested — issues and PRs welcome. Requires `bash` 3.2+ (works with stock
macOS `/bin/bash`), `git`, and optionally `cargo`/`cargo-sweep` and `pnpm`.

## Safety

- `uninstall` restores any pre-existing `~/.cargo/config.toml` / `~/.npmrc` from backups, or removes
  the files if disk-janitor created them. State is tracked under `~/.disk-janitor/state`.
- Every destructive action is age-gated and previewable with `--dry-run`.

## License

MIT — see [LICENSE](LICENSE).
