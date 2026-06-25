# Contributing

Thanks for your interest! disk-janitor is intentionally small — one bash script plus docs.

## Ground rules

- **POSIX-ish bash, 3.2 compatible.** It must run on stock macOS `/bin/bash` (3.2). No associative
  arrays, no `${var@Q}`, no `mapfile`/`readarray`.
- **`shellcheck` clean.** Run `shellcheck bin/disk-janitor install.sh` before sending a PR.
- **Never delete user data.** Only regenerable build artifacts and abandoned worktree *checkouts*.
  Source code and agent chat history (`~/.claude/projects`, `~/.codex/sessions`, …) are off-limits.
- **Every destructive path must be previewable** via `--dry-run`.

## Testing

```sh
shellcheck bin/disk-janitor install.sh
bats tests/roundtrip.bats          # or: ./tests/run.sh  (no bats required)
```

Tests run in a throwaway `HOME` with `DISK_JANITOR_NO_SCHED=1`, so they never modify your machine or
load a real scheduler.

## Especially welcome

- Linux testing (systemd/cron paths, `hardlink`/reflink dedup on btrfs/xfs).
- Support for other agent worktree layouts beyond `.claude/worktrees/agent-*`.
- Other package managers / build systems with the same per-worktree duplication problem.
