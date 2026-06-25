#!/usr/bin/env bash
# No-bats fallback test runner: same round-trip assertions as roundtrip.bats.
set -uo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
SB="$(mktemp -d)"
mkdir -p "$SB/.codex"
printf 'existing codex guidance\n' > "$SB/.codex/AGENTS.md"
printf 'prefer-frozen-lockfile=true\n' > "$SB/.npmrc"
dj() { env -i HOME="$SB" PATH="$PATH" DISK_JANITOR_HOME="$SB/.dj" DISK_JANITOR_NO_SCHED=1 TERM=dumb bash "$REPO/bin/disk-janitor" "$@"; }

fail=0
check() { if eval "$2"; then printf '  ✓ %s\n' "$1"; else printf '  ✗ %s\n' "$1"; fail=1; fi; }

dj install --with-agent-guidance >/dev/null 2>&1
echo "after install:"
check "cargo config written"   "grep -q 'managed-by: disk-janitor' '$SB/.cargo/config.toml'"
check "npmrc set"              "grep -q 'package-import-method=' '$SB/.npmrc'"
check "original npmrc backed up" "[ -f '$SB/.dj/state/backups/npmrc' ]"
check "guidance block added"   "grep -q 'disk-janitor:worktrees' '$SB/.codex/AGENTS.md'"
check "PATH symlink created"   "[ -L '$SB/.local/bin/disk-janitor' ]"
check "scheduler state saved"  "[ -f '$SB/.dj/state/scheduler' ]"

dj uninstall >/dev/null 2>&1
echo "after uninstall:"
check "cargo config removed"   "[ ! -e '$SB/.cargo/config.toml' ]"
check "original npmrc restored" "grep -q 'prefer-frozen-lockfile=true' '$SB/.npmrc'"
check "guidance block removed"  "! grep -q 'disk-janitor:worktrees' '$SB/.codex/AGENTS.md'"
check "original guidance intact" "grep -q 'existing codex guidance' '$SB/.codex/AGENTS.md'"
check "symlink removed"        "[ ! -e '$SB/.local/bin/disk-janitor' ]"

rm -r "$SB"
[ "$fail" -eq 0 ] && echo "ALL PASS" || { echo "FAILURES"; exit 1; }
