#!/usr/bin/env bats
# install -> uninstall round-trip in a throwaway HOME. No scheduler activation,
# no touching the real machine.

setup() {
  REPO="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
  SB="$(mktemp -d)"
  mkdir -p "$SB/.codex"
  printf 'existing codex guidance\n' > "$SB/.codex/AGENTS.md"
  printf 'prefer-frozen-lockfile=true\n' > "$SB/.npmrc"   # pre-existing, must be restored
}

teardown() { rm -rf "$SB"; }

dj() {
  env -i HOME="$SB" PATH="$PATH" DISK_JANITOR_HOME="$SB/.dj" \
      DISK_JANITOR_NO_SCHED=1 TERM=dumb bash "$REPO/bin/disk-janitor" "$@"
}

@test "version prints" {
  run dj version
  [ "$status" -eq 0 ]
  [[ "$output" == *"disk-janitor v"* ]]
}

@test "install configures dedup, symlink, and scheduler state" {
  run dj install --with-agent-guidance
  [ "$status" -eq 0 ]
  grep -q 'managed-by: disk-janitor' "$SB/.cargo/config.toml"
  grep -q 'package-import-method=' "$SB/.npmrc"
  [ -f "$SB/.dj/state/backups/npmrc" ]              # original npmrc backed up
  grep -q 'disk-janitor:worktrees' "$SB/.codex/AGENTS.md"
  [ -L "$SB/.local/bin/disk-janitor" ]
  [ -f "$SB/.dj/state/scheduler" ]
}

@test "uninstall reverts everything cleanly" {
  dj install --with-agent-guidance
  run dj uninstall
  [ "$status" -eq 0 ]
  [ ! -e "$SB/.cargo/config.toml" ]                 # we created it -> removed
  grep -q 'prefer-frozen-lockfile=true' "$SB/.npmrc" # original restored
  ! grep -q 'disk-janitor:worktrees' "$SB/.codex/AGENTS.md"
  grep -q 'existing codex guidance' "$SB/.codex/AGENTS.md"
  [ ! -e "$SB/.local/bin/disk-janitor" ]
  [ ! -e "$SB/.dj/state/scheduler" ]
}

@test "run --dry-run deletes nothing" {
  mkdir -p "$SB/Projects/demo"
  run dj run --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"[dry-run]"* ]]
}
