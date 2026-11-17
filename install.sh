#!/usr/bin/env bash
# Bootstrap installer: copy the CLI onto your PATH and run `disk-janitor install`.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# Install the complete runtime through its atomic publisher before exposing the
# canonical command. Never copy individual live helper modules here.
"$here/bin/disk-janitor" install "$@"

# Best-effort: man page + shell completions (Homebrew handles these automatically).
share="${XDG_DATA_HOME:-$HOME/.local/share}"
mkdir -p "$share/man/man1" && install -m 0644 "$here/man/disk-janitor.1" "$share/man/man1/disk-janitor.1" 2>/dev/null && echo "Installed man page"
mkdir -p "$share/bash-completion/completions" && install -m 0644 "$here/completions/disk-janitor.bash" "$share/bash-completion/completions/disk-janitor" 2>/dev/null
mkdir -p "$share/zsh/site-functions"          && install -m 0644 "$here/completions/disk-janitor.zsh"  "$share/zsh/site-functions/_disk-janitor" 2>/dev/null
mkdir -p "$HOME/.config/fish/completions"      && install -m 0644 "$here/completions/disk-janitor.fish" "$HOME/.config/fish/completions/disk-janitor.fish" 2>/dev/null
echo "Installed shell completions (bash/zsh/fish)"

