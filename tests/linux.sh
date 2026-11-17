#!/usr/bin/env bash
# Run from an isolated source copy; installation tests use disposable homes.
set -euo pipefail
cd "$(dirname "$0")/.."
test "$(uname -s)" = Linux
mkdir -p evidence
uname -sm
id
python3 --version
bash --version | head -n 1
shellcheck --version
shellcheck bin/disk-janitor install.sh tests/linux.sh tests/run.sh
bash tests/run.sh
python3 -m unittest discover -s tests -v
