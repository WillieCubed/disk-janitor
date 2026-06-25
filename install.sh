#!/usr/bin/env bash
# Bootstrap installer: copy the CLI onto your PATH and run `disk-janitor install`.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
dest="$HOME/.local/bin"
mkdir -p "$dest"
install -m 0755 "$here/bin/disk-janitor" "$dest/disk-janitor"
echo "Installed $dest/disk-janitor"
case ":$PATH:" in
  *":$dest:"*) ;;
  *) echo "NOTE: $dest is not on your PATH. Add it, e.g.:  export PATH=\"$dest:\$PATH\"" ;;
esac
exec "$dest/disk-janitor" install "$@"
