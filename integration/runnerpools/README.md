# Shared local and CI admission

`bin/runnerpools_bridge.py` and the generated `reviewed-runtime` source implement
one admission transaction. The root broker holds its existing global resource
lock, then the bound owner's existing admission mutex. Local admission holds that
same mutex while reading root commitments, sampling physical free bytes and
committing its claim. Root admission reads bounded, validated local running
claims under the mutex. Waiting records are not counted as admitted work.

The broker publishes a sanitized durable commitment **before** committing a
creating generation journal. Generation transitions and preparation/execution
watchdogs refresh the snapshot. Confirmed idle cleanup releases its claim;
uncertain cleanup preserves it. No PID, environment variable or command identity
grants root authority, and the bridge executes no submitted command.

The bridge source is included as plain Python in the existing protected
`process_control.py` payload. The filename set is unchanged, preserving the
installer's exact before/after receipt and interrupted-update checks.

## Prepare and activate

The checked-in candidate is source, not deployment evidence. `prepare.py` copies
public Python source only; it never edits installed runtime or credentials.
It rejects changed integration anchors. For a fresh candidate with a complete
public operator package:

```sh
python3 integration/runnerpools/prepare.py \
  --source '/Library/Application Support/RunnerPools/studio' \
  --package "$HOME/.local/share/hypertext-studio/command/current" \
  --output /absolute/writable/fresh-candidate
```

Install the matching local CLI and `runnerpools_bridge.py` first. From that
candidate's complete package, use the supported full-profile operator path:

```sh
python3 /absolute/writable/fresh-candidate/package/skills/self-hosted-runner/scripts/runner_operator.py \
  --org TheHypertextStudio setup --apply --repair-runtime
```

This source-only repair retains supported integrity verification, all-slot quiescence and native
administrator handoff. It does not enroll repositories, change provider policy or
dispatch/retry CI. A busy, stale, drained or uncertain installation remains
preserved according to the existing installer. Native authorization can require
the operator's foreground Terminal.

The native hook discovers installed profiles through the existing strict
discovery API, verifies their complete runtime receipts, requires their identical
bridge source and idle journals, and derives the owner from the actual home UID
and `pwd` account record. It verifies the matching installed local module and
guard hook before publishing the root binding under both locks. Another bound
account cannot be silently replaced. There are no agent configuration flags.
The root reader verifies every immutable release component and canonical helper
alias, and checks the regular stable dispatcher against its reviewed hash pinned
in the protected broker source. It never imports the owner's installer or helpers.

The protected binding is
`/Library/Application Support/RunnerPoolsAdmission/config.json`; its sanitized
snapshot is `commitments.json` beside it. A completely absent binding directory
is explicitly legacy, independent admission. Once activation begins, malformed,
missing, replaced, future-dated or wrong-owner state blocks new admission and
preserves existing commitments. Snapshots are durable commitments, not leases:
old snapshots keep their claims, while empty snapshots still permit safe local
work. Every subsequent CI admission must commit under the same bound mutex.

## Verification

Submit `python3 -m unittest discover -s tests -p test_runnerpools_bridge.py -v`
through `disk-janitor submit -- ...`. Tests exercise the actual copied broker
and actual embedded local guard in disposable fixtures: both admission orders,
cross-process mutex contention, per-device claims, multiple profiles, journal
commit ordering, failed/successful cleanup, snapshot validation, legacy and
partial activation, and native provisioning fences. These establish the source
integration, not deployment or completed hosted CI.
