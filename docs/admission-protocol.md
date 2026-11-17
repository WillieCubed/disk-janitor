# Shared admission protocol

disk-janitor decides when a job may start from free slots, free disk space and
memory pressure. Some work on a machine is started by other programs: a
self-hosted CI runner pool, a VM host, a build farm agent. If disk-janitor cannot
see that work, it admits jobs into space the other program has already promised,
and the other program does the same in return.

The shared admission protocol lets such a program, a **provider**, take part in
admission without disk-janitor knowing anything about it. Everything is plain
files and one lock. No command is executed across the boundary, and no process
ID, environment variable or command line grants authority.

The reference implementation is [`bin/commitments.py`](../bin/commitments.py).
A provider may import it or implement the format below.

## Roles

- **disk-janitor** reads every provider's commitments and counts each one as a
  running job when it admits work. It publishes its own running jobs for
  providers to read.
- **A provider** publishes what it has committed to run, and before admitting new
  work it reads disk-janitor's running jobs under disk-janitor's admission lock.

With no provider registered, both sides admit independently, exactly as before.

## Registry

Providers live in one directory owned by the provider's privileged account
(normally root) and not writable by group or others:

| Platform | Registry |
| --- | --- |
| macOS | `/Library/Application Support/disk-janitor/providers/` |
| Linux | `/var/lib/disk-janitor/providers/` |

Each provider has its own subdirectory, named with lowercase letters, digits and
hyphens, starting with a letter and at most 32 characters. It holds two files,
both owned by the registry owner, mode `0644`, one hard link, at most 256 KiB.

### binding.json

Written once, when the provider is set up for one user's disk-janitor:

```json
{
  "version": 1,
  "provider": "ci-pool",
  "user_uid": 501,
  "guard_home": "/Users/example/.disk-janitor",
  "lock_identity": [16777230, 12345678]
}
```

`lock_identity` is the device and inode of `guard_home/admission.lock` at binding
time. If the lock file is later replaced, the binding no longer matches and the
provider becomes unavailable rather than silently unshared.

### commitments.json

Replaced atomically whenever the provider's committed work changes:

```json
{
  "version": 1,
  "provider": "ci-pool",
  "updated_at": 1763337600.0,
  "user_uid": 501,
  "lock_identity": [16777230, 12345678],
  "claims": [
    {
      "id": "linux/9f86d081884c7d659a2feaa0c55ad015",
      "label": "linux runner",
      "path": "/var/lib/ci-pool",
      "device": 16777230,
      "disk_bytes": 42949672960,
      "memory_bytes": 8589934592,
      "reserve_bytes": 21474836480
    }
  ]
}
```

| Field | Meaning |
| --- | --- |
| `id` | Unique within the provider; letters, digits and `._:/-`, at most 128 characters. |
| `label` | Shown to people in disk-janitor's status, at most 80 characters. |
| `path`, `device` | Where the work writes, and that filesystem's device number. |
| `disk_bytes` | Disk space the work may still use on that device. |
| `memory_bytes` | Memory the work holds. |
| `reserve_bytes` | Free space the provider keeps on that device. |

At most 256 claims. A commitment is durable, not a lease: an old snapshot keeps
its claims, because a stopped provider cannot start new work without updating
it. An empty `claims` list releases everything.

## Admission

**disk-janitor** counts every claim of every trustworthy provider as a running job
that holds one admission slot. One slot always stays open to local jobs, so
commitments a provider never withdrew cannot block disk-janitor completely.

**A provider** admits new work like this:

1. Take its own resource lock.
2. Take disk-janitor's lock: an exclusive `flock` on `guard_home/admission.lock`,
   after checking that the file still has the bound `lock_identity`.
3. Read disk-janitor's running jobs from `guard_home/guard-reservations/*.json`.
   A job counts when its `state` is `running` (and it has no
   `retention_unsettled`), or when it is `cancelled` without
   `cancellation_teardown_confirmed: true`. Each such job holds its `memory` and,
   for each entry of `volumes`, `budget` bytes plus `reserve` free bytes on that
   `device`.
4. Measure free space and decide.
5. Publish the updated `commitments.json` **before** starting the work it covers.
6. Release both locks.

Always take the locks in that order. disk-janitor takes only its own lock, so the
order cannot deadlock.

## Nested work

A provider sets `DISK_JANITOR_BROKER=<provider name>` in the environment of the
work it starts. disk-janitor refuses to submit a job from inside that
environment, because the provider has already admitted it; a second reservation
would count the same work twice.

## Failure handling

| State | Result |
| --- | --- |
| No registry, or no subdirectory for a provider | Independent admission. |
| Subdirectory without `binding.json` | That provider is unavailable: registration is incomplete. |
| Malformed, wrong owner, writable, replaced lock, wrong user, or `updated_at` in the future | That provider is unavailable. |
| Binding for another user | Ignored for this user. |

An unavailable provider's commitments are preserved, never treated as released.
disk-janitor reports the problem, keeps admitting with the claims of the other
providers, and never lets an unavailable provider block every slot.

## Setting up a provider

From the provider's privileged setup, with `commitments.py` importable:

```python
from commitments import Provider

pool = Provider('ci-pool')
pool.bind('/Users/example/.disk-janitor', user_uid=501)

with pool.transaction() as shared:
    if shared is None:
        ...  # not bound: admit independently
    else:
        running = shared.local_claims()
        ...  # decide using running jobs and measured free space
        shared.publish([...])  # before starting the work
```

`bind` writes `commitments.json` first and `binding.json` second, so a reader
never sees a binding without a snapshot. To unregister, remove the provider's
subdirectory.
