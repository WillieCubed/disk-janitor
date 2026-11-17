# disk-janitor

Submit work. The tool owns admission, queueing, capacity recovery and teardown.

```sh
job=$(disk-janitor submit -- pnpm test)
disk-janitor wait "$job"
disk-janitor logs "$job"
```

No disk estimates, owner labels, output-root setup, reserve exceptions or restartability flags are required.

## Job commands

| Command | Behavior |
| --- | --- |
| `submit -- COMMAND [ARGS...]` | Durably accept one distinct invocation and print its job ID. The worker inherits the submitting execution permissions, environment and working directory. |
| `status [JOB] [--json]` | List jobs and capacity, or inspect one outcome and its artifact path. |
| `logs JOB [-f]` | Read or follow the last 256 KiB of diagnostic output. Explicit command artifacts are retained separately. |
| `wait JOB` | Wait for terminal settlement and return its exit code. Interrupting the observer does not cancel work. |
| `cancel JOB` | Ask the owning guardian to cancel a job. Agent clients cannot cancel another agent's job. |

Every `submit` is new work, even if the command is identical. After losing a submit receipt, inspect `status` instead of blindly repeating the submission. A successful acceptance is not a successful command.

States are `queued`, `running`, `cancelling`, `succeeded`, `failed`, `cancelled`, and `unknown`. Unknown returns 125; cancelled returns 143. Other command exit codes are preserved, including known launch failures. Cancellation cannot undo external side effects that have already happened.

## Deterministic lifecycle

A private durable job record identifies each invocation. The existing guard remains the sole admission authority: there is no competing queue broker or privileged command-execution daemon. Permission-preserving workers submit to that shared state machine and retain the original execution context after the client exits. Stable backend IDs and held lifetime locks prevent a second worker or observer from replaying a running or uncertain job. Observers never execute stored commands.

A job waits for one thing only: a free slot. The number of slots follows the machine, one per four cores and per 16 GiB of memory, whichever is fewer (`MAX_RUNNING` overrides it), so builds stay fast instead of oversubscribing the CPU. Waiting is first come, first served, and `status` shows each queued job's position and how many slots are busy. A slot is a kernel lock held by the running job and a place in the queue is a locked ticket, so a crashed job or a stale record can never occupy either. Commands that plainly run no build tool, such as `git push` or a short script, take no slot and start at once. A job still waiting after an hour fails with that reason, and `status` flags a running job that has produced no output for two hours.

Disk is decided at the moment a job has its slot. With at least the floor free (`FLOOR_GIB`, 5 GiB by default) it starts. Below the floor, one recovery pass of a few seconds runs, and the job then starts or fails with the numbers: how much is free, how much is needed and how much the pass freed. A job never waits for disk, and a missing required mount is likewise an immediate failure with its reason. Nothing else delays or refuses a start. Other jobs' records, retention measurement, a recovery in progress and busy locks are not consulted; state that would once have paused admission is written to `admission-notices.log` and ignored. Estimates are recorded for the job's owner and are not held against other jobs.

Arbitrary submitted commands are nonrestartable. A tool name does not prove a build or test is free of external side effects. Existing explicitly registered disposable legacy jobs retain bounded cooperative retry; that policy is not an agent-supplied option on the job API. The original worker can replace a failed guardian only before a durable execution commitment and after proving no live execution lease or outcome exists. Command completion is captured durably before frontend handoff; matching surviving completion evidence can resolve an earlier unknown without another launch. Losing all trusted execution/outcome evidence settles Unknown rather than inventing success or replaying side effects.

Command/workspace observations are kept as bounded private hashes, not argument strings. Observed output and filesystem pressure can raise future estimates. Ordinary commands have no proven output confinement, so a small artifact directory does not justify reducing their write budget. Estimates remain predictions rather than OS-enforced quotas.

## Capacity recovery and outputs

Recovery is demand-driven. A watchdog runs every minute and, when less than the low-water mark is free (`LOW_WATER_GIB`, 30 GiB by default), reclaims authorized inactive output until that much is free again, so a starting job rarely meets its floor. A job that does meet its floor asks for the same recovery with its own floor and a time limit. Recovery remeasures physical free space after each batch and stops when the demand is met; no cleanup runs above the low-water mark. It never waits for running jobs and no job waits for it: each unit is removed only on proof that nothing is using it. Source, uncommitted work, credentials, databases, active output and unique job artifacts are preserved.

The watchdog also retires reservation records whose guardian and process group are gone, after making their outcome durable, and it treats a job left waiting beside a free slot as a fault: the oldest waiter is told to start.

Gradle `build` output directories inside git checkouts are reclaimed when the checkout is idle. A directory qualifies when it is named `build`, sits beside a Gradle build script, is not under `src` or `node_modules`, and holds nothing git tracks or would add. The checkout is idle when no process has its working directory or an open file inside it and no live submitted job runs there. Checkouts are found from the repositories under `PROJECT_DIRS` and their `git worktree` lists, wherever those worktrees live. A directory holding a keystore, key or database file is left alone.

Automatic reclamation also covers inactive Cargo incremental output and positively identified generated dependency object/archive/metadata files in proven shared Cargo profiles, Gradle local task cache and marked transform build-cache entries, and standard Xcode DerivedData. Exported binaries, root libraries and unmarked locations are preserved. Dependency downloads, disk images, source worktrees and other retained environments are excluded. Managed artifacts are exposed as `DISK_JANITOR_ARTIFACT_ROOT` and retained after completion; do not put unique deliverables into a disposable compiler cache. Existing shared Cargo output and pnpm clone linking remain in use.

Activity detection inspects actual executable identity and structured Java entrypoints; a queued guardian mentioning a future compiler is not a running compiler. Validated cache units are removed in bounded native batches, with fresh process/open-file and identity checks, per-batch pressure sampling and measured filesystem free-space reports. Protected content in one unit does not prevent unrelated eligible units from being reclaimed. Allocation totals are estimates; `filesystems` reports actual before/after availability, including concurrent writes and shared/clone storage effects.

The full weekly cleanup still requires that no job is running and skips itself otherwise. The tool does not kill protected work or delete user data to make room; when room cannot be made, the job that needed it fails with the numbers.

A live controller outside the owned command group monitors required filesystem reserves. On supported Linux systems it can pause that group under pressure, request authorized recovery, and resume the same processes after capacity returns. A native parent-death continuation prevents loss of the controller from stranding stopped work. Darwin monitors pressure without stopping nonrestartable work because it lacks that safe orphan-thaw mechanism. Status distinguishes pressure observation from pressure blocking, with its reason and start time. Cancellation observes the cache fence before resuming stopped processes for teardown. This is sampled cooperative protection: other writers, escaped descendants and stop latency can exceed a reserve. Loss of all safe live control evidence cannot authorize signalling a recycled PID, command replay or deletion of active output.

## Integration and setup

Run `./install.sh --with-agent-guidance` once. Runtime components are Python standard library, the existing Bash guard, and standard OS tools used for activity inspection. Normal agents use the five job commands; they do not manipulate private records, locks or scheduler policy.

Runtime installation stages a complete content-addressed release, verifies its ownership and checksums, and activates it with one atomic `current` symlink change. Previous releases and backups of the former installed regular files are retained. CLI/helper aliases share that pointer; shims resolve it once before executing a helper so later upgrades do not mix imported runtime modules. Redirected or modified installation state stops the update before activation.

Runtime releases are retained immutably and activated through one current-release pointer. A stable dispatcher resolves that pointer once and executes the complete physical release. Existing workers keep their original release; rollback does not reconstruct or repeat commands.

The installer creates scoped executable shims and adds a reversible PATH block to zsh and bash startup files. New shells automatically manage noninteractive `cargo`, `rustc`, `gradle`, `gradlew`, `xcodebuild`, `swift`, `swiftc`, `pnpm`, `npm`, `yarn`, `bun`, `make`, `gmake`, `cmake`, `ninja`, `pytest`, `py.test`, `tsc`, `vitest` and `jest` invocations. The shims preserve command arguments, working directory, environment, stdin, separate stdout/stderr and exit status through synchronous guard execution. Bare invocations appear in public job status and wait; their streams are delivered to the original caller and are not retained by logs. They retain artifacts in `DISK_JANITOR_ARTIFACT_ROOT`; detached submissions retain the normal bounded diagnostic log. No shell function, pre-execution trap, privileged executor or Python/shell override is installed.

A nested shim joins only its actual live managed process group, verified against a held owned guard lease and the runtime's bound private process-group record. An environment variable alone cannot authorize execution without admission. Work started by an external broker that shares admission through the [provider protocol](docs/admission-protocol.md) is marked with `DISK_JANITOR_BROKER` and is rejected instead of creating a second reservation; brokers whose writes do not traverse host tool shims, such as VM hosts, account for their own work through that protocol.

Terminal invocations pass directly to the original executable, preserving its controlling terminal and job control without claiming a managed reservation. Use detached submission for noninteractive workflows. PATH coverage applies in new shells after installation. Already running shells, explicit executable paths such as `./gradlew` or `/usr/bin/xcodebuild`, aliases/functions that select another executable, direct interpreter entrypoints and environments that replace PATH can bypass executable lookup. Use the normal `submit -- COMMAND` boundary for those workflows; the installer does not rewrite source launchers or override the shell. Noninteractive Bash only inherits its caller's PATH; zsh reads the managed `.zshenv` block. Uninstall removes only the managed blocks and generated shims, preserving later user edits and original startup-file backups. Symlinked startup files are preserved and stop shell setup before it writes startup files.

Existing `run` cleanup, `guard`, `admit`, `recover` and `reclaim` callers remain compatible during migration, but are not the normal agent interface.

The worker preserves the original sandbox/approval context. It does not reconstruct work under a more privileged daemon after a worker loss. A surviving owned guardian can still finish and publish its receipt; total executor/evidence loss becomes Unknown. Private state is not a security boundary against another process with the same OS user's unrestricted filesystem privileges.

## Verification

Run `python3 -m unittest discover -s tests -v`, `bash tests/run.sh`, and `shellcheck bin/disk-janitor install.sh`. Tests use disposable homes and real tiny child processes, including lost workers/guardians, cancellation, concurrency, inherited sandbox restrictions and pressure recovery.

`formal/Jobs.tla` specifies protocol safety and conditional liveness. TLC checks finite configurations and deliberate unsafe mutations; `formal/README.md` records exact bounds, assumptions, state counts and limits. These are bounded model checks plus runtime conformance tests, not an unbounded proof, a complete implementation refinement proof, or exactly-once external effects. Java/TLC are verification-only dependencies, not runtime requirements.

Source code is licensed under MIT; see LICENSE.
