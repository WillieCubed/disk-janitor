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

The machine chooses conservative disk and memory estimates, checks actual required filesystems and mount identity, and preserves the 20 GiB internal reserve. Declared external media retain their reserve. All fitting jobs may run concurrently; there is no job-count cap or fixed CPU reservation. An aged request reserves conflicting capacity so a stream of smaller jobs cannot starve it; independent backfill can continue. Estimates are admission commitments, not kernel-enforced I/O quotas: arbitrary commands and unrelated applications can exceed them.

Arbitrary submitted commands are nonrestartable. A tool name does not prove a build or test is free of external side effects. Existing explicitly registered disposable legacy jobs retain bounded cooperative retry; that policy is not an agent-supplied option on the job API. The original worker can replace a failed guardian only before a durable execution commitment and after proving no live execution lease or outcome exists. Command completion is captured durably before frontend handoff; matching surviving completion evidence can resolve an earlier unknown without another launch. Losing all trusted execution/outcome evidence settles Unknown rather than inventing success or replaying side effects.

Command/workspace observations are kept as bounded private hashes, not argument strings. Observed output and filesystem pressure can raise future estimates. Ordinary commands have no proven output confinement, so a small artifact directory does not justify reducing their write budget. Estimates remain predictions rather than OS-enforced quotas.

## Capacity recovery and outputs

Recovery is demand-driven. It considers the oldest live waiting request plus active remaining commitments, rather than summing all queued work. No cleanup runs when the disk demand fits. Under pressure, a short-lived maintenance fence lets finite active users drain, reclaims only authorized inactive output, remeasures physical free space, and stops when demand fits. This avoids hourly cache thrash. Source, uncommitted work, credentials, databases, active output and unique job artifacts are preserved.

Automatic reclamation covers inactive Cargo incremental output and positively identified generated dependency object/archive/metadata files in proven shared Cargo profiles, Gradle local task cache and marked transform build-cache entries, and standard Xcode DerivedData. Exported binaries, root libraries and unmarked locations are preserved. Dependency downloads, disk images, source worktrees and other retained environments are excluded. Managed artifacts are exposed as `DISK_JANITOR_ARTIFACT_ROOT` and retained after completion; do not put unique deliverables into a disposable compiler cache. Existing shared Cargo output and pnpm clone linking remain in use.

Activity detection inspects actual executable identity and structured Java entrypoints; a queued guardian mentioning a future compiler is not a running compiler. Validated cache units are removed in bounded native batches, with fresh process/open-file and identity checks, per-batch pressure sampling and measured filesystem free-space reports. Protected content in one unit does not prevent unrelated eligible units from being reclaimed. Allocation totals are estimates; `filesystems` reports actual before/after availability, including concurrent writes and shared/clone storage effects.

The conservative global cleanup fence protects legacy and unknown users. A permanently held service or unavailable capacity can therefore prevent reclamation or admission; the tool does not kill protected work or delete user data to manufacture liveness.

A live controller outside the owned command group monitors required filesystem reserves. On supported Linux systems it can pause that group under pressure, request authorized recovery, and resume the same processes after capacity returns. A native parent-death continuation prevents loss of the controller from stranding stopped work. Darwin monitors pressure without stopping nonrestartable work because it lacks that safe orphan-thaw mechanism. Status distinguishes pressure observation from pressure blocking, with its reason and start time. Cancellation observes the cache fence before resuming stopped processes for teardown. This is sampled cooperative protection: other writers, escaped descendants and stop latency can exceed a reserve. Loss of all safe live control evidence cannot authorize signalling a recycled PID, command replay or deletion of active output.

## Integration and setup

Run `./install.sh --with-agent-guidance` once. Runtime components are Python standard library, the existing Bash guard, and standard OS tools used for activity inspection. Normal agents use the five job commands; they do not manipulate private records, locks or scheduler policy.

Runtime installation stages a complete content-addressed release, verifies its ownership and checksums, and activates it with one atomic `current` symlink change. Previous releases and backups of the former installed regular files are retained. CLI/helper aliases share that pointer; shims resolve it once before executing a helper so later upgrades do not mix imported runtime modules. Redirected or modified installation state stops the update before activation.

Runtime releases are retained immutably and activated through one current-release pointer. A stable dispatcher resolves that pointer once and executes the complete physical release. Existing workers keep their original release; rollback does not reconstruct or repeat commands.

The installer creates scoped executable shims and adds a reversible PATH block to zsh and bash startup files. New shells automatically manage noninteractive `cargo`, `rustc`, `gradle`, `gradlew`, `xcodebuild`, `swift`, `swiftc`, `pnpm`, `npm`, `yarn`, `bun`, `make`, `gmake`, `cmake`, `ninja`, `pytest`, `py.test`, `tsc`, `vitest` and `jest` invocations. The shims preserve command arguments, working directory, environment, stdin, separate stdout/stderr and exit status through synchronous guard execution. Bare invocations appear in public job status and wait; their streams are delivered to the original caller and are not retained by logs. They retain artifacts in `DISK_JANITOR_ARTIFACT_ROOT`; detached submissions retain the normal bounded diagnostic log. No shell function, pre-execution trap, privileged executor or Python/shell override is installed.

A nested shim joins only its actual live managed process group, verified against a held owned guard lease and the runtime's bound private process-group record. An environment variable alone cannot authorize execution without admission. RunnerPools declarations without that verified scope are rejected instead of creating a second reservation; the host broker bridge is a separate integration because VM writes do not traverse host tool shims.

Terminal invocations pass directly to the original executable, preserving its controlling terminal and job control without claiming a managed reservation. Use detached submission for noninteractive workflows. PATH coverage applies in new shells after installation. Already running shells, explicit executable paths such as `./gradlew` or `/usr/bin/xcodebuild`, aliases/functions that select another executable, direct interpreter entrypoints and environments that replace PATH can bypass executable lookup. Use the normal `submit -- COMMAND` boundary for those workflows; the installer does not rewrite source launchers or override the shell. Noninteractive Bash only inherits its caller's PATH; zsh reads the managed `.zshenv` block. Uninstall removes only the managed blocks and generated shims, preserving later user edits and original startup-file backups. Symlinked startup files are preserved and stop shell setup before it writes startup files.

Existing `run` cleanup, `guard`, `admit`, `recover` and `reclaim` callers remain compatible during migration, but are not the normal agent interface.

The worker preserves the original sandbox/approval context. It does not reconstruct work under a more privileged daemon after a worker loss. A surviving owned guardian can still finish and publish its receipt; total executor/evidence loss becomes Unknown. Private state is not a security boundary against another process with the same OS user's unrestricted filesystem privileges.

## Verification

Run `python3 -m unittest discover -s tests -v`, `bash tests/run.sh`, and `shellcheck bin/disk-janitor install.sh`. Tests use disposable homes and real tiny child processes, including lost workers/guardians, cancellation, concurrency, inherited sandbox restrictions and pressure recovery.

`formal/Jobs.tla` specifies protocol safety and conditional liveness. TLC checks finite configurations and deliberate unsafe mutations; `formal/README.md` records exact bounds, assumptions, state counts and limits. These are bounded model checks plus runtime conformance tests, not an unbounded proof, a complete implementation refinement proof, or exactly-once external effects. Java/TLC are verification-only dependencies, not runtime requirements.

Source code is licensed under MIT; see LICENSE.
