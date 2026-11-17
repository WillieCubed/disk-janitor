# Bounded verification of durable jobs

`Jobs.tla` is a deliberately small abstract protocol model, checked with TLC.
It is not a proof of arbitrary submitted programs, the operating system, or a
complete refinement proof of the Python/Bash implementation.

## Protocol and assumptions

Each submission has a fresh identity, abstracted as its acceptance-order integer.
The same identity is the durable backend identity throughout its lifecycle.
Identical commands remain different submissions. UUID collision resistance,
private atomic durable metadata, file-lock mutual exclusion, truthful identity
and receipt validation, and sandbox inheritance are implementation assumptions;
the model does not verify filesystem or OS implementations of those primitives.

`fresh` is an internal pre-submission state. The public states are `queued`,
`running`, `cancelling`, `succeeded`, `failed`, `cancelled`, and `unknown`.
Admission atomically measures physical capacity, selects eligible work and
publishes commitments under the existing admission mutex. Local jobs have no
second scheduler daemon, CPU reservation or arbitrary job-count cap. All fitting queued
jobs are eligible before age reservation. Once a job ages, the oldest aged job
reserves the next opportunity; incompatible new admissions drain until it fits.
Age is abstracted to a fair threshold crossing, not a wall-clock timer.

Disk is a single fixed, mounted filesystem measured in abstract units, with
truthful finite full-job upper bounds. Memory has independently checked finite
commitments. The model conservatively charges each active job's whole budget
until verified owned-group teardown. It does not model writes byte by byte,
multiple mounts, pending-write debt after a crash, permanent retained growth,
mount substitution, symlink races or adversarial unrelated writers. Those need
runtime checks and fault tests. `PhysicalFree` abstracts the measured capacity
before these finite job holdings and after accounting for the remaining caches.
Resource holdings are released/reconciled at `Teardown`, an explicit finite
holding assumption. Unique retained outputs are protected, never automatic
cleanup candidates, and are not assumed to disappear in the real system.
External brokers that share admission through docs/admission-protocol.md, and
executable PATH shims, are not modeled here; disposable tests check those
boundaries separately. Neither those tests nor this model establish end-to-end
refinement across the broker and native operating-system services.

Only inactive proven Cargo-generated units (incremental plus dependency objects),
Gradle task/transform build-cache and Xcode DerivedData output
can be recovered. Pressure requests a maintenance fence; admission pauses and
all active consumers drain before cleanup. A recovery pass removes a nonempty subset of the finite approved cache-unit
inventory; remaining pressure may request another pass. Caches are never refilled
in this bounded model. The three model units are symbolic capacity chunks, not
a claim that a real category is removed in one OS operation. Protected source, credentials,
databases and unique job artifacts are represented by a disjoint protected set.
Recovery is assumed authorized and able to complete; the model abstracts its
ownership/process-use/path checks to this predicate and global drain.

`Finish` supplies trustworthy durable completion evidence. `LoseProof` represents
final unrecoverable loss of that evidence, leading through teardown to `unknown`;
it never supplies success. Observation never starts stored work. Public jobs are
nonrestartable. In the separate legacy configuration, only job 1 is explicitly
restartable, may yield at most twice, and can retry only after owned-group
teardown. Even that legacy job cannot retry after unknown outcome. `DelayProof` separately represents a provisional evidence gap: verified teardown
may expose `unknown`, and a matching authoritative `LateReceipt` may later resolve
it without increasing the launch count. This is distinct from `LoseProof`, whose
loss is final. No fairness assumption forces a delayed receipt to appear.

`Finish` abstracts the direct supervisor's durable `.outcome` followed by final
`.result` publication after owned-group teardown. Filesystem publication and
receipt identity validation remain runtime obligations. Admission and the first
command launch are one abstract action: a proven pre-command guard handoff retry
is an implementation stuttering step, not another abstract command launch. The
model does not establish that the worker's durable `execution_committed` marker,
controller leases, or prelaunch retry implementation refine that abstraction.

The Linux runtime capacity controller can stop and resume the same owned process
group when its kernel-assisted recovery contract is available. Other platforms
report pressure without assuming recoverable suspension.
This model instead assumes truthful fixed full-job bounds and finite holding; it
does not model sampled reserve overshoot, stop latency, dynamic predictions,
learning, hysteresis, Linux cgroups, or filesystem quotas. Runtime tests check the
controller separately. A sampled safety monitor is not a hard disk quota.

Conditional progress additionally assumes:

- An authorized executor remains available in the original permitted context.
- Fair CPU/scheduling lets submissions, age crossing, eligible admission,
  running-job stop, teardown, maintenance request and recovery eventually run.
- Every running command releases its finite resource holding (or can be stopped
  and its owned group verified gone); arbitrary infinite services are excluded.
- Sufficient simultaneous disk and memory capacity eventually exists for every
  individual job. Here the constants are stable and cache recovery provides it;
  this is stronger than capacity merely flickering for isolated instants.
- Only finitely many submissions and explicitly bounded retries occur in this
  model. The age policy is checked for these bounds, not proven for an infinite
  arrival stream.

Consequently progress means eventual terminal settlement, which includes failure,
cancellation and unknown. It does not promise command success. Queued work cannot
be treated as completed merely because it was accepted.

## Checked properties

State invariants: well-typed durable states, pending evidence and counters; disk reserve and memory
commitment safety; no protected deletion; at most one launch of an arbitrary job;
no replay after either provisional or final proof loss; no manufactured success; bounded legacy retries;
success requires completion evidence; no launch before submission; reservation
held throughout cancellation; a fitting eligible job has enabled admission.

Action safety: no admissions under the maintenance fence, cleanup requires the
fence and a fully drained active set, and admission respects the oldest aged
reservation. Fair conditional temporal properties: all submitted jobs eventually
settle, every queued job eventually leaves the queue, and maintenance eventually
leaves the fenced state. The work-conserving property establishes enabled
compatible admission, not a real-time utilization bound.

`tests/test_formal_conformance.py` checks the implementation boundary: three
identical submissions have distinct stable identities and are nonrestartable;
60 combinations of live/stale reservation, result and cancellation observations are checked twice
through both `view` and `list` without launching a command; wrong-owner and
wrong-command success receipts are rejected. Late authoritative receipts resolve
provisional unknown observations without executing commands, and stale terminal
metadata cannot override a held execution lease. Worker/guardian lifetime lease loss
settles unknown without observation launching commands. Explicit uncertain receipts remain
unknown even if their numeric exit code is zero. This is observational conformance,
not exhaustive implementation refinement or admission-race verification.

## Reproduction

The existing `tla2tools.jar` is TLC 2.19 (2024-08-08), SHA-256:

```
936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
```

`check.py` verifies that digest and runs cases sequentially. Each Java invocation
uses `-Xmx640m`, serial GC, the built-in `MemFPSet`, and at most two TLC workers. Its temporary state store
is removed afterward. The installed admission guard mediates the whole suite:

```sh
job=$(disk-janitor submit -- env JANITOR_FORMAL_JAVA="$(command -v java)" python3 formal/check.py)
disk-janitor logs "$job" -f
disk-janitor wait "$job"
```

Run from the repository root with Java 21 available. `MemFPSet` is explicit:
the bundled TLC 2.19 default `MSBDiskFPSet` reached the expanded three-job graph
but then failed its actual-fingerprint probability report with division by zero.
The independent in-memory run completed the same 72,139 distinct-state graph and
reported a nonzero actual-fingerprint bound. A tool exception is never accepted
as a positive result. Logs retain the chosen fingerprint implementation. Java/TLC are development
verification dependencies only; normal jobs and recovery do not require them.
The public submit interface selects resource policy. The runner exits zero only
when positive models pass and negative controls expose their expected defects.

## Matrix and limits

Positive configurations check three-job legacy safety and conditional liveness,
three-job public nonrestartable conditional liveness, and a four-job public safety
scenario. `FourJobScenario` retains all outcome paths for the oldest job while
restricting the three younger jobs to successful completion. It expands fitting
concurrency coverage without claiming all four-job outcome combinations. The
unconstrained four-job experiments were stopped for cost and are not passing
verification evidence.
Three-job configurations use disk capacity four/reserve one and memory three
(legacy) or two (public). The four-job configuration uses disk six/reserve one,
memory four and no retries. Only legacy job 1 may retry, at most twice.

The durable-job matrix contains 13 passing runner checks:

| Positive case | Generated / distinct states |
| --- | --- |
| Three-job legacy safety | 222089 / 72139 |
| Three-job legacy conditional liveness | 222089 / 72139 |
| Three-job public conditional liveness | 86645 / 27651 |
| Four-job constrained public safety | 109880 / 17524 |

All four positive cases exhausted their queues. Negative controls stop at their
expected counterexample; their state counts are not exhaustive graph sizes.

Deliberate mutations must expose admission without pending commitments,
reservation release during cancellation, replay after proof loss, and success
without completion proof. Missing executor, insufficient capacity, and absent
fairness must expose temporal counterexamples. Negated reachability invariants
must expose traces with three simultaneous compatible jobs and a late receipt
resolving a provisional unknown. Those two expected counterexamples are coverage
witnesses, not detected defects. They do not assert a utilization or latency bound.

`formal/results/last-run.json` records each completed matrix case with model and
configuration SHA-256 hashes and generated/distinct/remaining-state counts.
Individual logs retain full commands, fingerprints, collision estimates, traces
and tool/platform information. The runner requires positive completion markers
or the precise expected counterexample, and rejects tool failures. These are
bounded exhaustive graph checks subject to TLC fingerprint collision risk; they
are not unbounded mathematical proofs, infinite-arrival starvation proofs, hard
runtime capacity guarantees, or complete implementation refinement.

## Sampled pressure-controller model

`Pressure.tla` is a separate small protocol model of the monitor. It does not
assume the truthful full-job bounds used by `Jobs.ResourceSafe`. Its finite bounds
are one already-launched command, two arbitrary owned write bursts of one or two
units, two unrelated-group steps, free space zero through two, reserve one, one
maintenance pass, and at most one controller death. No arrival or retry stream is
represented. The unrelated group retains its running permission throughout normal
actions; its steps represent signal isolation, not a disk accounting model.

Linux permits suspension after an acknowledged installed parent-death contract.
Controller death wakes the direct supervisor into `thaw-wait`; it must acquire
the shared cache fence before forwarding CONT to the owned command group. Darwin
observes pressure without entering a suspended state. Positive invariants check
group isolation, one launch, no writes while paused, and the fence at every
transition back to running. Conditional progress after controller loss assumes
the live supervisor/handler executes, fair fence acquisition, and that the finite
authorized maintenance pass eventually releases its fence. An indefinitely held
external fence, OS/kernel failure, or lost supervisor is outside that claim.

The model abstracts stable owned process-group identity, installed signal-handler
semantics, descriptor lifetime, receipt publication, STOP acknowledgement and the
kernel parent-death operation. It is not a proof of libc/prctl, PID reuse safety,
signal delivery latency, real memory pressure or the Python implementation.
`tests/test_runtime_capacity.py` separately exercises owned-group isolation,
fence-aware thaw/cancellation, observation-only behavior and the Linux kernel
parent-death path using disposable real processes.

| Pressure case | Generated / distinct states | Expected result |
| --- | --- | --- |
| Linux kernel-assisted suspension | 358 / 162 | Pass, exhausted queue |
| Darwin observation only | 181 / 72 | Pass, exhausted queue |
| Unsafe suspension without parent-death recovery | 323 / 150 | Frozen-orphan temporal counterexample |
| Hard reserve despite arbitrary between-sample writes | 4 / 4 | Reserve counterexample |

Replay and unrelated-group signalling mutations also require invariant
counterexamples. The hard-reserve counterexample records a known impossibility
for this sampled design; it is not reported as a hard-capacity guarantee. A burst
may cross the reserve before the next sample, and controller-loss recovery can
restore execution without a live monitor. Hysteresis, adaptive estimates, multiple
filesystems, cache eligibility and broker transactions are outside this model.

The combined runner has 19 cases: 13 durable-job cases and these six
pressure cases. Its JSON records the selected model for each case. Negative-control
counts can vary with worker exploration order; only positive exhausted graphs are
reported as complete state-space counts.
