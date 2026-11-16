# Complete the managed build lifecycle

Willie explicitly requested implementation of the five remaining areas and opted out of further design questions. Continue the single existing admission authority, the user's source/data exclusions and submission permission context. This design records implementation decisions, not additional user approvals.

## Approach

Extend the installed Python/Bash guard and durable job protocol. Do not introduce a second command-execution daemon or infer exactly-once external effects. Transparent, synchronous PATH shims cover ordinary build tool invocations and join only a genuinely held guard in their process ancestry. They preserve foreground streams and do not intercept shells, Python or arbitrary commands. Explicit paths and unmanaged environments remain visible coverage limits. The root-owned RunnerPools scheduler needs a reviewed adapter at its VM resource-lifetime boundary, not a nested reservation inside a guest; source availability alone does not establish installation.

## Capacity and recovery

Learn bounded, private command/workspace estimates from attributable artifact allocation, with conservative cold starts. Record actual filesystem pressure separately from attribution. A controller outside the owned command's process group can freeze that group at reserve pressure, retain its execution identity, request the existing authorized reclamation and resume after capacity and fences permit. No automatic termination or replay of arbitrary nonrestartable work; only the previously authorized explicitly restartable scheduler contract permits bounded preemption/retry. Sampling is not a kernel quota and cannot control group escapes or unrelated writers.

Write command completion proof durably before frontend handoff, validate owner/command identity, and reconcile surviving evidence without replay. A worker may replace a failed prelaunch guardian only while retaining the original permission context and proving no execution commitment, live lease or outcome. Total evidence/executor loss remains an honest unknown outcome. Stronger claims require an external idempotency/transaction contract rather than an agent guess.

## Ownership and evidence

Route all ten historical failures as evidence-only notices to the three original owners under the user's new direct instruction. Preserve the LogDate/runner no-run/no-poll/no-requeue restriction. Archived routing may require reversible restoration; do not restart implementation or historical jobs. Record each exact send and outcome, and restore archive status after acknowledgement.

## Verification and delivery

Use disposable homes and actual child processes for runtime, streams, pressure, cancellation and crash tests. Exercise Linux in an isolated container without home/secrets mounts or changes to existing containers. Extend TLA+/TLC with late outcome reconciliation and relevant negative controls, report bounds/fairness/capacity/executor assumptions, and distinguish protocol checking from complete implementation/OS refinement. Verify the combined suite, installation roundtrip, live public workflow and managed PATH resolution. Deploy only reviewed files atomically with backup and compare checksums; preserve pre-existing dirty work and Git index. Protected runner runtime installation must use its supported reviewed maintenance procedure rather than invalidate integrity receipts.
