------------------------------ MODULE Jobs ------------------------------
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS JobCount, DiskCapacity, DiskReserve, MemoryCapacity,
          MaxRetries, Restartable, AuthorizedExecutor,
          BadAdmission, BadReplay, BadRelease, BadProof

Jobs == 1..JobCount
ApprovedCaches == {"cargo-generated-unit", "gradle-build-unit", "xcode-derived-data"}
Protected == {"source", "credentials", "database", "unique-job-artifact"}
Terminal == {"succeeded", "failed", "cancelled", "unknown"}
States == {"fresh", "queued", "running", "cancelling"} \cup Terminal
Disk(j) == IF j = 1 THEN 2 ELSE 1
Memory(j) == 1

VARIABLES state, attempts, aged, outcome, lostAt, proven, deleted, fence, pendingProof, lateResolved
vars == <<state, attempts, aged, outcome, lostAt, proven, deleted, fence, pendingProof, lateResolved>>

RECURSIVE TotalDisk(_), TotalMemory(_)
TotalDisk(js) == IF js = {} THEN 0 ELSE
    LET j == CHOOSE x \in js: TRUE IN Disk(j) + TotalDisk(js \ {j})
TotalMemory(js) == IF js = {} THEN 0 ELSE
    LET j == CHOOSE x \in js: TRUE IN Memory(j) + TotalMemory(js \ {j})

Queued == {j \in Jobs: state[j] = "queued"}
Held == {j \in Jobs: state[j] \in {"running", "cancelling"}}
RemainingCaches == ApprovedCaches \ deleted
PhysicalFree == DiskCapacity - Cardinality(RemainingCaches)
AdmissionHeld == IF BadRelease THEN {j \in Jobs: state[j] = "running"} ELSE Held
Fits(j) == /\ TotalDisk(AdmissionHeld) + Disk(j) + DiskReserve <= PhysicalFree
           /\ TotalMemory(Held) + Memory(j) <= MemoryCapacity
FitsAlone(j) == /\ Disk(j) + DiskReserve <= DiskCapacity
                /\ Memory(j) <= MemoryCapacity
AgedQueued == Queued \cap aged
Oldest(js) == CHOOSE j \in js: \A k \in js: j <= k
Eligible == IF AgedQueued # {} THEN
               {j \in AgedQueued: j = Oldest(AgedQueued) /\ Fits(j)}
            ELSE {j \in Queued: Fits(j)}
Pressure == /\ Queued # {}
            /\ RemainingCaches # {}
            /\ \E j \in Queued: ~Fits(j)

Init == /\ state = [j \in Jobs |-> "fresh"]
        /\ attempts = [j \in Jobs |-> 0]
        /\ aged = {}
        /\ outcome = [j \in Jobs |-> "none"]
        /\ lostAt = [j \in Jobs |-> 0]
        /\ proven = {}
        /\ deleted = {}
        /\ fence = FALSE
        /\ pendingProof = {}
        /\ lateResolved = {}

\* j is a fresh UUID abstracted to its monotone acceptance-order key. Every
\* submission is distinct even if argv is identical. No command contents run here.
Submit(j) == /\ state[j] = "fresh"
             /\ \A k \in Jobs: k < j => state[k] # "fresh"
             /\ state' = [state EXCEPT ![j] = "queued"]
             /\ UNCHANGED <<attempts, aged, outcome, lostAt, proven, deleted, fence, pendingProof, lateResolved>>

Age(j) == /\ state[j] = "queued" /\ j \notin aged
          /\ aged' = aged \cup {j}
          /\ UNCHANGED <<state, attempts, outcome, lostAt, proven, deleted, fence, pendingProof, lateResolved>>

\* Measurement, choice and reservation publication are one mutex action.
\* BadAdmission deliberately omits other jobs' pending write commitments.
Admit(j) == /\ AuthorizedExecutor /\ ~fence /\ state[j] = "queued"
            /\ IF BadAdmission
                  THEN /\ Disk(j) + DiskReserve <= PhysicalFree
                       /\ TotalMemory(Held) + Memory(j) <= MemoryCapacity
                  ELSE j \in Eligible
            /\ state' = [state EXCEPT ![j] = "running"]
            /\ attempts' = [attempts EXCEPT ![j] = @ + 1]
            /\ aged' = aged \ {j}
            /\ UNCHANGED <<outcome, lostAt, proven, deleted, fence, pendingProof, lateResolved>>

Finish(j, result) == /\ state[j] = "running"
                     /\ result \in {"succeeded", "failed"}
                     /\ state' = [state EXCEPT ![j] = "cancelling"]
                     /\ outcome' = [outcome EXCEPT ![j] = result]
                     /\ proven' = IF BadProof THEN proven ELSE proven \cup {j}
                     /\ UNCHANGED <<attempts, aged, lostAt, deleted, fence, pendingProof, lateResolved>>

CancelQueued(j) == /\ state[j] = "queued"
                   /\ state' = [state EXCEPT ![j] = "cancelled"]
                   /\ aged' = aged \ {j}
                   /\ UNCHANGED <<attempts, outcome, lostAt, proven, deleted, fence, pendingProof, lateResolved>>
CancelRunning(j) == /\ state[j] = "running"
                    /\ state' = [state EXCEPT ![j] = "cancelling"]
                    /\ outcome' = [outcome EXCEPT ![j] = "cancelled"]
                    /\ UNCHANGED <<attempts, aged, lostAt, proven, deleted, fence, pendingProof, lateResolved>>

\* A guardian/receipt failure is not evidence of success or permission to replay.
LoseProof(j) == /\ state[j] = "running"
                /\ state' = [state EXCEPT ![j] = "cancelling"]
                /\ outcome' = [outcome EXCEPT ![j] = "unknown"]
                /\ lostAt' = [lostAt EXCEPT ![j] = attempts[j]]
                /\ UNCHANGED <<attempts, aged, proven, deleted, fence, pendingProof, lateResolved>>

\* An evidence gap is an observation, not proof of completion or permission
\* to replay. A matching authoritative receipt may arrive after verified drain.
DelayProof(j) == /\ state[j] = "running"
                 /\ state' = [state EXCEPT ![j] = "cancelling"]
                 /\ outcome' = [outcome EXCEPT ![j] = "unknown"]
                 /\ pendingProof' = pendingProof \cup {j}
                 /\ UNCHANGED <<attempts, aged, lostAt, proven, deleted, fence, lateResolved>>
LateReceipt(j, result) == /\ state[j] = "unknown" /\ j \in pendingProof
                          /\ result \in {"succeeded", "failed", "cancelled"}
                          /\ state' = [state EXCEPT ![j] = result]
                          /\ proven' = proven \cup {j}
                          /\ pendingProof' = pendingProof \ {j}
                          /\ lateResolved' = lateResolved \cup {j}
                          /\ UNCHANGED <<attempts, aged, outcome, lostAt, deleted, fence>>

\* Only the legacy explicit disposable-job contract may cooperatively retry.
\* It is a request: reservation stays held until verified owned-group teardown.
Yield(j) == /\ state[j] = "running" /\ j \in Restartable
            /\ attempts[j] <= MaxRetries /\ lostAt[j] = 0
            /\ state' = [state EXCEPT ![j] = "cancelling"]
            /\ outcome' = [outcome EXCEPT ![j] = "queued"]
            /\ UNCHANGED <<attempts, aged, lostAt, proven, deleted, fence, pendingProof, lateResolved>>

\* Abstracts verified teardown of the owned group and release/remeasurement of
\* finite resource holdings. Observers never execute a stored command.
Teardown(j) == /\ state[j] = "cancelling"
               /\ state' = [state EXCEPT ![j] = outcome[j]]
               /\ outcome' = [outcome EXCEPT ![j] = "none"]
               /\ UNCHANGED <<attempts, aged, lostAt, proven, deleted, fence, pendingProof, lateResolved>>

RequestMaintenance == /\ ~fence /\ Pressure
                      /\ fence' = TRUE
                      /\ UNCHANGED <<state, attempts, aged, outcome, lostAt, proven, deleted, pendingProof, lateResolved>>
\* Global drain is intentionally conservative: no active cache consumer survives.
Recover == /\ fence /\ Held = {} /\ RemainingCaches # {}
           /\ \E reclaimed \in SUBSET RemainingCaches:
                 /\ reclaimed # {}
                 /\ deleted' = deleted \cup reclaimed
           /\ fence' = FALSE
           /\ UNCHANGED <<state, attempts, aged, outcome, lostAt, proven, pendingProof, lateResolved>>

UnsafeReplay(j) == /\ BadReplay /\ state[j] = "unknown" /\ ~fence
                   /\ Fits(j)
                   /\ state' = [state EXCEPT ![j] = "running"]
                   /\ attempts' = [attempts EXCEPT ![j] = @ + 1]
                   /\ UNCHANGED <<aged, outcome, lostAt, proven, deleted, fence, pendingProof, lateResolved>>

JobStep(j) == \/ Submit(j) \/ Age(j) \/ Admit(j)
              \/ (\E r \in {"succeeded", "failed"}: Finish(j, r))
              \/ CancelQueued(j) \/ CancelRunning(j) \/ LoseProof(j) \/ DelayProof(j)
              \/ (\E r \in {"succeeded", "failed", "cancelled"}: LateReceipt(j, r))
              \/ Yield(j) \/ Teardown(j) \/ UnsafeReplay(j)
Next == (\E j \in Jobs: JobStep(j)) \/ RequestMaintenance \/ Recover

SafetySpec == Init /\ [][Next]_vars
\* Fair execution and finite resource holding are explicit hypotheses, not claims
\* about arbitrary programs. Fairness on Stop permits failure or Unknown outcomes.
Stop(j) == (\E r \in {"succeeded", "failed"}: Finish(j, r))
           \/ CancelRunning(j) \/ LoseProof(j) \/ DelayProof(j) \/ Yield(j)
Spec == /\ SafetySpec
        /\ WF_vars(RequestMaintenance) /\ WF_vars(Recover)
        /\ \A j \in Jobs: /\ WF_vars(Submit(j)) /\ WF_vars(Age(j))
                           /\ WF_vars(Admit(j)) /\ WF_vars(Stop(j))
                           /\ WF_vars(Teardown(j))

TypeOK == /\ state \in [Jobs -> States]
          /\ attempts \in [Jobs -> 0..(MaxRetries + 2)]
          /\ aged \subseteq Jobs
          /\ outcome \in [Jobs -> ({"none", "queued"} \cup Terminal)]
          /\ lostAt \in [Jobs -> 0..(MaxRetries + 1)]
          /\ proven \subseteq Jobs
          /\ deleted \subseteq (ApprovedCaches \cup Protected)
          /\ fence \in BOOLEAN
          /\ pendingProof \subseteq Jobs
          /\ lateResolved \subseteq proven
ResourceSafe == /\ TotalDisk(Held) + DiskReserve <= PhysicalFree
                /\ TotalMemory(Held) <= MemoryCapacity
NoProtectedDeletion == deleted \cap Protected = {}
NoArbitraryReplay == \A j \in Jobs \ Restartable: attempts[j] <= 1
PendingProofSafe == \A j \in pendingProof:
    /\ state[j] \in {"cancelling", "unknown"}
    /\ j \notin proven /\ lostAt[j] = 0
NoUnknownReplay == \A j \in Jobs: lostAt[j] > 0 => attempts[j] = lostAt[j]
NoUnknownSuccess == \A j \in Jobs: lostAt[j] > 0 => state[j] # "succeeded"
BoundedRetries == \A j \in Jobs: attempts[j] <= MaxRetries + 1
SuccessHasProof == \A j \in Jobs: state[j] = "succeeded" => j \in proven
NoLaunchBeforeSubmit == \A j \in Jobs: state[j] = "fresh" => attempts[j] = 0
HoldsUntilTeardown == \A j \in Jobs:
    state[j] = "cancelling" => outcome[j] \in ({"queued"} \cup Terminal)
WorkConserving == (~fence /\ AuthorizedExecutor /\ Eligible # {}) =>
    (\E j \in Jobs: ENABLED Admit(j))
NoAdmissionUnderFence == [][fence => attempts' = attempts]_vars
CleanupDrained == [][deleted' # deleted => (fence /\ Held = {})]_vars
AgeReservation == [][\A j \in Jobs:
    (attempts'[j] > attempts[j] /\ AgedQueued # {}) => j = Oldest(AgedQueued)]_vars
\* Negated reachability witnesses: expected counterexamples establish that
\* checking safety is not vacuous about throughput or late receipt resolution.
NeverThreeConcurrent == Cardinality(Held) < 3
NeverLateResolved == lateResolved = {}
\* The four-job scenario expands concurrency while bounding outcome combinations:
\* job 1 keeps every failure path; the three younger jobs complete successfully.
FourJobScenario == \A j \in Jobs \ {1}:
    /\ state[j] \notin {"failed", "cancelled", "unknown"}
    /\ outcome[j] \notin {"failed", "cancelled", "unknown"}
NoUnknownObservationReplay == [][\A j \in Jobs:
    state[j] = "unknown" => attempts'[j] = attempts[j]]_vars
AllSettle == \A j \in Jobs: <>(state[j] \in Terminal)
QueuedProgress == \A j \in Jobs: (state[j] = "queued") ~> (state[j] # "queued")
MaintenanceProgress == fence ~> ~fence
=============================================================================
