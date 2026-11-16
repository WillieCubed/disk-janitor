---------------------------- MODULE Pressure ----------------------------
EXTENDS Naturals, TLC

CONSTANTS Platform, BadParentDeath, BadReplay, BadSignalOther
Reserve == 1
Modes == {"running", "paused", "thaw-wait", "done"}
VARIABLES mode, controllerAlive, fence, free, writes, unrelatedRunning,
          unrelatedWrites, launches, recovered, warning
vars == <<mode, controllerAlive, fence, free, writes, unrelatedRunning,
          unrelatedWrites, launches, recovered, warning>>

Init == /\ mode = "running" /\ controllerAlive = TRUE /\ fence = "owned"
        /\ free = 2 /\ writes = 0 /\ unrelatedRunning = TRUE
        /\ unrelatedWrites = 0 /\ launches = 1 /\ recovered = FALSE
        /\ warning = FALSE

\* Two finite arbitrary write bursts can cross the reserve between samples.
Write == /\ mode = "running" /\ writes < 2
         /\ \E amount \in 1..2:
               free' = IF amount <= free THEN free - amount ELSE 0
         /\ writes' = writes + 1
         /\ UNCHANGED <<mode, controllerAlive, fence, unrelatedRunning,
                       unrelatedWrites, launches, recovered, warning>>
UnrelatedWrite == /\ unrelatedRunning /\ unrelatedWrites < 2
                  /\ unrelatedWrites' = unrelatedWrites + 1
                  /\ UNCHANGED <<mode, controllerAlive, fence, free, writes,
                                unrelatedRunning, launches, recovered, warning>>

\* Linux suspension assumes the supervisor has acknowledged its installed kernel
\* parent-death contract. The negative control permits STOP without that contract.
\* On Darwin, pressure is observed; no recoverable suspension is assumed.
Sample == /\ controllerAlive /\ mode = "running" /\ free < Reserve
          /\ warning' = TRUE
          /\ mode' = IF Platform = "linux" THEN "paused" ELSE mode
          /\ fence' = IF Platform = "linux" THEN "free" ELSE fence
          /\ unrelatedRunning' = IF BadSignalOther THEN FALSE ELSE unrelatedRunning
          /\ UNCHANGED <<controllerAlive, free, writes, unrelatedWrites, launches, recovered>>

\* Kernel CONT wakes only the direct supervisor. Its handler first reacquires
\* the shared cache fence; only then may it forward CONT to the owned group.
ControllerDies == /\ controllerAlive
                  /\ controllerAlive' = FALSE
                  /\ mode' = IF mode = "paused" /\ Platform = "linux" /\ ~BadParentDeath
                              THEN "thaw-wait" ELSE mode
                  /\ UNCHANGED <<fence, free, writes, unrelatedRunning,
                                unrelatedWrites, launches, recovered, warning>>
Reacquire == /\ mode = "thaw-wait" /\ fence = "free"
             /\ mode' = "running" /\ fence' = "owned"
             /\ UNCHANGED <<controllerAlive, free, writes, unrelatedRunning,
                           unrelatedWrites, launches, recovered, warning>>
Resume == /\ controllerAlive /\ mode = "paused" /\ fence = "free" /\ free >= Reserve
          /\ mode' = "running" /\ fence' = "owned"
          /\ UNCHANGED <<controllerAlive, free, writes, unrelatedRunning,
                        unrelatedWrites, launches, recovered, warning>>

\* One finite maintenance pass abstracts an available authorized maintenance
\* executor. Releasing its fence eventually is a liveness assumption.
TakeMaintenance == /\ fence = "free" /\ mode \in {"paused", "thaw-wait"} /\ ~recovered
                   /\ fence' = "maintenance"
                   /\ UNCHANGED <<mode, controllerAlive, free, writes, unrelatedRunning,
                                 unrelatedWrites, launches, recovered, warning>>
Recover == /\ fence = "maintenance" /\ ~recovered
           /\ free' = 2 /\ recovered' = TRUE
           /\ UNCHANGED <<mode, controllerAlive, fence, writes, unrelatedRunning,
                         unrelatedWrites, launches, warning>>
ReleaseMaintenance == /\ fence = "maintenance" /\ recovered
                      /\ fence' = "free"
                      /\ UNCHANGED <<mode, controllerAlive, free, writes, unrelatedRunning,
                                    unrelatedWrites, launches, recovered, warning>>
Finish == /\ mode = "running" /\ mode' = "done" /\ fence' = "free"
          /\ UNCHANGED <<controllerAlive, free, writes, unrelatedRunning,
                        unrelatedWrites, launches, recovered, warning>>
Replay == /\ BadReplay /\ ~controllerAlive /\ mode \in {"paused", "thaw-wait"} /\ launches = 1
          /\ launches' = 2
          /\ UNCHANGED <<mode, controllerAlive, fence, free, writes,
                        unrelatedRunning, unrelatedWrites, recovered, warning>>

Next == Write \/ UnrelatedWrite \/ Sample \/ ControllerDies \/ Reacquire \/ Resume
        \/ TakeMaintenance \/ Recover \/ ReleaseMaintenance \/ Finish \/ Replay
SafetySpec == Init /\ [][Next]_vars
Spec == /\ SafetySpec /\ WF_vars(Reacquire) /\ WF_vars(TakeMaintenance)
        /\ WF_vars(Recover) /\ WF_vars(ReleaseMaintenance)

TypeOK == /\ mode \in Modes /\ controllerAlive \in BOOLEAN
          /\ fence \in {"owned", "free", "maintenance"} /\ free \in 0..2
          /\ writes \in 0..2 /\ unrelatedWrites \in 0..2
          /\ unrelatedRunning \in BOOLEAN /\ launches \in 1..2
          /\ recovered \in BOOLEAN /\ warning \in BOOLEAN
NoReplay == launches = 1
NoUnrelatedSignal == unrelatedRunning
DarwinNeverPaused == Platform = "darwin" => mode \notin {"paused", "thaw-wait"}
WritesHaveFence == mode = "running" => fence = "owned"
NoWriteWhilePaused == [][(mode \in {"paused", "thaw-wait"} => writes' = writes)]_vars
ReacquireBeforeCONT == [][(mode \in {"paused", "thaw-wait"} /\ mode' = "running" => fence' = "owned") ]_vars
ControllerLossProgress == (~controllerAlive /\ mode \in {"paused", "thaw-wait"})
                          ~> (mode \notin {"paused", "thaw-wait"})
\* Intentionally false: sampled observation is not an OS-enforced hard quota.
HardReserve == free >= Reserve
=============================================================================
