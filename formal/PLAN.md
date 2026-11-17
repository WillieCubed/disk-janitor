# Bounded durable-job verification

Check durable job safety and conditional progress with explicit finite bounds,
counterexample controls, and runtime observation conformance. Preserve exact
commands, state counts and model/configuration digests with the results.

- [x] Define fresh ordered job identities, durable states, atomic admission,
  cancellation, proof loss, bounded explicit retry, and fenced cache recovery.
- [x] Check full three-job outcomes and a constrained four-job concurrency
  scenario with small integer disk/memory resources.
- [x] Check conditional progress under explicit executor/capacity/fairness assumptions.
- [x] Distinguish provisional missing evidence, late authoritative completion and
  final proof loss without permitting replay or premature reservation release.
- [x] Require concrete counterexamples for unsafe admission, replay, early release,
  false success, missing executor/capacity/fairness and negated coverage witnesses.
- [x] Check receipt observation and final-summary extraction at the runtime/tool
  boundaries without claiming complete implementation refinement.
- [x] Separately check the small Linux suspension/Darwin observation protocol,
  owned-group isolation, controller-loss thaw and cache-fence reacquisition.
  Require frozen-orphan and hard-reserve overshoot counterexamples for the
  deliberately unsafe or impossible claims.
- [x] Preserve configurations, commands, tool digest, counts, and limitations.
