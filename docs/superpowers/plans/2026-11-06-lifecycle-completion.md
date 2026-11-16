# Managed Build Lifecycle Completion Plan

> **For agentic workers:** Use superpowers:subagent-driven-development or superpowers:executing-plans task by task.

**Goal:** Finish practical build coverage, measured capacity control, evidence-based recovery, owner routing and platform/formal verification.

**Architecture:** Extend the existing guard as sole admission authority. Keep execution in the submitting permission context; deterministic machinery owns policy and recovery.

**Tech Stack:** Python standard library, Bash, native process/filesystem inspection, TLA+/TLC, disposable Linux container.

**Spec:** ../specs/2026-11-06-lifecycle-completion-design.md

## Global constraints

- Preserve source, uncommitted work, credentials, databases, unique artifacts, active outputs and platform approvals.
- Reclaim only the authorized proven inactive Cargo/Gradle/Xcode categories; no per-path approval inventory.
- Ordinary commands are nonrestartable; never infer idempotence from executable name or replay an uncertain outcome.
- Do not run, poll or requeue the restricted LogDate/runner product checks.
- Preserve dirty repository state and index; work in the existing isolated snapshot.

## Review focus

- PATH recursion, foreground stdin/stdout/stderr, signals and nested real guard versus forged environment.
- Frozen group cancellation and controller/guardian crash without untracked writers or unsafe cache release.
- Pressure observations versus attributable writes, mount replacement and competing allocations.
- Prelaunch retry proof versus committed/external effects; late evidence cannot authorize another launch.
- Root broker trust/locking/integrity boundaries and Linux-specific process/filesystem behavior.

## Tasks

- [ ] Coverage worker: RED tests for shims/ancestry/streams; implement coverage helper, reversible install and tested CI adapter; report actual installed coverage.
- [ ] Runtime worker: RED tests for adaptive estimates, owned-group pressure control and durable evidence/prelaunch recovery; implement modules and guard hooks.
- [ ] Verification worker: Linux suite on isolated source/container, stronger model and negative controls, exact evidence and runtime contract alignment.
- [ ] Root: route all ten cases once per verified outcome, preserving owner scope and archive state.
- [ ] Root: integrate private dispatch/install/docs, review combined safety and liveness, meaningful suite and installation checks.
- [ ] Root: atomically install verified changes with backup, verify live commands/streams/queue and checksum/dirty-index preservation; report remaining precise gaps.
