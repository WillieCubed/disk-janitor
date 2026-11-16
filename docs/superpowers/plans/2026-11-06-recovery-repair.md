# Recovery Repair Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Fix activity false positives and make authorized cache reclamation effective and fast without agent intervention.

**Architecture:** Keep the existing admission authority and recovery fences. Detect actual executable/Java activity, classify cache units by category/provenance, validate once, revalidate identity and bulk-remove validated batches with current pressure checks.

**Tech Stack:** Python standard library, existing Bash CLI, native rm, unittest; existing TLA+/TLC model and conformance checks.

**Spec:** docs/superpowers/specs/2026-11-06-recovery-repair.md

## Global Constraints

No new broker/daemon or public policy options. No source, credentials, databases, unique/active outputs, images, dependency downloads or worktree deletion. Existing sandbox and platform approvals apply. Preserve the dirty repository and its index. Prior user direction authorizes execution without design questions or repeated routine disk approvals.

## Review Focus

- Queued or quoted argv mentioning compilers must not block recovery; executed compilers and real Java entrypoints must.
- Protected content, symlinks and changes after validation must survive; eligible unrelated cache units must still be recovered.
- Large cache inventories must use bounded bulk operations and bounded process inspection, not per-entry subprocesses.
- Actual physical capacity must control stopping, including clone/hard-link allocation differences.
- Inspection failures and live/nonrestartable guards must preserve resources; maintenance intent must clear on every exit.

### Task 1: Activity detection

Files: bin/recovery.py activity/busy helpers; tests/test_recovery_activity.py.
Interface: activity() returns process descriptors and open paths; busy(kind,path,processes,opened) supports existing injected test strings conservatively at command start.
- [x] Write and observe RED regressions for queued guardians, Java entrypoints and inspection failure.
- [x] Implement platform executable/argv inspection without third-party dependencies; verify real own-process fixtures and legacy tests.

### Task 2: Discovery and batch recovery

Files: bin/recovery.py; tests/test_recovery_bulk.py; CLI/man/README/version metadata as needed.
Interface: candidates(home) continues producing (kind,path); preserve snapshot() compatibility. recover() keeps existing fence/pressure contract and adds measured free-space evidence.
- [x] Observe RED tests for Cargo format/provenance discovery, marked Gradle transforms and bulk behavior across many Xcode units.
- [x] Implement category validation, protected-unit isolation, identity revalidation and native batches. Add safety, mutation, pressure-stop and bounded-inspection regressions.
- [x] Benchmark representative real fixture trees through installed submit/observe API; run the full suite, roundtrip, lint and formal conformance/TLC when assumptions/code changes require it.

### Task 3: Audit, review and installation

Files: private evidence/repair-20261106 audit and installation receipts; selected source/runtime/doc files only.
- [x] Classify all historical failed jobs read-only, with receipt/log limitations and cautious supersession evidence.
- [x] Obtain independent review of destructive classification, batching, activity races and compatibility; fix concrete findings once with regression tests.
- [x] Verify concurrent edits against baseline; atomically replace helpers/entry point with backups and unchanged index. Verify live version, activity, dry-run/authorized recovery, job submission/observation and maintenance health.
- [x] Report actual installed behavior, measurements, audit findings and remaining limits. Do not commit unrelated existing changes.
