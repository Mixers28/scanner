# Scanner MVP Sprint Plan (Coder Ingestion)

Version: 1.0  
Date: 2026-02-14  
Canonical source: `SPEC.md`

## 1. Purpose

This plan breaks `SPEC.md` into implementation sprints and ticket-sized deliverables that a coder can execute directly with clear tests and acceptance criteria.

## 2. Global Execution Rules

1. `SPEC.md` is canonical. If any conflict exists with `spec_v01.md`, follow `SPEC.md`.
2. MVP is Windows-only.
3. No scope expansion without explicit architect update to `SPEC.md`.
4. Each ticket must include tests for changed behavior.
5. Context gate after each ticket (mandatory):
   - Update `docs/NOW.md` (progress + immediate next action).
   - Append to `docs/SESSION_NOTES.md` (what changed + why).
   - Update `docs/PROJECT_CONTEXT.md` only if high-level decision changed.

## 3. Sprint Cadence

- Sprint length: 1 week
- Target: 6 delivery sprints + 1 hardening sprint

## 4. Sprint 0 - Foundation and Contracts

### S0-T1: Project skeleton and module boundaries
- Scope:
  - Create `src/scanner/{common,storage,collector,baseline,whitelist,anomaly,verify,reporting,service}`.
  - Add package init files and basic module readme/docstrings.
- Tests:
  - Import smoke test for all modules.
- Acceptance:
  - Modules import cleanly and package layout matches `SPEC.md`.

### S0-T2: Shared types, enums, and config schema
- Scope:
  - Define core enums (`severity`, `incident_state`, `verdict`).
  - Define shared event/entity data types.
  - Add config schema and validation loader.
- Tests:
  - Schema validation success and failure cases.
  - Enum/type serialization tests.
- Acceptance:
  - Invalid configs fail with actionable errors.
  - Shared types are consumable by all modules.

### S0-T3: Storage bootstrap and migrations
- Scope:
  - Implement SQLite initialization.
  - Add migration version table and first migration.
- Tests:
  - DB init idempotency.
  - Migration upgrade path test.
- Acceptance:
  - Fresh and existing DB paths initialize without data loss.

## 5. Sprint 1 - Collector and Telemetry Persistence

### S1-T1: Process collector
- Scope:
  - Capture process start/stop with PID/PPID/path (best-effort signer).
  - Normalize process fields.
- Tests:
  - Process event normalization unit tests.
  - Collector emits expected event envelope.
- Acceptance:
  - Process events persist in `telemetry_event`.

### S1-T2: Resource collector
- Scope:
  - Poll per-process CPU/memory/disk metrics at configured interval.
- Tests:
  - Interval and sample-shape tests.
- Acceptance:
  - Resource samples persist and align to schema.

### S1-T3: Network collector (best-effort)
- Scope:
  - Capture per-process outbound network tuples (IP/host/port/protocol, bytes if available).
- Tests:
  - Best-effort mapping tests with fallback handling.
- Acceptance:
  - Network events are captured without crashing on unavailable fields.

### S1-T4: Event caps and retention hook
- Scope:
  - Enforce max events/minute and retention cleanup trigger.
- Tests:
  - Cap/drop behavior tests.
- Acceptance:
  - Collector remains stable under burst load.

## 6. Sprint 2 - Baseline Engine

### S2-T1: Learning and monitor modes
- Scope:
  - Implement baseline mode state machine (`learning` -> `monitor`).
- Tests:
  - Mode transition tests by time window and thresholds.
- Acceptance:
  - Service transitions correctly and deterministically.

### S2-T2: Baseline statistics and confidence
- Scope:
  - Compute per-identity frequency, parent patterns, network/resource norms.
  - Implement confidence score.
- Tests:
  - Percentile, variance, and confidence unit tests.
- Acceptance:
  - Baseline profiles are reproducible from same input stream.

### S2-T3: Versioned snapshot persistence
- Scope:
  - Persist and load baseline snapshots with versioning.
- Tests:
  - Restart persistence tests.
- Acceptance:
  - Baseline version is stable across restart unless a new commit occurs.

## 7. Sprint 3 - Whitelist and Safety Rails

### S3-T1: Rule model and matching engine
- Scope:
  - Implement `program_allow`, `behavior_allow`, `temporary_allow`.
- Tests:
  - Match/no-match unit tests for all scopes.
- Acceptance:
  - Deterministic matching with clear rationale.

### S3-T2: Safety rails enforcement
- Scope:
  - Deny name-only rules.
  - Require hash for unsigned executables in user-writable paths.
- Tests:
  - Validation tests for rejected/accepted rules.
- Acceptance:
  - Unsafe rules are blocked by default.

### S3-T3: Candidate proposal and approval metadata
- Scope:
  - Generate candidate whitelist entries from stable baseline behavior.
  - Persist `source`, `rationale`, `approved_ts`.
- Tests:
  - Proposal eligibility tests.
  - Approval persistence tests.
- Acceptance:
  - Approved rules become active and versioned.

## 8. Sprint 4 - Anomaly Scoring and Incident Lifecycle

### S4-T1: Signal calculation
- Scope:
  - Implement required signals from `SPEC.md` including hard-flag condition.
- Tests:
  - Signal detection unit tests per signal code.
- Acceptance:
  - Required signals compute consistently.

### S4-T2: Score mapping and severity
- Scope:
  - Aggregate signal points and map `info|warning|critical`.
- Tests:
  - Threshold mapping tests.
  - Hard-flag escalation tests.
- Acceptance:
  - Severity mapping matches spec.

### S4-T3: Dedupe, cooldown, and incident updates
- Scope:
  - Incident signature generation.
  - Open/update behavior with cooldown.
- Tests:
  - Duplicate suppression and cooldown tests.
- Acceptance:
  - Repeated events update incidents without alert spam.

## 9. Sprint 5 - Verification and Reporting

### S5-T1: Verification adapter framework
- Scope:
  - Implement adapter registry and normalized adapter output.
- Tests:
  - Adapter contract tests.
- Acceptance:
  - Adapter outputs conform to `verdict/evidence/timing` contract.

### S5-T2: Verification cache and timeout budget
- Scope:
  - Cache by file hash with TTL.
  - Enforce per-incident verification time budget.
- Tests:
  - Cache hit/miss and timeout tests.
- Acceptance:
  - Repeated scans avoid redundant work; timeout returns partial results safely.

### S5-T3: Report renderer
- Scope:
  - Generate JSON + HTML (+ optional text) with plain-language summary first.
- Tests:
  - Render format tests and required plain-language section checks.
- Acceptance:
  - Every incident report includes required user-facing explanation fields.

## 10. Sprint 6 - Orchestration, Soak, and Release Candidate

### S6-T1: Service orchestrator and status CLI
- Scope:
  - Wire module lifecycle, health checks, retention jobs.
  - Add `status` CLI command.
- Tests:
  - Service lifecycle integration tests.
- Acceptance:
  - Start/stop/status works consistently in dev and service modes.

### S6-T2: Windows service runtime path
- Scope:
  - Implement Windows Service install/run flow (or documented fallback mode).
- Tests:
  - Service startup smoke tests on target host.
- Acceptance:
  - Tool runs as background service on Windows.

### S6-T3: Soak and performance validation
- Scope:
  - Run 24h stability and performance checks.
- Tests:
  - Soak test report with CPU/memory/DB size stats.
- Acceptance:
  - Meets `SPEC.md` MVP acceptance criteria and performance targets.

## 11. Required Test Commands (Baseline)

Use these as mandatory checks per ticket (adjust as repo evolves):

```bash
python3 -m pytest -q
```

## 12. Done Criteria

A ticket is done only when all are true:
1. Scope implemented with no spec drift.
2. Tests added/updated and passing.
3. Context gate completed (`NOW.md` + `SESSION_NOTES.md`, plus `PROJECT_CONTEXT.md` if needed).
4. Handoff output includes blockers, assumptions, and next executable action.
