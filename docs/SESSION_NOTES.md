# Session Notes – Session Memory (SM)

> Rolling log of what happened in each focused work session.  
> Append-only. Do not delete past sessions.

<!-- SUMMARY_START -->
**Latest Summary (auto-maintained by Agent):**
- Completed Sprint 6 (Orchestration, Soak & Release Candidate): service orchestrator, Windows service runtime, soak/perf scaffold, export-report CLI, E2E pipeline tests.
- 220 tests pass (up from 193). All MVP acceptance criteria implemented.
<!-- SUMMARY_END -->

---

## Maintenance Rules (reduce drift)

- Append-only entries; never rewrite history.
- Update this summary block every session with the last 1–3 sessions.
- Roll up stable decisions to PROJECT_CONTEXT and active tasks to NOW.

---

## Example Entry

### 2025-12-01

**Participants:** User,VS Code Agent, Chatgpt   
**Branch:** main  

### What we worked on
- Set up local MCP-style context system.
- Added handoffkit CLI and VS Code tasks.
- Defined PROJECT_CONTEXT / NOW / SESSION_NOTES workflow.

### Files touched
- docs/PROJECT_CONTEXT.md
- docs/NOW.md
- docs/SESSION_NOTES.md
- docs/AGENT_SESSION_PROTOCOL.md
- docs/MCP_LOCAL_DESIGN.md
- handoffkit/__main__.py
- pyproject.toml
- .vscode/tasks.json

### Outcomes / Decisions
- Established start/end session ritual.
- Agents will maintain summaries and NOW.md.
- This repo will be used as a public template.

---

## Session Template (Copy/Paste for each new session)
## Recent Sessions (last 3-5)

### 2026-04-22 (Session 10)

**Participants:** User, Claude Code
**Branch:** main

### What we worked on
- Completed all Sprint 6 tickets and remaining MVP gaps.
- `export-report` CLI subcommand: reads incident + verification results from SQLite, writes JSON/HTML/text report files.
- E2E pipeline integration tests (`tests/test_e2e_pipeline.py`): covers SPEC §8 Scenarios A (critical/hard-flag), B (unusual parent → warning), C (resource spike → incident), plus CLI roundtrip test.
- Soak/performance scaffold (`tests/test_soak_performance.py`): N-cycle stability, per-cycle timing budget, retention stability, status field coverage.
- Updated `docs/NOW.md` and this file to reflect Sprint 6 completion.

### Files touched
- `src/scanner/__main__.py` — added `cmd_export_report` + `export-report` subparser
- `tests/test_e2e_pipeline.py` — new file (Scenarios A/B/C + CLI export roundtrip)
- `tests/test_soak_performance.py` — new file (stability, timing, retention, status)
- `docs/NOW.md` — sprint status updated
- `docs/SESSION_NOTES.md` — this entry

### Outcomes / Decisions
- 220 tests pass. All SPEC §8 MVP acceptance criteria are covered by automated tests.
- 24h soak and Windows Service install-smoke-test remain as manual steps on target Windows host.

---

### 2026-02-17 (Session 9)

**Participants:** User, Claude Code
**Branch:** main

### What we worked on
- Implemented all Sprint 5 tickets (S5-T1 through S5-T3) from `docs/SPRINT_PLAN.md`.
- S5-T1: Verification adapter framework — `VerificationAdapter` ABC with `safe_check` (timing + error handling), `AdapterRegistry` for registration and bulk execution, `SignatureAdapter` (MVP stub). Contract enforces verdict/evidence/timestamp/duration_ms.
- S5-T2: Verification cache — `VerificationCache` backed by SQLite with configurable TTL, `run_verification_with_budget` orchestrates adapters within a time budget, returns partial results on timeout, caches non-error results by file hash.
- S5-T3: Report renderer — `PlainLanguageSummary` with 5 mandatory fields (what happened, why it matters, what changed, checks ran, safe next actions). `build_plain_language_summary` auto-generates from incident data. `render_json`, `render_html`, `render_text` output formats. HTML includes XSS-safe escaping and styled severity badges.

### Files touched
- src/scanner/verify/__init__.py
- src/scanner/verify/adapters.py (new)
- src/scanner/verify/cache.py (new)
- src/scanner/reporting/__init__.py
- src/scanner/reporting/renderer.py (new)
- tests/test_verify_adapters.py (new — 13 tests)
- tests/test_verify_cache.py (new — 10 tests)
- tests/test_reporting.py (new — 15 tests)
- docs/NOW.md
- docs/SESSION_NOTES.md

### Outcomes / Decisions
- Sprint 5 complete; 193 tests pass.
- SignatureAdapter is a stub returning UNKNOWN — real Authenticode check is post-MVP scope.
- Error adapter results are not cached to avoid poisoning the cache.
- HTML renderer uses inline styles (no external CSS dependency) for offline use.
- Next implementation step is Sprint 6 orchestration (`S6-T1`).

---

### 2026-02-17 (Session 8)

**Participants:** User, Claude Code
**Branch:** main

### What we worked on
- Implemented all Sprint 4 tickets (S4-T1 through S4-T3) from `docs/SPRINT_PLAN.md`.
- S4-T1: Signal calculation — 6 individual signal detectors (new_identity, unsigned_writable, unusual_parent, new_network_dest, resource_spike, burst_launch) plus hard-flag escalation check. `evaluate_signals` runs all checks and returns detected signals.
- S4-T2: Score mapping — `compute_score` sums signal points, `map_severity` maps to info/warning/critical per SPEC thresholds. `score_signals` combines with hard-flag check.
- S4-T3: Incident lifecycle — `build_incident_signature` for deterministic dedup by (host, identity, signal codes). `IncidentManager` creates/updates incidents in SQLite with configurable cooldown suppression. Severity escalation on update.

### Files touched
- src/scanner/anomaly/__init__.py
- src/scanner/anomaly/signals.py (new)
- src/scanner/anomaly/scoring.py (new)
- src/scanner/anomaly/incidents.py (new)
- tests/test_anomaly_signals.py (new — 23 tests)
- tests/test_anomaly_scoring.py (new — 12 tests)
- tests/test_anomaly_incidents.py (new — 13 tests)
- docs/NOW.md
- docs/SESSION_NOTES.md

### Outcomes / Decisions
- Sprint 4 complete; 155 tests pass.
- Hard-flag escalation (unsigned + writable + outbound network) overrides score-based severity to CRITICAL.
- Incident signature uses first 16 chars of sha256 for compactness.
- Cooldown is per-signature, not per-identity — different signal patterns for same identity create separate incidents.
- Next implementation step is Sprint 5 verification & reporting (`S5-T1`).

---

### 2026-02-17 (Session 7)

**Participants:** User, Claude Code
**Branch:** main

### What we worked on
- Implemented all Sprint 3 tickets (S3-T1 through S3-T3) from `docs/SPRINT_PLAN.md`.
- S3-T1: Rule model — `WhitelistRule` dataclass with `program_allow`, `behavior_allow`, `temporary_allow` scopes. `match_program` and `match_behavior` functions with deterministic first-match semantics and rationale strings.
- S3-T2: Safety rails — `validate_rule` enforces: (1) no name-only rules (identity_key required), (2) unsigned + user-writable must include file_hash.
- S3-T3: Candidate proposals — `propose_candidates` generates rules from high-confidence baseline profiles. `approve_rule` stamps `approved_ts`. `WhitelistStore` persists versioned rules to SQLite with validation gate, active-rule loading, and version pruning.

### Files touched
- src/scanner/whitelist/__init__.py
- src/scanner/whitelist/rules.py (new)
- src/scanner/whitelist/safety.py (new)
- src/scanner/whitelist/proposals.py (new)
- tests/test_whitelist_rules.py (new — 12 tests)
- tests/test_whitelist_safety.py (new — 10 tests)
- tests/test_whitelist_proposals.py (new — 11 tests)
- docs/NOW.md
- docs/SESSION_NOTES.md

### Outcomes / Decisions
- Sprint 3 complete; 107 tests pass.
- Safety rails are enforced at persistence time — `WhitelistStore.save_rules` silently skips invalid rules with a warning log.
- Candidate proposals require explicit `approve_rule` call before `load_active_rules` returns them.
- Next implementation step is Sprint 4 anomaly scoring (`S4-T1`).

---

### 2026-02-17 (Session 6)

**Participants:** User, Claude Code
**Branch:** main

### What we worked on
- Implemented all Sprint 2 tickets (S2-T1 through S2-T3) from `docs/SPRINT_PLAN.md`.
- S2-T1: Baseline mode state machine — `learning` → `monitor` transition based on configurable time window, persisted in SQLite `baseline_mode` table, survives restarts.
- S2-T2: Per-identity statistics — `IdentityProfile` tracks launch frequency, parent patterns, network destinations, and resource percentiles (p50/p90/p99). `BaselineAggregator` ingests telemetry events. Confidence scoring with weighted factors.
- S2-T3: Versioned snapshot persistence — `BaselineSnapshotStore` saves/loads profile sets with version numbers, supports version listing, pruning to keep last N versions.

### Files touched
- src/scanner/baseline/__init__.py
- src/scanner/baseline/mode.py (new)
- src/scanner/baseline/stats.py (new)
- src/scanner/baseline/snapshot.py (new)
- tests/test_baseline_mode.py (new — 8 tests)
- tests/test_baseline_stats.py (new — 17 tests)
- tests/test_baseline_snapshot.py (new — 8 tests)
- docs/NOW.md
- docs/SESSION_NOTES.md

### Outcomes / Decisions
- Sprint 2 is complete; 74 tests pass.
- Confidence scoring uses weighted factors: launch count (0.4), resource samples (0.3), parent diversity (0.15), network observation (0.15), with configurable min_samples threshold (default 30).
- Mode state is stored in a separate `baseline_mode` table (created by the manager, not via migrations) for simplicity.
- Next implementation step is Sprint 3 whitelist and safety rails (`S3-T1`).

---

### 2026-02-17 (Session 5)

**Participants:** User, Claude Code
**Branch:** main

### What we worked on
- Implemented all Sprint 1 tickets (S1-T1 through S1-T4) from `docs/SPRINT_PLAN.md`.
- S1-T1: Process collector — polling-based diff of PID snapshots, emits `process_start`/`process_stop` events with normalized identity keys.
- S1-T2: Resource collector — per-process CPU/memory/disk I/O sampling via psutil.
- S1-T3: Network collector — best-effort outbound connection capture with exe resolution caching.
- S1-T4: Event rate limiter (sliding-window cap) and retention cleanup hook (deletes telemetry older than configured days).
- Added SQLite migration 2 (pid column on telemetry_event) and persist/query methods to SQLiteStorage.
- Added `psutil>=5.9,<8` as runtime dependency and created `requirements.txt`.

### Files touched
- requirements.txt (new)
- src/scanner/collector/__init__.py
- src/scanner/collector/process_collector.py (new)
- src/scanner/collector/resource_collector.py (new)
- src/scanner/collector/network_collector.py (new)
- src/scanner/collector/rate_limiter.py (new)
- src/scanner/storage/sqlite_store.py (migration 2 + persist/query)
- tests/test_process_collector.py (new)
- tests/test_resource_collector.py (new)
- tests/test_network_collector.py (new)
- tests/test_rate_limiter.py (new)
- tests/test_storage_bootstrap.py (updated migration version assertions)
- docs/NOW.md
- docs/SESSION_NOTES.md

### Outcomes / Decisions
- Sprint 1 is complete; all 41 tests pass.
- Authenticode signer extraction is stubbed as `unsigned` for MVP — real verification deferred to Sprint 5 verify module.
- psutil is the sole new runtime dependency; satisfies offline/local invariant.
- Next implementation step is Sprint 2 baseline engine (`S2-T1`).

---

### 2026-02-14 (Session 4)

**Participants:** User, Codex Agent  
**Branch:** main  

### What we worked on
- Implemented Sprint 0 deliverables: module scaffolding, shared contracts, config validator, and SQLite bootstrap.
- Added new tests for module imports, config validation, identity behavior, and storage migration idempotency.
- Updated NOW to reflect completed Sprint 0 foundation tasks and next step (`S1-T1`).

### Files touched
- src/scanner/__init__.py
- src/scanner/common/__init__.py
- src/scanner/common/types.py
- src/scanner/common/config.py
- src/scanner/common/identity.py
- src/scanner/storage/__init__.py
- src/scanner/storage/sqlite_store.py
- src/scanner/collector/__init__.py
- src/scanner/baseline/__init__.py
- src/scanner/whitelist/__init__.py
- src/scanner/anomaly/__init__.py
- src/scanner/verify/__init__.py
- src/scanner/reporting/__init__.py
- src/scanner/service/__init__.py
- tests/test_scanner_foundation.py
- tests/test_storage_bootstrap.py
- docs/NOW.md
- docs/SESSION_NOTES.md

### Outcomes / Decisions
- Sprint 0 is implementation-ready and validated by tests.
- Process identity key implementation keeps `product_name` out of hashing logic.
- Next implementation step is Sprint 1 process collector (`S1-T1`).

### 2026-02-14 (Session 3)

**Participants:** User, Codex Agent  
**Branch:** main  

### What we worked on
- Converted the architect sprint outline into a coder-ingestible markdown artifact.
- Added explicit ticket-level scopes, tests, acceptance criteria, and done gates.
- Updated NOW to reflect completed planning tasks and immediate next step (`S0-T1`).

### Files touched
- docs/SPRINT_PLAN.md
- docs/NOW.md
- docs/SESSION_NOTES.md

### Outcomes / Decisions
- Sprint execution is now directly handoff-ready for coder role prompts.
- Step-level context checkpointing remains mandatory between tickets.

### 2026-02-14 (Session 2)

**Participants:** User, Codex Agent  
**Branch:** main  

### What we worked on
- Added a step-level context writeback gate to reduce drift between chats.
- Updated role templates so every role output now includes mandatory `SESSION UPDATES`.
- Aligned workflow docs so teams checkpoint NOW/SESSION_NOTES after each step.

### Files touched
- docs/AGENT_SESSION_PROTOCOL.md
- docs/PERSISTENT_AGENT_WORKFLOW.md
- docs/NOW.md
- docs/SESSION_NOTES.md
- handoffkit/templates/architect.md
- handoffkit/templates/coder.md
- handoffkit/templates/reviewer.md
- handoffkit/templates/qa_tester.md
- handoffkit/templates/polish.md

### Outcomes / Decisions
- Next-step progression is now gated on context writeback.
- Handoff responses are required to carry explicit context update instructions.
- Rehydration quality should improve for long pauses/new chats.

### 2026-02-14

**Participants:** User, Codex Agent  
**Branch:** main  

### What we worked on
- Performed a spec review comparing `SPEC.md` and `spec_v01.md`.
- Merged core requirements and deterministic contracts into canonical `SPEC.md`.
- Locked MVP platform scope to Windows-first and aligned context docs.

### Files touched
- SPEC.md
- spec_v01.md
- docs/PROJECT_CONTEXT.md
- docs/NOW.md
- docs/SESSION_NOTES.md

### Outcomes / Decisions
- `SPEC.md` remains canonical; `spec_v01.md` is now reference draft only.
- MVP starts Windows-only; cross-platform support is post-MVP.
- Process identity key excludes `product_name` to improve stability.

### 2026-02-13

**Participants:** User, Codex Agent  
**Branch:** main  

### What we worked on
- Reviewed repo state and ran `python3 -m handoffkit preflight`.
- Reframed project context from template workflow to scanner product intent.
- Defined the scanner MVP in a new `SPEC.md` with baseline, whitelist, anomaly, verification, and reporting requirements.

### Files touched
- docs/PROJECT_CONTEXT.md
- docs/NOW.md
- docs/INVARIANTS.md
- docs/Repo_Structure.md
- docs/SESSION_NOTES.md
- SPEC.md

### Outcomes / Decisions
- Project scope is now explicitly an offline, local background security tool.
- Baseline + fit-for-purpose whitelist + local verification scans are locked as MVP behavior.
- Preflight dependency on `SPEC.md` is now satisfied.

### 2026-02-04

**Participants:** User, Codex Agent  
**Branch:** main  

### What we worked on
- Added required SPEC + Invariants to handoff packs and introduced `handoffkit preflight`.
- Created baseline `SPEC.md` and `docs/INVARIANTS.md`.
- Updated workflow docs and templates to reflect the new requirements.

### Files touched
- handoffkit/__main__.py
- handoffkit.config.json
- handoffkit/handoffkit.config.json
- SPEC.md
- docs/INVARIANTS.md
- docs/Repo_Structure.md
- docs/PERSISTENT_AGENT_WORKFLOW.md
- docs/AGENT_SESSION_PROTOCOL.md
- handoffkit/templates/architect.md

### Outcomes / Decisions
- SPEC + Invariants are required artifacts for handoff packs.
- Preflight validation is part of the recommended workflow.

### 2025-12-01 (Session 2)

**Participants:** User, Codex Agent  
**Branch:** main  

### What we worked on
- Re-read PROJECT_CONTEXT, NOW, and SESSION_NOTES to prep session handoff.
- Tightened the summaries in PROJECT_CONTEXT.md and NOW.md to mirror the current project definition.
- Reconfirmed the immediate tasks: polish docs, add an example project, and test on a real repo.

### Files touched
- docs/PROJECT_CONTEXT.md
- docs/NOW.md
- docs/SESSION_NOTES.md

### Outcomes / Decisions
- Locked the near-term plan around doc polish, example walkthrough, and single-repo validation.
- Still waiting on any additional stakeholder inputs before expanding scope.

### 2025-12-01

**Participants:** User, Codex Agent  
**Branch:** main  

### What we worked on
- Reviewed the memory docs to confirm expectations for PROJECT_CONTEXT, NOW, and SESSION_NOTES.
- Updated NOW.md and PROJECT_CONTEXT.md summaries to reflect that real project data is still pending.
- Highlighted the need for stakeholder inputs before populating concrete tasks or deliverables.

### Files touched
- docs/PROJECT_CONTEXT.md
- docs/NOW.md
- docs/SESSION_NOTES.md

### Outcomes / Decisions
- Documented that the repo currently serves as a template awaiting real project data.
- Set the short-term focus on collecting actual objectives and backlog details.

### [DATE – e.g. 2025-12-02]

**Participants:** [You, VS Code Agent, other agents]  
**Branch:** [main / dev / feature-x]  

### What we worked on
- 

### Files touched
- 

### Outcomes / Decisions
-

### 2026-04-22

**Participants:** User, Codex Agent  
**Branch:** main  

### What we worked on
- Reviewed the scanner codebase as a senior Python code review, focusing on scanner usefulness and verification usefulness.
- Fixed several runtime issues around signer semantics, status persistence, verification persistence, and repo self-containment.
- Removed the unused repo-local `handoffkit` workflow and related tests/docs wiring.
- Implemented the first real verification slice by replacing the `signature` stub with a Windows Authenticode-backed adapter using `Get-AuthenticodeSignature`.
- Verified the changes with focused verification tests, full scanner tests, and scanner CLI smoke checks.

### Files touched
- src/scanner/verify/adapters.py
- src/scanner/verify/windows_authenticode.py
- src/scanner/verify/cache.py
- src/scanner/service/orchestrator.py
- src/scanner/storage/sqlite_store.py
- src/scanner/common/config.py
- src/scanner/collector/network_collector.py
- src/scanner/collector/resource_collector.py
- src/scanner/collector/process_collector.py
- src/scanner/anomaly/signals.py
- src/scanner/anomaly/scoring.py
- src/scanner/__main__.py
- tests/test_verify_adapters.py
- tests/test_verify_cache.py
- tests/test_service_orchestrator.py
- tests/test_network_collector.py
- tests/test_resource_collector.py
- tests/test_anomaly_signals.py
- tests/test_anomaly_scoring.py
- tests/test_storage_bootstrap.py
- tests/test_e2e_pipeline.py
- docs/NOW.md
- docs/PROJECT_CONTEXT.md
- docs/Repo_Structure.md
- docs/PERSISTENT_AGENT_WORKFLOW.md
- docs/AGENT_SESSION_PROTOCOL.md
- docs/MCP_LOCAL_DESIGN.md
- docs/SPRINT_PLAN.md

### Outcomes / Decisions
- Missing signer data is no longer treated as `unsigned`; `unknown` remains distinct from confirmed unsigned.
- Verification results and service status are now persisted and exported correctly.
- The repo no longer depends on `handoffkit`; workflow memory lives directly in the docs.
- Authenticode is now a real Windows-native verification step; next morning’s highest-value task is adding `WindowsDefenderAdapter`.
- Current validation state:
  - `python3 -m pytest -q` passes with `227 passed, 13 subtests passed`
  - `PYTHONPATH=src python3 -m scanner run --db /tmp/scanner-authenticode.db --max-cycles 1`
  - `PYTHONPATH=src python3 -m scanner status --db /tmp/scanner-authenticode.db`

### Restart Notes
- Start from the verification subsystem, not the orchestrator or reporting paths.
- First implementation target: `WindowsDefenderAdapter` with local file scan, normalized evidence, and clear verdict mapping.
- After Defender lands, add Windows-host validation with:
  - a known Microsoft-signed binary
  - a known unsigned binary
  - a safe malware-test artifact such as EICAR if practical

## Archive (do not load by default)
...
