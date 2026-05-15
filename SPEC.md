# SPEC - Scanner MVP (Canonical)

Version: 0.2  
Last updated: 2026-02-14  
Status: Draft (implementation-ready)

## 0. Summary

Scanner is a local, offline-first security monitor that runs continuously, learns per-machine baseline behavior, detects material deviations, verifies suspicious activity using local checks, and reports incidents in plain language.

`SPEC.md` is the canonical implementation spec. If any conflict exists with `spec_v01.md`, this file wins.

## 1. Goals and Non-Goals

### 1.1 Goals (MVP)
- Offline-first operation with no required cloud dependency.
- Local telemetry + local decisioning + local storage.
- Explainable incident output for non-technical users.
- Low-noise alerting with dedupe/cooldown.
- Safe default behavior (no automatic destructive remediation).

### 1.2 Non-Goals (MVP)
- Enterprise fleet/SaaS control plane.
- Kernel drivers and invasive hooks.
- Full EDR/tamper-proof parity against admin-level adversaries.

## 2. Target Platform and Runtime (MVP)

- OS scope: Windows-only for MVP (Windows 10/11 and Server 2019+).
- Runtime mode: Windows Service preferred; Scheduled Task fallback; foreground CLI mode for dev/test.
- Privilege model: LocalSystem or dedicated service account with minimum required rights.

## 3. Module Architecture

- `collector`: process/network/resource telemetry ingestion.
- `baseline`: learning mode, baseline snapshots, drift control.
- `whitelist`: fit-for-purpose allow rules + safety rails.
- `anomaly`: signal scoring, severity mapping, dedupe/cooldown.
- `verify`: local verification adapters (signature/AV/rules), cached results.
- `reporting`: JSON/HTML/text incident output with plain-language first.
- `service`: orchestrates lifecycle, scheduling, storage, retention, and health.

## 4. Data Contracts

### 4.1 Process Identity (critical)

Use a stable identity key to avoid false merges and noisy churn.

`process_identity` fields:
- `image_path_norm` (required)
- `signer_publisher` (required; `unsigned` if unavailable)
- `file_hash` (required for unsigned executables in user-writable paths)
- `product_name` (optional metadata only; **not part of identity key**)

Canonical key:
- `identity_key = sha256(lower(image_path_norm) + "|" + lower(signer_publisher) + "|" + hash_or_empty)`

### 4.2 Core entities

- `telemetry_event`: envelope + typed payload (`process_start`, `process_stop`, `net_conn`, `resource_sample`, `service_state`).
- `baseline_profile`: per-identity behavior stats, confidence, version linkage.
- `whitelist_entry`: `program_allow | behavior_allow | temporary_allow`, with rationale/source/timestamps.
- `incident`: severity, score, signals/evidence, lifecycle state, summary output.
- `verification_result`: adapter verdict/evidence/duration/cache metadata.

## 5. Functional Requirements

### 5.1 Collector
- Process telemetry: starts/stops, PID/PPID, image path, signer (best-effort), optional command line.
- Network telemetry (best-effort): outbound endpoint patterns, port/protocol, bytes where available.
- Resource telemetry: CPU%, memory, disk I/O sampled at configurable interval.
- Event-driven source preferred; polling fallback required.
- Configurable intervals/caps: process/resource/network poll intervals and max events per minute.

### 5.2 Baseline
- Modes: `learning` (default first 7 days) then `monitor`.
- Configurable learning window: 1–30 days (default 7).
- Track per-identity launch frequency, parent patterns, network norms, and resource percentiles.
- Baseline snapshots must be versioned and reused after service restart.

### 5.3 Whitelist
- Candidate allow rules proposed from stable baseline behavior.
- Explicit user approval required before broad allowlisting of unknown behavior.
- Safety rails:
  - deny name-only allow rules,
  - unsigned + user-writable executable must include file hash binding.

### 5.4 Anomaly
- Score signal deviations and map severity:
  - `info` 1-2
  - `warning` 3-5
  - `critical` >=6 or hard flag
- Required signals include:
  - new process identity,
  - unsigned in user-writable location,
  - unusual parent chain,
  - new destination/port pattern,
  - sustained resource spike,
  - burst launch frequency.
- Required hard escalation:
  - unsigned + user-writable + outbound network => minimum `critical`.
- Deduplicate by incident signature and apply cooldown (default 30 min).

### 5.5 Verify
- Run local checks on anomaly:
  - signature verification,
  - local heuristic/rule checks,
  - optional local AV adapter (when available).
- Adapter return contract:
  - `verdict`: `clean|suspicious|malicious|unknown|error`
  - `evidence`: key/value list
  - `timestamp`, `duration_ms`
- Cache verification by file hash for 7-day default TTL.
- Total verification budget default 30 seconds per incident.

### 5.6 Reporting
- Output formats: JSON + HTML; optional plain text.
- Plain-language section is mandatory and must include:
  - what happened,
  - why it matters,
  - what changed vs baseline,
  - what checks ran,
  - safe next actions.
- Technical appendix is optional and can include raw signals, endpoints, and adapter output.

## 6. Storage and Retention

- SQLite is recommended default store.
- Prototype fallback: JSONL allowed for early experimentation only.
- Default retention policy:
  - `telemetry_event`: 7 days rolling,
  - `incident` + `verification_result`: 90 days,
  - keep last 10 `baseline` versions,
  - keep last 50 `whitelist` versions.

## 7. Non-Functional Targets

- CPU target: average < 2% at idle; short verification burst < 10% for < 5s.
- Memory target: < 400MB resident.
- Local DB cap: 500MB rolling (configurable).
- Explainability: every incident includes score-driving signals + evidence.

## 8. MVP Acceptance Criteria

1. Service runs for 24h without crashes and respects retention policy.
2. Baseline persists and is reused across service restarts.
3. Detection scenario A passes:
   - unsigned executable in user-writable directory making outbound connection => `critical`.
4. Detection scenario B passes:
   - unusual parent chain not allowlisted => `warning` or `critical` by score.
5. Detection scenario C passes:
   - sustained resource spike above learned threshold => incident generated.
6. Verification executes at least one adapter and normalizes verdict output.
7. User-facing report clearly explains incident and recommended safe action.

## 9. Test Strategy

- Unit tests:
  - identity normalization/key stability,
  - whitelist matching safety rails,
  - scoring and severity mapping,
  - baseline threshold comparisons.
- Integration tests:
  - telemetry -> baseline -> anomaly -> verify -> reporting pipeline.
- Manual tests:
  - controlled scenarios A/B/C,
  - performance budget checks on target Windows host.

## 10. Post-MVP

- Cross-platform collectors (Linux/macOS).
- Interactive allowlist UI.
- Optional opt-in export integrations.
- Stronger tamper-awareness and self-integrity controls.
