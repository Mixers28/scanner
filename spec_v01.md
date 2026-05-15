# SPEC — Scanner MVP (v0.1) [Reference Draft]

NOTE: `SPEC.md` is the canonical implementation spec as of 2026-02-14.
This file is retained as extended reference material and appendix content.
If any content conflicts with `SPEC.md`, follow `SPEC.md`.

Version: 0.1
Last updated: 2026-02-13
Status: Draft (implementation-ready)

## 0. Summary

Scanner is a local, offline-first security monitoring tool that learns “normal” behavior on a specific machine and alerts users to unusual activity in plain language. It emphasizes explainability, low overhead, and safe defaults (no destructive actions in MVP).

---

## 1. Product Intent

Build a local security tool that:
- runs continuously in the background,
- collects lightweight telemetry (process/network/resource),
- learns a baseline of normal machine behavior,
- detects material deviations not covered by user-approved allow rules,
- verifies suspicious items using local checks,
- produces plain-language incident summaries plus optional technical detail.

---

## 2. Goals and Non-Goals

### 2.1 Goals (MVP)
- Offline-first: works without internet connectivity.
- Privacy-preserving: telemetry and decisions stay local.
- Explainable: every incident includes “what changed” + evidence.
- Low-noise: dedupe/cooldowns to prevent alert spam.
- Safe-by-default: no automatic termination/quarantine/deletion.

### 2.2 Non-Goals (MVP)
- Enterprise fleet management / remote dashboards / SaaS control plane.
- Kernel drivers or invasive hooking.
- Full EDR parity (tamper-proofing against admin-level malware).

---

## 3. Target Platform and Privileges (MVP)

### 3.1 Target OS
- Windows-first MVP (Windows 10/11, Windows Server 2019+).
- Future: cross-platform collectors may be added, but are out of MVP scope.

### 3.2 Execution model
- Runs as a Windows Service (preferred) OR Scheduled Task (fallback).
- Includes a CLI runner for development/testing.

### 3.3 Privileges
- Service account: LocalSystem (preferred) OR a dedicated service account with required rights.
- UI/Viewer (optional in MVP): runs as standard user and reads local report/history.

---

## 4. Definitions

### 4.1 Process Identity (critical)
All baseline + whitelist + anomaly scoring use a consistent identity:

**process_identity**
- image_path (normalized)
- signer_publisher (e.g., “Microsoft Corporation” or “unsigned/unknown”)
- product_name (optional, best-effort)
- file_hash (optional; required for high-risk unsigned locations)

Rationale: prevents merging unrelated apps and reduces false positives after upgrades.

### 4.2 Incident
A structured record describing an anomaly, its evidence, verification results, severity, and lifecycle state.

### 4.3 States (Incident lifecycle)
- open → acknowledged → resolved
- (optional) false_positive (resolved with rationale)

---

## 5. System Overview (Modules)

- collector
- baseline
- whitelist
- anomaly
- verify
- reporting
- service (orchestrator)

---

## 6. Functional Requirements

## 6.1 collector

### 6.1.1 Telemetry Types (MVP)
1) Process telemetry
- process start/stop (timestamp)
- PID, parent PID
- image path
- command line (optional; configurable)
- signer/publisher (best-effort)
- user/session (best-effort)

2) Network telemetry (best-effort)
- per-process outbound connections: dest IP/hostname (if available), port, protocol
- bytes sent/received (best-effort)
- DNS query mapping (best-effort)

3) Resource telemetry (aggregated)
- per-process CPU%
- working set / memory
- disk IO bytes read/write (best-effort)

### 6.1.2 Collection Method (event vs polling)
For each telemetry type, implement:
- Primary: event-driven when available
- Fallback: polling

Minimum required behavior:
- Process start/stop: event-driven preferred; fallback polling every 2s–5s.
- Resource: polling every 5s (configurable).
- Network: polling every 5s–10s (configurable), best-effort attribution to process.

### 6.1.3 Field Guarantees
- Guaranteed: timestamp, event_type, PID, image_path (if process known)
- Best-effort: signer, command_line, hostname, bytes, DNS mapping

### 6.1.4 Telemetry Volume Control
- Collectors must support sampling and caps.
- Provide knobs:
  - process_poll_interval_seconds
  - resource_poll_interval_seconds
  - network_poll_interval_seconds
  - telemetry_retention_days

---

## 6.2 baseline

### 6.2.1 Modes
- Learning mode (default first 7 days)
- Monitor mode (after baseline committed)

### 6.2.2 Learning window
Default: 7 days of telemetry.
Configurable: 1–30 days.

### 6.2.3 Baseline features (per process_identity)
Store “normal” ranges for:
- launch frequency (per hour/day)
- typical parents (parent process_identity buckets, simplified)
- typical network ports and destination patterns (coarse)
- CPU/memory/disk IO percentiles (p50/p90 recommended)
- “time-of-day” activity buckets (optional; coarse)

### 6.2.4 Drift policy (MVP)
- Baseline is “locked” after learning, but may be updated via controlled drift:
  - rolling update for stable processes only (high confidence and low variance)
  - otherwise require manual “relearn” or explicit user action

### 6.2.5 Confidence
Define confidence score [0..1] based on:
- observation_count
- stability (variance)
- recency

---

## 6.3 whitelist

### 6.3.1 Whitelist scopes (MVP)
- program_allow: (image_path + signer_publisher) optionally + hash for unsigned
- behavior_allow: program_allow + (port + protocol) + destination pattern (coarse)
- temporary_allow: same as above but expires

### 6.3.2 Safety rails
- Forbid “name-only” allow rules.
- Unsigned executable from user-writable directories requires explicit confirmation and uses hash binding by default.

### 6.3.3 Workflow
- Tool proposes candidates after learning (stable + high confidence).
- User explicitly approves.
- Store rationale + timestamp + source.

---

## 6.4 anomaly

### 6.4.1 MVP scoring model
Compute a risk score by combining signals. Each signal contributes points; severity is mapped from score + specific “hard flags”.

Signals (examples):
- NEW_PROCESS_IDENTITY (first seen): +2
- UNSIGNED_IN_USER_WRITABLE_DIR: +4 (hard flag)
- UNUSUAL_PARENT_CHAIN (not in baseline parents): +3
- NEW_NETWORK_DESTINATION_PATTERN: +2
- UNUSUAL_PORT (not seen for this process): +2
- RESOURCE_SPIKE_SUSTAINED (above baseline p90 for N intervals): +2
- BURST_LAUNCH_FREQUENCY (above baseline): +2

Hard flags (escalation):
- unsigned + user-writable + outbound network → minimum severity = critical

### 6.4.2 Material deviation definition
A deviation is “material” if:
- it exceeds baseline thresholds (percentile-based) OR
- it matches a “new/rare” signal AND is not allowlisted

### 6.4.3 Severity mapping (MVP)
- info: score 1–2, no hard flags
- warning: score 3–5, no hard flags
- critical: score ≥6 OR hard flag triggered

### 6.4.4 Deduplication and cooldown
- Same incident signature (process_identity + key signals) should not re-alert more than once per cooldown window (default 30 minutes).
- Continues to update the existing incident record with new evidence.

---

## 6.5 verify

### 6.5.1 Verification steps (offline-first)
Run on anomaly:
- signature verification (signed/unsigned, publisher, chain status if available)
- local reputation rules (built-in heuristics)
- optional local AV/Defender scan adapter (if available)

### 6.5.2 Adapter contract (MVP)
Each adapter receives:
- file_path
- file_hash (if computed)
- context (incident_id, process_identity)

Returns:
- verdict: clean | suspicious | malicious | unknown | error
- evidence: array of {key, value}
- timestamp
- duration_ms

### 6.5.3 Caching
- Cache verification results by file_hash for a TTL (default 7 days).
- Do not re-scan identical hashes within TTL unless forced.

### 6.5.4 Timeouts
- Total verification budget per incident: configurable (default 30s).
- If exceeded, return partial results and mark verification as incomplete.

---

## 6.6 reporting

### 6.6.1 Report outputs (MVP)
- JSON (machine-readable)
- HTML (human-readable)
- optional text summary for console

### 6.6.2 Plain-language summary template
Must include:
- What happened
- Why it matters (in simple terms)
- What changed vs baseline (bullets)
- What Scanner checked (verification steps)
- Recommended next steps (safe actions)

### 6.6.3 Technical appendix (optional)
- raw signals, scores
- parent chain snapshot
- network endpoints (best-effort)
- verification adapter outputs
- links to local event IDs (if present)

---

## 6.7 service (orchestrator)

Responsibilities:
- start/stop module lifecycle
- schedule polling/event subscriptions
- manage local storage, retention, and compaction
- baseline mode transitions (learning → monitor)
- enforce performance budgets (sampling/caps)
- handle incident lifecycle and dedupe/cooldown

---

## 7. Storage, Data Model, and Retention

### 7.1 Storage (MVP)
- SQLite recommended for local persistence (single-file DB).
- Alternate: JSONL files (acceptable for prototype, not recommended for production).

### 7.2 Identifiers
- host_id: stable machine identifier (generated at first run)
- event_id: UUID
- incident_id: UUID
- baseline_version: integer increment per commit
- whitelist_version: integer increment per change set

### 7.3 Tables / entities (MVP)
telemetry_event
- event_id, host_id, ts, type
- pid, ppid
- image_path, signer_publisher, product_name, file_hash (optional)
- network fields (best-effort): dest_ip, dest_host, port, protocol, bytes_out, bytes_in
- resource fields (optional): cpu_pct, mem_bytes, disk_read_bytes, disk_write_bytes

baseline_profile
- baseline_version, host_id, process_identity fields
- feature stats (percentiles, parent buckets, known ports)
- confidence, observation_count, last_updated_ts

whitelist_entry
- whitelist_version, host_id
- scope: program_allow | behavior_allow | temporary_allow
- match fields (path, signer, hash optional, behavior fields)
- rationale, source (tool/user), approved_ts, expires_ts (nullable)

incident
- incident_id, host_id, created_ts, updated_ts
- severity, score, state
- process_identity fields
- summary_plain, summary_html (optional), summary_json
- key_signals (array)
- baseline_version_at_time, whitelist_version_at_time

verification_result
- incident_id, adapter_name, ts, duration_ms
- verdict, evidence_json
- cache_key (hash), cache_expires_ts

### 7.4 Retention policy (MVP defaults)
- telemetry_event: 7 days rolling
- incidents + verification: 90 days
- baselines/whitelists: keep last 10 versions

---

## 8. Performance Budgets (Non-Functional, measurable)

Default budgets (MVP targets):
- CPU: average < 2% on idle; burst < 10% for < 5s during verification
- Memory: < 400MB resident (service)
- Disk: DB size cap 500MB rolling (configurable)
- Telemetry write rate: capped; drop or sample if exceeded

---

## 9. Safety, Threat Model, and Limitations

### 9.1 Safety defaults
- No automatic destructive actions in MVP.
- Recommendations should be “safe steps” (e.g., investigate, quarantine manually via OS/AV, upload to your internal analysis workflow).

### 9.2 Threat model (MVP assumptions)
- If malware has admin/system privileges, it may disable or mislead Scanner.
- Scanner is not a replacement for EDR; it is a local behavioral monitor + explainable alerting tool.

### 9.3 Tamper awareness (lightweight)
- Detect if service stops unexpectedly and record an event.
- Optional: self-integrity check (hash of Scanner binaries/config) and report mismatch.

---

## 10. Repo Layout (Suggested)

pc-scanner/
  src/
    engine/
      collector/
      baseline/
      whitelist/
      anomaly/
      verify/
      reporting/
      service/
      common/
  profiles/
  rules/
  tests/
  docs/
  build/

---

## 11. Acceptance Criteria (MVP, deterministic)

1) Runtime stability
- Service runs 24h with no crashes and respects retention caps.

2) Baseline persistence
- After learning, baseline is reused across restart and baseline_version remains stable.

3) Detection scenarios (must pass all)
- Scenario A: unsigned executable launched from a user-writable directory makes an outbound connection → critical incident.
- Scenario B: unusual parent chain (e.g., office app → shell) without allowlist → warning/critical depending on score.
- Scenario C: sustained resource spike from a new process_identity above baseline p90 for N intervals → warning incident.

4) Verification execution
- At least one verification adapter runs and returns a normalized verdict; caching prevents repeat scans for identical hashes.

5) Reporting quality
- User receives a plain-language summary that includes: what changed vs baseline, what was checked, and safe next steps.

---

## 12. Test Strategy (Initial)

- Unit tests:
  - process_identity normalization
  - whitelist matching
  - score aggregation + severity mapping
  - baseline percentiles / threshold comparisons
- Integration tests:
  - telemetry → baseline → anomaly → verify → report pipeline
- Manual smoke tests:
  - run controlled scenarios A/B/C
  - validate overhead budgets via OS performance counters

---

## 13. Future Work (Post-MVP)

- UI viewer and interactive allowlisting workflow
- Better network attribution (where OS permits)
- Optional remote export (explicit opt-in) to internal SIEM
- Cross-platform collectors
- More robust tamper resistance (beyond MVP)

# Appendix A — Module Contracts (v0.1)

This appendix defines deterministic interfaces, shared types, and JSON schemas so implementation can proceed without interpretation.
Design goal: each module can be implemented/tested in isolation, connected via an in-process event bus + shared storage interface.

---

## A1) Shared Conventions

### A1.1 Timestamps, IDs, versions
- `ts`: ISO-8601 UTC string, e.g. `2026-02-13T12:34:56.789Z`
- `uuid`: RFC4122 v4 string
- `host_id`: stable UUID generated on first run and persisted
- `baseline_version`: integer, increments on commit
- `whitelist_version`: integer, increments on any change set

### A1.2 Severity and verdict enums
- `severity`: `info | warning | critical`
- `incident_state`: `open | acknowledged | resolved | false_positive`
- `verdict`: `clean | suspicious | malicious | unknown | error`

### A1.3 Process identity (canonical key)
`process_identity_key = sha256(lower(image_path_norm) + "|" + signer_norm + "|" + product_norm + "|" + hash_or_empty)`
- `image_path_norm`: normalized Windows path (see A2.2)
- `signer_norm`: publisher string or `unsigned`
- `product_norm`: optional product name or empty
- `hash_or_empty`: required for unsigned binaries in user-writable dirs (policy); otherwise empty string allowed

---

## A2) Shared Types (Data Shapes)

### A2.1 TelemetryEvent (base)
All telemetry is represented as events with `type` and a standard envelope.

```json
{
  "event_id": "uuid",
  "host_id": "uuid",
  "ts": "2026-02-13T12:34:56.789Z",
  "type": "process_start | process_stop | net_conn | resource_sample | service_state",
  "pid": 1234,
  "ppid": 567,
  "user": "DOMAIN\\user",
  "process": {
    "image_path": "C:\\Program Files\\App\\app.exe",
    "image_path_norm": "c:\\program files\\app\\app.exe",
    "signer_publisher": "Microsoft Corporation",
    "product_name": "AppName",
    "file_hash": "sha256hex",
    "identity_key": "sha256hex"
  },
  "data": {}
}

A2.2 Path normalization (Windows)

Implement NormalizePath(path):

    expand environment vars where possible

    resolve \\?\ prefix and normalize slashes to \

    collapse .. and .

    lowercase drive letter and the full string

    return best-effort; if fails, keep original lowercased

Define IsUserWritableDir(path_norm) (MVP heuristic):

    starts with:

        c:\\users\\

        %appdata% expanded paths: c:\\users\\<u>\\appdata\\roaming\\

        c:\\users\\<u>\\appdata\\local\\

        c:\\users\\<u>\\downloads\\

        c:\\windows\\temp\\ (treat as writable risk)

A2.3 ProcessEvent.data

    process_start:

{
  "command_line": "string (optional)",
  "session_id": 1
}

    process_stop:

{
  "exit_code": 0
}

A2.4 NetConnEvent.data

{
  "direction": "outbound | inbound",
  "protocol": "tcp | udp",
  "dest_ip": "1.2.3.4",
  "dest_host": "example.com (best-effort)",
  "dest_port": 443,
  "bytes_out": 12345,
  "bytes_in": 67890,
  "dns_query": "example.com (best-effort)"
}

A2.5 ResourceSampleEvent.data

{
  "cpu_pct": 12.3,
  "mem_bytes": 123456789,
  "disk_read_bytes": 123456,
  "disk_write_bytes": 654321
}

A3) Storage Contract (Local Persistence)

All modules depend on a single storage abstraction.
A3.1 IStorage interface (language-agnostic)

Init(db_path) -> void

PutTelemetryEvent(event: TelemetryEvent) -> void
QueryTelemetry(host_id, ts_from, ts_to, filters?) -> TelemetryEvent[]

PutBaselineProfile(profile: BaselineProfile) -> void
GetCurrentBaseline(host_id) -> BaselineSnapshot | null
ListBaselines(host_id, limit) -> BaselineSnapshotMeta[]

PutWhitelistEntry(entry: WhitelistEntry) -> void
UpdateWhitelistEntry(entry_id, updates) -> void
GetWhitelistSnapshot(host_id) -> WhitelistSnapshot

PutIncident(incident: Incident) -> void
UpdateIncident(incident_id, updates) -> void
GetIncident(incident_id) -> Incident | null
FindOpenIncidentBySignature(host_id, signature) -> Incident | null
ListIncidents(host_id, ts_from?, ts_to?, state?, severity?, limit?) -> Incident[]

PutVerificationResult(result: VerificationResult) -> void
GetCachedVerification(cache_key) -> VerificationResult | null

EnforceRetention(policy: RetentionPolicy) -> RetentionStats
Vacuum/Compact() -> void (optional)

A3.2 RetentionPolicy

{
  "telemetry_days": 7,
  "incidents_days": 90,
  "max_baseline_versions": 10,
  "max_whitelist_versions": 50,
  "max_db_mb": 500
}

A4) Module Contracts
A4.1 collector
Responsibilities

    emit TelemetryEvents from OS sources

    support event-driven primary + polling fallback

    respect sampling/caps

Interface

Start(config: CollectorConfig, emit: (TelemetryEvent) -> void, log: (LogEvent)->void) -> CollectorHandle
Stop(handle: CollectorHandle) -> void
Health(handle) -> CollectorHealth

CollectorConfig (core)

{
  "process_poll_interval_seconds": 2,
  "resource_poll_interval_seconds": 5,
  "network_poll_interval_seconds": 10,
  "capture_command_line": false,
  "max_events_per_minute": 6000
}

A4.2 baseline
Responsibilities

    maintain learning window

    compute per-process_identity stats and confidence

    commit baseline snapshot version

Interface

Ingest(event: TelemetryEvent) -> void
GetMode(host_id) -> "learning" | "monitor"
ShouldCommit(host_id, now_ts) -> boolean
Commit(host_id, now_ts) -> BaselineSnapshotMeta
LoadCurrent(host_id) -> BaselineSnapshot | null
EvaluateConfidence(process_identity_key) -> float

BaselineSnapshot (structure)

{
  "host_id": "uuid",
  "baseline_version": 3,
  "created_ts": "2026-02-13T00:00:00Z",
  "learning_window_days": 7,
  "process_profiles": {
    "identity_key": {
      "image_path_norm": "string",
      "signer_publisher": "string|unsigned",
      "product_name": "string",
      "observation_count": 1234,
      "confidence": 0.83,
      "launch_freq": { "per_hour_p50": 0, "per_hour_p90": 2 },
      "parents": { "allowed_parent_keys": ["sha256..."], "novelty_budget": 0 },
      "network": {
        "ports_seen": [80, 443],
        "dest_patterns": ["*.microsoft.com", "ip:1.2.3.0/24 (optional)"]
      },
      "resources": {
        "cpu_pct_p50": 1.2, "cpu_pct_p90": 12.0,
        "mem_bytes_p50": 50000000, "mem_bytes_p90": 200000000
      }
    }
  }
}

A4.3 whitelist
Responsibilities

    store allow rules (program/behavior/temporary)

    enforce safety rails

    versioned snapshots for reproducibility

Interface

MatchProgram(process: ProcessIdentity) -> WhitelistMatchResult
MatchBehavior(process: ProcessIdentity, net: NetConnEvent.data) -> WhitelistMatchResult
List(host_id, active_only?) -> WhitelistEntry[]
ProposeCandidates(baseline: BaselineSnapshot) -> WhitelistEntryDraft[]
Add(host_id, entry: WhitelistEntryDraft, approved_by: "user"|"tool") -> WhitelistEntry
Disable(entry_id, reason) -> void
GetSnapshot(host_id) -> WhitelistSnapshot

WhitelistEntryDraft/Entry

{
  "entry_id": "uuid",
  "host_id": "uuid",
  "whitelist_version": 12,
  "scope": "program_allow | behavior_allow | temporary_allow",
  "match": {
    "image_path_norm": "c:\\program files\\app\\app.exe",
    "signer_publisher": "Microsoft Corporation|unsigned",
    "file_hash": "sha256hex (required for unsigned in writable dirs)",
    "behavior": {
      "protocol": "tcp",
      "dest_port": 443,
      "dest_pattern": "*.example.com (optional)"
    }
  },
  "rationale": "string",
  "source": "user|tool",
  "approved_ts": "ts",
  "expires_ts": "ts|null",
  "is_enabled": true
}

Safety rail checks (must implement)

    deny if missing signer+path in program_allow

    deny name-only matches

    if signer is unsigned and IsUserWritableDir(image_path_norm) then require file_hash

A4.4 anomaly
Responsibilities

    score signals per event and/or per rolling window

    open/update incidents with dedupe/cooldown

    produce explainable evidence

Interface

Evaluate(event: TelemetryEvent, baseline: BaselineSnapshot|null, whitelist: WhitelistSnapshot) -> AnomalyDecision[]
Tick(now_ts) -> void  // used for sustained signals/windowing

AnomalyDecision

Represents either: (a) “no incident” or (b) “open/update incident”.

{
  "action": "none | open_incident | update_incident",
  "incident_signature": "sha256hex",
  "process_identity_key": "sha256hex",
  "score": 7,
  "severity": "critical",
  "signals": [
    {"code": "UNSIGNED_IN_USER_WRITABLE_DIR", "points": 4, "evidence": {"path": "..."}}
  ],
  "cooldown_applied": false,
  "recommended_next_steps": ["string", "string"]
}

Scoring rules (MVP required)

Implement these signal functions:

    NEW_PROCESS_IDENTITY (not in baseline.process_profiles): +2

    UNSIGNED_IN_USER_WRITABLE_DIR: +4 (hard flag)

    UNUSUAL_PARENT_CHAIN (parent not in allowed_parent_keys): +3

    NEW_NETWORK_DESTINATION_PATTERN: +2

    UNUSUAL_PORT: +2

    RESOURCE_SPIKE_SUSTAINED: +2 (requires N consecutive samples, default N=3)

    BURST_LAUNCH_FREQUENCY: +2 (above baseline p90)

Severity mapping:

    info 1–2; warning 3–5; critical >=6 OR hard flag “unsigned+writable+outbound”

Dedupe/cooldown

    incident_signature = sha256(host_id + process_identity_key + sorted(signal_codes_topN) + key_context)

    if an open incident exists for signature:

        update evidence and updated_ts

        only emit alert output if now_ts - last_alert_ts > cooldown_minutes (default 30)

A4.5 verify
Responsibilities

    run offline verification steps

    call adapters (e.g., signature, Defender scan)

    cache by hash

Interface

Verify(incident: Incident, storage: IStorage, config: VerifyConfig) -> VerificationBundle
RegisterAdapter(adapter: IVerifyAdapter) -> void

VerifyConfig

{
  "total_timeout_seconds": 30,
  "cache_ttl_days": 7,
  "adapters_enabled": ["signature", "defender_optional"]
}

Adapter interface

Name() -> string
CanRun(context: VerifyContext) -> boolean
Run(context: VerifyContext, cancel_token) -> VerificationResult

VerifyContext

{
  "incident_id": "uuid",
  "host_id": "uuid",
  "file_path": "string",
  "file_hash": "sha256hex|null",
  "signer_publisher": "string|unsigned",
  "image_path_norm": "string"
}

VerificationResult

{
  "result_id": "uuid",
  "incident_id": "uuid",
  "adapter_name": "signature",
  "ts": "ts",
  "duration_ms": 120,
  "verdict": "unknown",
  "evidence": [{"key": "is_signed", "value": "false"}],
  "cache_key": "sha256(file_hash|file_path|adapter_name)",
  "cache_expires_ts": "ts"
}

A4.6 reporting
Responsibilities

    generate JSON + HTML incident reports

    ensure plain-language summary is always present

    write artifacts to disk

Interface

Render(incident: Incident, bundle: VerificationBundle, config: ReportConfig) -> ReportArtifacts
Write(artifacts: ReportArtifacts, out_dir) -> WrittenPaths

ReportConfig

{
  "include_technical_appendix": true,
  "formats": ["json", "html"]
}

ReportArtifacts

{
  "incident_id": "uuid",
  "host_id": "uuid",
  "ts": "ts",
  "json": { "..." : "..." },
  "html": "<html>...</html>",
  "plain_text": "string"
}

A4.7 service (orchestrator)
Responsibilities

    load config

    init storage

    start collector, baseline, anomaly, verify, reporting

    enforce retention and performance caps

    expose CLI endpoints

Interface

Run(config_path) -> exit_code
Stop() -> void
Status() -> ServiceStatus

ServiceStatus

{
  "host_id": "uuid",
  "mode": "learning|monitor",
  "baseline_version": 3,
  "whitelist_version": 12,
  "collector_health": {"ok": true, "last_event_ts": "ts"},
  "db_size_mb": 123.4
}

A5) Incident Type (stored entity)

{
  "incident_id": "uuid",
  "host_id": "uuid",
  "created_ts": "ts",
  "updated_ts": "ts",
  "last_alert_ts": "ts|null",
  "state": "open",
  "severity": "warning",
  "score": 4,
  "process": {
    "identity_key": "sha256hex",
    "image_path": "string",
    "image_path_norm": "string",
    "signer_publisher": "string|unsigned",
    "product_name": "string",
    "file_hash": "sha256hex|null",
    "pid": 1234,
    "ppid": 567
  },
  "baseline_version_at_time": 3,
  "whitelist_version_at_time": 12,
  "signals": [
    {"code": "UNUSUAL_PARENT_CHAIN", "points": 3, "evidence": {"parent": "..."}} 
  ],
  "summary_plain": "string",
  "recommendations": ["string"],
  "technical": {
    "event_ids": ["uuid", "uuid"],
    "network_endpoints": [{"dest_ip":"1.2.3.4","port":443}],
    "resource_samples": [{"cpu_pct": 12.3}]
  }
}

Appendix B — JSON Schemas (Draft 2020-12, minimal)
B1) scanner-config.schema.json (MVP)

{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "ScannerConfig",
  "type": "object",
  "required": ["collector", "retention", "verify", "reporting"],
  "properties": {
    "collector": {
      "type": "object",
      "required": ["process_poll_interval_seconds","resource_poll_interval_seconds","network_poll_interval_seconds"],
      "properties": {
        "process_poll_interval_seconds": {"type":"integer","minimum":1,"maximum":30},
        "resource_poll_interval_seconds": {"type":"integer","minimum":1,"maximum":60},
        "network_poll_interval_seconds": {"type":"integer","minimum":1,"maximum":120},
        "capture_command_line": {"type":"boolean"},
        "max_events_per_minute": {"type":"integer","minimum":100,"maximum":60000}
      }
    },
    "baseline": {
      "type":"object",
      "properties": {
        "learning_window_days": {"type":"integer","minimum":1,"maximum":30},
        "enable_drift": {"type":"boolean"},
        "drift_min_confidence": {"type":"number","minimum":0,"maximum":1}
      }
    },
    "anomaly": {
      "type":"object",
      "properties": {
        "cooldown_minutes": {"type":"integer","minimum":1,"maximum":1440},
        "resource_spike_intervals": {"type":"integer","minimum":2,"maximum":20}
      }
    },
    "verify": {
      "type":"object",
      "required":["total_timeout_seconds","cache_ttl_days"],
      "properties": {
        "total_timeout_seconds":{"type":"integer","minimum":5,"maximum":300},
        "cache_ttl_days":{"type":"integer","minimum":1,"maximum":30},
        "adapters_enabled":{"type":"array","items":{"type":"string"}}
      }
    },
    "reporting": {
      "type":"object",
      "properties": {
        "formats":{"type":"array","items":{"enum":["json","html","text"]}},
        "include_technical_appendix":{"type":"boolean"},
        "out_dir":{"type":"string"}
      }
    },
    "retention": {
      "type":"object",
      "required":["telemetry_days","incidents_days","max_db_mb"],
      "properties": {
        "telemetry_days":{"type":"integer","minimum":1,"maximum":90},
        "incidents_days":{"type":"integer","minimum":7,"maximum":365},
        "max_baseline_versions":{"type":"integer","minimum":1,"maximum":50},
        "max_whitelist_versions":{"type":"integer","minimum":1,"maximum":500},
        "max_db_mb":{"type":"integer","minimum":50,"maximum":5000}
      }
    }
  }
}

Appendix C — Implementation Checklist (v0.1)
C1) Build order (recommended)

    common/ types + normalization + hashing utilities

    storage/ SQLite schema + IStorage implementation + retention enforcement

    collector/ process start/stop + polling fallback → write telemetry_event

    baseline/ ingest + stats + commit baseline_version

    whitelist/ matching + safety rails + versioning

    anomaly/ scoring + dedupe/cooldown + incident creation/update

    verify/ signature adapter + caching

    reporting/ JSON + HTML renderer

    service/ orchestrator wiring + config loader + status command

    Tests for identity normalization, whitelist matching, scoring, retention

C2) CLI commands (minimum)

    scanner.exe status

    scanner.exe run --config path (foreground)

    scanner.exe install-service / uninstall-service (optional if you choose Service)

    scanner.exe export-report --incident <id>

Appendix D — VS Code Agent Task Definition (copy/paste)

You are implementing Scanner v0.1. Follow Appendix A contracts exactly.

    Do not invent new fields without updating schemas.

    Prioritize determinism: stable IDs, versioning, retention, and cooldown.

    Every incident must include signals with evidence and a plain-language summary.

    Implement in small PR-sized steps; each step must include at least one unit test.
    Deliverables:

    SQLite schema migrations

    IStorage implementation

    Module skeletons with interfaces

    A minimal end-to-end pipeline that triggers Scenario A (unsigned in user-writable dir + outbound) as critical.
