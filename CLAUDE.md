# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

`scanner` is a local, offline-first Windows security monitor. It learns normal process/network/resource behavior during a baseline period, then flags anomalies in plain language for non-technical users. Key constraints from `docs/INVARIANTS.md`:

- No required cloud/backend dependency — fully offline MVP.
- No automatic destructive remediation in MVP — user must approve responses.
- Reports always lead with plain-language explanation; technical detail is secondary.
- `SPEC.md` is canonical. `spec_v01.md` is reference only. If they conflict, follow `SPEC.md`.

## Commands

```bash
# Install (editable, dev mode)
pip install -e ".[service,hub]"

# Run all tests
python -m pytest -q

# Run a single test file
python -m pytest tests/test_anomaly_scoring.py -q

# Run a single test by name
python -m pytest tests/test_anomaly_scoring.py::test_hard_flag_escalation -q

# Run scanner foreground (dev)
PYTHONPATH=src python -m scanner run --db scanner.db

# Check status
PYTHONPATH=src python -m scanner status --db scanner.db

# Export an incident report
PYTHONPATH=src python -m scanner export-report --incident <id> --db scanner.db --formats json,html,text

# Install / uninstall as Windows Service (requires pywin32)
PYTHONPATH=src python -m scanner install-service
PYTHONPATH=src python -m scanner uninstall-service

# Start hub server (multi-host mode, requires scanner[hub])
PYTHONPATH=src python -m scanner hub --api-key <key>

# Launch GUI dashboard (requires tkinter)
PYTHONPATH=src python -m scanner gui --db scanner.db
```

## Architecture

The pipeline runs as a single background process (foreground dev or Windows Service) orchestrated by `service/orchestrator.py`:

```
Collectors → Storage → Baseline → Anomaly → Verify → Reporting
```

**Module responsibilities:**

| Package | Purpose |
|---|---|
| `collector/` | Polls process starts/stops (`process_collector`), network connections (`network_collector`), and per-process CPU/mem/IO (`resource_collector`). `rate_limiter` caps event ingestion. |
| `storage/` | `SQLiteStorage` — single SQLite file, migration-versioned schema. Tables: `telemetry_event`, `baseline_profile`, `whitelist_entry`, `incident`, `verification_result`, `scanner_status`. |
| `baseline/` | `BaselineModeManager` transitions `learning → monitor`. `BaselineAggregator` computes frequency/parent/network/resource norms. `BaselineSnapshotStore` persists versioned profiles. |
| `whitelist/` | `rules.py` — three scopes: `program_allow`, `behavior_allow`, `temporary_allow`. `safety.py` enforces rails (no name-only rules; unsigned binaries in user-writable paths require hash). `proposals.py` auto-generates candidates from stable baseline behavior. |
| `anomaly/` | `signals.py` evaluates signal codes against baseline. `scoring.py` maps signal points → severity (`info/warning/critical`), with hard-flag escalation. `incidents.py` deduplicates and manages cooldown. |
| `verify/` | Adapter registry pattern (`adapters.py`). `windows_authenticode.py` shells to `Get-AuthenticodeSignature`. `cache.py` caches by file hash with TTL and enforces per-incident time budgets. |
| `reporting/` | `renderer.py` — `build_plain_language_summary` + `render_json/html/text`. Every report must include user-facing explanation fields. |
| `service/` | `orchestrator.py` — `ScannerService` wires the full lifecycle loop. `win_service.py` — pywin32 Windows Service wrapper. |
| `common/` | `types.py` — `Severity`, `IncidentState`, `Verdict` enums, `ProcessIdentity`, `TelemetryEvent`. `config.py` — `DEFAULT_CONFIG` + `validate_config`. `identity.py` — path normalization and identity key derivation. |
| `agent/` | `push.py` — `HubPushClient` forwards telemetry/incidents to an optional central hub. |
| `hub/` | `server.py` — FastAPI hub for multi-host aggregation (optional; `scanner[hub]` extras). |
| `gui/` | `app.py` — tkinter dashboard (optional; stdlib only). |

## Data flow detail

1. **`ScannerService.run()`** loops: collect → persist → baseline-ingest → anomaly-evaluate → verify → generate reports.
2. Baseline stats accumulate per `identity_key` (derived from normalized image path + signer). After the learning window, mode transitions to `monitor` and anomaly scoring activates.
3. An anomaly becomes an **incident** when `score_signals` assigns a severity. `IncidentManager` deduplicates by signature and applies cooldown before raising an alert.
4. Verification adapters run against suspicious file paths; results are cached by file hash to avoid redundant scans. Current adapters: `signature` (Authenticode). Next planned: `WindowsDefenderAdapter`.
5. Reports are rendered into `reports/` and can be re-exported any time via `export-report --incident <id>`.

## Context gate (mandatory after each ticket)

Per `docs/SPRINT_PLAN.md` rule 5, after every completed ticket:
- Update `docs/NOW.md` (progress + next action).
- Append to `docs/SESSION_NOTES.md` (what changed + why).
- Update `docs/PROJECT_CONTEXT.md` only if a high-level decision changed.

## Current sprint status

See `docs/NOW.md` for current focus. As of the last session: sprints 0–6 complete, 227 tests passing. Next work: `WindowsDefenderAdapter`, then optional YARA adapter.
