# NOW - Working Memory (WM)

> This file captures the current focus / sprint.
> It should always describe what we're doing right now.

<!-- SUMMARY_START -->
**Current Focus (auto-maintained by Agent):**
- Sprints 0–6 complete. Core scanner, reporting, export, and service orchestration are implemented.
- Verification subsystem now has a real Windows Authenticode-backed `signature` adapter instead of the old stub.
- Full test suite is green at 227 tests plus 13 subtests.
- `handoffkit` has been removed from the active repo workflow; memory is maintained directly in docs.
- Next: add real malware validation adapters, starting with Windows Defender, then optional YARA.
<!-- SUMMARY_END -->

---

## Current Objective

Continue hardening the verification subsystem so it combines real signer trust evaluation with local malware detection on Windows.

---

## Active Branch

- `main`

---

## What We Are Working On Right Now

- [x] S5-T1: Verification adapter framework.
- [x] S5-T2: Verification cache and timeout budget.
- [x] S5-T3: Report renderer (JSON + HTML + text with plain-language summary).
- [x] S6-T1: Service orchestrator and status CLI.
- [x] S6-T2: Windows service runtime path (win_service.py, install/uninstall).
- [x] S6-T3: Soak and performance validation scaffold (tests/test_soak_performance.py).
- [x] export-report CLI command (src/scanner/__main__.py).
- [x] E2E pipeline integration tests covering Scenarios A/B/C (tests/test_e2e_pipeline.py).
- [x] Replace verification signature stub with a real Windows Authenticode-backed adapter.
- [x] Persist service status and verification evidence cleanly through CLI/report export paths.
- [x] Remove repo-local `handoffkit` workflow/tests and replace VS Code tasks with scanner-relevant utilities.

---

## Next Small Deliverables

- Add `WindowsDefenderAdapter` for real local malware scanning of suspicious files.
- Decide adapter verdict mapping and evidence schema for Defender detections, scan failures, and unavailable-engine cases.
- Add optional `YaraAdapter` behind config after Defender is stable.
- Run Windows-host smoke tests for Authenticode on a known Microsoft-signed binary, a known unsigned file, and a tampered sample if available.
- Manual 24h soak run on target Windows host: `PYTHONPATH=src python3 -m scanner run --db soak_test.db`
- Install pywin32 on Windows and smoke-test `PYTHONPATH=src python3 -m scanner install-service`.

---

## Drift Guards (keep NOW fresh)

- Keep NOW to 5–12 active tasks; remove completed items.
- After each completed step/ticket, run micro-checkpoint writeback (`NOW.md` + `SESSION_NOTES.md`).
- Refresh summary blocks every session.
- Move stable decisions into PROJECT_CONTEXT.

---

## Notes / Scratchpad

- Scanner is local/offline first; avoid cloud dependencies in MVP.
- Alerts must be interpretable by non-technical users before adding advanced detail.
- The `signature` adapter now shells to `Get-AuthenticodeSignature` on Windows and normalizes trust status into `clean` / `suspicious` / `unknown`.
- Immediate next coding slice: implement `WindowsDefenderAdapter`, then update export/reporting tests to show concrete malware-engine evidence.
