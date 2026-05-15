# Project Context – Long-Term Memory (LTM)

> High-level design, tech decisions, constraints for this project.  
> This is the **source of truth** for agents and humans.

<!-- SUMMARY_START -->
**Summary (auto-maintained by Agent):**
- Project has pivoted from a memory-template repo to `scanner`, a local/offline background security monitor.
- The tool builds a baseline of process, network, and resource behavior before classifying anomalies.
- Fit-for-purpose whitelisting is generated from tool knowledge plus explicit user review and approval.
- Suspicious behavior triggers local verification scans and plain-language risk summaries for non-technical users.
- Verification is moving from MVP stubs to real Windows-native checks, starting with Authenticode.
- MVP platform scope is now Windows-first to reduce implementation risk.
<!-- SUMMARY_END -->

---

## 1. Project Overview

- **Name:** scanner
- **Owner:** TBD
- **Purpose:** Build a local, offline security tool that runs in the background, learns normal system behavior, and warns users about unusual activity in language they can understand.
- **Primary Stack:** Python runtime + local system telemetry + local signature/rule scanners + Markdown/Git project memory.
- **Target Platforms:** Windows-only for MVP (Windows 10/11 and Server 2019+), with cross-platform collectors deferred post-MVP.

---

## 2. Core Design Pillars

- Local and offline by default.
- Explain findings in simplified, layman-friendly terms.
- Build trust through transparent baseline and whitelist decisions.
- Use defense-in-depth by combining behavioral anomaly checks with known-threat scanning.
- Keep memory/docs versioned and explicit for human-agent collaboration.

---

## 3. Technical Decisions & Constraints

- Language(s): Python for monitoring/analysis tooling; Markdown for project memory/docs.
- Framework(s): Lightweight local services/CLI; avoid cloud-managed dependencies.
- Database / storage: Local-only telemetry/baseline store (SQLite or local files), plus Git-tracked docs.
- Hosting / deployment: Local install and background service/daemon operation.
- Non-negotiable constraints:
  - No mandatory cloud connectivity.
  - No automatic destructive response actions without explicit user approval.
  - Documentation stays in plain Markdown for easy review.
  - Handoffs require SPEC + Invariants to reduce drift.

---

## 4. Memory Hygiene (Drift Guards)

- Keep this summary block current and <= 300 tokens.
- Move stable decisions into the Change Log so they persist across sessions.
- Keep NOW to 5–12 active tasks; archive or remove completed items.
- Roll up SESSION_NOTES into summaries weekly (or every few sessions).

---

## 5. Architecture Snapshot

- Background telemetry collector captures:
  - Process starts/stops and command lineage
  - Network endpoints/volumes
  - Resource usage patterns (CPU, memory, I/O)
- Baseline engine learns expected behavior over a configurable observation period.
- Fit-for-purpose evaluator compares observed behavior against generated whitelist + user-approved exceptions.
- Verification pipeline runs local antivirus/signature/rule-based checks when anomalies are detected.
- Notification/reporting engine outputs plain-language summaries with actionable user guidance.
- Project docs continue to serve as coordination memory for development.

---

## 6. Links & Related Docs

- Roadmap: TBD
- Design docs: `docs/MCP_LOCAL_DESIGN.md`, `docs/AGENT_SESSION_PROTOCOL.md`
- Specs: `SPEC.md`, `docs/Repo_Structure.md`
- Product / UX docs: `docs/PROJECT_CONTEXT.md`, `docs/NOW.md`
- Invariants: docs/INVARIANTS.md

---

## 7. Change Log (High-Level Decisions)

Use this section for **big decisions** only:

- `2026-02-04` – Require SPEC + Invariants in handoff packs and add preflight validation.
- `2026-02-13` – Reposition project to build `scanner`, an offline background security monitoring tool with baseline + whitelist + anomaly verification flow.
- `2026-04-22` – Start replacing verification stubs with real Windows-native checks; Authenticode lands first, Windows Defender is the next planned adapter.
