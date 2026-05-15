# Agent Session Protocol

Version: 1.0  
Owner: You

## Purpose
Define how a human and a local code agent coordinate using this repo’s memory files so every session starts with shared context and ends with consistent writeback.

## Memory Files
- Long-term memory (LTM): `docs/PROJECT_CONTEXT.md`
- Working memory (WM): `docs/NOW.md`
- Session memory (SM): `docs/SESSION_NOTES.md`
- Design notes: `docs/MCP_LOCAL_DESIGN.md`

## Canonical Artifact
- `SPEC.md` is the source of truth for implementation.
- Architect creates/updates it; everyone else must follow it.

## Handoff Loop
Architect -> Coder -> Reviewer <-> Coder (until pass) -> QA -> Polish

## Hard Anti-Drift Rules
Every handoff prompt must include:
- Invariants (non-negotiables)
- SPEC.md (full or excerpt)
- Only relevant code snippets/diff

Reviewer rule:
- Reviewer must not redesign; only evaluate against SPEC.md, best practices, and current docs (Context7).

Context update gate (mandatory after each implementation step):
- Do not start the next step/ticket until context writeback is done.
- Minimum writeback:
  - Update `docs/NOW.md` progress/checklist and immediate next action.
  - Append a short entry to `docs/SESSION_NOTES.md` with what changed and why.
  - Update `docs/PROJECT_CONTEXT.md` only when high-level constraints/decisions changed.
- If pausing work, ensure `NOW.md` includes a restart-ready "next command/action".

## Start Session (Context Hydration)
Preferred: review the memory docs directly, or use the utility tasks in `.vscode/tasks.json` for tests and smoke runs.

Agent instructions:
1. Read (in order): `docs/PROJECT_CONTEXT.md`, `docs/NOW.md`, `docs/SESSION_NOTES.md` (recent).
2. Summarize context in 3–6 bullets.
3. Wait for the next instruction.

## End Session (Writeback + Checkpoint)
Preferred: update the docs directly in the workspace, then commit with normal Git commands if you want a checkpoint.

Human steps:
1. Add 2–5 bullets describing what happened this session (what changed, why).
2. Let the agent update the memory files in the workspace.
3. Commit the result if you want a checkpoint.

Writeback expectations:
- `docs/PROJECT_CONTEXT.md`: update only when higher-level decisions/constraints changed; refresh summary blocks if present.
- `docs/NOW.md`: update immediate next steps and current focus; refresh summary blocks if present.
- `docs/SESSION_NOTES.md`: append a new dated entry (do not overwrite previous entries).
