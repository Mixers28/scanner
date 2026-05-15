# Persistent Agent Workflow Design

This document is the source of truth for the persistent agent workflow.

Version: 1.0
Owner: You

## Purpose
This repo uses a local memory kit to enable a persistent agent workflow. The
goal is a predictable loop where humans and agents share the same context and
write back durable memory in Markdown.

## Core Ideas
- Keep memory in plain Markdown tracked by Git.
- Use direct doc review and normal Git workflow for explicit handoff.
- Keep everything local, stable-API only, and Windows-friendly.

## System Components
### Memory Files
- Long-term memory (LTM): `docs/PROJECT_CONTEXT.md`
- Working memory (WM): `docs/NOW.md`
- Session memory (SM): `docs/SESSION_NOTES.md`

### Session Protocol
- Start session: read LTM -> WM -> recent SM, then summarize context.
- End session: append session notes and update LTM/WM summaries.
- During session: after each step/ticket, run a micro-checkpoint writeback to NOW + SESSION_NOTES before continuing.

## Primary Workflows
1. Start a session by reviewing `docs/PROJECT_CONTEXT.md`, `docs/NOW.md`, and recent `docs/SESSION_NOTES.md`.
2. Provide instructions to the agent, using file or diff context when helpful.
3. After each completed step/ticket, update `docs/NOW.md` and append to `docs/SESSION_NOTES.md` (micro-checkpoint gate).
4. At session end, write back to memory docs and commit with normal Git commands if desired.

## Constraints
- CLI must run on macOS/Linux/WSL.
- No external services or network dependencies.

## Testing
- Manual smoke tests for doc-driven workflow and writeback flow.
