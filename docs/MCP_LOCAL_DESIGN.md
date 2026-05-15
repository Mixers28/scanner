# Local MCP Design – Files as Memory

Version: 0.2  
Owner: You

## Purpose
This repo uses **plain files + Git** as a structured, persistent memory system for humans and AI coding agents. It is “MCP-like” in spirit (explicit context hydration + writeback), but stays fully local and transparent.

Goals:
- Give agents durable, version-controlled memory.
- Keep memory fully local, inspectable, and editor-friendly.
- Make the workflow portable across projects.

## Memory Layers
We treat `docs/` as a small set of memory layers:
- **Long-term memory (LTM)**: `docs/PROJECT_CONTEXT.md` (constraints, design, decisions)
- **Working memory (WM)**: `docs/NOW.md` (current focus, next steps)
- **Session memory (SM)**: `docs/SESSION_NOTES.md` (append-only timeline)
- **Index/meta memory (IM)** (optional): future extensions (indexes, search, embeddings)

## Summary Blocks
Some docs include an agent-maintained summary block:
```markdown
<!-- SUMMARY_START -->
...summary content...
<!-- SUMMARY_END -->
```

Rules:
- Owned by the local code agent.
- Keep it ~3–8 bullets and easy to diff.
- Humans can edit in emergencies, but normal flow is agent-maintained.

## Session Events
This system defines two explicit events:

### Start Session (“Context Hydration”)
Triggered by directly opening the core docs or using the utility tasks in `.vscode/tasks.json`.

Flow:
- You provide the relevant docs and task context to the agent.
- The agent reads `PROJECT_CONTEXT` → `NOW` → recent `SESSION_NOTES`, then summarizes context.

### End Session (“Writeback + Checkpoint”)
Triggered by updating the docs in the workspace and committing normally when needed.

Flow:
- You add brief notes for the agent (2–5 bullets).
- The agent updates memory files in the workspace.
- You commit and push separately if desired.

## Roles
- **Local code agent** (e.g., VS Code Code Agent): reads/writes repo files and keeps memory docs accurate and diff-friendly.
- **External assistant** (optional): can help with planning/review when provided context, but cannot see the workspace unless you paste files.

## Extensions (Optional)
If you extend the kit, keep the core principles (human-readable, Git-versioned, editor-native). Common additions:
- Per-branch session notes (e.g., `SESSION_NOTES_main.md`)
- A small context index file (e.g., `context_index.json`)
- Local search or embeddings tooling (kept out of the critical path)

## Design Philosophy
This kit is intentionally:
- **Simple on purpose** (no hidden state, no daemon)
- **Explicit** (start/end are conscious rituals)
- **Portable** (drop `docs/` + `pyproject.toml` + `.vscode/` into almost any repo)

It complements “real” MCP server implementations by offering a lightweight memory layer you fully control.
