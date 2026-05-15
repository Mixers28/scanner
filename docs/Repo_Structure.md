scanner/
├── docs/
│   ├── AGENT_SESSION_PROTOCOL.md
│   ├── INVARIANTS.md
│   ├── MCP_LOCAL_DESIGN.md
│   ├── NOW.md
│   ├── PERSISTENT_AGENT_WORKFLOW.md
│   ├── PROJECT_CONTEXT.md
│   ├── Repo_Structure.md
│   └── SESSION_NOTES.md
├── .vscode/
│   └── ...
├── src/
│   └── scanner/
│       ├── agent/
│       ├── anomaly/
│       ├── baseline/
│       ├── collector/
│       ├── common/
│       ├── gui/
│       ├── hub/
│       ├── reporting/
│       ├── service/
│       ├── storage/
│       ├── verify/
│       └── whitelist/
├── tests/
│   └── ...
└── SPEC.md

Current runtime layout:

scanner/
└── src/scanner/
    ├── collector/      # process/network/resource telemetry collectors
    ├── baseline/       # behavior learning + baseline persistence
    ├── whitelist/      # fit-for-purpose evaluation + user-approved allow rules
    ├── anomaly/        # anomaly scoring/threshold logic
    ├── verify/         # signature and verification adapters
    ├── reporting/      # layman-friendly summaries and exports
    └── service/        # background loop/orchestration
