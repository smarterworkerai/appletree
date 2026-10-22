<!-- pz:project:init:agents -->
## Agentic Delivery Workflow

For ADW/release/deployment/test work in this repository:

1. Load generic ADW skill(s) from `agentic-delivery` for the requested stage.
2. Read `.adw/ADW.md` for this repository's concrete adapter.
3. Follow the context-layer instructions declared in `.adw/ADW.md`.

Do not infer production approval from context alone. Do not print or overwrite secrets. Deployment success requires artifact identity, deployment status, project-specific smoke/E2E evidence, and revision/digest parity where applicable.
<!-- /pz:project:init:agents -->
