## Agentic Delivery Workflow

For ADW/release/deployment/test work in this repository:

1. Load generic ADW skill(s) from `agentic-delivery` for the requested stage.
2. Read `.adw/ADW.md` for this repository's concrete adapter.
3. Follow `mise-helper/vendor/pzagent-adw-context/policy.md` and use public
   `mise run adw:*` / `mise run pz:*` tasks for delivery operations. Do not
   replace their gates with raw API, Git ref or provider mutation commands.

Treat both committed `mise-helper/vendor/` trees as read-only released inputs;
repin them through the context sync workflow. Keep workflow copies byte-identical
to their pinned bundle templates. Put project facts in the adapter and project
command file rather than editing vendor code or CI gates.

Release lines are feature → demo → main even without a demo deployment target.
Never use the GitHub merge button; after exact-head maintainer approval use
`pz:release:promote` for fast-forward promotion. Initialization, a passing CI run
or preview permission grants no production approval. Trust-root comments
(`BOOTSTRAP_ENABLED` / `BOOTSTRAP_DISABLED`) require the human administrator’s
exact current fingerprint decision; do not manufacture one from CI or context.

Do not print or overwrite secrets. Values stay in the private operator inputs
or provider Environment; tracked examples contain empty values only. Endpoints,
SSH resolution and opaque provider IDs stay private. An approved hostname may
appear only in the tracked `infra/` deployment/routing definition when that is
its declared source of truth; do not copy it into adapter prose or vendor files.

Deployment success requires artifact identity, deployment status, project-specific
smoke/E2E evidence, and runtime/manifest/current digest parity. Keep the prior
immutable release and private operation ID for canonical recovery.
