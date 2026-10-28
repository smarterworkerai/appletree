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
or preview permission grants no production approval. Signed released repins need
no consumer provider-token secret. Trust-root decisions follow the standing rule
below; `BOOTSTRAP_DISABLED` and revocation remain human-only.

Do not print or overwrite secrets. Values stay in the private operator inputs
or provider Environment; tracked examples contain empty values only. Endpoints,
SSH resolution and opaque provider IDs stay private. An approved hostname may
appear only in the tracked `infra/` deployment/routing definition when that is
its declared source of truth; do not copy it into adapter prose or vendor files.

Deployment success requires artifact identity, deployment status, project-specific
smoke/E2E evidence, and runtime/manifest/current digest parity. Keep the prior
immutable release and private operation ID for canonical recovery.

## Trust-root standing pre-approval

Effective with provider v0.17.0, after the v0.16.0 repins are complete. Repository
rules must adopt this exception before an agent uses it. `BOOTSTRAP_DISABLED` and
revoking this rule remain administrator decisions.

ADW trust-root standing pre-approval (administrator, from 2026-10-28 until revoked)
An agent may post `BOOTSTRAP_ENABLED <fingerprint>` on a PR in any smarterworkerai
ADW repository when all of these hold:

1. An agent that did not author the head posted an approving exact-head review
   verdict for that head on the PR.
2. The poster recomputed the fingerprint itself, it equals the controller's
   expected line, and the comment body is only that line.
3. The trusted diff is one of:
   a) an exact published provider release (any number of trusted files) or its
      demo->main promotion;
   b) a change to consumer-owned trusted files (the ADW task manifest).
   Unreleased provider code is never pushed to a consumer; it reaches GitHub only
   as the next published release.

Never after an administrator BOOTSTRAP_DISABLED for that fingerprint. Anything else:
don't post; report on the PR and continue with other work.
