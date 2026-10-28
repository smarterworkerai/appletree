<!-- pz:project:init:agents -->
## Agentic Delivery Workflow

For ADW/release/deployment/test work in this repository:

1. Load generic ADW skill(s) from `agentic-delivery` for the requested stage.
2. Read `.adw/ADW.md` for this repository's concrete adapter.
3. Follow the context-layer instructions declared in `.adw/ADW.md`.

Do not infer production approval from context alone. Do not print or overwrite secrets. Deployment success requires artifact identity, deployment status, project-specific smoke/E2E evidence, and revision/digest parity where applicable.
<!-- /pz:project:init:agents -->

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
