# Appletree delivery adapter

This project uses `pzagent-adw-context`. Machine facts are in
`pzagent-adapter.json` and `adw-task-manifest.json`; exact released pins are in
`pzagent-context-lock.json`. Read the vendored `policy.md` before delivery work.

The v0.17.1 context pin includes `.adw/pzagent-context-release.json`, containing
the signed provider statement and signature. Tagged context sync verifies it;
local checks bind it to the lock, and the controller verifies it offline with
the pinned provider key. The provider-token lookup and workflow secret input
are removed. First adoption from an updater older than v0.17.0 needs two canonical
syncs with a repin commit between them; later signed upgrades use one sync.

## Release lines

Feature candidates target `demo`; a separately reviewed same-source companion
promotes `demo` to `main`. Use `mise run pz:release:promote` for both transitions.
Publishing and deployment remain separate operator decisions under the plan.

Temporary hotfix apply and restore are unsupported: this project has no hotfix
build hook. Changes use the immutable release workflow and separately approved
deployment.

## Application and quality

The static Three.js app produces one `web` component. It has no database,
persistent storage, application secrets or telephony. Docker recipes and output
mappings live in `pz-release.json`; Java is not a build dependency.

Run `mise run adw:check` and `mise run adw:context:check` before deterministic
work. The required committed gate is `mise run adw:verify:full`: Vite build,
hygiene, syntax/configuration analysis, page-validator unit tests and an HTTP
smoke of the real compiled page and all script/style assets, followed by
Chromium WebGL rendering and viewport-resize checks on an ephemeral loopback
server. Installation includes the pinned SDK's Chromium headless shell. Optional full
container integration runs only when requested. No billable test is needed.

## Existing provider resources

The adapter binds the existing project and three Compose applications by logical
name. All three are declared active after canonical explicit adoption confirmed
the existing project, environments and Compose apps without provider mutations.
Adoption never grants deletion ownership.
Keep private journals in the operator home. Existing resources are re-adopted
without mutation after a context repin, then examined and claimed only after
approval of the exact report. The claim changes description markers and private
journals only. Never recreate resources or change DNS/TLS as part of onboarding.

Shared Dokploy project ownership is recorded once for the repository. Other
targets reference that claim; environment and Compose claims stay scoped to
each target. Private Dokploy journals can be rebuilt from intact live ownership
markers without provider writes. Every new claim still requires a fresh
examination and approval of its exact digest.

Actual routed origins are private operator inputs named `APPLETREE_PREVIEW_URL`,
`APPLETREE_DEMO_URL` and `APPLETREE_PRODUCTION_URL`. They are not application
settings. Readiness retains the bundled request validation and verifies the
routed page title, scene canvas and compiled assets. Digest parity and container
health are still proven by the shared provider runtime hook.

After CI publication, apply reviewed configuration and perform a separate
`pz:workflow:deploy-existing --verify` using the exact immutable release. The
first deployment does not combine configuration with `--sync-config`. Verify
status, health, readiness and runtime/manifest/current parity for each target.
Use the recorded prior release for approved recovery when available; never
invent a prior pointer or image to bypass an identity refusal.

The archive tag preserves the old onboarding. Old pointer mapping, retirement
and package deletion are cancelled. Any rollback, unrelated setting change or
new approval scope requires its own decision.

## Routed release identity

`.adw/routed-content.json` opts all three declared targets into the shared source
check using their existing probe environment keys. The release packager passes
its selected source as `APPLICATION_SHA`; the runtime recipe validates it and
bakes the JSON marker after copying the compiled page. Nginx serves the exact
marker route without SPA fallback or persistent caching. The marker is checked
against the artifact source before deployment pointers advance and against the
current manifest source during status. A wrong source or absent marker refuses.

Probe origins live in `<operator-home>/profile/probes.json`; workflows are
addressed by `--operation <id>` under `<operator-home>/journals/`. The removed
operation-directory flags are not used. Each release-line promotion still needs
an exact-head review, and each ownership claim needs its exact examined digest
approved before metadata writes.

## Browser E2E

Preview E2E uses the project-owned browser hook. It preserves the bundled
active-target and routed-origin validation, checks the page and assets, then
launches Chromium with no provider credentials. Fast executes the initial
WebGL scene check; full also verifies resize. The hook accepts only exact,
nonempty executed counts with zero skips and returns safe reason codes on
failure. Canonical source binding and operator approvals remain required.
The Appletree scene makes no billable calls. Routed E2E is operator-triggered;
the local integration smoke exercises the compiled scene without provider access.
