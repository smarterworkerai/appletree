# appletree

A Three.js scene with a stylized apple tree, served as a static application.
A layered sun disc stays in camera space and follows the upper-right view as the
viewport changes.

## Development and validation

Use the toolchain declared in `mise.toml`. Node builds the static app; pinned
ORAS supports operator registry tasks, and Docker is an operator prerequisite.
The committed `mise.lock` records tool downloads for CI. When changing tool
pins in `mise.toml`, refresh the lock with `mise lock` and commit both files
before hosted quality so installation leaves the checkout clean:

```bash
mise run adw:install
mise exec -- npm run dev
mise run adw:verify:full
```

The required graph builds the Vite application, checks source and delivery
configuration, runs unit tests for the page/asset validator and the actual Three.js
sun scene, and serves the compiled output for an HTTP and real Chromium smoke. It verifies
the page title and compiled assets, initializes the WebGL scene at 1280×720,
then resizes to 800×600 and checks the drawing buffer and screenshots.
`adw:install` installs the pinned Playwright SDK's Chromium headless shell.
The local smoke uses an ephemeral loopback server and makes no billable calls. The optional `adw:test:integration:full` builds
and probes the actual container and runs only when explicitly requested.

## Delivery

[Project guidance](.adw/ADW.md) describes the release lines and operator steps.
The single `web` component has an immutable image and application manifest.
Reviewed feature candidates advance to `demo`, then the same source advances to
`main`, through `pz:release:promote`. Publication uses the canonical GitHub
workflow and its exact quality producer; deployment uses the public tasks.

The environment definitions in `infra/dokploy/` reference an operator-owned
`APPLETREE_IMAGE` digest. Existing Dokploy routing and resource names are
preserved. The static app has no application secrets, database, storage or
telephony. Provider credentials and routed probe origins stay in the private
operator environment, and example files contain empty values.

No old registry mapping, pointer retirement or package deletion is part of this
onboarding. The archive tag preserves the prior onboarding source.

Publication reuses compatible compiled CI output when available. A proof-only
main-promotion run instead uses the canonical release build, which produces the
verified handover before packaging the runtime image. Local development and
quality builds continue to compile the Vite page without creating a release.

Routed readiness identifies page and asset requests consistently with the bundled
probe, and verifies the page contract and actual compiled dependencies.

Delivery uses the released context pin in `.adw/pzagent-context-lock.json`.
The v0.17.1 pin also includes `.adw/pzagent-context-release.json`: the signed
provider statement and signature, verified by tagged sync and the offline
trust-root controller. Its provider-token lookup and workflow secret input are
removed. Signed upgrades from v0.17.0 use one sync;
[.adw/ADW.md](.adw/ADW.md) records the initial adoption procedure.

The released runtime can resume a failed delete after rechecking the same owned
resource, retains private Kubernetes failure diagnostics, and reads Dokploy handover
credentials only from the top-level `env:` block in the operator profile.
Diagnostics distinguish absent provider bindings from duplicate matches and name
missing image-variable keys to restore before deployment.
The runtime verifies that each Compose resource matches its declared placement.
Omitted placement uses remote semantics; manager-local targets require explicit
local placement and a recorded manager identity for cleanup.
All three targets opt into routed source identity:
the runtime image bakes the release recipe's selected source SHA into
`/.well-known/adw-release.json`, served as JSON with `Cache-Control: no-store`.
Deployment checks that marker before advancing pointers; status compares it
with the current manifest source. A wrong SHA or missing marker refuses even
when container digest parity passes. The marker contains no credentials or
operator input. Local page builds and the scene remain unchanged.

The declared preview `adw:test:e2e:fast` and `adw:test:e2e:full` tasks use the
project browser hook against the private adapter-bound origin. Fast executes
one WebGL scene check; full also executes the resize check. Both require
nonempty execution with zero skips and retain the canonical source, target and
operator-approval gates. These routed tests are operator-triggered; local
compiled-page browser validation is part of `adw:test:integration:fast`.
No provider mutation or deployment is part of browser validation.
