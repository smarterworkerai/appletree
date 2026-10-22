# appletree

A Three.js scene with a stylized apple tree, served as a static application.

## Development and validation

Use the toolchain declared in `mise.toml`:

```bash
mise run adw:install
mise exec -- npm run dev
mise run adw:verify:full
```

The required graph builds the Vite application, checks source and delivery
configuration, runs unit tests for the page/asset validator, and serves the
compiled output for an HTTP smoke. It verifies the scene canvas, page title and
all compiled script/style assets. The optional `adw:test:integration:full` builds
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
