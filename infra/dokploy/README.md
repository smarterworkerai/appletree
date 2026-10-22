# Existing static application targets

The adapter binds the existing project and three environment-specific Compose
apps. Canonical explicit adoption confirmed all roles as adopted with zero
provider mutations; it grants no deletion ownership. Keep operator journals
outside the checkout and preserve existing routing, TLS and volumes.

Each definition serves the existing `appletree` service on internal port 3333.
Dokploy owns the public route; no service labels or host port mapping are added.
`APPLETREE_IMAGE` is the sole provider image setting and must resolve to the
published immutable `web` component. Key schemas and empty examples document
only that key. There are no application secrets or persistent data.

Apply reviewed configuration through `adw:deploy:config:apply`, then deploy the
CI-published manifest in a separate `pz:workflow:deploy-existing --verify`
invocation. The first deployment does not use `--sync-config`. Deployment must
prove exact runtime/manifest/current parity, container health and routed
readiness, including the compiled script and stylesheet assets.

Actual origins are private values named `APPLETREE_PREVIEW_URL`,
`APPLETREE_DEMO_URL` and `APPLETREE_PRODUCTION_URL`. They are probe inputs,
never Compose or application settings. New release pointers start with this
onboarding; old package mapping, pointer retirement and deletion are cancelled.
