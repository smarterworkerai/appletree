# Migration notes

## 0.2.5

The unused Mise variable projection and its self-validating contract are removed. The package no longer ships `pzagent-context.toml`, declares `variable_entrypoint`, creates or validates `mise/conf.d/pzagent-context.toml`, or inventories `schemas/context-vars.schema.json`. Existing consumers should manually delete `mise/conf.d/pzagent-context.toml` when overlaying the `0.2.5` provider files; synchronization does not delete it.

## 0.2.4

Publication authorization no longer queries or requires GitHub review state. The fail-closed contract remains the authorized admin or maintainer actor, exact merged same-repository PR and source SHA, protected destination identity, and exact successful CI run and attempt. Publication authorization records no longer contain the misleading `reviewed_head` field.

## 0.2.3

Project-hook requests no longer include the independently changing context package version. Wire compatibility is governed by `schema_version`; exact source refs, package versions, and bundle checksums continue to prove bundle provenance. Consumers must remove `bundle_version` from closed hook keys and repin the full immutable bundle and lock together.

## 0.2.2

Destination quality proof now discovers candidates from the exact commit association with bounded propagation retries. The only fallback is scoped to adapter-declared promotion source/target identities; repository-wide closed pull-request scans are removed. Repin the full immutable bundle and lock together; do not alter an existing tag.

## 0.2.1

CI quality evidence reuse is independent of PR review state. Exact checkout tree, compatible contract, trusted proof source, successful required job, and merge ordering remain required. Publication authorization still checks review separately. Repin the full immutable bundle and lock together; do not alter an existing `0.2.0` tag.

## Read-only provider cutover

Consumers may source `adw:deploy:config:plan`, `adw:deploy:status`, `adw:health`, and `adw:readiness` from the context layer. The shared runtime owns capability/target validation, exact Dokploy discovery, credential handling, and redacted plan assembly. Project adapters retain provider logical names and tracked paths; narrow exact-HEAD hooks retain topology and semantic probe behavior. Dokploy credentials may be inherited from the active Hermes process or read from an explicit `--profile-root`. This does not enable any remote-write capability.

## 0.2.0

Initial experimental vendored runtime. Consumers must pin the exact release commit and checksums, add the generic → context → project include order, copy `pzagent-context.toml`, and provide the closed project adapter. The first v1→v2 adoption is one reviewed big-bang change (bundle, lock, manifest, adapter, project tasks, and committed GitHub workflow together), **not** an old-engine `context_sync.py` repin. The first PR has no trusted v2 base, so automatic proof is unavailable; run full quality, obtain independent review, and follow the explicit bootstrap merge gate. Subsequent v2 updates use the new runtime's immutable pin/checksum procedure. Future incompatible `0.x` releases require explicit adapter, hook, schema, task, and evidence review. Downgrade requires `--allow-downgrade`.
