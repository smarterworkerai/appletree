# Appletree ADW Adapter

This repository uses Agentic Delivery Workflow contract v2 with `pzagent-adw-context`. Machine-critical values live in `.hermes/adw-task-manifest.json` and `.hermes/pzagent-adapter.json`; this file records only lifecycle and operator guidance.

## Release lines

- `main` owns production.
- `demo` owns demo.
- Feature branches fork from `demo` and may use the isolated PR-preview target.
- Promotion is `feature → demo → main`, always through reviewed PRs.

## Validation

- Fast branch feedback: `mise run adw:verify:minimal`
- Full required quality graph: `mise run adw:verify:full`
- Contract validation: `mise run adw:check`
- Context integrity: `mise run adw:context:check`
- Optional production-image integration: `mise run adw:test:integration:full`

The full quality graph builds the Vite bundle, checks syntax and repository hygiene, validates the project descriptors, runs adapter unit tests, and executes a local HTTP integration smoke. CI invokes the same canonical tasks.

## Deployment lifecycle

The project adapter declares one active Dokploy target for PR-preview, demo, and production. Provider discovery uses logical project/environment/resource names at runtime; mutable IDs and credentials are never stored in Git.

Normal deployment consumes an immutable application release manifest and digest-pinned image through the shared pzagent deployment engine. Preview hotfixes are separately authorized temporary operations and may use the allowlisted `pr-preview` SSH alias; demo and production hotfixes are forbidden. Project hooks may build artifacts and prove semantic state, but all provider writes, readback, locking, compensation, and pointer promotion remain owned by the shared engine.

Public routes:

- preview: `https://appletree-preview.lan.smarterworker.cc`
- demo: `https://appletree-demo.smarterworker.cc`
- production: `https://appletree.smarterworker.cc`

## Recovery

A failed shared deployment restores the prior Environment bytes and redeploys only when the safety engine can still prove exclusive ownership of the image key. Otherwise stop for manual recovery. Preview hotfix restore requires the exact private restore artifact and fresh approval.

## Project pitfalls

- Keep Dokploy routing out of Compose service labels; domains are platform-owned.
- `APPLETREE_IMAGE` must be an immutable GHCR digest for normal releases.
- Never put Dokploy IDs, endpoints, tokens, SSH resolution, or secret values in repository files.
- Do not treat successful static-site HTTP response as image identity proof; runtime proof must also match the expected image assignment.
