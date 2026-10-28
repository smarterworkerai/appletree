# <Project> ADW Adapter

The project directory is `.adw/`, or `.hermes/` in existing projects. Both present refuse with `project_directory_conflict`; paths below use `.adw/`. Operator profile paths are unchanged.


This project uses `pzagent-adw-context`. Machine facts live only in `.adw/pzagent-adapter.json` (topology) and `.adw/adw-task-manifest.json` (capabilities); the exact context pin is `.adw/pzagent-context-lock.json`; shared operating rules are in `mise-helper/vendor/pzagent-adw-context/policy.md`. Record here only lifecycle facts, exact validation commands and project pitfalls. Never a secret, endpoint, opaque provider ID, SSH resolution, port, key path or 40-character SHA.

Repository `smarterworkerai/<repo>`, context `pzagent-adw-context`.

## Release lines

- `main`: production release line
- `demo`: integration release line, present even without a demo deployment environment
- Work branches: reviewed preview candidates; feature → demo → main; promotion by `mise run pz:release:promote -- --pr <n> --line <demo|main>`

## Environments, routes and bindings

Fill these from reviewed adapter facts and private operator handles before
activation; delete the demo row if no demo runtime exists. Keep the `demo` branch.

| Environment | Logical target / binding | Release kind | Probe key | Verification |
|---|---|---|---|---|
| `pr-preview` | `<preview-target> / <preview-binding>` | `<application>` | `<PROJECT>_PREVIEW_URL` | `adw:validate-deployment -- pr-preview --target <preview-target>` |
| `production` | `<production-target> / <production-binding>` | `<application>` | `<PROJECT>_PRODUCTION_URL` | `adw:validate-deployment -- production --target <production-target>` |
| `demo` (optional runtime) | `<demo-target> / <demo-binding>` | `<application>` | `<PROJECT>_DEMO_URL` | `adw:validate-deployment -- demo --target <demo-target>` |

For Dokploy targets, record Compose/key-schema paths under `infra/dokploy/`,
owning service names and
internal routing ports in the machine-readable declaration, not duplicate
values here. The approved preview pattern is `<repo>-preview.<team-preview-domain>`;
resolve its real zone from the private operator inventory. Keep manager/server
names, domain-to-server maps, actual probe origins and provider resource IDs in
private operator notes. Different preview/production servers may share a manager.

For Dokploy targets, the maintainer fills private `.env.deploy` from
`.env.deploy.example` (or uses a private operator home). The agent writes
non-secret settings in reviewed Compose and lists missing secret/private keys;
only those names belong in the key schema and `.env.<environment>.example`.
The maintainer fills private `.env.<environment>` with secrets/private values,
then copies intended entries from it and pastes them key by key below image
lines in the target Compose page’s Environment tab in the Dokploy UI, then saves. Never replace the whole
block or overwrite rotated values from a stale copy. Omit image keys from
private files and pasted entries; deployment owns them. Both private file types
are mode 0600. Target files are not automatically loaded or uploaded.
For Kubernetes targets, the agent names secret source keys in
`deploy/k8s/.env.<environment>.example` and the private
`kubernetes-provisioning.json`. The maintainer fills `.env.<environment>` and
passes it with `--env-file` to `pz:provider:provision`, which creates that
target's Secrets from it on top of `.env.deploy`.
Supported credential keys load automatically; arbitrary
probe/server selectors require explicit export, with probe origins alternatively
in private `profile/probes.json`. Consult the installed Dokploy bootstrap reference
for resolution order and first provisioning/configuration/deployment sequence.

## Deployable units

- `<unit>`: `ghcr.io/smarterworkerai/<repo>-<unit>`, built from `<Dockerfile path>`; release kind `<application|…>`

## Validation and recovery

- Local: focused checks while working; `mise run adw:verify:full` once on the clean committed head. Full verification supersedes minimal; reuse its result while the head stays unchanged.
- Deployment proof: `mise run adw:validate-deployment -- <environment>` (digest parity, health, readiness).
- Live E2E (billable, preview only): `mise run adw:test:e2e:fast -- pr-preview`.
- Rollback: `mise run pz:release:rollback -- …`, then a bug issue for the failed release.
- Manual recovery notes: `<none | …>`

## Known pitfalls

- Replace generic `PROJECT_*` identities consistently before first publication;
  one image variable/component per service. Later logical target/package renames
  change pointer/release identities.
- First deploy: provision → operator supplies Environment → config plan/apply →
  domain/service mapping → separate verified deploy without `--sync-config`.
- Default routed probes accept any 2xx and send `Accept: application/json`;
  semantic body assertions require a project hook or smoke check.
- A bounded deploy timeout does not prove rollout termination. Keep its operation
  ID and recover through `pz:workflow:resume` instead of a second deployment.
- `<project-specific, current, non-secret>`

---

## Optional sections

Add only the ones this project needs; delete the rest.

### Branch and environment map

Exceptions to the default lines, for example an explicitly selected `feature/*` branch that may be previewed.

### External integrations and sidecars

Per integration: purpose, owning service, routing relationship, verification command or evidence, rollback or disable path.

### Access handles

Approved non-secret handles this project opts into (SSH alias names, file-exchange variable names). Shared handles from the context are not universal; opt in here.

### Command expansions

Project-specific meanings for `implement <work>`, `deploy it`, `rollback <environment>`, `E2E/regression`.

### Admin closure

Issue closing rules, PR body expectations, deployment report expectations.
