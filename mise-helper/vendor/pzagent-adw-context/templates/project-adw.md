# <Project> ADW Adapter

The project directory is `.adw/`, or `.hermes/` in existing projects. Both present refuse with `project_directory_conflict`; paths below use `.adw/`. Operator profile paths are unchanged.


This project uses `pzagent-adw-context`. Machine facts live only in `.adw/pzagent-adapter.json` (topology) and `.adw/adw-task-manifest.json` (capabilities); the exact context pin is `.adw/pzagent-context-lock.json`; shared operating rules are in `mise-helper/vendor/pzagent-adw-context/policy.md`. Record here only lifecycle facts, exact validation commands and project pitfalls. Never a secret, endpoint, opaque provider ID, SSH resolution, port, key path or 40-character SHA.

Repository `smarterworkerai/<repo>`, context `pzagent-adw-context`.

## Release lines

- `main`: production
- `demo`: demo
- Work branches: reviewed preview candidates; promotion by `mise run pz:release:promote -- --pr <n> --line <demo|main>`

## Deployable units

- `<unit>`: `ghcr.io/smarterworkerai/<repo>-<unit>`, built from `<Dockerfile path>`; release kind `<application|…>`

## Validation and recovery

- Local: `mise run adw:verify:minimal` while working, `mise run adw:verify:full` once on the committed head.
- Deployment proof: `mise run adw:validate-deployment -- <environment>` (digest parity, health, readiness).
- Live E2E (billable, preview only): `mise run adw:test:e2e:fast -- pr-preview`.
- Rollback: `mise run pz:release:rollback -- …`, then a bug issue for the failed release.
- Manual recovery notes: `<none | …>`

## Known pitfalls

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
