# Generate a project ADW mise adapter

Use this guide to create reviewable project-owned files that implement ADW mise task contract v2. Generation discovers facts; it does not authorize operational work.

## Required output layout

Use `.adw/` for a new generic project. Use `.hermes/` only when the selected context package requires that legacy path. Never create both.

```text
mise.toml
mise/conf.d/<context>.toml              # only for an opted-in context
.adw/adw-task-manifest.json
.adw/ADW.md
.gitignore                              # excludes .adw/evidence/
mise-helper/                            # only new ADW/mise helper code
mise-helper/vendor/agentic-delivery/
mise-helper/vendor/<context>/           # only when opted in
```

The generic vendored snapshot contains `tasks.toml`, `adw_contract.py`, schemas, and source metadata. Normal execution must not depend on network access.

Start variable discovery from `templates/project-vars.example.toml` and, when a context is explicitly selected, `templates/context-vars.example.toml`. Replace or remove every placeholder; do not copy irrelevant keys into a project.

## Mise version policy

The root template sets `min_version = { hard = "2026.9.5" }`. This is a hard compatibility floor, not an exact lock of the mise executable. `2026.9.5` is the lowest passing version; the snapshot was also validated with `2026.9.13`. Tools managed by mise are pinned through exact project declarations and `mise.lock`; the mise executable may be newer than the hard minimum.

## Generation procedure

1. Inspect the repository's actual language/toolchain files, modules, package managers, existing scripts, CI commands, deployable units, environment mappings, health/readiness behavior, and E2E suites.
2. Record facts and unknowns. Never invent an environment, route, command, image, target ID, secret, or validation behavior.
3. Set the required hard minimum for mise. Pin project tools in exact declarations and `mise.lock`. Keep `mise install` for toolchain installation and map project dependency preparation to `adw:install`.
4. Copy the exact approved generic snapshot to `mise-helper/vendor/agentic-delivery/`. Record its immutable 40-character Git commit SHA, checksum, and accepted SemVer range.
5. If a context is explicitly declared, synchronize its exact task snapshot and non-secret global vars. Record one context ref/checksum for both. Context-wide vars go in `mise/conf.d/<context>.toml`.
6. Configure task include precedence: generic snapshot, optional context snapshot, then project-local task definitions.
7. Declare every canonical capability in `<project-dir>/adw-task-manifest.json` as `supported` or `unsupported`. Keep `adw:describe` and `adw:check` supported.
   Store each provider ref/checksum once in the top-level source registry and reference it by source ID from capabilities. Declare `adw:local:clean` unsupported unless a reviewed context/project backend exists.
8. Implement project overrides. Existing project scripts may be called in place. Put every newly created ADW/mise-specific helper and test under root `mise-helper/`.
9. Define manifest-declared environment values and per-capability supported subsets. Reject unknown values before side effects.
10. Define the exact `adw:verify:minimal` fast allowlist and the complete `adw:verify:full` graph.
11. For mutations, use the canonical `:apply` task names. Do not add approval flags; authorization remains outside the task.
12. Configure human console output plus atomic redacted JSON under `<project-dir>/evidence/`. Add that path to `.gitignore`.
13. Update `<project-dir>/ADW.md` as narrative documentation that links to the manifest instead of duplicating it.
14. Produce a reviewable diff and run `mise run adw:check`.

The generator must not execute `adw:install`, quality tasks, deployment tasks, E2E, context sync, hotfix, or any other operational/mutating capability. Running `adw:check` is the only automatic post-generation operation.

## Unsupported capabilities

Keep the canonical generic stub. It exits 0 and writes `status=unsupported`. Do not replace an unsupported capability with a no-op success implementation.

If a selected aggregate requires an unsupported child, it must return non-zero `blocked` rather than silently omit the child.

## Project task implementation

Prefer thin task definitions that call existing commands or focused helpers. Complex parsing, HTTP, redaction, synchronization, or identity logic belongs in tested files under `mise-helper/`, not a long TOML string.

Project-local definitions override context definitions; context definitions override generic stubs. `adw:describe` and evidence must expose the effective source/ref/checksum after overrides.

## Context synchronization

Normal tasks run the vendored context snapshot. `adw:context:check` reports drift only. `adw:context:sync` is an explicitly requested local mutation that fetches the immutable source, verifies checksum/compatibility, updates vendored task and vars snapshots together, and leaves a reviewable diff.

Never put secret values in a synchronized fragment. Store only approved non-secret handles/defaults and secret environment-variable names.

## Validation checklist

- [ ] Every canonical capability is explicit.
- [ ] Core describe/check tasks are supported.
- [ ] Every declared task exists after include resolution.
- [ ] Environment subsets refer only to manifest values.
- [ ] Minimal/full graphs contain supported tasks only.
- [ ] Mutating tasks are classified and named `:apply` where defined by the ABI.
- [ ] Exact source refs/checksums and SemVer ranges are recorded.
- [ ] Effective provenance is observable.
- [ ] `<project-dir>/evidence/` is Git-ignored.
- [ ] No secret values or raw private infrastructure values are committed.
- [ ] The generated reviewable diff passes `adw:check`.
