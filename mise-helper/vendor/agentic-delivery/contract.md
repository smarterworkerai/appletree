# ADW mise task contract v2

## Purpose

This contract defines the stable boundary between Agentic Delivery Workflow orchestration and deterministic project operations. ADW, CI, and humans invoke the same canonical mise tasks. Projects and optional context layers implement those tasks without exposing tool- or provider-specific decisions to generic ADW.

The contract and schema version is `2.2.0`. Version 2.2 adds `.adw/` project-directory support while retaining `.hermes/` for existing projects; both present is a contract error. Version 2.1 introduced the source registry and `adw:local:clean`. `adw_contract.py manifest-migrate` performs reviewed compatible-v2 migration to 2.2.0. Historic immutable v1/v2.0 tags remain in Git history; the v2 directory is the active compatible-major snapshot. Breaking task, manifest, evidence, status, or behavioral changes require a major version bump.

## Ownership boundary

Generic ADW owns task semantics, orchestration policy, review and approval gates, and interpretation of evidence. A project owns commands, components, routes, deployment-provider calls, health semantics, and E2E behavior. An optional context layer may supply shared task implementations and non-secret defaults.

Mise covers deterministic executable operations only. Human approval, subagent review, PR state, branch protection, merge policy, and hosted-CI orchestration are not mise tasks.

CI calls mise tasks directly. CI does not invoke ADW stages, and ADW does not invoke CI as a project command.

## Project files

The ADW project directory is `.adw/`, or `.hermes/` for existing projects. Both present is `contract-error`; neither present is `blocked`. New generic adapters use `.adw/`, while a selected context that hard-codes `.hermes/` continues to use the legacy directory.

The machine source of truth is the ADW project directory's `adw-task-manifest.json`. `.adw/ADW.md` (or `.hermes/ADW.md` for an existing project) is narrative and references the manifest instead of duplicating structured capability or environment data.

New ADW/mise-specific helper code and its tests belong under project-root `mise-helper/`. Existing project scripts may remain in their established locations and be called by tasks.

Evidence defaults to `<project-dir>/evidence/<run-id>/` and must be Git-ignored.

The project config declares a hard minimum mise version. The compatibility floor remains `2026.9.5` after validation with both `2026.9.5` and `2026.9.13`; newer compatible mise releases are allowed. Exact reproducibility applies to project tools through explicit versions and `mise.lock`, not by locking the mise executable itself.

## Fixed task ABI

Every canonical capability is declared as `supported` or `unsupported`, and every canonical task name exists. `adw:describe` and `adw:check` are always supported.

### Core

```text
adw:describe
adw:check
```

`adw:describe` returns the project identity, contract, environment enum, capability declarations, and effective source provenance.

`adw:check` is side-effect-free. It validates the manifest, task catalog, verification graphs, effective task source paths, source SHA-256 checksums, source metadata, and evidence contract. It may invoke only `adw:describe` and unsupported stubs. It must not execute build, test, network, deployment, or E2E operations.

The top-level `sources` object is keyed by stable source IDs. Each record contains `layer`, `ref`, `checksum`, and project-relative `path`; each capability stores only one source ID. Generic and context `ref` values are immutable 40-character Git commit SHAs; project-local sources use the review commit's `HEAD`. Missing, duplicate, malformed, and unknown source references fail closed. `adw:check` resolves source IDs, compares mise task sources to those paths and hashes each local snapshot once. A later include may override an earlier layer only when the manifest records that effective source.

### Canonical side-effect classes

The side-effect class is fixed by task name and is validated even when the capability is declared `unsupported` (the unsupported stub itself remains non-mutating):

- `read-only`: `adw:describe`, `adw:check`, `adw:deploy:config:plan`, `adw:deploy:status`, `adw:health`, `adw:readiness`, `adw:context:check`;
- `local-write`: `adw:install`, `adw:build`, `adw:lint`, `adw:static-analysis`, `adw:test:unit`, `adw:test:integration:fast`, `adw:test:integration:full`, `adw:verify:minimal`, `adw:verify:full`, `adw:deploy:config:pull`, `adw:context:sync`, `adw:local:clean`;
- `remote-write`: `adw:deploy:config:apply`, `adw:deploy:apply`, `adw:test:e2e:fast`, `adw:test:e2e:full`, `adw:validate-deployment`, `adw:hotfix:apply`, `adw:hotfix:restore`;
- `destructive`: no v2 public task.

### Local preparation and quality

```text
adw:install
adw:build
adw:lint
adw:static-analysis
adw:test:unit
adw:test:integration:fast
adw:test:integration:full
adw:verify:minimal
adw:verify:full
```

`mise install` installs the pinned toolchain. `adw:install` prepares project dependencies.

`adw:verify:minimal` runs a manifest-declared fast allowlist. It is non-promotable feedback only and does not automatically add lint, static analysis, or the complete required quality graph.

`adw:verify:full` runs every supported required local quality capability: build, lint, static analysis, unit and **fast** integration as declared by the project. It does not launch hosted CI or subagent review; it is not a promise to run every optional test.

Both verification graphs contain only supported local-quality leaf tasks (`adw:build`, `adw:lint`, `adw:static-analysis`, `adw:test:unit`, and `adw:test:integration:fast`). `integration:full` and both E2E suites are individually runnable optional capabilities, never automatic verification children. Non-execution of an optional suite is neither a pass nor a waiver/documentation obligation. An explicitly executed suite must report honest non-empty results through project-owned checks.

ADW defaults inner feature/bugfix integration to minimal validation. Release-line integration requires full validation plus the external ADW review/approval gates.

### Deployment

All environment arguments are opaque values from the manifest enum. Generic ADW never invents or hardcodes environment names. Environment-scoped tasks also accept an optional `--target <logical-target>`. When omitted, the project chooses its declared active target; when present, the project validates it against its own inventory. A target is a bounded logical identifier only—not a provider, namespace, host, remote ID, endpoint, credential, or child-command argument.

```text
adw:deploy:config:pull <environment>
adw:deploy:config:plan <environment>
adw:deploy:config:apply <environment>
adw:deploy:apply <environment>
adw:deploy:status <environment>
adw:health <environment>
adw:readiness <environment>
adw:test:e2e:fast <environment>
adw:test:e2e:full <environment>
adw:validate-deployment <environment>
```

Tasks ending in `:apply` mutate state. They do not implement approval flags or interactive confirmation. Both environment-scoped E2E tasks are `remote-write` and require separate per-run authorization, target validation and provider safety gates. `adw:validate-deployment` is limited to required runtime semantics (including health, readiness and project-required write-path checks); it must not invoke either E2E suite implicitly. ADW/human policy authorizes invocation; manifest side-effect metadata lets every caller distinguish inspection from mutation.

Projects encode provider methods, routes, payloads, redaction, live-ID lookup, polling, readback, and idempotency in project-owned tasks/helpers.

### Temporary hotfix

```text
adw:hotfix:apply <environment>
adw:hotfix:restore <environment>
```

The apply task is one public aggregate; the restore task is a separately approved, artifact-bound recovery operation. Hidden tasks and helper functions may implement apply's internal build, transfer, mutation, and identity checks.

The capability lists its supported environments. Only those environments are disposable hotfix targets. A supported hotfix requires a clean working tree and a local HEAD that exactly equals its remote-tracking branch after readback.

The artifact uses a unique non-release identity tied to the commit. Transfer transport is project/context owned. The desired artifact identity must be proven on the target and in the running deployment.

If running identity is proven, `adw:hotfix:apply` returns exit code 0. A failed health/readiness check remains a prominent separate finding and does not trigger automatic rollback. No automatic rollback is required for a successful hotfix; a later restoration is an explicitly approved separate `adw:hotfix:restore <environment>` task, bound to the private restore artifact and exact target, never an automatic quality child.

### Context snapshots

```text
adw:context:check
adw:context:sync
```

`adw:context:check` is read-only and only operates when the manifest declares exactly one generic source and the trusted `smarterworkerai/agentic-delivery` `main` branch plus a safe release-index path. It retrieves that upstream index over HTTPS, records the consumer generic pin and selected latest compatible immutable ref/version, and returns one of `current`, `update-available`, `update-required`, `incompatible-major`, or `lookup-unavailable`. `current` requires both immutable ref and snapshot checksum to match; a same-ref/different-checksum pin is a contract error. `require-current-compatible` blocks stale pins and unavailable lookup in CI. Moving branches and tags are never final resolved refs.

`adw:context:sync` is an explicit local-write maintenance task. It downloads the selected immutable GitHub codeload archive, safely stages only the index-declared snapshot subtree, verifies the canonical `tasks.toml` checksum, and atomically replaces only the vendor snapshot before updating manifest pins for review; it never commits, opens a PR, or runs automatically from `check` or normal CI.

### Local cleanup

`adw:local:clean` is an optional local-write capability. Generic ADW declares only the ABI and an unsupported stub; a context or project layer owns the implementation. Scoped mode requires a bounded `--prefix` and may select only unused resources with matching ADW ownership markers. Aggressive mode is `--aggressive --yes`, rejects `--prefix`, and is reserved for an explicit local human operation; implementations must reject CI or implicit invocation. It may empty `/tmp` contents and prune all unused Docker containers, images, volumes, networks and build cache, but must not stop active resources. Maven and npm caches are outside both modes.

## Include precedence and offline operation

Effective task precedence is:

```text
generic agentic-delivery snapshot
→ optional context snapshot
→ project-local override
```

Shared layers may define canonical `adw:*` tasks directly. Projects record effective task source/ref/checksum.

Normal execution uses exact vendored snapshots under `mise-helper/vendor/agentic-delivery/` and `mise-helper/vendor/<context>/`. Remote Git retrieval is restricted to explicit sync, uses an immutable 40-character commit SHA plus checksum, and must not be required for offline task execution.

Each project records an exact consumed ref/checksum and an accepted SemVer range. An incompatible major version is a contract error.

## Capability behavior

Unsupported task stubs exit 0 and emit `status=unsupported`. This means the task invocation itself behaved as declared. When an aggregate or requested ADW goal requires that capability, the aggregate/orchestrator returns non-zero `blocked`.

Canonical statuses:

```text
passed
failed
skipped
unsupported
blocked
contract-error
```

Exit classes:

- `0`: declared operation completed, including a direct unsupported stub;
- `1`: supported operation failed;
- `20`: required precondition/capability blocked execution;
- `21`: manifest, task catalog, schema, or compatibility contract error.

Skipped and unsupported work must never be represented as passed.

## Evidence

Tasks print concise human-readable progress to stderr and write separate redacted JSON evidence conforming to `schemas/adw-task-evidence.schema.json`. When a task returns a machine-readable payload, such as `adw:describe`, stdout contains only that JSON payload.

Project and context task implementations should invoke `adw_contract.py run --task <task> [--environment <value>] [--child <canonical-task>]... -- <command>`. The adapter validates the complete manifest and source checksums before execution. A nonzero child exit becomes the public `failed` exit class `1`; the raw child exit remains in the evidence finding. The adapter persists only the selected target environment name and declared canonical child task names, and does not persist child command arguments or environment-variable values. Only aggregate tasks may declare unique, non-self-referential children. Unsupported generic stubs use `adw_contract.py unsupported`, return zero only when the manifest declares that canonical task unsupported, and record `unsupported`.

An aggregate may report `passed` only after every declared child evidence file exists under the same run ID and its run ID, task name, status, exit class, contract/schema version, effective source, source revision and execution window validate. Child evidence must have been generated during this aggregate execution; reusing a previous result with the same run ID is a contract error. `adw:verify:minimal` and `adw:verify:full` must declare exactly the corresponding manifest verification graph.

The JSON Schemas enforce closed structure and directly expressible constraints. The dependency-free Python validator is normative for cross-object invariants that Draft 2020-12 cannot compare dynamically, including supported-capability verification coverage and source-registry/file containment checks.

`ADW_RUN_ID` is inherited when supplied and generated otherwise. It must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`; invalid values are rejected before task execution and cannot escape the evidence root. The resolved value is exported to child processes, so aggregate and child records share the run ID and identify relationships. Evidence records contract/schema version, task, status, exit code, source revision, effective task source/ref/checksum, arguments, timestamps, children, and findings.

Writes are atomic. Secret values, credentials, raw private endpoints, and private-key paths are forbidden. A manifest may list required secret environment-variable names, never their values.

## Manifest absence

If the ADW project manifest is absent, ADW returns `blocked` and offers generation of a reviewable adapter diff. It does not infer and execute ad-hoc project commands.

## Context neutrality

This specification defines interfaces and observable behavior. It does not prescribe a programming language, build system, image format, transfer transport, deployment provider, CI provider, project name, organization, or concrete environment name.
