# pzagent ADW runtime policy

Package `0.15.5`. The runtime enforces capabilities, environments, logical targets, side-effect classes and approvals; this page lists only the rules an agent or operator must follow that code cannot enforce.

## Ownership

The project directory is `.adw/`, or `.hermes/` in existing projects. Both present refuse with `project_directory_conflict`; operator home/profile paths are unchanged. Paths below use the modern spelling.

- Generic ADW: lifecycle mechanics and universal gates.
- This bundle: pz release defaults, GitHub/GHCR/Dokploy engines, secret-safe evidence. Deployment orchestration uses the declarative deployment definition and the provider settings store; provider-specific formats remain implementation details.
- Project: topology, packages, routes, ports, volumes, hooks, credentials, endpoints and mutable runtime facts.
- Exact provenance lives only in `.adw/pzagent-context-lock.json` and `.adw/adw-task-manifest.json`. `.adw/ADW.md` must not contain a 40-character SHA; `adw:context:check` rejects it. Only `adw:context:sync` updates the vendored bundle and pins.
- `.adw/adw-task-manifest.json` is the only source of capability and environment declarations; the project adapter contains only project facts and is normalized against that same-revision manifest.

Every remote `adw:*` task (config, deploy, status/health/readiness, validation, E2E, hotfix) writes a generic ADW evidence record to `<evidence.root>/<ADW_RUN_ID>/`; an unsafe `ADW_RUN_ID` is rejected before any provider access.

Exit classes: 0 success, 1 failure, 20 unsupported/usage, 21 contract/integrity. Project hooks that block should return a specific, content-safe `reason_code` (for example `e2e-browser-missing`) rather than a catch-all, because it is the only cause an operator sees. Machine stdout is one bounded JSON object; progress goes to stderr. Secrets, raw provider settings, endpoints, opaque IDs and SSH resolution never enter evidence.

## Running local gates

- Run tasks expected to take 300 seconds or longer (full verification, integration, image builds) as a tracked background process with one completion notification. Record the handle, working directory, exact command and source HEAD.
- Before reporting, read back the exit status and complete output. A timeout, detached start or notification is not success.
- Before a retry, prove the prior run exited or kill its full process tree. Never start duplicate runs.
- This is scheduling only: it never authorizes a remote write or unattended deploy, hotfix, rollback, restore, publication or cleanup.

## Validation cadence

- While implementing, run focused tests only. Build one coherent wave, then validate it.
- `adw:verify:full` supersedes minimal: never run `adw:verify:minimal` next to it. Run full once, as a tracked background process, on the committed clean exact HEAD. Re-run only if that HEAD changed or the run was interrupted/invalid; reuse evidence on an unchanged HEAD.
- Request one independent final review per wave. A later correction re-runs only the gates its change invalidates.

## GitHub readback

Use `gh api` REST endpoints for authoritative PR, issue, branch, commit, review, workflow and check-run state. A GraphQL error never means "not found": switch to REST, request explicit fields, paginate, and count mechanically. After any mutation, read back the exact target through REST before reporting success.

## CI and merge gate

- `.github/workflows/{ci,trust-root-bootstrap,publish-release,cleanup-retention}.yml` must be byte-identical to the corresponding `templates/github/` files; `ci.py workflow-drift` enforces all four. `pz:workflows:sync` writes them; `--check` reports drift without writing.
- Before merging, run with values from REST readback:

  ```sh
  python3 mise-helper/vendor/pzagent-adw-context/ci.py premerge-check --repository "$REPO" --pr "$PR" --target "$TARGET" --expected-sha "$HEAD" --adapter .adw/pzagent-adapter.json
  ```

  After merge, `proof-destination` (same arguments without `--pr`) proves the destination. Exit 21 means blocked; the JSON `reason` says why.
- A green CI run is never merge permission. The implementing agent performs merge and promotion mechanics after a maintainer's PR review approval (on GitHub or in a PR comment), within the accepted plan. Self-merge requires explicit authorization in that plan step. Provider fast-forward merge, tag and Release mechanics need no separate per-step OK after that review approval; consumer promotions still use the canonical task below. Every `BOOTSTRAP_ENABLED` / `BOOTSTRAP_DISABLED` comment remains human-only. Failing acceptance or work outside the accepted plan requires a stop and report.
- Promote into a protected release line only with `mise run pz:release:promote -- --pr N --line LINE`. Its only/default strategy is a non-forced fast-forward of the live, proved PR head. The GitHub merge button, `gh pr merge`, merge commits, squash and rebase create a different or unproved destination identity and are forbidden for promotion.
- The operator command needs the human operator PAT loaded as `GITHUB_TOKEN`; a workflow `GITHUB_TOKEN` cannot be used because GitHub suppresses the destination push workflow for ref updates made by that token.
- Never commit or push directly to `main`. It moves only through a declared protected-line promotion pair (normally `demo` to `main`), keeping `main` an ancestor of the source line. The tool enforces this rule; CI reports unproved or merge-commit destination heads because the current GitHub plan cannot enforce linear history.
- Full integration and E2E suites are human-triggered, never part of the automatic gate.
- First adoption onto a completely ADW-free default uses the released provider's operator launcher with explicit greenfield opt-in. It invokes the same public promotion task outside consumer code/configuration, after full released provider/generic byte and mode verification and successful exact hosted quality. No ENABLED comment is required or accepted as greenfield authority; a matching current administrator DISABLED still refuses. Any partial installation or existing controller refuses new greenfield admission. Seed demo/main promotions precede first publication/deployment; the installed-default read-only seed proof expires when the default moves. Complete initial publication before the next main merge. See the provider onboarding guide and GitHub bootstrap reference. Existing-controller rules below continue to apply to later repins and scope expansions.
- A PR that changes trusted CI/provenance paths waits for an admin comment `BOOTSTRAP_ENABLED <fingerprint>` (printed by the trust-root workflow). That bypasses only the old-source comparison, never CI, merge or publication authorization. When the repository secret `PZAGENT_PROVIDER_TOKEN` (read-only on the provider repository) is set, a repin that vendors exactly a published provider release is approved automatically: the default-branch controller verifies the release tag, commit, `bundle.json` bytes, every changed vendored file, all four committed workflow templates, and the manifest-only context source update. It preserves that decision as `pzagent-trust-root-decision-<pr>-<head>`; head CI verifies the exact latest completed source-branch `pull_request_target` run and artifact identity without receiving the provider token. Missing, expired, waiting or foreign artifacts fall back to the exact live admin comment. Any other trusted change, or any doubt, keeps the admin comment.
- Three refusal reasons name why no decision exists: `bootstrap_required` means an administrator must decide (the controller rejected the revision, or a visible run's artifact waits for the comment); `bootstrap_controller_missing` means no controller run was listed for the PR head; `bootstrap_controller_unusable` means a run exists without a usable completed artifact. The last two are transient: every read-only proof lookup (`pz:release:promote` pre-check and read-back, CI `classify`, the gate's appearance grace) retries them for at most 60 s in 5 s polls before failing with the reason and, for the operator, the exact listing to rerun with your token. `bootstrap_required`, fingerprint, identity, checksum and contract mismatches and `undeclared_promotion_pair` are never retried.
- Cold adoption of a published release that expands `TRUSTED_PATHS` needs one administrator comment: the old default-branch controller automatically approves the exact released vendor for its smaller scope, and the new vendored classifier reports `bootstrap_required` for its current fingerprint. The smaller-scope artifact grants no authority over newly trusted paths; explicit denials and all binding and integrity checks are preserved. A human posts `BOOTSTRAP_ENABLED <current fingerprint>` and reruns the failed jobs. An unpublished candidate without automatic approval can require both the old gate fingerprint and the new classifier fingerprint; obtain each from actual task output and rerun all jobs after both human comments are visible. Never infer or reuse fingerprints across PRs. Once the default branch vendors the new trusted-path set, subsequent exact released-vendor repins use the normal artifact-backed no-comment path.

## CI decision ownership

Trusted decision roots own CI provenance, proof/gate acceptance, publication authorization, integrity/producer binding, promotion and registry retention/deletion eligibility. Dispatch, I/O, provider observations and project hooks may supply data only to named trusted validators. The protected `modules/ci/trusted_decisions.json` declares roots, exact observation exports and reviewed dynamic/process boundaries. Producer CI checks the dependency closure, including relative/function-local imports and package initializers, and refuses undeclared dependencies, stale entries and unreviewed calls. This is a review guard, not Python runtime isolation; broad CLI dispatchers are not roots simply because they launch operations.

The operational deploy/config/hotfix chain remains outside that CI authority closure. Canonical CI has no provider credentials, provider-write tasks or nonce issuer; provider and target-pointer writes are operator-host operations today. Publication/retention write jobs depend on authorization and revalidate the exact CI receipt. Future CI provider writes require a trusted job/environment gate and nonce issuer after human approval, plus renewed closure classification. Trusted registry readers check immutable digest/manifest identity and compare-and-set expectations independently of operational pointer writers; retention refreshes the protected graph before deletion.

Preserve the existing trusted-path order, non-empty ordered-subset rule, explicit denials and all integrity/producer/PR/head/base binding checks. An older artifact authorizes no newly trusted path; expanded-scope cold adoption needs the administrator's current fingerprint decision. Document each new decision owner and prove the actual cold negative/positive cases before release.

## Release helpers

- Publish and deploy through CI first. `pz:release:promote` moves the line; `publish-release.yml`, dispatched for the exact PR or destination SHA, reuses the quality proof and issues the authorization receipt; `pz:workflow:deploy-existing … --verify` deploys what CI published. `pz:workflow:publish` / `pz:workflow:publish-deploy` (build on the operator host, push to the registry) are a fallback only when the CI path cannot work for this change (no usable quality proof or evidence chain, workflow unavailable, repository without the publication action) and the human explicitly insists after being told why. Report a locally built release as operator-attested, not CI-proven, in the deployment report and the issue.
- `pz:release:prove-merged-branch -- --pr N --source-branch B --target-branch T` is the read-only proof required before deleting a merged work branch (live PR, live refs, ancestry or tree equivalence). It never deletes or pushes.
- `pz:rehearsal -- --lane ENV=KIND [--lane …] --ref REF [--billable] [--no-rollback]` runs the standard preview rehearsal (contract, read-only sweep, refusal checks without credentials, publish-deploy, same-release redeploy, rollback and forward, hotfix round trip, optional live E2E, isolation readback) and writes `handover/rehearsal-*/report.md` for a client or auditor. Lanes must be hotfix-capable preview environments. A refusal only passes when the guard under test refused, never because credentials were absent.

## Caches

`cache.py` is an optimization, not a contract. One `.adw/adw-cache.json` may hold both `dependencies` and `build_results` sections (schema `2.0.0`); the older two-file layout with `adw-build-cache.json` still works. Cache hits are never quality evidence, release identity or approval. Only a successful protected push saves a cache. Keep credentials and build outputs out of declared cache paths.

## Temporary hotfix

- Preview only; demo and production hotfixes are forbidden. Approval asserts exclusive ownership of the target until restore or completion; start no other deploy/config/rollback in that window.
- The build hook returns fully qualified image repositories tagged `:hotfix-<source-sha12>`. SSH transport keeps that tag; registry transport resolves it to `@sha256:<digest>` before any write to the provider settings store.

## Local cleanup

`adw:local:clean --prefix <prefix>` removes only `/tmp/<prefix>*` and Docker resources labelled `com.smarterworkerai.adw.owner=<prefix>` (put the label in Dockerfiles and on disposable top-level Compose volumes/networks, never on Dokploy deployment volumes). `--aggressive --yes` is interactive-only, lists every unused volume first and may delete databases.

## Provider defaults

Dokploy provisioning uses `pz:provider:provision` and `pz:provider:deprovision`
on the operator host only. Plans make no remote writes. The installed software
version and typed lifecycle API contract must match before mutation. Private
caches record created IDs outside the checkout. Server-side operation/nonce/role
markers are the ownership authority, permitting cleanup from another operator
machine with credentials. An owned ancestor retains scoped runtime identity for
interrupted cleanup. Operator receipts contain a public operation ID, per-role
ownership, logical bindings, counts and hashes, and grant no CI authority.
Read-only `--list` discovers marked operations without remote IDs or nonce.
Explicit adoption never grants deletion. Cleanup uses only created IDs, refuses
foreign children and proves runtime absence independently of provider row
deletion. Server registration, credentials, DNS and TLS remain separate scopes.

Kubernetes provisioning selects an explicit private kubeconfig context and owns
only the target namespace, pull secret and application Secrets. Cluster-wide
TLS stays with local k3d setup or the remote cluster's operator. Provisioning
checks TLS readiness without reading shared Secrets. Private journals bind
operation markers and UIDs; cleanup needs the commissioning journal and deletes only
resources created by that operation. Older ownership models are foreign. Namespace deletion requires fresh full inventories,
bounded control-plane defaults and UID/resource-version preconditions. The
public root CA is compared without reading credentials. Events are stateless
and disappear with the owned namespace; other foreign children refuse cleanup.

Only explicitly registered deployment providers are supported. A different provider uses a new logical target, with separate pointers and approval scope. `image_variables` is the canonical image map; `compose_variables` remains a strict alias. Provider defaults handle runtime proof, status and probes; projects keep topology, routes and optional overrides. A missing optional capability refuses with `provider_capability_unsupported` rather than skipping a safety predicate. Hotfix locking and restore evidence remain shared. New provider implementations require an explicit trust-boundary decision before registration.
