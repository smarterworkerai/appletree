# pzagent ADW runtime policy

Package version `0.2.5` is experimental as a whole. Capabilities are controlled by the closed project adapter, environment subsets, logical target allowlists, side-effect classes, and existing human approvals. No feature-level experimental flags exist.

Generic ADW owns lifecycle mechanics and universal gates. This bundle owns pz release defaults, GitHub/GHCR/Dokploy policy, reusable engines, and secret-safe evidence. Projects own concrete topology, package names, provider names, routes, ports, volumes, desired state, hooks, credentials, endpoints, opaque IDs, and mutable runtime facts.

Exit classes: 0 success, 1 operation/quality failure, 20 unsupported or usage, 21 contract/context/integrity. Machine stdout is one bounded JSON object; progress is stderr. Secrets, raw Environment text, endpoints, opaque IDs, and SSH resolution never enter evidence.

## Provenance ownership

`.hermes/pzagent-context-lock.json` and `.hermes/adw-task-manifest.json` are the machine-authoritative exact context provenance records. A project `.hermes/ADW.md` is human lifecycle documentation and must not contain a 40-character Git SHA; `adw:context:check` rejects that duplication. Context sync updates the vendored bundle, lock, the central context source record, and every context-owned capability source record together. It never rewrites project adapters, project tasks, or runtime configuration.

## Long-running local task execution

Run an ADW task as a tracked background process when it is expected to approach or exceed the agent foreground execution limit. Use 300 seconds as the conservative threshold when no repository-specific timing evidence exists; full verification, integration suites, container builds, and similarly broad local gates default to background execution.

The runner must retain the process/session handle, working directory, exact command, and source HEAD; request one completion notification; and read back the final exit status and complete output before reporting a result. A timeout, detached start, or notification is not success. Before retrying, prove the prior process has exited or terminate its full process tree; never start duplicate validation runs blindly.

This scheduling rule prevents loss of local validation evidence at infrastructure foreground limits. It grants no authorization for deployment, provider mutation, hotfix, rollback, restore, publication, destructive cleanup, or any other remote write. Such operations retain their approval, serialization, supervision, and readback requirements and must not be converted into unattended background work merely because they are long-running.

## Validation cadence and evidence economy

Build one coherent delivery wave before invoking broad aggregate gates. During implementation, run only the focused tests, validators, and adversarial cases affected by the current change. Batch mechanical checksum, vendoring, lock, manifest, evidence, and documentation updates before broad validation and independent review.

Do not run `adw:verify:minimal` immediately before or after `adw:verify:full`; full verification supersedes minimal verification. Run minimal verification at most once for a wave that will not run full verification. When full verification is required, run it once as a tracked background process on the final clean exact HEAD, after all intended wave changes are committed. Re-run it only if that HEAD changes, the process is interrupted, or the result is incomplete or invalid. Never repeat a successful broad gate on an unchanged exact HEAD; read back and reuse its recorded evidence.

Use one independent final review for the complete reviewable delivery wave rather than separate reviews for mechanical repins or intermediate corrections. Focused safety review may precede a high-risk remote operation, but it does not require repeating unrelated aggregate quality gates. Any correction after final review starts a new final-candidate HEAD and invalidates only the evidence whose contract is bound to the old HEAD.

## GitHub state readback

Use `gh api` with an exact REST endpoint as the primary path for authoritative PR, issue, commit, branch, review, workflow, and check-run readback. High-level `gh pr`, `gh issue`, `gh status`, and search conveniences may depend on GraphQL fields that are unavailable or deprecated (including Projects-related fields), so they are not a required dependency of a delivery gate.

A GraphQL error is not evidence that the requested object is absent. Do not retry the same failing query blindly and do not downgrade the failure to an empty result. Translate the lookup to the corresponding REST endpoint, preserve every identifier exactly, request explicit fields, paginate when applicable, and compute asserted counts mechanically. Convenience commands may still perform supported mutations, but every external state change must be verified by reading back the exact target through REST before success is reported.

## Exact-tree CI and merge gate (read-only)

The consumer commits `.github/workflows/ci.yml` byte-identical to `mise-helper/vendor/pzagent-adw-context/templates/github/ci.yml`; `ci.py workflow-drift --root .` runs before classification. `ci` and `delivery` in `.hermes/pzagent-adapter.json` declare the stable required check, workflow, quality task names, CI-only check names, and promotion source→target pairs. A project hook cannot authorize reuse. The shared CLI uses `gh api` with `GH_TOKEN` and only read permissions (`contents`, `actions`, `checks`, `pull-requests`). Do not give deployment/provider credentials to the CI classifier or proof steps.

From the consumer checkout with the pinned bundle installed, set `REPO`, `PR`, `HEAD` (full PR head SHA), and `TARGET` (protected destination) from authoritative GitHub readback, then run:

```sh
python3 mise-helper/vendor/pzagent-adw-context/ci.py premerge-check --repository "$REPO" --pr "$PR" --target "$TARGET" --expected-sha "$HEAD" --adapter .hermes/pzagent-adapter.json
python3 mise-helper/vendor/pzagent-adw-context/ci.py proof-destination --repository "$REPO" --target "$TARGET" --expected-sha "$HEAD" --adapter .hermes/pzagent-adapter.json
```

`proof-pr` has the same PR arguments and is used by the successful PR-attached `required-quality` reuse step; it is **not** premerge authorization while its own job is pending. `premerge-check` rereads the completed current job, exact checkout-tree/manifest checksums, live head/base refs, FF test-merge tree, current approval, trusted reviewed-base code, the prior reviewed merged full gate for promotion, and declared CI-only checks. `proof-destination` rereads the closed merged PR through destination-branch-filtered inventory, destination ref, review and the exact job. A stale review, pending/skipped/failed or mismatched job, missing prior root, new merge tree, fork, incomplete inventory, modified proof implementation, or missing trusted base returns exit 21 and bounded JSON `{"status":"blocked","reason":"..."}`. Never interpret a full-gate CI success alone as merge permission; merge itself still needs explicit authorization. A missing reuse proof selects the required full graph for a new PR or protected push. Optional full integration and both E2E suites are independently human-triggered and never part of the automatic required graph.
