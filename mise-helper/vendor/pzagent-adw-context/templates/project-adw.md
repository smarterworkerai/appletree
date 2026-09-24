# Project ADW Adapter

This project uses `pzagent-adw-context`. Machine-critical values live only in `.hermes/pzagent-adapter.json`; this document records lifecycle, exact validation, recovery, and project-specific pitfalls.

## Release Lines

- `main`: production
- `demo`: demo
- Work branches: reviewed preview candidates

## Validation and Recovery

Document exact canonical tasks, runtime proof, rollback, and manual recovery. Never place secrets, endpoints, opaque provider IDs, SSH resolution, users, ports, or key paths here.

### Long-running local gates

Start local ADW validation expected to run for 300 seconds or longer as a tracked background process with one completion notification. Record its process/session handle, working directory, exact command, and source HEAD. After notification, read back the exact exit status and complete output before declaring PASS or FAIL. Before retrying an interrupted run, prove the prior process has exited or terminate its full process tree; do not launch duplicate runs blindly.

This is an execution-scheduling rule only. It does not authorize remote writes or unattended deployment, hotfix, rollback, restore, publication, or cleanup operations; all existing approvals, serialization, supervision, and readback gates remain mandatory.

### Validation cadence

During implementation, run focused tests and validators only. Batch code, vendoring, checksum, lock, manifest, evidence, and documentation changes into one coherent reviewable wave before aggregate validation. Do not run `adw:verify:minimal` together with `adw:verify:full`; full supersedes minimal. Use minimal at most once when no full run is planned. When full verification is required, commit the final candidate first and run full exactly once as a tracked background process on that clean exact HEAD. Repeat it only after an exact-HEAD change, interruption, or invalid/incomplete result; reuse recorded evidence on an unchanged HEAD.

Request one independent final review for the complete wave, not one review per mechanical repin or correction. A post-review correction creates a new candidate and requires only the affected focused checks plus the final exact-HEAD gates whose contracts were invalidated.

### GitHub readback reliability

Use `gh api` REST endpoints for authoritative PR, issue, branch, commit, review, workflow, and check-run state. Do not make a delivery gate depend on GraphQL-backed `gh pr`, `gh issue`, status, or search convenience commands: unavailable or deprecated fields can fail an otherwise valid lookup. A GraphQL error never means “not found.” Switch to the exact REST endpoint, preserve identifiers, request explicit fields, paginate lists, and calculate claimed counts mechanically. After any GitHub mutation, verify the exact target through REST before reporting success.

## Temporary Hotfix Exclusivity

Temporary hotfix apply and restore are operator-serialized preview operations, not provider-CAS transactions. Approval asserts exclusive ownership of the logical target for the entire build, registry push, Environment write, deployment, runtime proof, and any compensation. During that window, do not start another deploy/config/rollback/restore or edit the Dokploy Environment manually.

The project hotfix build hook must return each image as a fully qualified registry repository with the exact source-labelled tag `:hotfix-<source-sha12>`. The shared provider validates that convention and the OCI source/revision labels before transfer. SSH transport preserves that exact tag for runtime use; registry transport resolves it to an immutable `@sha256:<digest>` reference before any Environment write. Runtime proof must accept only the transport-appropriate form. The runtime changes only pre-existing declared image keys, preserves every non-owned Environment byte, persists private restore evidence before the write, performs exact readback, and proves the running image identity. Demo and production hotfixes are forbidden.
