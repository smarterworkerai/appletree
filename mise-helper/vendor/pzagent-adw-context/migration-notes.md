# Migration notes

## 0.15.5

- Opt-in `.adw/routed-content.json` selects declared logical targets and an
  existing probe environment key. The app serves a baked JSON `source_sha`
  marker; deploy verification checks it against the artifact source before
  promoting pointers, and status checks the current manifest source. The
  response must be HTTP 200, JSON and at most 4 KiB. Same-origin redirects only;
  no declaration reports `disabled`. This is operational evidence, not CI authority.
- Bundled HTTP probes now use the same bounded, same-origin transport as the
  public helper. Configure the final HTTPS origin directly: HTTP-to-HTTPS
  redirects are cross-origin and refuse.
- Successful sandbox CI, including the one allowed ghost rerun, requires
  `trust-root-gate` and `required-quality` exactly once with `success`.
  Unrelated conditional jobs may settle as skipped or neutral.

- Independent review fixes: an explicit operator home selects resumptions in
  that same home; linked or non-private workflow state refuses, receipt-only
  directories are not open workflows, and legacy IDs explain how to finish
  with the previous release. Examine and claim serialize on the stable
  ownership journal and across targets. Stable configuration hashes bind the
  examination before and during claim, without storing Environment values.
  Interrupted claims accept only the approved original
  description or the exact intended marker, including lost acknowledgements;
  later observations preserve the original approved private report.
- Kubernetes journal rebuild and identity annotation negotiate
  `PartialObjectMetadata` for both GET and PATCH through a target-scoped private
  kubectl Unix proxy. No full-object fallback or `kubectl annotate` is used.
  Annotation patches test UID, resourceVersion, operation and nonce, then read
  metadata back; Secret data is never requested. A server that cannot provide
  metadata-only responses refuses.
- Project hooks can import `fetch` from the vendored `modules/http_probe.py`:
  the bundled probe identity (`PROBE_HEADERS`, `User-Agent: pzagent-health`),
  bounded timeout and body, same-origin redirects only. Replace hand-written
  urllib probes whose default agent a routed origin may refuse.
- `adw:context:check` refuses a release kind whose implemented `adw:build`
  declares neither `release_commands` nor the bundled `release_build.py`
  producer, since publication would have no `PZ_ADW_BUILD_DIR` handover. Add
  `release_commands`; onboarding now rehearses a release-mode build and
  `pz:release:package` before the first PR.
  An unimplemented declared build refuses. Legacy direct task declarations
  without a command file report an explicit skip; empty tool pins or a disabled
  lockfile likewise report a visible lock-check skip.
- Declared probe base URLs load from `<home>/profile/probes.json` (private
  file, exact allow-list of the adapter's probe keys; an explicit environment
  value wins; values are never printed), so operator deploys no longer need them
  exported by hand.
- `mise.lock` is enforced: with `lockfile = true` and tool pins,
  `adw:context:check` refuses a missing lock or one that does not cover every
  `[tools]` pin. `pz:project:init` runs `mise lock` for uncovered pins and
  commits nothing. Existing consumers: run `mise lock` and commit `mise.lock`.
- Adopted Dokploy resources can be taken into full ownership:
  `pz:provider:examine` reports adopted and claimable roles, ancestor marker previews and existing claim references,
  the runtime scope and an examination digest (original descriptions stay
  private); `pz:provider:claim --approve-examination-digest` writes only
  description markers under a new `claim-<id>` operation, reads them back and
  records `claimed` ownership. Projects and environments are claimed once at resource level (stable marker
  and private ancestor journal); later targets verify and reference that claim.
  Cleanup retains claimed siblings, refuses foreign children and deletes ancestors
  only when empty. An interrupted last-child deletion resumes idempotently. Deprovisioning claimed
  data-bearing Compose scope requires `--confirm-data-loss --backup-reference`.
- `pz:provider:journal:rebuild` rebuilds or verifies ownership journals
  read-only (Dokploy from server markers by `--operation`, Kubernetes from object
  metadata by environment/target); `--write` persists a missing journal.
  Kubernetes provisioning annotates created objects with repository,
  environment and target; `--annotate-identity --write` adds them to objects
  created earlier while their ownership journal is present.
- One operator home: `--profile-root`, `PZ_ADW_PROFILE_ROOT` or the XDG default,
  with `profile/`, `journals/` and `releases/<version>/`. Ownership journals are
  keyed by repository/environment/target and found by operation ID; completed
  decommissions are archived so a target can be provisioned again.
- Operations are addressed by ID: `--operation <id>` replaces `--operation-dir`
  and `--deprovision-operation` replaces `--deprovision-operation-dir` (removed;
  both refuse with guidance). Workflow status/resume select the single open
  operation, optionally scoped by environment/target/line/PR. Workflow operation journals move from the gitignored `handover/`
  to `<home>/journals/<owner>/<repo>/<operation-id>/`; release retention
  protects in-flight operations in both places. Finish or resume operations in
  flight with the previous release before upgrading; `--operation` refuses an ID
  found only in `handover/`.
- Moving: no migration command. Move or regenerate profile files into
  `<home>/profile/`, rebuild ownership journals of created/claimed resources,
  re-adopt adopted ones (zero mutations) and claim them; old journals and
  `~/.local/share/adw-handover/` remain as an archive. Kubernetes PoC objects
  created before identity annotations are re-provisioned after the release
  (deprovision, provision, redeploy) instead of copying journals;
  `--annotate-identity` applies only to objects whose journal is present at the
  new key.

## 0.15.4

Project tasks can opt into language-neutral dependency caches using
`dependency_cache = true`. This enables only the supplied cache root and explicit
`cache_env` bindings; it adds no Maven/npm variables or flags. Existing
`maven_cache` behavior and workspace choices are preserved. Declare language
lockfiles, tools and credential-free cache paths as described in the provider
dependency-cache guide. Caches remain optimization only, never quality evidence.

Read-only GitHub failures now carry a separate bounded diagnostic class through
destination/prior-association proof errors. HTTP status, timeout, operating-system
and malformed-response classes disclose no body or header values. Destination
proof uses the existing bounded transient read-only retry and reuses one exact-SHA
association observation within the same proof; it adds no persistent cache.
Identity, binding, checksum, administrator-denial and contract checks remain
authoritative. The reviewed GitHub GET process-call and function-scope pins are
updated for HTTP-header observation; routes, methods and read limits stay closed.
The trusted path list, its order, release/admission checks and workflow templates
are unchanged. Sandbox proof now waits for consistent completed run/job metadata
within its existing deadline before accepting outcomes; it never infers success
from contradictory metadata or retries an uncertain mutation.

Adapter loading rejects interpreter-prefixed file commands. Context checks
resolve every declared hook executable without running it or contacting a
provider. Use a Python file path directly; the dispatcher supplies the interpreter.
The generic task-contract check stays provider-neutral. Run both checks during
onboarding, before remote work.

Download released archives, launcher and checksums once beneath the private
operator release directory outside every checkout, reusing versioned assets and
verifying checksums on every use. With Mise lockfile generation enabled, generate
and commit `mise.lock` before quality/export. Repin canonically and obtain a new
exact-head review. No runtime deployment or ownership migration is part of repin.

## 0.15.3

An explicitly admitted released operator now takes a fresh complete live default
snapshot before consulting controller runs. When that snapshot proves the entire
ADW root absent, it validates greenfield admission directly. GitHub returns 404
for the unregistered workflow in this case; that response previously prevented
the independent admission from being considered.

There is no general 404-as-absence rule. Without an operator admission, controller
lookups and their failures behave exactly as before, with zero extra greenfield
reads. If the live default contains a controller or any ADW root, controller-first
processing remains unchanged and a completed decision keeps priority. The merged
seed bridge remains unchanged. Admission still checks published complete release
bytes, PR/default/source identity and administrator denials, and rechecks those
bindings before the existing non-forced ref write. CI remains quality evidence
only. No trusted path or call-boundary pin is added or changed.

Repin canonically to this release and obtain a new exact-head review before
retrying first adoption with its published checksummed launcher. Failed attempts
before the fix made no ref change; no reset or administrator enabled comment is
needed. First publication must still finish before the next main merge.

## 0.15.2

Live default-root inspection uses the canonical repository metadata endpoint;
failed reads still refuse and never prove absence.

Initial adoption without a default-branch ADW root uses explicit operator-only
greenfield admission. The released operator launcher verifies complete provider
and generic release snapshots, all four workflow copies and the live absent
default root before canonical promotion. First adoption needs operator opt-in,
with no ENABLED comment; explicit administrator DISABLED still refuses. CI on an
absent default produces quality evidence only; it grants no authority. Existing
controller paths remain unchanged. Any controller or partial installation refuses
greenfield mode; ordinary promotion cannot use a comment-only fallback when the
default has no runtime. The live PR/default and explicit denials are rechecked at
the ref-write boundary. Initial seed promotions precede publication/deployment;
subsequent delivery uses the normal controller and publisher.

The standalone `pzagent-greenfield` release asset runs outside every checkout
with isolated Python, Mise and authenticated `gh`; no provider checkout or
external Python package is needed. Download it with `SHA256SUMS` and verify its
checksum first. Before loading runtime code it checks both released checksum
rows/assets, its own bytes against the release source, and the complete runtime
inventory, Git blobs and modes. Exact-head consumer JSON is passive input only.
A fresh private operator installation invokes the same canonical task and uses
a persistent repository/PR/line/head/base journal key. Provider 0.15.2+ release
admission requires the launcher asset and both checksum rows; older provider and
generic release checksum formats remain unchanged.

Normal provenance follows the controller first, with no extra greenfield API
reads. Greenfield validation is consulted only with explicit process admission
or for a closed, merged PR whose controller is missing or unusable. Final
controller decisions and typed refusals take precedence; seed denial checks
cannot be skipped by a raw enabled comment.
A raw ENABLED comment requires a present controller run. An installed repository
whose controller never ran now refuses with `bootstrap_controller_missing`;
fix or rerun the controller instead of relying on a comment alone.

After main is seeded, a read-only proof bridge accepts only the closed, merged,
same-repository seed PR while its FF result/head equals the live default SHA.
Its immutable base must contain no trusted/ADW/vendor file, and executing runtime
and templates must equal the installed default bytes and modes. Current admin
denial still refuses. This grants no admission or write and expires when the
default moves: complete initial publication before the next main merge.

`modules.ci.greenfield` is a new trusted decision owner, appended to the existing
trusted-path order. It binds one process-local admission to repository, PR, head,
base and default SHA; CI data and serialized receipts cannot create that authority.
The operator promotion wrapper and CLI add only the explicit admission boundary;
normal publication, producer, quality and artifact integrity checks remain intact.

Quality tool fingerprints now use one fixed, read-only Mise JSON listing for
every source-declared tool, including Java, Node, Go, Rust, Python and
backend-qualified tools. Installed/active status, exact declaration/source and
resolved version components are validated; empty declarations, aliases/ranges,
objects, missing tools or malformed/duplicate/oversized output refuse with
`quality_toolchain_invalid`. Fingerprints contain sorted name-to-version values,
never paths. Java/Node have no fixed major restriction. Old compiler-string
archives are not reusable across this repin: a fresh hosted quality run is needed.
The initializer adds repeatable `--tool NAME=VERSION`; `--java`/`--node` remain.

## 0.15.1

Quality output provenance reads the Java/Node build-tool declarations from the
source-bound `mise.toml` `[tools]` table. Node-only consumers probe and record
only Node 22; Java-only consumers only Java 21; dual consumers retain the same
full observed-version fingerprint. Missing, unsupported, malformed, empty or
wrong-version declarations and unavailable declared tools refuse. Operator tools
are outside this Java/Node build fingerprint. No environment or project hook can
substitute a declaration.

Kubernetes provisioning now receives only the selected context alias's declared
pull/application keys. Other target and k3d-profile keys grant no provisioning
access; cluster-only inputs remain excluded. Private-profile parents above the
resolved root may be symlinks; the root and paths inside it still refuse links,
including the nested operation journal path. Cleanup that confirms an already
requested deletion is absent now persists `deleted: true`; planning remains
read-only and interrupted cleanup never repeats that deletion.

Trusted changes are limited to `pzagent_context.py`, `modules/quality_outputs.py`
and four existing function-scope pins in `modules/ci/trusted_decisions.json`. Fixed subprocess argv,
callsite hashes, validators, roots, classifications and the trusted-path list are
unchanged. Source, producer, recipe, stage and payload integrity binding remains
unchanged. Cold sandbox adoption and exact-head review precede release.

## 0.15.0

- Replace public `pz:cluster:up` / `pz:cluster:teardown` with `pz:k3d:up` /
  `pz:k3d:teardown`, without aliases. Internal CLI subcommands are unchanged.
- Separate local k3d infrastructure and cluster-wide TLS from Kubernetes target
  provisioning. Run
  `pz:k3d:up`, then `pz:provider:provision` for each explicit target. Kubernetes
  provisioning uses an explicit kubeconfig context on local or remote clusters;
  repeated provisioning preserves its own namespace, pull and application Secrets.
  Older bootstrap-owned objects and other operations are refused; there is no
  compatibility adoption or migration shim.
- The trusted CLI credential allow-list supplies declared pull/app Secret keys
  to Kubernetes provider provisioning; Cloudflare, ACME email and bind-address
  keys remain excluded. Shared TLS stays with the local cluster task or the
  remote cluster prerequisite, checked read-only before target writes.
  Project hooks and tool subprocesses still
  receive no bootstrap credentials. This requires an administrator trust-root
  decision and sandbox proof; it grants no deployment or CI authority.
- Correct generated Dokploy describe/config-plan/runtime-proof hook declarations
  and refresh the tracked scaffold. Document configuration application followed
  by a separate first deployment without `--sync-config`, preserving the empty
  restoration-snapshot refusal.

## 0.14.0

Dokploy now has canonical operator-only provisioning and deprovisioning tasks.
They validate the supported software version and typed API contract, create or
explicitly adopt named targets without deploying, and keep opaque ownership IDs
in private mode-0600 journals outside the checkout. Public operation receipts
contain logical bindings, counts and hashes only. Existing matching resources
need explicit adoption, which never grants deletion rights.

Readback-based resume never blindly repeats an uncertain create or delete.
Cleanup removes only journaled created resources, refuses foreign children,
preserves volumes, handles the implicit default environment, and independently
checks runtime cleanup after the provider API removes its row. CI refuses these
operator lifecycle commands before credential or provider access.




Ownership authority lives in versioned server-side description markers carrying
a public operation ID, nonce, logical target, role and parent ownership. Receipts
include operation ID and per-role ownership without IDs or nonce. Deprovision
`--operation ID` inventories these markers and works on another operator machine
without the commissioning journal; `--list` discovers operations read-only.
An owned ancestor retains runtime scope so lost child-delete acknowledgements
can be checked from a fresh machine. Edited/removed markers, collisions, changed
parents and foreign children refuse. Cached default flags never replace server
ownership; only the observed implicit production environment can omit a marker.
Half-created marked resources can be cleaned
without their original cache. Local private journals support resumable work; an
omitted cleanup profile defaults below the operator state directory. Newly
created Compose apps are initialized to raw source mode with exact readback,
because the installed create API defaults to github; adopted settings stay intact.
Provisioning preserves one JSON stdout object and prints its public operation ID
on stderr as the final displayed line.
Environment inventories normalize the supported API's nested project relation
only after matching its observed identity to the requested project. Missing,
foreign, contradictory or duplicate identities refuse before ownership decisions;
the request filter alone never establishes parent ownership.
Configuration reads recognize an explicitly null Environment on a newly created
Compose app as empty. Missing or malformed fields still refuse; existing
Environment text is preserved exactly, without writing provider settings.
For a newly owned pristine Compose app, provisioning combines raw-source setup
with empty image-variable slots from the uniquely matching release kind and
binding key schema. Empty definition/Environment and no scoped runtime are
required before initialization. Adopted or already-configured settings are not
rewritten; secret keys and undeclared image keys are never initialized. Other
required application settings remain operator prerequisites. Plans bind the key
selection; uncertain initialization acknowledgements require exact readback and
never authorize a blind retry. Shared missing-key and runtime-history guards
remain unchanged.

Pointer retirement is a separate trusted decision owner, `pointer_retirement`.
Its path is appended to `TRUSTED_PATHS` without reordering earlier entries, and
the declaration names its exact GitHub/provider observation exports and validators.
Provisioning, API transport and lifecycle receipts retain observation status.
The dispatcher and tasks expose operator-only plan/apply with an exact operation
digest; CI refuses before credentials. A completed private owned decommission,
target/binding removal and fresh scoped resource/runtime absence are mandatory.

Retirement moves only that target's current/rollback tags by expected-digest
checks onto unique, byte-verified, non-runnable OCI placeholders. Fresh package,
release-reference, protected-head and active-operation graphs must permit deleting
only those exact owned placeholder versions, followed by API and registry
readback. A foreign tag/reference or concurrent pointer change refuses. Former
release manifest/image digests are retained and checked after cleanup; resume
reconciles lost copy/delete acknowledgements without recreating deleted artifacts.
Normal retention eligibility is unchanged and can refuse an incomplete operation
until its placeholders have been retired. Orphan reporting is read-only and is
also included in retention preview; it never confers deletion authority.


## 0.13.2

- Recreated Kubernetes targets can deploy when a provider readback proves the bounded owned runtime empty, even when immutable registry current/rollback pointers survive teardown. No CLI flag, new authority input, protocol or trusted path changes.
- The proof checks owned declarative objects plus Pods and ReplicaSets in the bound context/namespace; bootstrap Secrets and PVCs are excluded. Namespace identity and the original snapshot bind the journal; read errors, non-empty or ambiguous observations refuse. Retained PVC counts and the registered previous manifest are recorded.
- Restore-on-failure returns a proven-empty target to empty runtime rather than deploying an image set that never ran. Scoped orphan deletion preserves bootstrap Secrets, PVCs and foreign dependents; only validated target-owned nonpersistent objects are removed. Normal storage guards and Dokploy behavior are unchanged.
- Keep failed old-version journals. After adopting this release, start a fresh canonical deployment operation for the same verified immutable application and reviewed configuration; never edit journal/pointer history to fabricate an initial state.

## 0.13.1

Private local-cluster bootstrap now supports closed `app_secrets` declarations.
Namespace-scoped application Secrets are created through stdin only and must
match the exact profile, context-alias target labels and declared key set.
Existing owned Secrets are preserved on retry; bootstrap never reads back values
or rotates generated passwords. Only internal database, storage, signing and
internal-service keys accept `generate: random-32`. Third-party/API credentials
require explicit environment-key sources; publication/Cloudflare credentials
cannot be repurposed. All referenced source keys are stripped from project
commands, hooks and cluster subprocesses. Application manifests still refuse
rendered Secret objects.

When the private cluster profile is absent, canonical cluster up can initialize
it from a tracked, bounded `infra/k8s/cluster-profile.json` seed. The closed seed
names cluster namespaces/context aliases and optional TLS/pull/application-secret
sources, with an explicit `PZ_ADW_K3D_BIND_ADDRESS` input. Local defaults pin K3s,
ports, dedicated storage and no registry. Plan validates without writing. Real
up creates a mode-0600 private file outside the repository after preflight;
existing private profiles are never overwritten. No address or credential value
is returned in task output. Missing/invalid facts refuse before cluster writes.

The CLI, adapter, provider registry, trusted decision declaration, workflow
bytes, publication authorization and existing approval/ownership gates are
unchanged. This is local operator bootstrap, not a new deployment mode or
permission to activate an environment. Recreating-cluster proofs use staging TLS;
production issuance and billable voice tests retain their own human decisions.

## 0.13.0

Kubernetes is a second deployment provider under adapter 1.2.0. It uses explicit
private context aliases, bounded server-side diff/apply and rollout, PVC and
ownership guards, ready-replica/observed-image proof and routed health/readiness.
Live/collision reads explicitly include server managed fields. Runtime Pods must
belong to the selected workload UID, following the ReplicaSet chain for
Deployments. Unchanged claim defaults and controller metadata are preserved or
normalized without permitting storage resize/deletion or retention changes.
Existing Dokploy adapters and immutable target names retain their behavior.
Hook image results accept strict DNS registry references (optional valid port),
reject IP literals/userinfo/traversal/uppercase, and explicitly bind every image
key and package to the declared release components before returning. Immutable
digests remain required except the existing source-bound hotfix tags. Registry
port handling is shared with the canonical digest-reference parser. Publication
authority, execution modes and approval receipts are unchanged.

Kubernetes hotfix transport is registry-only; restore re-applies its recorded
manifest and refuses unrelated configuration changes. Hotfix writes use the
same SSA manager as normal deployment; an existing image-Update artifact can
recover only its recorded immutable image fields after full non-image and
ownership validation, followed by exact full-manifest readback. Controller-owned
Deployment revision annotations are excluded; user annotations stay protected.
No force-conflicts or blind retries are used; exact no-op readback skips writes.

The operator credential set now includes Kubernetes context/configuration keys
and CF_DNS_API_TOKEN. Project build/test commands strip them; Cloudflare
credentials never reach project hooks. Rendered configuration snapshots and
restore artifacts are private; provider-manifest restore payloads stay under
private handover even for a CI invocation, outside public evidence collection.
Public results contain hashes, artifact references and key names.

New `pz:release:pointers:handover` supports read-only planning and an
exact-operation approval, validates immutable current/rollback graphs, copies
with expected-target checks and keeps a resumable journal. Existing destination
pointers need `--replace` and approval. It does not activate a runtime. A partial
handover is retained for explicit resume; no manifest deletion substitutes for
removing a tag.

`pz:project:init --provider kubernetes` generates shadow targets, explicit image
mappings and a local Kustomize base/overlays using the HTTP example templates.
Application ports/routes/probes must be reviewed before activation; image and
operator URL example values stay empty. Kubernetes runtime code stays outside CI
authority. Trusted adapter/registry/credential changes require the reviewed
closure declaration and full frozen-head sandbox proof before release. The
reviewed registry declaration adds Kubernetes as an observation implementation
and reaches the existing transaction compatibility re-exports; trusted retention
continues to validate immutable component/protected-root identity. The ordered
trusted path scope, CI decision owners and loader validation remain unchanged.
`bundle:provider` selects default hooks by the exact active target on mixed
adapters, while explicit provider selectors and project overrides retain precedence.

`pz:cluster:up` and `pz:cluster:teardown` manage one private-profile-bound local
k3d cluster and optional loopback registry in existing human mode. Ownership,
foreign-cluster fingerprints and complete leftover checks are mandatory. The
sole Docker cleanup exception removes an exact empty, app=k3d-labelled orphan
network only when k3d lists no such cluster. Fixed diagnostic categories retain
useful failure information without raw provider output. External DNS, credentials,
cached images and the dedicated directory remain operator-owned.

The local lifecycle selects/journals a positive loopback API port and verifies
its exported TLS endpoint before namespace writes. Optional closed `tls` and
`image_pull` profile blocks add pinned/checksummed cert-manager, bounded
Cloudflare DNS-01 issuance of one wildcard in the bundled Traefik namespace,
a single default TLSStore, and namespace-scoped GHCR pull Secrets. The install decoder accepts kubectl's multi-document JSON stream and refuses
partial, duplicate or oversized inventories before apply. Missing
TLSStore CRDs and foreign default stores refuse; no second ingress controller.
Pull inputs use GHCR_PULL_TOKEN, GHCR_USERNAME and ACME_EMAIL; publication
authentication keys cannot serve as cluster pull-token keys.
Inputs travel from declared environment keys to stdin only; metadata/Ready
readback returns no values. Bootstrap keys are stripped from every child and
refused even in project-task inheritance. Pull credentials are referenced by
workload imagePullSecrets through private context profiles. All bootstrap
resources disappear with canonical cluster teardown; changed profiles are
accepted only after completed teardown and verified resource absence. Local
acceptance requires staging issuance, idempotence and complete teardown. This
is a bounded lifecycle option, not a generic TLS/provisioning API; later
flagship activation remains a human decision.

Existing CI jobs use fast recorded-JSON fake-kubectl executable tests; no cluster
starts on PRs or pushes. Local real public-task acceptance is required whenever
the driver changes and is reported operator-run, not CI-proven. No execution
mode, receipt bypass or publication authority changes. Rehearsal accepts target
lanes and already-published immutable refs, fingerprints untouched active targets
and stops after the first failure. The consumer uses a shared base and thin
overlays with manual Compose synchronization; contract/parity automation is
deferred.

## 0.12.1

The trust-root bootstrap workflow reads the live pull-request state before checking out the default-branch controller. Closed or merged pull requests finish successfully without evaluating a decision, uploading a decision artifact or publishing a check run. Open pull requests retain the exact-head administrator and released-vendor gates. Consumers receive the updated template through canonical context sync; all four workflows must remain template-identical.

Promotion observes the ref up to four times, two seconds apart, after its single non-forced fast-forward request. Only the saved previous SHA is retryable. A foreign or malformed ref still refuses immediately; a persistently old ref remains uncertain with the journal in `requested`. Resuming observes the saved operation and never repeats the ref write. Exact merged-PR and destination proofs remain mandatory.

Producer fixtures disable automatic Git garbage collection and maintenance before creating commits, avoiding background cleanup races. Skill release archives exclude `__pycache__`, `.pyc` and `.pyo`; the package validator checks the actual built archive before publication. Producer CI also runs the decision-closure and canonical AST-fingerprint tests on Python 3.11, 3.12 and 3.13.

The existing trusted workflow template and promotion owner change, requiring the private sandbox feature, promotion, administrator-comment rerun and cold-adoption proofs before release. The ordered trusted scope, decision owners, closure declaration, explicit-denial handling, artifact integrity and authority boundaries are unchanged. Consumer adoption is a released repin; live controller output determines any human decision.

## 0.12.0

Declarative project commands and deterministic project initialization. Eight local project tasks use `modules/project_tasks.py`; `adw:verify:full` remains context-owned, preserving child evidence and CI quality export. Stubs refuse with actionable unimplemented-task names. The runner supports ordered argv commands, isolated/shared workspaces, explicit environment clearing, Maven caches, report collection and timing attachments.

`pz:project:init` creates marker-owned configuration, valid schema 1.1.0 project facts, release recipes, empty example values and the four unchanged canonical workflows. It defaults to `.adw/`, supports legacy `.hermes/`, refuses Kubernetes until its provider is implemented, and requires pinned vendor provenance. It never creates provider resources or secrets. Re-running unchanged input reports no changes; unowned or edited files require explicit `--force`, while unsafe paths always refuse.

Local project commands strip operator credentials, registry auth-config paths and SSH/approval handles by default. Named inheritance exceptions require an explicit per-task list and bounded justification; examples and ordinary build/test commands need none. `pz:project:init --refresh-manifest` refreshes only the project wrapper checksum and refuses protected context-task overrides. Onboarding includes verified archive acquisition, exact source-ref selection, an offline fixture path and explicit example-overlay commands.

Compatibility: the scaffold uses adapter schema 1.1.0, eight project wrappers plus the context-owned full graph, and existing human execution mode for read-only release inspection. No trusted decision code, declaration, workflow template or authority rule changes. Consumers may keep existing task wrappers as thin executor adapters, preserving their project-source checksum during a released repin.

## 0.11.0

R3 supports the project directory `.adw/`, retaining `.hermes/` for existing projects. A single filesystem resolver selects `.adw`, otherwise `.hermes`, otherwise `.adw` for a new project; both present refuse with `project_directory_conflict`. Operator home/profile paths are separate and unchanged.

The ordered trusted-path tuple preserves all 51 entries from 0.10.0 and appends only `.adw/adw-task-manifest.json`, the alternate location of the existing manifest authority. Both manifest paths are released-vendor eligible; a directory migration still requires an explicit exact-head administrator decision rather than treating a manifest removal as a pure source-record repin. No older artifact gains authority over a newly changed path; ordered-subset, explicit-denial and all integrity/binding rules remain unchanged.

Exact-SHA remote metadata reads select one coherent directory and distinguish absent content from transport or permission failure. Workflow jobs resolve and export `ADW_PROJECT_DIR` after checkout; cache declarations explicitly check both locations. Context sync preserves the selected layout while staging. The three legacy fixtures stay byte-identical; the fourth uses the same second-project adapter with generic 2.2.0 and the modern directory. Only canonical AST scope hashes changed by path routing are refreshed in the decision boundary declaration; its roots, validators, process calls and observation permissions are unchanged.

The full R3 implementation and fresh dual-layout sandbox proof belong to this one provider PR. Release 0.11.0 only after final exact-head review and proof. Consumers adopt the release and migrate the project directory in one reviewed PR, update project references and validate the full graph before canonical promotions.

## 0.10.0

R2b defines CI decision ownership and adds a producer-side dependency review guard. The ordered trusted-path tuple preserves every prior entry and appends these existing decision owners plus the protected boundary declaration:

- `modules/execution.py`: selects the operator-versus-CI receipt policy.
- `modules/build_outputs.py`: validates payload identity and integrity seals.
- `modules/retention.py`: selects deletion candidates from protected reference graphs.
- `modules/operator_registry.py`: validates immutable manifest/layer bytes and release identity.
- `modules/operator_lines.py`: accepts exact PR promotion and destination proofs.
- `modules/merged_source_proof.py`: accepts the merged-work-branch cleanup proof.
- `modules/operator_state.py`: validates and locks resumable decision journals.
- `modules/ci/trusted_decisions.json`: declares reviewed roots, observation exports and dynamic/process boundaries.

A decision root owns CI provenance, proof/gate acceptance, publication authorization, integrity or producer binding, promotion, or retention/deletion eligibility. Dispatchers, provider observations and project hooks do not confer that authority. Explicit observation exports retain named trusted validators; the producer tests reject undeclared direct/transitive dependencies, unvalidated decision acceptance, stale allowlist entries and unreviewed dynamic/process boundaries. This is a review guard, not Python runtime isolation. AST fingerprints use a canonical node/field encoding across Python versions; empty or absent schema fields and source positions do not alter identity, while nonempty fields, expression contexts and code changes remain significant.

The older controller's artifact confers no authority over newly trusted paths. It must still pass every binding and integrity check and report a non-empty ordered subset of the current changed trusted paths. Explicit denials remain authoritative; expanded-scope cold adoption requires the administrator's `BOOTSTRAP_ENABLED <current fingerprint>`. No gate, producer, sealing or refusal check is relaxed. Obtain actual per-PR/head/base fingerprints rather than reusing an earlier decision.

R2b is delivered in two provider PRs: the trusted-decision criterion (#116, issue #112) and live-status identity (#117, issue #114). The first is merged without tagging; 0.10.0 is released only after the second's independent exact-head review and fresh sandbox/preview proof.

`adw:deploy:status` now adds `health` and `release` blocks for the selected logical target: immutable manifest/source/component identity, current/rollback digests and runtime/manifest/current parity. It starts at the declared current pointer, uses canonical validated registry reads and never searches tags. Missing rollback is `absent`; identity failures have fixed reasons and retain health, with the existing refusal exit 21. Healthy/proven remains exit 0, and failed-health behavior is retained. The hook ABI and generic task/evidence contract do not change. Use this task instead of one-off readback collectors.

The provider protocol adds `observed_image_refs(owned_keys)` for unique digest-only runtime images, sharing Docker observations with default hooks. `live_image_refs` keeps configured-reference semantics for retention; configured-but-not-running images remain protected. Registry credentials and authentication configuration stay out of hook subprocesses. Status uses only provider GETs and canonical registry reads, with a final current-pointer concurrency check. The existing trusted protocol and CLI change under the same trusted scope; this PR requires its own exact-head decision and sandbox proof. Consumers repin the released bundle through the canonical sync task, then prove preview status parity. No application or deployment configuration change is needed.

An observed container must be running and healthy with a health block, matching the existing default-hook predicate. Exited, restarting, unhealthy or healthless containers refuse with `runtime_container_not_running`. All matching containers still count for cardinality: an exited leftover plus a running container refuses ambiguity, consistently with the default hooks.

## 0.9.0

Deployment orchestration now dispatches through the typed registered-provider protocol. Dokploy discovery, byte-preserving configuration transactions, bounded deployment correlation, log guards and cancellation live in its provider implementation. Shared approval, journaling, publication/retention predicates, hotfix locking and restore evidence retain their semantics. Retention resolves credentials per target inside provider discovery after its read-only status probe, rather than one lookup before the inventory loop. This changes only observation order; every failure still precedes deletion and the shared root/authorization predicates stay. Unknown provider kinds refuse with `provider_unsupported`; unsupported optional state/volume capabilities refuse with `provider_capability_unsupported`.

`release_kinds.image_variables` is canonical. `compose_variables` remains an alias; identical declarations normalize to one map, while conflicting declarations refuse with `image_variable_alias_conflict`. Existing adapters and argv project hooks remain accepted. Select default runtime hooks with `hooks.dispatcher.command: bundle:dokploy`; per-operation `command` retains project overrides. Optional binding `plan` declares safe role/order semantics; `probes` declares an exported base-URL key and health/readiness paths, with no URL values committed. Default runtime proof derives services from the tracked declaration and requires exact image/project/service identity and one running healthy container per service.

Set `.hermes/pz-release.json` `hooks.build` to `bundle:release_build` for the default release builder/packager. Remove `package_hook` to use matching packaging. The canonical project release-build branch invokes `modules.release_build.command`; local builds and project recipes remain project-owned. Image labels, sealed stage identities, source fingerprints, recipe/cache declarations and immutable publication checks are preserved.

The target loader reads `infra/deployment-targets/*.yml` against the bundled schema; add explicit `schema_version: 1.0.0` headers before replacing the old project loader. The unused `compose_inputs` module is removed. Its three dead tests are the only baseline-ID exception; runtime image equality proof and its refusal strings stay.

Adoption order: remove superseded project helpers, choose bundled defaults and required project overrides, declare probe/plan facts, update inventory version headers, run canonical context sync and full verification, then validate preview status/deployment. The ordered trusted-path tuple appends only the provider registry/protocol; implementations keep their previous trust status. Cold adoption therefore requires the human administrator's current-scope `BOOTSTRAP_ENABLED` decision. A combined code-removal/task-ownership transition may also require the old controller's exact fingerprint. Obtain each from actual output; never reuse decisions across PRs. Git must reach `origin` non-interactively before promotion.

The final provider head requires all four live CONTRIBUTING item-4 sandbox cases and the two-lane preview rehearsal before maintainer review, merge and release.

## 0.8.0

Publication now uses the bundle's release coordinator and quality output handover.
The `publish-release.yml` template accepts `release_kind` for every declared kind,
using exact authorization, immutable inventory, compatible quality import or
canonical ADW build, packaging and publication. Optional Docker caches remain an
optimization. Producer binding and sealed stages are unchanged.

An older default-branch controller's decision confers no authority over newly trusted paths. Cold adoption of a release that adds trusted paths needs the administrator's `BOOTSTRAP_ENABLED <current fingerprint>`; explicit denials are preserved.

Select an optional mutable pointer explicitly with `publication_pointer` and
`expected_pointer_digest`. The selected pointer must be declared by the release
kind. Pointer selection is independent of the PR or destination proof scope;
leaving both inputs empty publishes only immutable references. A template never
assumes that every release kind has a pointer named after the proof scope.

Consumers repin with `adw:context:sync`, which now writes all four pinned workflow
files: `ci.yml`, `trust-root-bootstrap.yml`, `publish-release.yml` and
`cleanup-retention.yml`. Use `pz:workflows:sync` for explicit reconciliation or
`pz:workflows:sync --check` for read-only drift reporting. Repinning replaces
manual workflow copying. Cleanup still requires explicit dispatch and defaults
to a dry run. The classifier refuses drift in any of the four files.

For the first adoption from a pre-0.8.0 runtime, the sync invocation itself still
executes the old installed code. Run `pz:workflows:sync` once after that repin to
install the four templates. Subsequent context syncs execute the new runtime and
perform workflow reconciliation automatically.

Consumer checklist, in order:

1. Repin with `adw:context:sync`.
2. Run `pz:workflows:sync` once when adopting from a pre-0.8.0 runtime.
3. Declare `native_provenance` per component in `pz-release.json` wherever a
   project-side native check existed. The `voice-runtime` declaration in the
   consumer fixture is the example; the provider's `docs/releasing.md` names its
   exact path. Without the declaration the check is silently skipped.
4. Remove the project `adw:verify:full` override and its export call **in the same
   PR**: context sync already records `source: context` in the manifest, while a
   project task override still takes precedence until removed. The new runtime
   refuses sync and context checks with `context_task_override_requires_removal`
   if project tasks or inline mise tasks still override `adw:verify:full` or
   `adw:describe`. Remove the override before syncing with the new runtime. The
   first adoption still executes the older installed sync code, so its PR must
   remove the override before running the new context check.
5. Delete project quality-output and CI release coordinator copies, their tests
   and per-kind publication workflows.
6. Expect one `bootstrap_required` stop for adoption of newly trusted paths,
   following the administrator-comment procedure below.

After repinning, delete project quality-output and CI release coordinator copies,
their superseded tests, and per-kind publication workflows. Remove the project
`adw:verify:full` override and its export call so the context wrapper runs the
manifest's full verification graph, retaining the shared workspace for CI export.
Consumers keep build commands, packaging hooks and native dependency recipes.
`adw:describe` adds context extension tasks under `context_tasks` without changing
the canonical ADW capability set. Context sync updates these wrapper source records.

`adw:verify:full` copies the tracked source into an isolated workspace and runs
`adw:install` and every leaf in `verification.full` with `ADW_SHARED_WORKSPACE`
set to that copy. Leaves must build and write outputs under `ADW_SHARED_WORKSPACE`
when it is set; a leaf that ignores it makes the CI export fail with
`quality source changed during verification` or
`declared quality output is unavailable`.

The local workspace includes tracked and nonignored untracked source files;
gitignored inputs, generated output directories and local environment files are
excluded. Source symlinks are refused. Required inputs must be tracked or generated
by a verification leaf under `ADW_SHARED_WORKSPACE`; do not depend on an ignored
developer-local input already being present in the isolated copy.

Component stage mappings remain in `pz-release.json` (`quality_exports`,
`components`, `platforms`). An optional component `native_provenance` declaration
names `record` (workspace-relative), `platform_field`, and `files`. Each digest
field maps to `{root: source|workspace, path: relative-path}`. Declare the same
platform, library and recipe digest comparisons formerly in the project helper;
there are no built-in component names, library paths or native recipes.

CI sets `ADW_BUILD_OUTPUT_DIR` outside the shared workspace. `adw:verify:full`
exports split archives and `upload-manifest.json` only in CI mode, after every
required leaf passes. Local quality does not export implicitly. The supported
Java 21 / Node 22 producer-tool check is retained from the original implementation.

Adopting a release that adds trusted paths (0.8.0 adds `quality_outputs.py`,
`quality_tasks.py`, `ci_release.py`, `workflows_sync.py` and the committed
`publish-release.yml` and `cleanup-retention.yml`) runs two verifiers: the
trust-root gate executes the consumer's default-branch controller, which approves
its own, smaller trusted-path scope automatically (`released-vendor`); the classify
step executes the vendored verifier, which knows the new paths, treats the
smaller-scope decision as granting no authority over them and reports
`bootstrap_required` with the current fingerprint. The administrator posts one
`BOOTSTRAP_ENABLED <current fingerprint>` and re-runs; afterwards same-scope
repins are automatic again.

The fixed reason identifiers introduced by the quality/coordinator/workflow tasks
(exit 21) are `quality_task_failed`, `ci_release_handover_failed`,
`quality_verification_graph_invalid`, `quality_ci_execution_required`,
`quality_native_provenance_invalid`, `quality_native_provenance_mismatch`,
`quality_output_path_invalid`, `workflow_template_drift`, `workflow_sync_failed`,
`workflow_template_unsafe` and `workflow_symlink_rejected`. Publication settings
add `ci_release_configuration_invalid`; context sync adds
`context_task_override_requires_removal` and `context_project_tasks_invalid`.
The quality CLI preserves its allowlisted fixed `ContractError` refusals,
including `quality_ci_execution_required`, `quality_verification_graph_invalid`
and the native-provenance identifiers. Fixed descriptive refusals such as
`CI quality source contains untracked files`,
`quality source changed during verification` and
`declared quality output is unavailable` also reach the caller unchanged.
Unknown contract errors, external exception data and operational errors retain
`quality_task_failed`. Coordinator failures retain `ci_release_handover_failed`
in hosted CI; the local lab preserves fixed coordinator messages and
identifier-only public-task diagnostics. Workflow sync maps raised validation
failures to `workflow_sync_failed`; direct helpers retain their specific failures.

Both `pz:quality:export` and the `adw:verify:full` wrapper write
`build_upload_manifest` to `GITHUB_OUTPUT` in CI mode when that output file is
provided. Human-mode export does not emit a CI step output. The import/prepare
workflow step sets `MISE_AUTO_INSTALL=false`, matching the canonical build step.

The coordinator's configuration step reads the registry from the release kind's
manifest and component packages and selects the first declared platform in
`pz-release.json`, or validates an explicit `PZ_CI_PLATFORM` against that list.
One publication job requires a single declared registry. The template logs in
only after configuration and passes the selected platform to canonical build;
it no longer assumes a registry or platform in its workflow text.

The implementing agent performs provider fast-forward merge, tag and Release
mechanics and consumer promotions after the maintainer's PR review approval,
within the accepted plan. Self-merge requires explicit authorization in that plan
step. Every `BOOTSTRAP_ENABLED` / `BOOTSTRAP_DISABLED` comment remains human-only;
failing acceptance or work outside the plan requires a stop and report.

## 0.7.4

The `authorize-publication` action now prints `blocked: publication proof invalid (<reason>)` for `ProofError`/`ApiError` refusals (fixed identifiers such as `destination_exact_gate_missing`, never response bodies), writes the same line to the step summary and exposes it as the action output `reason`; other error classes keep the generic text. Input descriptions in the action and in `templates/github/publish-release.yml` state that `ci_run_id` is the PR's own `pull_request` CI run for the source SHA (for destination scope the promotion PR's run, completed before the merge), never the destination branch's push run, and that `pr_number` for destination scope names the merged promotion PR. Trusted paths changed (action and template bytes), so the repin needs the usual released-vendor approval; `workflow-drift` is unaffected (`publish-release.yml` is not drift-checked). (#100)

## 0.7.3

Destination proofs for a promoted line no longer fail once a repository has 20 closed promotion PRs. `promotion_pulls` pages newest-first (100 per page, up to 3 pages), returns only the PRs whose head or merge commit is the proved SHA, and treats the inventory as incomplete only after 300 records without a match. The publication authorization accepts `pr_number` as an optional hint for `destination` scope and verifies that PR directly, so a consumer publication workflow that knows the promotion PR is independent of GitHub's commit association, which does not list fast-forwarded promotion PRs reliably; a hinted protected-branch source must still be a declared promotion pair.

Refusals without a decision now say why (#97): `bootstrap_required` only for an explicit controller rejection or a visible run whose artifact waits for the administrator; `bootstrap_controller_missing` when no controller run is listed for the PR head; `bootstrap_controller_unusable` when a run exists without a usable completed artifact. One transient-retry policy (`with_transient_retry`, 60 s ceiling, 5 s polls) now covers the `pz:release:promote` pre-check and CI `classify` as well as the existing gate appearance grace and read-back retry; it retries `bootstrap_controller_*`, `*_lookup_failed`, `destination_association_*`, `destination_candidate_*` and `destination_exact_gate_missing`, never `bootstrap_required`, identity, checksum, contract or promotion-pair refusals, and never wraps a mutation. The operator failure message carries the exact listing to rerun. What counts as approval is unchanged.

CI-first publication policy: agents publish and deploy through `pz:release:promote`, `publish-release.yml` and `pz:workflow:deploy-existing … --verify`; the local `pz:workflow:publish*` toolchain is a fallback only when CI cannot carry provenance for the change and the human explicitly insists, and such a release is reported as operator-attested. Stated in `SKILL.md`, `policy.md`, `references/release-and-deployment.md` and `references/agent-permissions.md`; the package validator checks the wording.

## 0.7.2

The trust-root gate no longer fails closed when its CI run starts before the controller run is visible. If no exact controller run exists yet, the gate keeps polling for up to 60 seconds (never beyond its wait bound) before falling back to the administrator comment; a visible pending run is awaited as before, and `wait_seconds=0` keeps the immediate fallback. Foreign or invalid runs and missing, expired or waiting artifacts still fall back immediately.

`pz:release:promote` proves the fast-forwarded destination by the PR it just merged (`destination_gate(..., pr_number=N)`) instead of rediscovering it through `commits/<sha>/pulls`, which lags `pulls/<n>` for a few seconds after a fast-forward and produced `destination_exact_gate_missing`; the read-back also retries transient rejections for up to 60 s before leaving the journal resumable. No second ref update is ever sent.

## 0.7.1

The CI proof and promotion path (`modules/ci/contract.py`) no longer hard-codes the generic contract version `2.1.2`. It accepts any `2.x` version that the vendored `mise-helper/vendor/agentic-delivery/adw_contract.py` at the same commit declares as `CONTRACT_VERSION`, mirroring the `adw:context:check` engine cross-check; a declaration that differs from the engine is `generic_engine_mismatch`. Without this, a consumer repin to generic 2.2.0 was refused by `pz:release:promote` (`contract_pin_mismatch`) and CI fell back to the full quality graph.

## 0.7.0

Repository restructure with no task, schema or workflow-template change. The Agent Skill is spec-conformant (flat metadata, `metadata.version` equals the bundle version), under 80 lines, and free of operator or project values; operator setup moved to the repository's `docs/operator-setup.md`. The skill ships one project adapter template (`templates/project-adw.md`, the compact form with an optional-sections appendix); the bundle's duplicate `templates/project-adw.md` is removed from the inventory. The pre-contract `ci-java.yml` and `docker-publish-ghcr.yml` skill templates are gone: consumers use the bundle's `templates/github/ci.yml` and `publish-release.yml`. References are consolidated (`references/release-and-deployment.md`, `references/project-adapter.md`, `references/bootstrap/`). The exact-edit helper now lives in the separate `pz-safe-edit` skill. The installer requires an exact commit and archive checksum, and a release workflow publishes tag-verified GitHub Releases. Consumers repin as usual; nothing in the vendored runtime behaves differently.

## 0.6.4

Released-vendor verification compares blob SHAs instead of downloading files: the consumer head tree (already read for the changed-path check) is compared with the provider release commit's recursive tree (`git/commits/<ref>` and `git/trees/<tree>?recursive=1` through the provider token), for every changed vendored file and for the workflow files against their templates. A blob SHA identifies the bytes exactly, so the decision is unchanged; when either tree is unavailable the previous per-file SHA-256 inventory comparison runs. The trust-root gate polls a pending controller run every 5 seconds instead of 15, because the controller now completes in a few seconds; the wait bound is unchanged.

## 0.6.3

Faster trust-root and promotion proofs with identical results. The changed-trusted-paths check reads one recursive Git tree per commit (`git/trees/<sha>?recursive=1`, now allowlisted) and compares the blob SHAs of the trusted paths instead of downloading every trusted file at head and base; a blob SHA identifies the bytes exactly, so the computed set and the bootstrap fingerprint are unchanged. A truncated, oversized, malformed or unreadable tree falls back to the previous per-file comparison with the same error classes. Reads addressed by a full commit or tree SHA (`contents/...?ref=<sha>`, `git/commits/<sha>`, `git/trees/<sha>`) are fetched once per client within one process; refs, pull requests, check runs, workflow runs and comments are still read live every time. Measured on a consumer's `demo -> main` destination proof with 36 trusted paths: 177 GitHub calls and 66 s before, 35 calls and 17 s after, with identical changed-path results.

## 0.6.2

Documentation-only follow-up: cold adoption has one extra step when the consumer's default branch predates a release that expands `TRUSTED_PATHS`. The default-branch gate computes the old fingerprint, while the PR-head classifier and promotion operator compute the new fingerprint; an administrator must post both exact `BOOTSTRAP_ENABLED` lines printed by those implementations on each affected PR, then use **Re-run all jobs**. Fingerprints remain bound to the PR number, head, base and exact trusted-path set and must never be copied between PRs. This is a one-release migration bridge: after the default branch vendors v0.6.1, later exact released-vendor repins return to artifact-backed approval without either comment. See [#81](https://github.com/smarterworkerai/pzagent-adw-context/issues/81).

Alignment with the generic layer: `adw:context:check` now rejects a mise executable older than the bundle's `minimum_mise` (2026.9.13; previously a hard-coded 2026.0.0) and requires the vendored `mise-helper/vendor/agentic-delivery/adw_contract.py` to declare the same `CONTRACT_VERSION` as the manifest's `contract.version`, because the generic `tasks.toml` checksum alone does not distinguish generic releases. Evidence records written by context remote tasks take `schema_version` and `contract_version` from the manifest's declared generic contract instead of a constant, so they stay valid when a project repins the generic layer (the 2.2.0 evidence schema pins both to `2.2.0`). A manifest without a `contract` block yields no record and a stderr warning, as before for other record errors. Evidence status now follows the task's exit class as the generic schema requires (0 passed or unsupported, 1 failed, 20 blocked, 21 contract-error): a pz guard refusal (exit 21, reported `blocked`) is recorded as `contract-error` with a `task.status` finding that keeps the reported label. Earlier records with `blocked`/21 were not valid against the generic schema.

Provider `main` must not advertise a published version after its inventoried bytes diverge from that release. The bundle now identifies these post-v0.6.1 bytes as 0.6.2; the v0.6.1 tag and GitHub Release remain immutable. This does not publish v0.6.2.

## 0.6.1

The canonical CI workflow keeps its v0.6.0-compatible `ci.py bootstrap-status --repository … --pr …` invocation, with no new flags, and consumes an immutable controller decision artifact instead of recomputing released-vendor approval without the provider token or trusting GitHub's same-SHA check-suite filing. The gate queries the exact source branch and head SHA for the latest completed `pull_request_target` controller run, downloads `pzagent-trust-root-decision-<pr>-<head>`, and verifies its server digest, repository/run identity, PR number, head, base, changed paths, controller binding, fingerprint and decision status. Missing, expired, waiting or foreign evidence falls back to the exact live administrator comment; only a visible pending exact controller run is polled, every 15 seconds for at most 300 seconds by default (600 maximum). On an unprivileged `pull_request` event, `bootstrap-status` selects the artifact-backed gate with its built-in wait; controller `pull_request_target` and `issue_comment` events keep producing decisions. The `trust-root-gate` and `required-quality` jobs each have a 20-minute job timeout; the controller-evidence wait remains independently bounded.

`classify` now depends on `trust-root-gate`, preventing a successful stale full-quality classification from being reused after trust-root approval. The waiting controller check remains `action_required` and its message gives the exact admin instruction. The admin-facing controller comment says **Re-run all jobs**. The head CI workflow never receives `PZAGENT_PROVIDER_TOKEN`; released-provider verification remains confined to the trusted controller.

Consumers must repin the complete bundle and recopy both `templates/github/ci.yml` and `templates/github/trust-root-bootstrap.yml`. Workflow drift and released-vendor verification now require both committed workflows to be byte-identical to those templates.

## 0.6.0

Adapter schema 1.1.0 reduces `.hermes/pzagent-adapter.json` to project facts. The sibling `.hermes/adw-task-manifest.json` is now the only source of capabilities and environments. The normalizing loader reads both files from the same revision and returns the existing runtime 1.0.0 shape, so provider code retains one internal contract. Legacy 1.0.0 adapters remain supported and must match the manifest when it is present; the missing-manifest compatibility fallback emits a deprecation warning and will be removed in 0.7.0.

The exact compact defaults are: empty `ci_only_checks`; CI workflow `.github/workflows/ci.yml` and required job `required-quality`; hotfix environments derived as the manifest-ordered intersection of `adw:hotfix:apply` and `adw:hotfix:restore`; pointer tags `target-{target}-current` and `target-{target}-rollback`; dispatcher `python3 mise-helper/pzagent_adapter.py` with `python3` PATH-allowlisted; E2E result keys `status, selected, executed, skipped`; and deployment-validation result key `images`. A provider-level Dokploy project supplies an omitted binding project.

A target string shorthand such as `"pr-preview": "application-preview"` expands to one active default target named exactly `pr-preview-dokploy`. The logical name is deliberately preserved because pointer tags and approval receipts bind it; changing the expansion would orphan live current/rollback pointers.

Consumer rewrite recipe: repin the complete 0.6.0 bundle first, then change the adapter schema to 1.1.0; remove the capability/environment copies and obsolete CI-task, provider-profile, retention-kind, and derived hotfix fields; replace eligible one-target groups with binding strings; hoist a repeated Dokploy project; and omit only the defaults listed above. Before committing, prove the old and new files normalize to deep-equal runtime objects.

## 0.5.3

A trust-root check whose external binding belongs to another same-SHA promotion PR is now ignored for the PR being validated. The gate recomputes that PR's exact live administrator decision; the mismatched check grants no authority, and a missing comment remains blocked.

## 0.5.2

A correctly-bound trust-root check that GitHub associates with an earlier same-head PR controller run is now treated as unprovable controller metadata. The gate recomputes the current PR's exact administrator comment live, preserving fail-closed trust while allowing evidence reuse across sequential feature-to-demo and demo-to-main PRs.

## 0.5.1

The canonical CI workflow now subscribes to pushes on both `demo` and `main`, so every protected release-line fast-forward can run destination proof and skip the already-successful full quality graph. Re-copy `templates/github/ci.yml`.

## 0.5.0

Breaking CLI change: `pz:release:promote` now requires `--pr N` and accepts only the default `--strategy fast-forward`. The live PR supplies the source branch and SHA; optional `--ref` is only an equality assertion. Merge and restore-tree promotion are removed, while restore-tree remains the release-line rollback default.

Promotion now reuses `pull_request_gate`, journals the exact quality run, tree and contract under operation schema `1.0.0`, writes the destination ref at most once, waits for GitHub to record the PR as merged, and finishes through `destination_gate`. An interrupted `requested` operation is resumed with `pz:workflow:resume` without replaying its ref update. Incomplete pre-0.5.0 source-line journals lack the required promotion evidence or rollback kind and cannot be resumed automatically; inspect their destination and start a new operation. New promotion and rollback journals retain schema `1.0.0` and remain compatible with status, resume and retention.

The REST behavior and credential choice were verified before implementation with [scratch PR #67](https://github.com/smarterworkerai/pzagent-adw-context/pull/67) and [push run 36725967776](https://github.com/smarterworkerai/pzagent-adw-context/actions/runs/36725967776): an operator-PAT non-forced ref update marked the PR merged at its exact head and triggered destination push CI.

## 0.4.5

The CI classifier now emits `proof_rejected` when exact-tree evidence reuse is refused while leaving the existing routing `reason` unchanged. Re-copy `templates/github/ci.yml` and `templates/github/actions/classify-ci-event/action.yml` to surface the content-safe rejection reason in job outputs and summaries. A protected destination whose head is a merge commit reports `destination_merge_commit` and runs the full quality graph.

## 0.4.4

Compatibility: remote-task evidence and CI contract validation now use agentic-delivery contract/schema 2.1.2, allowing consumers to repin the generic provider without version skew.

## 0.4.3

Compatibility: the bundle's declared minimum mise version is now `2026.9.13`, matching the exact version exercised by producer and generated consumer CI. Older mise versions are no longer claimed to be supported.

## 0.4.2

Fix: `pz:rehearsal` ran its kind-mismatch refusal before anything was published, using `--ref HEAD`, so it was refused by the "release is incomplete" check instead of the kind guard and reported as a failed check. The check now runs after publishing: a real published release is deployed with the wrong kind, and into the other kind's lane; both must be refused before provider access.

## 0.4.1

Fix: the trust-root controller's check run can be filed by GitHub into another workflow's check suite for the same head (for example the `ADW CI` `pull_request` run), which made `premerge-check`/`proof-*` fail with `bootstrap_controller_invalid`. Such a check's origin is unprovable, so it is now ignored and the decision is recomputed live from the PR diff and administrator comments. A forged or misfiled success check still cannot approve a trust-root change.

## 0.4.0

- `hotfix-apply` rejects an invalid `--run-id`/`ADW_RUN_ID` (pattern `^[a-z][a-z0-9-]{0,62}$`) before credentials, build or transfer. Previously some contract-valid IDs (uppercase, dots) failed only after the build.
- `adw:context:sync` resolves its GitHub token through the shared operator credential loader (`.env.deploy` or environment), child-scoped.
- The credential loader warns (stderr, path and mode only) when a credential file is readable by others.
- Remote `adw:*` tasks write generic ADW evidence records (`adw-task-evidence` 2.1.1) under `<evidence.root>/<ADW_RUN_ID>/`, and reject an unsafe `ADW_RUN_ID` before provider access. Exit codes and stdout are unchanged.
- Trust-root auto-approval for exact released-vendor repins when the optional `PZAGENT_PROVIDER_TOKEN` secret is configured. Re-copy `templates/github/trust-root-bootstrap.yml`; the change only takes effect once it is on the consumer's default branch.
- New `pz:release:prove-merged-branch` (read-only merged work branch proof) and `pz:rehearsal` (preview rehearsal with Markdown/JSON report).
- `cache.py --section dependencies|build_results`; optional combined `.hermes/adw-cache.json` (schema `2.0.0`). Re-copy `templates/github/ci.yml`; the legacy `adw-build-cache.json` keeps working.
- Bundles may be `stable` with version `>=1.0.0`; `0.x` stays `experimental`. Sync accepts `vN.x.y` tags and refuses to cross a stable major version.

## 0.3.0

Breaking: the `deploy_diag` diagnostic CI marker is removed. The CI classifier
no longer accepts `--marker` or emits `suppressed`; publishers no longer accept
`diagnostic_publish`. The closed adapter schema (still `1.0.0`) no longer
accepts `diagnostics`, `ci.diagnostic_marker` or `retention.diagnostic_days`:
delete them and re-copy `templates/github/ci.yml`. Publication receipts are now
schema `1.1.0` (legacy) and `2.2.0` (release) without a `diagnostic` field.

## 0.2.16

Dokploy config sync now snapshots the exact prior Compose, rejects named-volume
definition drift before provider writes, and can restore that snapshot together
with the previous immutable image set. Runtime completion is proven through
bounded Dokploy deployment correlation; optional log inspection blocks and
terminates destructive confirmation prompts without making SSH availability a
rollback condition. Interrupted terminal restore attempts can resume with a new
correlated operation. Cleanup now lists the exact unused-volume candidates:
scoped mode preserves declared deployment volumes, while explicitly approved
aggressive mode may delete every reviewed unused volume, including database
volumes, along with other unused host resources.

## 0.2.15

Release authorization receipts now bind the exact pull-request quality producer;
publishers must derive build-artifact identity from that receipt. Bounded ancestry
checks use breadth-first traversal so direct merge parents are considered before
deep history. Retention protects references in active publication and deployment
journals, requires an exact reviewed operation digest for human deletion, and can
scope a rehearsal to one already-eligible candidate. Local development candidates
remain rejected in hosted GitHub Actions and are accepted only in an explicit
ACT plus `LAB_RUN` simulation.


## 0.2.14

CI contract readback now validates the context lock package version against the
identity and version declared by the fetched immutable bundle instead of a
release-specific literal. This keeps publication authorization fail-closed for
mismatched pins without requiring contract code changes for each patch release.

## 0.2.13

Trust-root controller receipts now carry a deterministic external binding to the
repository, PR, head SHA and base SHA. Merged destination proof accepts that
binding after validating the complete GitHub Actions check/job/run chain, so it
remains exact even when GitHub removes the custom check's pull-request
association after merge. Legacy open-PR associations remain supported.

## 0.2.12

GitHub Actions registry operations authenticate the workflow token with the immutable `GITHUB_ACTOR` identity instead of querying the unsupported `/user` endpoint. The isolated ORAS login remains mandatory and fail-closed; human-operated token identity resolution is unchanged. Repin the complete bundle before using CI publication or retention.

## 0.2.11

Live PR ancestry proof follows bounded exact commit-parent hashes and no longer requests the potentially large GitHub compare diff inventory. Publication proof accepts the exact-head trust-root check receipt only after tracing its check ID through the GitHub Actions job and trusted default-branch `pull_request_target` controller run, so trust-root path rotations do not create a second head-side fingerprint. The two agentic-delivery provenance sources are exact content allowlist entries; only `adw_contract.py` receives a scoped 128 KiB content ceiling.

## 0.2.10

CI coordinators can compose the same public `pz:release:inspect`, `pz:release:package`, and `pz:release:publish` primitives used by human-operated workflows. Component inventory and opt-in publication-pointer CAS are explicit; CI publication requires a closed authorization receipt that is recomputed immediately before registry writes, while human publication retains its existing proof-free operator contract. Release authorization now supports exact live pull-request proof as well as merged destination proof. Consumer adapters must explicitly allow each mutable publication pointer. Trust-root fingerprinting treats only an explicit GitHub content 404 as file absence, so newly added protected sources can use the normal `BOOTSTRAP_ENABLED` flow without weakening other API failures.

## 0.2.9

Requires the agentic-delivery v2.1 source registry. Consumer capability provenance now references stable source IDs, generic manifest/task proof inputs participate in PR bootstrap protection, and `adw:local:clean` has a context implementation with scoped and explicitly confirmed aggressive modes. The candidate also incorporates the release CI, reusable cache/build-output, and local operator workflow work developed in the proving consumer feature branch.

## 0.2.8

The trust-root controller requests pull-request write permission because GitHub requires it to create or update bot comments on pull requests. Consumer CI now runs push workflows only on `main`; open developer branches are covered by `pull_request` `synchronize` events without a duplicate push workflow.

## 0.2.7

Trust-root decisions are now fail-fast. The trusted controller runs on PR open, reopen, and every synchronized head push instead of waiting for the main CI workflow to finish. The bundled CI also evaluates the decision from default-branch code before its expensive quality job, so a missing or declined exact admin comment stops the pipeline in the first stage. Reinstall both `ci.yml` and `trust-root-bootstrap.yml` byte-identically. GitHub branch protection or rulesets remain necessary for a platform-enforced merge-button lock; where the repository plan does not provide them, merge and successful-closure automation must refuse any PR whose exact-head `trust-root-bootstrap` check is not successful.

## 0.2.6

Trust-root rotations no longer require landing provenance sources on the destination branch before their dependent change. Install `templates/github/trust-root-bootstrap.yml` as `.github/workflows/trust-root-bootstrap.yml` and require the `trust-root-bootstrap` check on protected branches. When a PR changes trusted CI/provenance paths, the controller posts the exact `BOOTSTRAP_ENABLED <fingerprint>` comment it needs. Only an exact comment from a current repository administrator authorizes that PR head/base/path set; later pushes or base changes invalidate it. This bypasses only the circular trusted-source comparison. All normal quality, exact-tree, merge, and publication gates remain mandatory.

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
