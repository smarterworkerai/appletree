# Project delivery tasks

The eight project commands are implemented in `project-commands.toml`. They run
through `tasks.toml` and the source-bound context wrapper, with argv arrays and
no implicit shell. Full verification remains context-owned.

| Task | Application behavior |
| --- | --- |
| `adw:install` | `npm ci` from the reviewed lockfile. |
| `adw:build` | Vite compiles `src/` to `dist/`; release mode uses the bundled staged builder and sealed handover. |
| `adw:lint` | Project documentation/source whitespace and empty examples. |
| `adw:static-analysis` | Node syntax plus release recipe, pinned images and routing/key contracts. |
| `adw:test:unit` | Page/asset validator rejection cases. |
| `adw:test:integration:fast` | HTTP serves the actual compiled page and every referenced module/style asset. |
| `adw:test:integration:full` | Explicitly requested Docker runtime-image HTTP smoke with owned-resource cleanup. |
| `adw:verify:minimal` | Install and build. |
| `adw:verify:full` | Context-owned full graph and sealed compiled-output export. |

`site_hook.py` extends the bundled readiness hook: it retains request and target
validation, then checks the routed page title, scene canvas and compiled assets.
The adapter command names the Python file directly; the bundled dispatcher selects
the interpreter. The unit gate exercises that declaration against an HTTP page,
missing assets and an undeclared target. Private origins arrive only as the
adapter-declared probe environment keys, loaded from the private operator profile
into the task environment without printing their values.
When a proof-only CI run supplies no compiled artifact, publication selects a
fresh canonical build. The `adw:build` release command invokes the bundled
staged builder when `PZ_ADW_BUILD_DIR` is set, writing the source-bound
`build.json` and verified stage exports consumed by `pz:release:package`.
An ordinary Vite build remains the local quality command. A successful Vite
build alone does not supply a release handover.

The app has no runtime application secrets. `site_checks.py` also supplies the
local compiled HTTP smoke; it never infers an operator route.

Use `isolated_workspace = "maven"` for a disposable source snapshot or `"none"` for the current directory. Full verification passes one `ADW_SHARED_WORKSPACE` to every leaf. Source snapshots exclude ignored local inputs, credentials and build outputs and reject source symlinks.

Operator credential keys (`DOKPLOY`, `REGISTRY`, `SSH`, `KUBE`, `BOOTSTRAP`), SSH-agent handles, registry auth-config paths and approval handles are removed from inherited command environments by default. No exception is needed for the example or ordinary build/test tasks. A task that legitimately needs one inherited key must name it in `inherit_env = ["REGISTRY_TOKEN"]` and provide a short `inherit_env_reason` describing the authorized purpose without its value. These options are permitted only on that task, never in defaults; wildcards are refused. Undeclared operator bindings in `env`, command `env` or `cache_env` are refused. Declared TLS/pull bootstrap keys (including ACME email and registry username) always refuse project inheritance or explicit environment bindings. This scopes inherited environment data; it does not grant permission for an external operation or sandbox third-party programs' filesystem access.

Task options: `env` and `unset_env` (key names or trailing `*` prefixes), `reports` and optional `report_prefix` (relative glob patterns copied to `ADW_TEST_REPORT_DIR` even after a failure), `maven_cache` (optional dependency/result cache options), `cache_env` (optional cache-path bindings), and `release_commands` (install/build commands selected when `PZ_ADW_BUILD_DIR` is set). Cache keys remain owned by the existing cache module. Project-specific preparation can be the first command in a task.

Command options: `argv`, `cwd` (`workspace` or `repository`), `env`, `stdout_file` (workspace-relative log), and `workspace_pattern` (one regex capture for a workspace reported by a local orchestration script). Substitutions are literal `{workspace}`, `{repository}`, `{command_workspace}`, `{task}`, and, when enabled, `{dependency_cache}`. Other braces are preserved.

Command output goes to stderr. Stdout is one JSON result; exit classes are 0 success, 1 command failure, 20 usage, 21 contract/unimplemented. Evidence is generated through the generic contract; timing attachments retain only task/tool names, duration and outcome, never argv or Environment values. The context wrapper retains CI export and producer validation.

After editing `mise-helper/tasks.toml`, run `mise run pz:project:init -- --refresh-manifest`, then `mise run adw:check` and `mise run adw:context:check`. The refresh changes only the manifest's project source checksum, validates the generic manifest, and refuses context-owned full/describe overrides. Editing only `project-commands.toml` does not change the wrapper checksum; commit that file so source/proof inputs include the actual commands. Commit both vendored runtimes and the generated pin/manifest/configuration; `.gitignore` excludes credentials, caches, evidence and handover output, never `mise-helper/vendor/`. Do not change trusted CI/proof code or the four canonical workflows. Fill Docker recipes, real integration tests, provider resources and operator configuration before enabling remote capabilities. Read `docs/onboarding.md` in the provider repository for the complete handover.
