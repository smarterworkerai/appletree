# Deployment secrets

Deployment tasks read operator credentials and application values from pz-secretctl.
An explicit nonempty process variable overrides an operator credential. Deployment
tasks do not read `.env.deploy`, application dotenv files, or `--env-file` inputs.
Local development configuration keeps its existing behavior.

The per-key declarations in `infra/dokploy/` select generated values, human input,
shared API keys, and release-owned images. Keys with an empty declaration are
configuration supplied by Compose or ConfigMaps. Application IDs normally use
`appletree.<environment>.<KEY>` in `shared/appletree-<environment>`.

Use `pz-secretctl list --vault shared/appletree-production` to inspect names and
metadata. A person enters existing values through the exact command printed by
the task in their own terminal. Existing database passwords must be imported,
never replaced with newly generated values.

Inspect the environment with:

```bash
mise run pz:secrets:show -- pr-preview
```

Apply appends missing values. Only a named `--replace KEY` replaces an existing
value. `pz:secrets:show` compares values in memory and reports names and states.
A human uses an unlocked personal operator and terminal-only `pz-secretctl reveal`
to inspect values. Production writes still require their scoped human decision.

Probe origins use `DOKPLOY_<ENV>_URL` templates from the vault, with hyphens in the
environment replaced by underscores. The provider expands `{app}` to the project
name. A committed literal `probes.base_url` is the explicit exception.

Keep private files until the released provider is installed and the masked
comparison verifies the import. Their later removal is a separate operator step.

## Keys-only reference files

The root `.env.example` documents application secret names and their vault IDs
per environment. `.env.deploy.example` documents operator credential names and
probe templates. They contain no values and tasks do not load them as inputs.
Regenerate them in the same commit as a schema change:

```bash
mise run pz:secrets:examples
mise run pz:secrets:examples:check
mise run pz:secrets:show -- pr-preview --offline
```

Static analysis runs the example check, so full verification and CI refuse stale
documentation. The offline view reads the adapter and schemas without vault or
provider access.
