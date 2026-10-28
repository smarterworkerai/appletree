# Kubernetes scaffold

These are HTTP examples for the runnable `hello-k8s` fixture: port 8080,
`/health` and `/ready`. Review and replace these example application facts before
activation. Generated targets start shadowed and images remain empty; an
unconfigured example is not a deployment.

Kustomize overlays select a namespace and local base. The adapter explicitly
maps each image variable to a workload/container. Private context aliases,
kubeconfig, actual probe URL values and credentials belong to the operator
profile, never to these files. The Kubernetes provider rejects cluster-scoped
objects and Secret manifests; supply external Secrets through the separately
approved provisioning scope.

`deploy/k8s/.env.<environment>.example` lists only the application secret
source key names for that environment, with empty values. The maintainer fills a
private `.env.<environment>` copy and passes it to `pz:provider:provision` with
`--env-file`, which creates the target's Secrets from it on top of
`.env.deploy`.
