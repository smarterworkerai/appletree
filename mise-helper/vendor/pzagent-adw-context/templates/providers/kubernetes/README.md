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
