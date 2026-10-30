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

Application secret values come from the agent vault (#193): the key schema
declares each secret key's source (`generate`, `human`, `shared`) with the same
vault IDs as the environment's Dokploy targets, the private
`kubernetes-provisioning.json` names the one Secret that receives them
(`{namespace: {secret-name: "key-schema"}}`), and `pz:provider:provision`
creates it.
