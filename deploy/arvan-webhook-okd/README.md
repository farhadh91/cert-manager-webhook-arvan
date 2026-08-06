# cert-manager-webhook-arvan (OKD / OpenShift)

ArvanCloud DNS01 solver for cert-manager, packaged for OKD and OpenShift.

## What differs from the plain Kubernetes chart

| | `arvan-webhook` | `arvan-webhook-okd` |
|---|---|---|
| Container port | 443 | 8443 |
| `securityContext` | none | non-root, no privilege escalation, all capabilities dropped, read-only rootfs |
| SCC needed | `anyuid` in practice | `restricted-v2` (the default) |
| `replicaCount` | referenced but undefined in values | defined |

The port is the important one. Under `restricted-v2` the container runs as an
arbitrary UID from the namespace's allocated range, and a non-root process
cannot bind a port below 1024 — the webhook would crash-loop on 443. It now
listens on 8443, and the Service still publishes 443, so the APIService is
unaffected.

## Prerequisites

- cert-manager running in the cluster, including `cainjector` (it injects the
  `caBundle` into the APIService). Either the Red Hat cert-manager operator or
  the community install works.
- An ArvanCloud API key.

## Install

```bash
oc new-project cert-manager-webhook-arvan

oc -n cert-manager-webhook-arvan create secret generic arvan-credentials \
  --from-literal=apikey='YOUR_API_KEY'

helm install arvan-webhook ./deploy/arvan-webhook-okd \
  -n cert-manager-webhook-arvan \
  --set groupName=your.group.name
```

Verify:

```bash
oc get apiservice v1alpha1.your.group.name
```

`AVAILABLE` must be `True`.

## Values worth setting

| Key | Default | Notes |
|---|---|---|
| `groupName` | `hbahadorzadeh.github` | Must match the `groupName` in your Issuer and be unique in the cluster |
| `image.tag` | `0.4` | First release with the delegated-zone fix |
| `certManager.namespace` | `cert-manager` | Where cert-manager's ServiceAccount lives |
| `certManager.serviceAccountName` | `cert-manager` | Granted permission to call this webhook |
| `credentialsSecretRef` | `arvan-credentials` | Secret in the release namespace holding the API key |
| `securePort` | `8443` | Keep above 1024 on OpenShift |
| `networkPolicy.enabled` | `true` | Lets the kube-apiserver reach the pod; required under default-deny

## ClusterIssuer example

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-arvan
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: you@example.com
    privateKeySecretRef:
      name: letsencrypt-account-key
    solvers:
      - dns01:
          webhook:
            groupName: your.group.name
            solverName: arvancloud
            config:
              ttl: 120
              baseUrl: "https://napi.arvancloud.com"
              authApiSecretRef:
                name: arvan-credentials
                key: apikey
```

With a `ClusterIssuer`, cert-manager resolves `authApiSecretRef` in **its own**
namespace, so `arvan-credentials` must also exist in `cert-manager`. With a
namespaced `Issuer`, it resolves in the Issuer's namespace.

## If the pod will not start

- `container has runAsNonRoot and image will run as root` — the pod was admitted
  under `anyuid` rather than `restricted-v2`, so no UID was assigned. Either let
  it use `restricted-v2`, or set `podSecurityContext.runAsUser` to a UID in the
  namespace's range.
- `bind: permission denied` — `securePort` was set below 1024.
- APIService `AVAILABLE=False (MissingEndpoints)` — the pod is not ready yet,
  usually waiting on cert-manager to issue the serving certificate.
- APIService `AVAILABLE=False (FailedDiscoveryCheck)` with a healthy pod and a
  timeout in the message — the kube-apiserver cannot reach the pod. That is a
  NetworkPolicy problem; keep `networkPolicy.enabled` on.
- APIService stuck `AVAILABLE=False` otherwise — check that `cainjector` is
  running and that the `caBundle` on the APIService is populated.

## Delegated zones

The solver discovers the authoritative zone by asking the ArvanCloud API which
zone the account actually hosts, most specific first. A delegated child zone
therefore wins over its parent, and the TXT record is created in the zone whose
nameservers Let's Encrypt will query. No configuration is needed for this.
