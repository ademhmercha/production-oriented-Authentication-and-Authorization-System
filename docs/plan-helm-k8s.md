# Plan: Helm + Kubernetes deployment (local, free)

Status: approved 2026-09-10. Scope: chart under `deploy/helm/identity-platform/`,
chart validation in CI, optional self-hosted runner deploy workflow.

## Goal

Deploy the existing docker-compose stack to Kubernetes locally with minikube —
no cloud, no registry. Same three services, same single Docker image
(`Dockerfile`, `tsc -p tsconfig.build.json`), migrate/seed as one-shot jobs.

## Architecture mapping (compose -> k8s)

| docker-compose | Helm chart |
|---|---|
| auth-server :3001 | Deployment `identity-platform-auth-server` + ClusterIP, probes `/health/live` + `/health/ready`, `fsGroup: 1000` for the keys PVC |
| api-gateway :3000 | Deployment `identity-platform-api-gateway`, probe `/healthz`, Ingress `/api` + `/healthz` |
| resource-api :3002 | Deployment `identity-platform-resource-api`, probe `/health` |
| postgres :5432 | StatefulSet + PVC (volumeClaimTemplate) |
| redis :6379 | Deployment + PVC |
| mailhog :8025/1025 | Deployment + Service |
| migrate / seed services | Helm hook Jobs (weights 1 and 2) |
| x-common-env | ConfigMap (non-secret) + Secret (credentials) + per-container env |

## Chart structure

```
deploy/helm/identity-platform/
├── Chart.yaml
├── values.yaml                  # image, replicas, env, infra, ingress, storage
├── templates/
│   ├── _helpers.tpl             # fullname / labels / credentials-name helpers
│   ├── configmap.yaml           # non-secret env (mirrors x-common-env)
│   ├── secret.yaml              # KMS_MASTER_KEY, GATEWAY_SHARED_SECRET, POSTGRES_PASSWORD
│   ├── service.yaml             # ClusterIP for the 3 apps
│   ├── deployment.yaml          # values-driven loop over .Values.apps
│   ├── postgres.yaml            # StatefulSet + headless Service
│   ├── redis.yaml               # Deployment + Service + PVC
│   ├── mailhog.yaml             # Deployment + Service
│   ├── pvc.yaml                 # keys + redis-data claims
│   ├── migrate-job.yaml         # hook pre-install,pre-upgrade (weight 1)
│   ├── seed-job.yaml            # hook pre-install (weight 2)
│   └── ingress.yaml             # gateway /api + auth /docs /admin /oauth /.well-known
└── NOTES.txt
```

## Key decisions

1. **One image, three commands** — chart overrides the Dockerfile default CMD per
   app, same split the compose stack already uses.
2. **Migrations = Helm hook jobs**, not init containers:
   - `migrate`: `pre-install,pre-upgrade` (weight 1), waits for Postgres with a
     retry loop, runs `node dist/scripts/migrate.js`.
   - `seed`: `pre-install` only (weight 2), so upgrades never re-seed the admin.
   - Both run with `MIGRATIONS_DIR=/app/migrations` (image already copies
     migrations there).
3. **Secrets generated once, stable across upgrades** — secret.yaml uses
   `lookup` to reuse existing secret data; fresh values only on first install.
   - `KMS_MASTER_KEY` = `randBytes 32 | b64enc` (matches the app's 32-byte
     base64 requirement — a wrong-size key throws at startup).
   - `GATEWAY_SHARED_SECRET`, `POSTGRES_PASSWORD` = random.
   - Everything overridable in `values.yaml` (`secrets.*`).
4. **`DATABASE_URL` assembled in the container env** using Kubernetes
   `$(POSTGRES_PASSWORD)` expansion against the secret-provided variable —
   so the password never lands in a ConfigMap.
5. **Keys volume + fsGroup** — the image runs as `USER node` (uid 1000); the
   auth-server pod sets `fsGroup: 1000` so the empty `keys` PVC is writable.
6. **Operational constraint (documented in NOTES.txt):** auth-server stays at
   one replica — signing keys are files on a PVC (same limitation as compose).
7. **Infra bundled but togglable** — `infrastructure.enabled: false` +
   `serviceUrls.*` / `databaseUrl` overrides let you point at external
   Postgres/Redis.

## Bring-up (local, free)

```powershell
# 1. Docker Desktop running, then:
minikube start --driver=docker
minikube addons enable ingress

# 2. Build + load the image (no registry needed)
docker build -t identity-platform:local .
minikube image load identity-platform:local

# 3. Install
helm upgrade --install identity-platform deploy/helm/identity-platform

# 4. Reach it
minikube tunnel          # ingress host identity.local -> /etc/hosts entry
# or port-forward:
kubectl port-forward svc/identity-platform-api-gateway 3000:3000
kubectl port-forward svc/identity-platform-mailhog 8025:8025
# admin password (when not set in values):
kubectl logs jobs/identity-platform-seed
```

## Validation

- `helm lint deploy/helm/identity-platform`
- `helm template identity-platform deploy/helm/identity-platform > rendered.yaml`
- CI `chart` job on every PR (ubuntu runner): lint + render + assert key
  resources exist.
- Live: gateway `/healthz`, then `scripts/verify-all.ps1` against the ingress
  host.

## CI / self-hosted runner strategy

- **[build, committed]** `.github/workflows/ci.yml` gains a `chart` job:
  `helm lint` + `helm template` on the free ubuntu runner — every PR, no
  cluster needed.
- **[self-hosted, pending approval]** `.github/workflows/deploy-minikube.yaml`
  uses `runs-on: self-hosted` to build, `minikube image load`, and
  `helm upgrade --install`. Manual trigger ONLY (`workflow_dispatch`) with
  `concurrency` guard.

### Security note: self-hosted runners

A self-hosted runner executes workflow code on this machine. If the repository
is **public**, anyone can open a PR and run arbitrary code on your computer
(remote code execution). Hard requirements before enabling the deploy workflow:

- repo must be **private**, OR
- the workflow stays **manual-trigger only** and you accept the exposure
  (handle: only trusted users can fork/PR, and no CI secrets are granted to
  the workflow).

The runner runs as a Windows service (Actions Runner service); Docker Desktop
and minikube must be running and the service account must have docker access.

## README addition

Short "Deploy with Helm (local, free)" section with the 7 commands above and a
pointer to the self-hosted workflow.

## Out of scope (future)

External managed Postgres/Redis (values already support it), TLS certs via
cert-manager, HPA/autoscaling, KMS integration (aws-kms/azure-kv providers),
multi-replica auth-server with a shared key store.