# Kubernetes (Extended)

These manifests deploy the API, worker and migration job using an external PostgreSQL instance (with the `vector` extension available) and Redis. They are a deployment starting point, not a claim of a live hosted environment.

1. Build and push the Docker image to your own registry. Replace `incident-ai:release` in all three workload files with the same immutable image digest.
2. Apply `namespace.yaml` and `configmap.yaml`. Select your AI provider/model and integration settings.
3. Create `incident-ai-secrets` from your secret manager. `secret.example.yaml` documents required keys; never put real values in Git. Use a strong unique API key and webhook key, TLS database/Redis connections, and `DEMO_MODE=false`.
4. Apply `migrate.yaml` and wait for completion: `kubectl -n incident-ai wait --for=condition=complete job/incident-ai-migrate --timeout=120s`. Run one migration job before rolling out each release. Remove the old completed job when deploying another migration.
5. Apply `api.yaml` and `worker.yaml`. Check rollout and readiness before exposing the service.
6. Access locally with `kubectl -n incident-ai port-forward service/incident-ai-api 8000:8000`; configure your TLS ingress separately for public access. Keep `/metrics`, `/docs` and database services private in production.

All containers run as non-root, drop Linux capabilities and use a read-only root filesystem. Set an ingress request-size/rate policy and authentication policy appropriate for your organisation. Back up PostgreSQL and exercise a restore. Gracefully drain Celery workers before removal. The included shared API key is suitable for one trusted team; a multi-tenant service requires per-user authorisation and device ownership before launch.
