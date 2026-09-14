# Incident AI backend

FastAPI service for alert ingestion, incident triage, assistive analysis and postmortems. Python 3.12, SQLAlchemy, Alembic, PostgreSQL/pgvector, Redis and Celery. SQLite and deterministic adapters make the default local demo self-contained.

Companion app: [Incident AI for iOS](https://github.com/erykszczesniak/incident-ai-ios). The shared [API contract](docs/API-CONTRACT.md) is included in this repository.

## Quick start

```sh
uv sync --frozen
uv run alembic upgrade head
uv run uvicorn app.main:app --host 127.0.0.1 --port 8000
```

In another terminal run `uv run python scripts/demo.py --exports`. API docs: [Swagger UI](http://127.0.0.1:8000/docs). Use `X-API-Key: incident-ai-demo-key`. Settings are loaded from `.env` and environment variables; see `.env.example`. Do not use the demo key for a publicly reachable deployment.

For the complete local topology:

```sh
docker compose up --build -d
docker compose ps
docker compose logs -f api worker
```

Compose starts the API, PostgreSQL with pgvector, Redis and a Celery worker. The API applies Alembic migrations before serving. Data persists in named volumes. The API listens only on the Mac loopback address by default. `docker compose --profile observability up -d` adds Prometheus and a provisioned Grafana dashboard.

## Ingest an alert

```sh
curl -sS http://127.0.0.1:8000/api/v1/webhooks/generic \
  -H 'X-API-Key: incident-ai-demo-key' \
  -H 'Content-Type: application/json' \
  --data-binary @examples/generic-alert.json
```

The response contains the incident and a `duplicate` flag. Replaying the same `(source, external_id)` does not create another incident. Batch sources return an additional `results` array. Source adapters exist for `generic`, `grafana`, `sentry`, `cloudwatch` and `zabbix`; examples are provided for each. Recovery-only provider notifications are rejected; resolve the stored incident through the status API.

## API overview

All business routes use `/api/v1` and require an API key or configured signed bearer JWT. Webhook authentication also accepts a separate `X-Webhook-Key`. `/health`, `/ready`, `/metrics` and OpenAPI documentation are operational endpoints.

| Route | Behaviour |
| --- | --- |
| `POST /webhooks/{source}` | Normalize, redact and transactionally deduplicate alerts |
| `GET/POST /incidents` | Filter/paginate incident history or create an incident |
| `GET/PATCH/DELETE /incidents/{id}` | Inspect, transition/update or delete an incident |
| `GET /incidents/{id}/alerts` | Read source alerts |
| `GET/POST /incidents/{id}/logs` | Read or append bounded, redacted log batches |
| `GET/POST /incidents/{id}/timeline` | Read automatic events or add an operator note |
| `GET/POST /incidents/{id}/analysis` | Read or generate structured cause/remediation suggestions |
| `POST /incidents/{id}/analysis/jobs` | Queue a durable analysis job |
| `GET /jobs/{id}` | Inspect a job result |
| `GET/POST/PATCH /incidents/{id}/postmortem` | Read, generate or edit a Markdown draft |
| `GET /incidents/{id}/postmortem/markdown` | Download the Markdown artifact |
| `POST /incidents/{id}/postmortem/export/{destination}` | Export to Jira or Confluence, retaining the receipt |
| `GET /dashboard` | Incident counts, MTTR, acknowledgement and SLA statistics |
| `GET /search`, `GET /incidents/{id}/similar` | Semantic search when embeddings exist, lexical fallback otherwise |
| `POST /devices`, `DELETE /devices/{token}` | Register/unregister APNs destinations |
| `POST /incidents/{id}/archive` | Archive redacted logs as compressed JSONL |

OpenAPI is the generated source of truth for field types and validation. API DTOs are in `app/schemas/api.py`.

## AI and integrations

`LLM_PROVIDER=demo` produces transparent deterministic suggestions. Select `openai` or `anthropic`, set its API key and `LLM_MODEL` for live analysis. Provider responses must match a bounded Pydantic schema. Logs are redacted before the model sees them. Timeouts, rate limits and malformed responses trigger a clearly marked fallback; generated remediation is never executed.

Learned embeddings use the configured OpenAI embedding model. Anthropic analysis can use OpenAI embeddings if that key is also configured. The demo does not invent semantic embeddings; search reports `mode=lexical`. Analysis populates vectors. Changing embedding models/dimensions requires reanalysis of historical incidents before their vectors are comparable.

Jira uses Cloud REST v3 and Atlassian Document Format. Confluence uses Cloud REST v2 storage bodies. Successful exports retain a receipt so a repeated request reuses it. Exporting an edited postmortem does not silently mutate the already created remote artifact; use the receipt to review and update the remote document. In demo mode unconfigured destinations produce labelled simulated receipts. In production an unconfigured destination returns a typed integration error.

Slack, Teams and APNs notify on new incidents when configured. Individual delivery failures do not lose the incident. APNs requires the `.p8` key contents, key/team IDs, matching app bundle ID and a device token registered in the correct environment. S3 archives use gzip JSONL with the standard AWS credential chain or explicit environment credentials. Local demo archives are stored under `var/archives`.

## Quality checks

```sh
uv run ruff check .
uv run black --check .
uv run mypy app
uv run pytest
uv run alembic upgrade head
uv run alembic check
```

Unit and API tests use SQLite plus mocked outbound HTTP calls. To exercise real PostgreSQL migrations, pgvector and concurrent ingestion:

```sh
RUN_POSTGRES_TESTS=1 uv run pytest tests/test_postgres.py -v
```

This starts an ephemeral Docker testcontainer. Alternatively set `TEST_POSTGRES_URL` to a dedicated PostgreSQL server with `CREATE DATABASE` rights. The test creates and removes a uniquely named database; it never drops the supplied database. GitHub Actions provisions PostgreSQL, runs the same checks and builds the Docker image.

After starting Compose, `uv run python scripts/smoke_runtime.py` verifies readiness, all external source normalizers through HTTP, authentication, a real worker job, archival, search and metrics. It removes its test incidents afterwards. Run it in a demo environment; a configured worker can use the real selected AI provider.

## Layout

```text
app/api/             HTTP boundary
app/core/            configuration, authentication, errors, telemetry
app/domain/          incident, analysis, postmortem and search services
app/repository/      persistence models and sessions
app/schemas/         public DTOs
app/ai/              provider contracts, structured analysis, redaction
app/integrations/    alert sources, exporters, notifiers, archival
app/worker.py        Celery composition root
migrations/          Alembic revisions
tests/               API, adapter and real PostgreSQL tests
deploy/              Prometheus, Grafana and Kubernetes configuration
```

## Production configuration

Set `DEMO_MODE=false`, a random API key and separate webhook key (at least 32 characters each), and `REDIS_URL` for shared rate limits. Enable Celery for queued work. Use managed PostgreSQL, HTTPS ingress, private operational endpoints and a secret manager. JWT verification can be configured with a strong secret, issuer and audience; this service does not provide an identity-provider login UI. The initial authorisation model is one trusted team, not tenant isolation.

See `deploy/k8s/README.md` for migration and rollout order. Real external delivery and Kubernetes rollout require credentials/infrastructure owned by the operator and are intentionally separate from the local tests.
