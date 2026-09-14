# Incident AI API contract

API prefix `/api/v1`. Auth: `X-API-Key`. JSON uses snake_case, UUID string identifiers, ISO 8601 UTC timestamps. Error envelope: `{ "error": { "code": "...", "message": "..." }, "correlation_id": "..." }`.

## Models

- Incident: id, title, service, severity (`critical|high|medium|low`), status (`open|acknowledged|investigating|resolved`), description, created_at, updated_at, acknowledged_at (nullable), resolved_at (nullable).
- Alert: id, incident_id, source, external_id, title, service, severity, description, received_at.
- LogEntry: id, incident_id, timestamp, level, message.
- TimelineEvent: id, incident_id, kind, message, created_at.
- Analysis: id, incident_id, summary, probable_cause, confidence (0..1), evidence ([string]), remediation_steps ([string]), caveats ([string]), provider, is_fallback (bool), created_at.
- Postmortem: id, incident_id, markdown, version (int), created_at, updated_at, jira_issue_key (nullable), jira_issue_url (nullable), confluence_url (nullable).

## Routes

- GET `/health`, GET `/ready` (unprefixed, public)
- POST `/webhooks/{source}`: generic body `{external_id,title,service,severity,description,logs:[{timestamp?,level,message}]}`; sources generic, grafana, sentry, cloudwatch, zabbix. Response `{incident: Incident, duplicate: bool}`. Prefix applies. `X-Webhook-Key` (or API key for demo).
- GET `/incidents?status=&severity=&search=&limit=50&offset=0` -> `{items:[Incident],total,limit,offset}`. `status=active` excludes resolved.
- POST `/incidents` -> Incident, body `{title,service,severity,description}`.
- GET `/incidents/{id}` -> Incident.
- PATCH `/incidents/{id}` -> Incident, body `{status?,title?,description?,severity?}`.
- DELETE `/incidents/{id}` -> 204.
- GET `/incidents/{id}/alerts` -> [Alert].
- GET `/incidents/{id}/logs?limit=100&offset=0` -> [LogEntry].
- POST `/incidents/{id}/logs` body `{entries:[{timestamp?,level,message}]}` -> [LogEntry].
- GET `/incidents/{id}/timeline` -> [TimelineEvent] ascending.
- POST `/incidents/{id}/timeline` body `{message}` -> TimelineEvent.
- GET `/incidents/{id}/analysis` -> Analysis (404 before first run).
- POST `/incidents/{id}/analysis` -> Analysis.
- GET `/incidents/{id}/postmortem` -> Postmortem (404 before first run).
- POST `/incidents/{id}/postmortem` -> Postmortem.
- PATCH `/incidents/{id}/postmortem` body `{markdown}` -> Postmortem.
- GET `/incidents/{id}/postmortem/markdown` -> text/markdown download.
- POST `/incidents/{id}/postmortem/export/{destination}` -> `{destination,external_id,url,is_demo}`; destination jira or confluence.
- GET `/dashboard?days=30` -> `{total_incidents,active_incidents,resolved_incidents,mttr_minutes,acknowledgement_minutes,sla_compliance_percent,sla_target_minutes,by_severity:[{severity,count}],daily_counts:[{date,count}],services:[{service,count}]}`.
- POST `/devices` body `{token,platform:"ios",environment:"sandbox"}` -> `{registered:true}`.
- DELETE `/devices/{token}` -> 204.
- GET `/search?q=...&limit=10` -> `{items:[{incident:Incident,score:float}],mode:"semantic|lexical"}`.
- GET `/incidents/{id}/similar?limit=5` -> same search result.
- POST `/incidents/{id}/analysis/jobs` -> `{id,status:"queued"}`; GET `/jobs/{id}` -> `{id,status,result?,error?}`.
- POST `/incidents/{id}/archive` -> `{key,url?,is_demo}`.

## Adapter contract (Python)

Adapters live in app.ai and app.integrations. All injected by composition in API/service layer. They do not import ORM objects.

`app.ai.client`:
- `AnalysisResult(BaseModel)`: summary, probable_cause, confidence, evidence:list[str], remediation_steps:list[str], caveats:list[str], provider:str, is_fallback:bool.
- `LLMClient(Protocol)`: async analyze(context: dict[str, Any]) -> AnalysisResult; async embed(text: str) -> list[float].
- `get_llm_client(settings)` -> LLMClient. Providers demo, openai, anthropic; resilient wrapper handles timeouts and invalid output with marked fallback.
- `redact(text: str) -> str` available from app.ai.redaction.

`app.integrations.sources`:
- `NormalizedAlert(BaseModel)`: external_id,title,service,severity,description,logs:list[dict[str,Any]] (default empty); source normalizers validate inputs and produce deterministic IDs if necessary.
- `get_source(name: str)` -> AlertSource; `AlertSource.normalize(payload:dict[str,Any]) -> list[NormalizedAlert]`.

`app.integrations.exporters`:
- `ExportResult(BaseModel)`: destination,external_id,url,is_demo.
- `get_exporter(destination: str, settings)` -> Exporter; async `export(incident:dict[str,Any], markdown:str) -> ExportResult`.

`app.integrations.notifiers`:
- async `notify_incident(incident:dict[str,Any], settings, devices:list[dict[str,str]] | None = None) -> None` isolates failures; Slack/Teams optional.

`app.integrations.archival`: async `archive_logs(incident_id:str, logs:list[dict[str,Any]], settings) -> dict[str,Any]`.

Settings uses pydantic-settings, `.env`, case insensitive; extra env ignored. Fields required by adapters: llm_provider="demo", llm_model="", openai_api_key="", anthropic_api_key="", integration_timeout_seconds=15.0, llm_timeout_seconds=30.0, llm_max_retries=2, jira_base_url="", jira_email="", jira_api_token="", jira_project_key="", confluence_base_url="", confluence_email="", confluence_api_token="", confluence_space_id="", slack_webhook_url="", teams_webhook_url="", apns_key_id="", apns_team_id="", apns_private_key="", apns_bundle_id="com.erykszczesniak.IncidentAI", s3_bucket="", s3_endpoint_url="", aws_region="eu-central-1", demo_mode=True.

## Rules

All saved/returned log content is redacted. Analysis and postmortem text are assistive suggestions requiring review. No silently successful external exports when configuration is missing: demo exports explicitly mark is_demo=true; production missing config returns typed 503. Real exports stored for idempotent retries. Local demo defaults SQLite, Docker uses Postgres. iOS demo uses mock by default, settings can switch to live API.
