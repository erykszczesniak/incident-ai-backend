from functools import lru_cache

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Incident AI"
    database_url: str = "sqlite+aiosqlite:///./var/incident-ai.db"
    demo_mode: bool = True
    api_key: str = Field(default="incident-ai-demo-key", repr=False)
    webhook_key: str = Field(default="", repr=False)
    jwt_secret: str = Field(default="", repr=False)
    jwt_issuer: str = "incident-ai"
    jwt_audience: str = "incident-ai-api"
    allowed_origins: list[str] = ["http://localhost:8000", "http://127.0.0.1:8000"]
    max_request_bytes: int = Field(default=2_097_152, ge=1024, le=20_971_520)
    rate_limit_per_minute: int = Field(default=120, ge=1)
    sla_target_minutes: float = Field(default=60.0, gt=0)
    redis_url: str = ""
    celery_enabled: bool = False
    auto_analyze: bool = False
    llm_provider: str = "demo"
    llm_model: str = ""
    openai_api_key: str = Field(default="", repr=False)
    anthropic_api_key: str = Field(default="", repr=False)
    embedding_model: str = "text-embedding-3-small"
    embedding_dimensions: int = Field(default=1536, ge=1, le=4096)
    integration_timeout_seconds: float = Field(default=15.0, gt=0, le=120)
    llm_timeout_seconds: float = Field(default=30.0, gt=0, le=180)
    llm_max_retries: int = Field(default=2, ge=0, le=5)
    jira_base_url: str = ""
    jira_email: str = ""
    jira_api_token: str = Field(default="", repr=False)
    jira_project_key: str = ""
    jira_issue_type: str = "Task"
    confluence_base_url: str = ""
    confluence_email: str = ""
    confluence_api_token: str = Field(default="", repr=False)
    confluence_space_id: str = ""
    slack_webhook_url: str = Field(default="", repr=False)
    teams_webhook_url: str = Field(default="", repr=False)
    apns_key_id: str = ""
    apns_team_id: str = ""
    apns_private_key: str = Field(default="", repr=False)
    apns_bundle_id: str = "com.erykszczesniak.IncidentAI"
    s3_bucket: str = ""
    s3_endpoint_url: str = ""
    s3_demo_directory: str = "var/archives"
    aws_region: str = "eu-central-1"
    aws_access_key_id: str = Field(default="", repr=False)
    aws_secret_access_key: str = Field(default="", repr=False)
    aws_session_token: str = Field(default="", repr=False)
    otel_enabled: bool = False
    otel_service_name: str = "incident-ai"

    @model_validator(mode="after")
    def production_security(self) -> "Settings":
        if not self.demo_mode:
            if len(self.api_key) < 32 or self.api_key == "incident-ai-demo-key":
                raise ValueError(
                    "Production API_KEY must contain at least 32 characters"
                )
            if len(self.webhook_key) < 32:
                raise ValueError(
                    "Production WEBHOOK_KEY must contain at least 32 characters"
                )
            if self.jwt_secret and len(self.jwt_secret) < 32:
                raise ValueError("JWT_SECRET must contain at least 32 characters")
            if not self.redis_url:
                raise ValueError(
                    "Production requires REDIS_URL for distributed rate limits"
                )
        if self.celery_enabled and not self.redis_url:
            raise ValueError("CELERY_ENABLED requires REDIS_URL")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
