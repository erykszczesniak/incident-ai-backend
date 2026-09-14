"""Create incident storage and the optional PostgreSQL vector column.

Revision ID: 0001
Revises:
"""

import sqlalchemy as sa
from alembic import op
from pgvector.sqlalchemy import Vector

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def identifier() -> sa.Column:
    return sa.Column("id", sa.String(36), primary_key=True)


def incident_id(unique: bool = False) -> sa.Column:
    return sa.Column(
        "incident_id",
        sa.String(36),
        sa.ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        unique=unique,
    )


def timestamp(name: str = "created_at", nullable: bool = False) -> sa.Column:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("CREATE EXTENSION IF NOT EXISTS vector")
    op.create_table(
        "incidents",
        identifier(),
        sa.Column("title", sa.String(240), nullable=False),
        sa.Column("service", sa.String(120), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        timestamp(),
        timestamp("updated_at"),
        timestamp("acknowledged_at", True),
        timestamp("resolved_at", True),
        sa.Column(
            "embedding", Vector().with_variant(sa.JSON(), "sqlite"), nullable=True
        ),
        sa.Column("embedding_model", sa.String(120), nullable=True),
    )
    for column in ("service", "severity", "status", "created_at"):
        op.create_index(f"ix_incidents_{column}", "incidents", [column])
    op.create_table(
        "alerts",
        identifier(),
        incident_id(),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("external_id", sa.String(512), nullable=False),
        sa.Column("title", sa.String(240), nullable=False),
        sa.Column("service", sa.String(120), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        timestamp("received_at"),
        sa.UniqueConstraint("source", "external_id", name="uq_alert_source_external"),
    )
    op.create_index("ix_alerts_incident_id", "alerts", ["incident_id"])
    op.create_table(
        "log_entries",
        identifier(),
        incident_id(),
        timestamp("timestamp"),
        sa.Column("level", sa.String(16), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
    )
    op.create_index(
        "ix_log_incident_timestamp", "log_entries", ["incident_id", "timestamp"]
    )
    op.create_table(
        "timeline_events",
        identifier(),
        incident_id(),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        timestamp(),
    )
    op.create_index(
        "ix_timeline_events_incident_id", "timeline_events", ["incident_id"]
    )
    op.create_table(
        "analyses",
        identifier(),
        incident_id(),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("probable_cause", sa.Text(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("remediation_steps", sa.JSON(), nullable=False),
        sa.Column("caveats", sa.JSON(), nullable=False),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("is_fallback", sa.Boolean(), nullable=False),
        timestamp(),
    )
    op.create_index("ix_analyses_incident_id", "analyses", ["incident_id"])
    op.create_index("ix_analyses_created_at", "analyses", ["created_at"])
    op.create_table(
        "postmortems",
        identifier(),
        incident_id(unique=True),
        sa.Column("markdown", sa.Text(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        timestamp(),
        timestamp("updated_at"),
        sa.Column("jira_issue_key", sa.String(120), nullable=True),
        sa.Column("jira_issue_url", sa.Text(), nullable=True),
        sa.Column("confluence_url", sa.Text(), nullable=True),
    )
    op.create_table(
        "exports",
        identifier(),
        incident_id(),
        sa.Column("destination", sa.String(24), nullable=False),
        sa.Column("external_id", sa.String(120), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("is_demo", sa.Boolean(), nullable=False),
        timestamp(),
        sa.UniqueConstraint("incident_id", "destination", name="uq_export_destination"),
    )
    op.create_index("ix_exports_incident_id", "exports", ["incident_id"])
    op.create_table(
        "devices",
        sa.Column("token", sa.String(512), primary_key=True),
        sa.Column("platform", sa.String(16), nullable=False),
        sa.Column("environment", sa.String(16), nullable=False),
        timestamp(),
    )
    op.create_table(
        "jobs",
        identifier(),
        incident_id(),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        timestamp(),
        timestamp("updated_at"),
    )
    op.create_index("ix_jobs_incident_id", "jobs", ["incident_id"])


def downgrade() -> None:
    for table in (
        "jobs",
        "devices",
        "exports",
        "postmortems",
        "analyses",
        "timeline_events",
        "log_entries",
        "alerts",
        "incidents",
    ):
        op.drop_table(table)
    # The extension may be shared with other applications; leave it installed.
