"""Content-addressed gzip JSONL archives, redacted even at the storage boundary."""

import asyncio
import gzip
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from app.ai.redaction import redact_value
from app.integrations.errors import IntegrationError


async def archive_logs(
    incident_id: str, logs: list[dict[str, Any]], settings: Any
) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", incident_id):
        raise ValueError("Invalid incident identifier for archive")
    content = "".join(
        json.dumps(redact_value(entry), default=str, sort_keys=True, ensure_ascii=False)
        + "\n"
        for entry in logs
    ).encode()
    if len(content) > 20_000_000:
        raise IntegrationError(
            "Archive exceeds the 20 MB uncompressed limit.",
            code="archive_too_large",
            status_code=413,
        )
    digest = hashlib.sha256(content).hexdigest()[:24]
    key = f"incidents/{incident_id}/{digest}.jsonl.gz"
    compressed = gzip.compress(content, mtime=0)
    if not settings.s3_bucket:
        if not settings.demo_mode:
            raise IntegrationError(
                "S3_BUCKET must be configured before archiving.",
                code="integration_configuration",
            )
        directory = Path(getattr(settings, "s3_demo_directory", "var/archives"))
        target = directory / key

        def write_demo() -> None:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(compressed)

        await asyncio.to_thread(write_demo)
        return {"key": key, "is_demo": True}

    def upload() -> None:
        import boto3
        from botocore.config import Config

        options: dict[str, Any] = {
            "region_name": settings.aws_region,
            "config": Config(
                connect_timeout=settings.integration_timeout_seconds,
                read_timeout=settings.integration_timeout_seconds,
                retries={"mode": "standard", "max_attempts": 2},
            ),
        }
        if settings.s3_endpoint_url:
            options["endpoint_url"] = settings.s3_endpoint_url
        for setting, parameter in (
            ("aws_access_key_id", "aws_access_key_id"),
            ("aws_secret_access_key", "aws_secret_access_key"),
            ("aws_session_token", "aws_session_token"),
        ):
            if getattr(settings, setting, ""):
                options[parameter] = getattr(settings, setting)
        # A fresh Session avoids sharing the boto3 global Session across threads.
        client = boto3.session.Session().client("s3", **options)
        try:
            client.put_object(
                Bucket=settings.s3_bucket,
                Key=key,
                Body=compressed,
                ContentType="application/x-ndjson",
                ContentEncoding="gzip",
                ServerSideEncryption="AES256",
            )
        finally:
            client.close()

    try:
        await asyncio.to_thread(upload)
    except Exception as exc:
        raise IntegrationError(
            "S3 archival failed. Check storage permissions and retry.",
            code="archive_failed",
        ) from exc
    return {"key": key, "url": f"s3://{settings.s3_bucket}/{key}", "is_demo": False}
