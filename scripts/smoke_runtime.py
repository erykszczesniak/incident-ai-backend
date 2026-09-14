"""Verify a running demo deployment, including real Redis/Celery execution."""

from __future__ import annotations

import argparse
import json
import os
import time
import uuid
from pathlib import Path

import httpx


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--key", default=os.getenv("API_KEY", "incident-ai-demo-key"))
    args = parser.parse_args()
    checked: list[str] = []
    created: list[str] = []
    with httpx.Client(
        base_url=args.url, headers={"X-API-Key": args.key}, timeout=90
    ) as client:
        for path in ("/health", "/ready", "/openapi.json", "/metrics"):
            response = client.get(path)
            response.raise_for_status()
            checked.append(path)
        unauthenticated = client.get("/api/v1/incidents", headers={"X-API-Key": "bad"})
        assert unauthenticated.status_code == 401
        assert unauthenticated.json()["error"]["code"] == "unauthorized"
        checked.append("authentication")
        try:
            examples = Path(__file__).resolve().parents[1] / "examples"
            for source in ("grafana", "sentry", "cloudwatch", "zabbix"):
                payload = json.loads((examples / f"{source}-alert.json").read_text())
                suffix = uuid.uuid4().hex
                if source == "grafana":
                    payload["alerts"][0]["fingerprint"] = suffix
                elif source == "sentry":
                    payload["data"]["event"]["event_id"] = suffix
                elif source == "cloudwatch":
                    payload["AlarmArn"] += suffix
                else:
                    payload["event_id"] = suffix
                response = client.post(f"/api/v1/webhooks/{source}", json=payload)
                response.raise_for_status()
                created.append(response.json()["incident"]["id"])
                duplicate = client.post(f"/api/v1/webhooks/{source}", json=payload)
                duplicate.raise_for_status()
                assert duplicate.json()["duplicate"]
                checked.append(f"{source} ingest + deduplication")
            prefix = f"/api/v1/incidents/{created[0]}"
            queued = client.post(f"{prefix}/analysis/jobs")
            queued.raise_for_status()
            job_id = queued.json()["id"]
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                response = client.get(f"/api/v1/jobs/{job_id}")
                response.raise_for_status()
                job = response.json()
                if job["status"] in ("succeeded", "failed"):
                    break
                time.sleep(0.25)
            assert job["status"] == "succeeded", job
            assert job["result"]["incident_id"] == created[0]
            checked.append("persisted analysis job completed by worker")
            archive = client.post(f"{prefix}/archive")
            archive.raise_for_status()
            assert archive.json()["key"]
            checked.append("compressed redacted log archival")
            search = client.get("/api/v1/search", params={"q": "checkout"})
            search.raise_for_status()
            assert search.json()["items"]
            checked.append(f"incident search ({search.json()['mode']})")
            metrics = client.get("/metrics").text
            assert "incident_ai_http_requests_total" in metrics
            assert "incident_ai_http_request_duration_seconds_bucket" in metrics
            checked.append("Prometheus request and latency metrics")
        finally:
            for incident_id in created:
                client.delete(f"/api/v1/incidents/{incident_id}").raise_for_status()
    print(json.dumps({"status": "passed", "checks": checked}, indent=2))


if __name__ == "__main__":
    main()
