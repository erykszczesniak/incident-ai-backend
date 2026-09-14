"""Seed a realistic local demonstration through the public API, with assertions."""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request
from typing import Any


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--key", default=os.getenv("API_KEY", "incident-ai-demo-key"))
    parser.add_argument(
        "--exports",
        action="store_true",
        help="Also invoke configured Jira/Confluence exports",
    )
    args = parser.parse_args()

    def request(method: str, path: str, body: Any = None) -> Any:
        payload = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            f"{args.url.rstrip('/')}/api/v1{path}",
            data=payload,
            method=method,
            headers={"X-API-Key": args.key, "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as response:
                content = response.read()
                return json.loads(content) if content else None
        except urllib.error.HTTPError as exc:
            raise SystemExit(
                f"{method} {path}: {exc.code} {exc.read().decode()}"
            ) from exc
        except urllib.error.URLError as exc:
            raise SystemExit(
                f"Cannot reach {args.url}. Start the backend and check the URL: {exc.reason}"
            ) from exc

    scenarios = [
        {
            "external_id": "demo-checkout-pool-v1",
            "title": "Checkout error rate above 5%",
            "service": "checkout-api",
            "severity": "critical",
            "description": "Checkout requests are timing out after the 14:32 deployment.",
            "logs": [
                {
                    "level": "info",
                    "message": "deployment v2.8.1 completed; pool_size=10",
                },
                {
                    "level": "error",
                    "message": "database connection pool exhausted; waiting=84",
                },
                {
                    "level": "error",
                    "message": "POST /checkout 503 timeout after 30000ms",
                },
                {
                    "level": "warn",
                    "message": "user=customer@example.com token=demo-secret-value",
                },
            ],
        },
        {
            "external_id": "demo-worker-memory-v1",
            "title": "Worker memory usage increasing",
            "service": "notification-worker",
            "severity": "high",
            "description": "Delivery queue is growing and retries exceed normal thresholds.",
            "logs": [
                {
                    "level": "warn",
                    "message": "RSS 1.8GB; queue_depth=12450; retry_count=5",
                }
            ],
        },
        {
            "external_id": "demo-cache-latency-v1",
            "title": "Elevated cache latency",
            "service": "catalog-api",
            "severity": "medium",
            "description": "Brief cache miss spike during a scheduled catalog refresh.",
            "logs": [{"level": "info", "message": "cache warmup completed; p99=12ms"}],
        },
    ]
    incident_ids = []
    for payload in scenarios:
        result = request("POST", "/webhooks/generic", payload)
        incident_ids.append(result["incident"]["id"])
        print(f"{'Existing' if result['duplicate'] else 'Created'}: {payload['title']}")

    duplicate = request("POST", "/webhooks/generic", scenarios[0])
    assert duplicate["duplicate"] and duplicate["incident"]["id"] == incident_ids[0]
    primary = f"/incidents/{incident_ids[0]}"
    logs = request("GET", f"{primary}/logs")
    assert "demo-secret-value" not in json.dumps(logs)
    assert "customer@example.com" not in json.dumps(logs)
    incident = request("GET", primary)
    if incident["status"] == "open":
        request("PATCH", primary, {"status": "acknowledged"})
    incident = request("GET", primary)
    if incident["status"] == "acknowledged":
        request("PATCH", primary, {"status": "investigating"})
    request(
        "POST",
        f"{primary}/timeline",
        {"message": "On-call is comparing pool settings with v2.8.0."},
    )
    analysis = request("POST", f"{primary}/analysis")
    assert analysis["remediation_steps"]
    postmortem = request("POST", f"{primary}/postmortem")
    assert postmortem["markdown"]
    if args.exports:
        for destination in ("jira", "confluence"):
            result = request("POST", f"{primary}/postmortem/export/{destination}")
            print(f"{destination}: {result['url']} (demo={result['is_demo']})")
    recovered = f"/incidents/{incident_ids[2]}"
    if request("GET", recovered)["status"] != "resolved":
        request("PATCH", recovered, {"status": "resolved"})
    dashboard = request("GET", "/dashboard")
    assert dashboard["total_incidents"] >= 3
    assert dashboard["resolved_incidents"] >= 1
    print(
        json.dumps({"incident_id": incident_ids[0], "dashboard": dashboard}, indent=2)
    )
    print(
        "Verified ingestion, deduplication, redaction, analysis, timeline, postmortem and metrics."
    )


if __name__ == "__main__":
    main()
