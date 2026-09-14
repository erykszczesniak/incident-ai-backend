import json
import logging
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from app.ai.client import (
    AnalysisContent,
    AnthropicLLMClient,
    DemoLLMClient,
    EmbeddingUnavailable,
    OpenAILLMClient,
    ResilientLLMClient,
    _bounded_context,
    get_llm_client,
)
from app.ai.redaction import redact, redact_value
from app.core.config import Settings


def content() -> dict[str, Any]:
    return {
        "summary": "Observed timeouts.",
        "probable_cause": "A dependency may be slow.",
        "confidence": 0.4,
        "evidence": ["request timed out"],
        "remediation_steps": ["Inspect correlated traces before changes."],
        "caveats": ["Cause is not confirmed."],
    }


def completion(body: dict[str, Any]) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "choices": [
                {"finish_reason": "stop", "message": {"content": json.dumps(body)}}
            ]
        },
    )


@pytest.mark.parametrize(
    "secret",
    [
        "email=person@example.com",
        "password=supersecret",
        '"api_key": "sensitive value"',
        "Authorization: Bearer abcdefghijklmnop",
        "client_secret='confidential value'",
        "remote=192.168.10.25",
        "https://admin:strongpass@example.org/path",
        "AKIAABCDEFGHIJKLMNOP",
        "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "+48 123 456 789",
        "https://hooks.slack.com/services/T123/B456/private-webhook-secret",
        "https://api.push.apple.com/3/device/" + "a" * 64,
        "https://flow.example/trigger?api-version=1&sig=private-signature",
    ],
)
def test_redaction_is_effective_and_idempotent(secret: str) -> None:
    filtered = redact(secret)
    assert "REDACTED" in filtered
    assert filtered != secret
    assert redact(filtered) == filtered


def test_nested_redaction_removes_entire_secret_values() -> None:
    source = {
        "description": "Contact admin@example.com",
        "nested": [{"api_key": "unrecognizable", "access_token": {"nested": "secret"}}],
    }
    result = redact_value(source)
    assert "unrecognizable" not in json.dumps(result)
    assert "admin@example.com" not in json.dumps(result)
    assert source["nested"][0]["api_key"] == "unrecognizable"


def test_large_context_remains_valid_json_and_bounded() -> None:
    context = {
        "incident": {"title": "Error", "description": "password=abc " * 20_000},
        "logs": [{"message": "x" * 20_000} for _ in range(1_000)],
    }
    prompt = _bounded_context(context)
    assert isinstance(json.loads(prompt), dict)
    assert json.loads(prompt)["_context_truncated"] is True
    assert len(prompt) < 40_000
    assert "password=abc" not in prompt


@pytest.mark.parametrize(
    "changes",
    [
        {"confidence": 1.5},
        {"confidence": float("nan")},
        {"remediation_steps": []},
        {"summary": "a" * 4001},
        {"confidence": "0.7"},
        {"extra_field": "untrusted"},
    ],
)
def test_model_output_is_strictly_validated(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        AnalysisContent.model_validate(content() | changes)


def test_redaction_expansion_is_checked_against_model_output_bounds() -> None:
    with pytest.raises(ValidationError):
        AnalysisContent.model_validate(content() | {"summary": "a@b.co " * 500})


async def test_demo_is_deterministic_and_does_not_claim_semantic_embeddings() -> None:
    client = DemoLLMClient()
    context = {
        "incident": {"title": "DB incident", "service": "checkout"},
        "logs": [{"message": "connection pool exhausted"}],
    }
    first = await client.analyze(context)
    assert first == await client.analyze(context)
    assert first.provider == "demo" and first.is_fallback
    assert first.confidence <= 0.25
    assert "possible" in first.probable_cause
    with pytest.raises(EmbeddingUnavailable):
        await client.embed("database")


async def test_openai_request_is_structured_and_redacted() -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert request.url.path == "/v1/chat/completions"
        assert request.headers["authorization"] == "Bearer test-key"
        assert body["response_format"]["json_schema"]["strict"] is True
        assert body["store"] is False
        assert "person@example.com" not in request.content.decode()
        assert "abcd-secret" not in request.content.decode()
        return completion(
            content() | {"summary": "Contact agent@example.org for token=leaked-secret"}
        )

    result = await OpenAILLMClient(
        Settings(openai_api_key="test-key"), transport=httpx.MockTransport(respond)
    ).analyze({"incident": {"description": "person@example.com token=abcd-secret"}})
    assert result.provider == "openai" and not result.is_fallback
    assert (
        "agent@example.org" not in result.summary
        and "leaked-secret" not in result.summary
    )
    assert any("engineer" in caveat for caveat in result.caveats)


async def test_openai_retries_rate_limit_then_succeeds() -> None:
    calls = 0

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return (
            httpx.Response(429, headers={"retry-after": "0"})
            if calls == 1
            else completion(content())
        )

    client = OpenAILLMClient(
        Settings(openai_api_key="test-key", llm_max_retries=1),
        transport=httpx.MockTransport(respond),
    )
    result = await ResilientLLMClient(client, provider="openai", timeout=3).analyze({})
    assert calls == 2 and not result.is_fallback


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(401, json={"error": "secret response"}),
        httpx.Response(429, headers={"retry-after": "0"}),
        httpx.Response(200, json={"choices": []}),
        httpx.Response(
            200,
            json={
                "choices": [
                    {"finish_reason": "stop", "message": {"content": "not json"}}
                ]
            },
        ),
        httpx.Response(
            200,
            json={
                "choices": [{"finish_reason": "length", "message": {"content": "{}"}}]
            },
        ),
    ],
)
async def test_bad_provider_responses_become_explicit_fallback(
    response: httpx.Response,
) -> None:
    client = OpenAILLMClient(
        Settings(openai_api_key="test-key", llm_max_retries=0),
        transport=httpx.MockTransport(lambda request: response),
    )
    result = await ResilientLLMClient(client, provider="openai", timeout=3).analyze(
        {"title": "No context"}
    )
    assert result.is_fallback and result.provider == "openai:fallback"
    assert "secret response" not in result.model_dump_json()


async def test_timeout_isolated_with_no_sensitive_logging(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        logging.getLogger("incident_ai.ai"), "handlers", [caplog.handler]
    )

    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("sensitive-key", request=request)

    client = OpenAILLMClient(
        Settings(openai_api_key="sensitive-key", llm_max_retries=0),
        transport=httpx.MockTransport(timeout),
    )
    assert (
        await ResilientLLMClient(client, provider="openai", timeout=1).analyze({})
    ).is_fallback
    assert "analysis_fallback" in caplog.text and "sensitive-key" not in caplog.text


async def test_anthropic_uses_forced_validated_tool_output() -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert request.headers["anthropic-version"] == "2023-06-01"
        assert body["tool_choice"] == {"type": "tool", "name": "incident_analysis"}
        return httpx.Response(
            200,
            json={
                "stop_reason": "tool_use",
                "content": [
                    {
                        "type": "tool_use",
                        "name": "incident_analysis",
                        "input": content(),
                    }
                ],
            },
        )

    client = AnthropicLLMClient(
        Settings(anthropic_api_key="test-key"), transport=httpx.MockTransport(respond)
    )
    result = await client.analyze({})
    assert result.provider == "anthropic" and not result.is_fallback
    with pytest.raises(EmbeddingUnavailable):
        await client.embed("some incident")


async def test_embeddings_validate_dimension_and_filter_input() -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["dimensions"] == 3
        assert "secret@example.org" not in body["input"]
        return httpx.Response(200, json={"data": [{"embedding": [0.1, 0.2, 0.3]}]})

    client = OpenAILLMClient(
        Settings(openai_api_key="test-key", embedding_dimensions=3),
        transport=httpx.MockTransport(respond),
    )
    assert await client.embed("secret@example.org timeout") == [0.1, 0.2, 0.3]


@pytest.mark.parametrize(
    "vector", [[0.1], [0, 0, 0], [True, 1, 2], [1, float("nan"), 2], ["1", 2, 3]]
)
async def test_invalid_embeddings_cannot_poison_search(vector: list[Any]) -> None:
    # Raw JSON serialization permits NaN to exercise the outbound boundary validator.
    response = httpx.Response(
        200, content=json.dumps({"data": [{"embedding": vector}]})
    )
    client = OpenAILLMClient(
        Settings(openai_api_key="test-key", embedding_dimensions=3),
        transport=httpx.MockTransport(lambda request: response),
    )
    with pytest.raises(EmbeddingUnavailable):
        await client.embed("query")


async def test_missing_api_key_falls_back_but_unknown_provider_fails() -> None:
    assert (
        await get_llm_client(Settings(llm_provider="openai")).analyze({})
    ).is_fallback
    with pytest.raises(ValueError):
        get_llm_client(Settings(llm_provider="unsupported"))
