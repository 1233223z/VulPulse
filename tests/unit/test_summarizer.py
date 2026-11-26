from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace

import pytest
from anthropic.types.beta import BetaTextBlock

from vulpulse.ai.summarizer import (
    SummaryConfigurationError,
    SummaryDisabled,
    SummaryError,
    SummaryRefused,
    VulnSummarizer,
)
from vulpulse.config import Settings


class FakeMessages:
    def __init__(self, response: object) -> None:
        self.response = response
        self.calls: list[dict[str, object]] = []

    async def create(self, **kwargs: object) -> object:
        self.calls.append(kwargs)
        return self.response


class FakeClient:
    def __init__(self, response: object) -> None:
        self.messages = FakeMessages(response)
        self.beta = SimpleNamespace(messages=self.messages)
        self.closed = False

    async def close(self) -> None:
        self.closed = True


def make_vulnerability(description: str = "A sampled vulnerability description.") -> object:
    product = SimpleNamespace(vendor="apache", product="struts")
    cwe = SimpleNamespace(id="CWE-79", name="Cross-site Scripting")
    return SimpleNamespace(
        cve_id="CVE-2024-0001",
        title="Apache Struts issue",
        description=description,
        severity="critical",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N",
        epss_score=0.9,
        in_kev=True,
        exploit_available=True,
        published_at=datetime(2024, 1, 1),
        product_links=[SimpleNamespace(product=product, version_range="< 2.5.1")],
        cwe_links=[SimpleNamespace(cwe=cwe)],
        source_records=[SimpleNamespace()],
    )


def make_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "llm_enabled": True,
        "llm_api_key": "test-key",
        "llm_max_input_chars": 12000,
        "llm_max_tokens": 512,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)  # type: ignore[call-arg]


def make_response(
    *,
    text: str = "The affected product is Apache Struts.",
    stop_reason: str = "end_turn",
) -> object:
    return SimpleNamespace(
        content=[BetaTextBlock(type="text", text=text)],
        stop_reason=stop_reason,
        model="claude-opus-5-5",
    )


async def test_summarizer_calls_claude_with_bounded_prompt() -> None:
    fake_client = FakeClient(make_response())
    summarizer = VulnSummarizer(make_settings(), client=fake_client)

    result = await summarizer.summarize(make_vulnerability())

    assert result.text == "The affected product is Apache Struts."
    assert result.model == "claude-opus-5-5"
    call = fake_client.messages.calls[0]
    assert call["model"] == "claude-opus-5-5"
    assert call["max_tokens"] == 512
    assert call["output_config"] == {"effort": "low"}
    assert call["betas"] == ["server-side-fallback-2026-07-01"]
    assert call["fallbacks"] == "default"
    assert "untrusted" in str(call["system"])
    prompt = str(call["messages"][0]["content"])  # type: ignore[index]
    assert "CVE-2024-0001" in prompt
    assert "apache" in prompt
    assert "CWE-79" in prompt


async def test_summarizer_truncates_long_input() -> None:
    fake_client = FakeClient(make_response())
    summarizer = VulnSummarizer(
        make_settings(llm_max_input_chars=800),
        client=fake_client,
    )

    await summarizer.summarize(make_vulnerability("x" * 5000))

    prompt = str(fake_client.messages.calls[0]["messages"][0]["content"])  # type: ignore[index]
    assert "truncated" in prompt
    assert "x" * 5000 not in prompt


async def test_summarizer_rejects_disabled_or_missing_config() -> None:
    with pytest.raises(SummaryDisabled):
        VulnSummarizer(make_settings(llm_enabled=False))

    with pytest.raises(SummaryConfigurationError):
        VulnSummarizer(make_settings(llm_api_key=""))


async def test_summarizer_reports_refusal_and_truncation() -> None:
    refused = VulnSummarizer(
        make_settings(),
        client=FakeClient(make_response(stop_reason="refusal")),
    )
    with pytest.raises(SummaryRefused):
        await refused.summarize(make_vulnerability())

    truncated = VulnSummarizer(
        make_settings(),
        client=FakeClient(make_response(stop_reason="max_tokens")),
    )
    with pytest.raises(SummaryError, match="token limit"):
        await truncated.summarize(make_vulnerability())


async def test_summarizer_rejects_empty_text() -> None:
    summarizer = VulnSummarizer(
        make_settings(),
        client=FakeClient(make_response(text="")),
    )

    with pytest.raises(SummaryError, match="empty"):
        await summarizer.summarize(make_vulnerability())


async def test_summarizer_rejects_oversized_payload() -> None:
    summarizer = VulnSummarizer(
        make_settings(llm_max_input_chars=50),
        client=FakeClient(make_response()),
    )

    with pytest.raises(SummaryError, match="too large"):
        await summarizer.summarize(make_vulnerability())
