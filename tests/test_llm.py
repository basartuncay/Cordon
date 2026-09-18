"""Tests for cordon.llm: cost estimation and the API-key redaction
guarantee. No real network calls — AnthropicClient's underlying SDK client
is swapped for a stub that raises, so we only exercise the redaction path.
"""

from __future__ import annotations

import pytest

from cordon.llm import AnthropicClient, ModelConfig, _redact, estimate_cost_usd


def test_redact_replaces_secret_occurrences():
    assert _redact("token=sk-abc123 leaked", "sk-abc123") == "token=<redacted> leaked"


def test_redact_is_noop_for_empty_secret():
    assert _redact("nothing to hide", None) == "nothing to hide"
    assert _redact("nothing to hide", "") == "nothing to hide"


def test_estimate_cost_usd_matches_manual_calculation():
    cfg = ModelConfig(
        baseline_model="m",
        planner_model="m",
        quarantine_model="m",
        token_budget=1000,
        price_input_per_mtok_usd=3.0,
        price_output_per_mtok_usd=15.0,
        pricing_verified=False,
    )
    cost = estimate_cost_usd(input_tokens=1_000_000, output_tokens=1_000_000, cfg=cfg)
    assert cost == pytest.approx(18.0)


def test_estimate_cost_usd_zero_tokens_is_zero():
    cfg = ModelConfig(
        baseline_model="m",
        planner_model="m",
        quarantine_model="m",
        token_budget=1000,
        price_input_per_mtok_usd=3.0,
        price_output_per_mtok_usd=15.0,
        pricing_verified=False,
    )
    assert estimate_cost_usd(0, 0, cfg) == 0.0


def test_anthropic_client_never_leaks_api_key_in_error_messages(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-fake-secret-key")
    client = AnthropicClient(model="claude-sonnet-5")

    class ExplodingMessages:
        def create(self, **kwargs):
            raise RuntimeError("auth failed while using key sk-test-fake-secret-key")

    class ExplodingSDKClient:
        messages = ExplodingMessages()

    client._client = ExplodingSDKClient()  # swap out the real SDK client, no network

    with pytest.raises(RuntimeError) as exc_info:
        client.run(system="s", messages=[{"role": "user", "content": "hi"}])

    assert "sk-test-fake-secret-key" not in str(exc_info.value)


def test_anthropic_client_missing_key_error_does_not_echo_env(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    # Isolate from this repo's own .env (which may have a real key) so the
    # "no key anywhere" path is what's actually under test.
    monkeypatch.setattr("cordon.llm.load_dotenv", lambda *a, **kw: None)
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY is not set"):
        AnthropicClient(model="claude-sonnet-5")
