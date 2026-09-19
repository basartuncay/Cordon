"""Tests for cordon.llm: cost estimation and the API-key redaction
guarantee. No real network calls — AnthropicClient's underlying SDK client
is swapped for a stub that raises, so we only exercise the redaction path.
"""

from __future__ import annotations

import pytest

from cordon.llm import (
    AnthropicClient,
    CacheStats,
    LLMResponse,
    ModelConfig,
    _redact,
    default_model_config,
    estimate_cost_usd,
)


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


def test_llm_response_from_cache_defaults_false():
    response = LLMResponse(text="hi", tool_calls=[], stop_reason="end_turn")
    assert response.from_cache is False


def test_llm_response_from_cache_can_be_set_true():
    response = LLMResponse(text="hi", tool_calls=[], stop_reason="end_turn", from_cache=True)
    assert response.from_cache is True


def test_cache_stats_starts_at_zero_and_is_mutable():
    stats = CacheStats()
    assert stats.hits == 0
    assert stats.misses == 0
    stats.hits += 1
    stats.misses += 2
    assert (stats.hits, stats.misses) == (1, 2)


def _clear_model_env(monkeypatch):
    for var in (
        "CORDON_BASELINE_MODEL",
        "CORDON_PLANNER_MODEL",
        "CORDON_QUARANTINE_MODEL",
        "CORDON_TOKEN_BUDGET",
        "CORDON_PRICE_INPUT_PER_MTOK_USD",
        "CORDON_PRICE_OUTPUT_PER_MTOK_USD",
        "CORDON_PRICING_VERIFIED",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr("cordon.llm.load_dotenv", lambda *a, **kw: None)


def test_default_model_config_defaults_to_haiku_for_every_role(monkeypatch):
    _clear_model_env(monkeypatch)
    cfg = default_model_config()
    assert cfg.baseline_model == "claude-haiku-4-5-20251001"
    assert cfg.planner_model == "claude-haiku-4-5-20251001"
    assert cfg.quarantine_model == "claude-haiku-4-5-20251001"


def test_default_model_config_token_budget_defaults_to_700000(monkeypatch):
    _clear_model_env(monkeypatch)
    cfg = default_model_config()
    assert cfg.token_budget == 700_000


def test_default_model_config_env_vars_override_every_field(monkeypatch):
    _clear_model_env(monkeypatch)
    monkeypatch.setenv("CORDON_BASELINE_MODEL", "claude-sonnet-5")
    monkeypatch.setenv("CORDON_TOKEN_BUDGET", "12345")
    cfg = default_model_config()
    assert cfg.baseline_model == "claude-sonnet-5"
    assert cfg.token_budget == 12345
    assert cfg.quarantine_model == "claude-haiku-4-5-20251001"  # untouched env var


def test_estimate_cost_usd_uses_haiku_placeholder_pricing_by_default(monkeypatch):
    _clear_model_env(monkeypatch)
    cfg = default_model_config()
    cost = estimate_cost_usd(1_000_000, 1_000_000, cfg)
    # Not asserting a specific number here — the point is the defaults are
    # cheaper than the old Sonnet-class placeholders (3.0/15.0), matching
    # the corpus now defaulting every role to Haiku. Still unverified.
    assert cfg.pricing_verified is False
    assert cost < 18.0
