"""Model-agnostic LLM wrapper. Model names live in config/env, not code.

``AnthropicClient`` is the only real backend for now. Anything that needs
an LLM (baselines, and later the planner/quarantine models) takes an
``LLMClient`` so tests can inject a scripted fake instead of hitting a real
API.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Protocol

from cordon.dotenv import load_dotenv


@dataclass
class LLMUsage:
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class LLMResponse:
    text: str | None
    tool_calls: list[dict[str, Any]]
    stop_reason: str
    usage: LLMUsage = field(default_factory=LLMUsage)
    # Set by a caching wrapper (evals.cache.CachingLLMClient) when this
    # response came from disk instead of a real API call. Callers that
    # accumulate spend (planner.make_plan, quarantine.extract, the B0/B1
    # tool loops) check this and skip adding a cache hit's tokens to any
    # cost estimate.
    from_cache: bool = False


@dataclass
class CacheStats:
    hits: int = 0
    misses: int = 0


class LLMClient(Protocol):
    model: str

    def run(
        self,
        *,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> LLMResponse: ...


def _redact(text: str, secret: str | None) -> str:
    """Strip a secret value out of a string before it can reach a log/error/output."""
    if not secret:
        return text
    return text.replace(secret, "<redacted>")


class AnthropicClient:
    """Thin wrapper around the Anthropic Messages API.

    The API key is read once here and never returned, logged, or included in
    any exception message this class raises — see ``_redact``.
    """

    def __init__(self, model: str) -> None:
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - exercised only without the dep
            raise RuntimeError(
                "the 'anthropic' package is required for AnthropicClient "
                "(uv sync should have installed it)"
            ) from exc
        load_dotenv()
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set. Copy .env.example to .env and fill it in, "
                "or export it in your shell, before running a real eval."
            )
        self._client = anthropic.Anthropic(api_key=api_key)
        self._api_key = api_key
        self.model = model

    def run(
        self,
        *,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> LLMResponse:
        try:
            response = self._client.messages.create(
                model=self.model,
                max_tokens=1024,
                system=system,
                messages=messages,  # type: ignore[arg-type]
                tools=tools or [],  # type: ignore[arg-type]
            )
        except Exception as exc:
            # Never let a raw SDK exception (which may embed request details)
            # propagate without a pass through the redaction filter.
            raise RuntimeError(_redact(str(exc), self._api_key)) from None
        tool_calls = [
            {"id": block.id, "name": block.name, "input": block.input}
            for block in response.content
            if block.type == "tool_use"
        ]
        text_parts = [block.text for block in response.content if block.type == "text"]
        return LLMResponse(
            text="".join(text_parts) or None,
            tool_calls=tool_calls,
            stop_reason=response.stop_reason or "unknown",
            usage=LLMUsage(
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens,
            ),
        )


@dataclass
class ModelConfig:
    baseline_model: str
    planner_model: str
    quarantine_model: str
    token_budget: int
    price_input_per_mtok_usd: float
    price_output_per_mtok_usd: float
    pricing_verified: bool


def default_model_config() -> ModelConfig:
    load_dotenv()
    return ModelConfig(
        # Every role defaults to Haiku for now (cheap enough to pilot with;
        # override any of these three independently via env/.env when a
        # stronger planner model is warranted).
        baseline_model=os.environ.get("CORDON_BASELINE_MODEL", "claude-haiku-4-5-20251001"),
        planner_model=os.environ.get("CORDON_PLANNER_MODEL", "claude-haiku-4-5-20251001"),
        quarantine_model=os.environ.get("CORDON_QUARANTINE_MODEL", "claude-haiku-4-5-20251001"),
        # --budget-usd is the primary spend guard in practice; this is a
        # generous per-run ceiling mainly meant to catch a runaway loop.
        token_budget=int(os.environ.get("CORDON_TOKEN_BUDGET", "700000")),
        # Placeholder $/MTok figures for Haiku-class pricing — NOT verified
        # against a current pricing page. Set CORDON_PRICING_VERIFIED=true
        # once you've checked them for the model actually configured above;
        # until then treat any printed cost estimate as a rough order of
        # magnitude, not a bill.
        price_input_per_mtok_usd=float(os.environ.get("CORDON_PRICE_INPUT_PER_MTOK_USD", "1.0")),
        price_output_per_mtok_usd=float(os.environ.get("CORDON_PRICE_OUTPUT_PER_MTOK_USD", "5.0")),
        pricing_verified=os.environ.get("CORDON_PRICING_VERIFIED", "false").strip().lower()
        == "true",
    )


def estimate_cost_usd(input_tokens: int, output_tokens: int, cfg: ModelConfig) -> float:
    return (input_tokens / 1_000_000) * cfg.price_input_per_mtok_usd + (
        output_tokens / 1_000_000
    ) * cfg.price_output_per_mtok_usd
