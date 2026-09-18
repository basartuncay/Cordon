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


class LLMClient(Protocol):
    model: str

    def run(
        self,
        *,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> LLMResponse: ...


class AnthropicClient:
    """Thin wrapper around the Anthropic Messages API."""

    def __init__(self, model: str) -> None:
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - exercised only without the dep
            raise RuntimeError(
                "the 'anthropic' package is required for AnthropicClient "
                "(uv sync should have installed it)"
            ) from exc
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set. Copy .env.example to .env and fill it in, "
                "or export it in your shell, before running a real eval."
            )
        self._client = anthropic.Anthropic(api_key=api_key)
        self.model = model

    def run(
        self,
        *,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> LLMResponse:
        response = self._client.messages.create(
            model=self.model,
            max_tokens=1024,
            system=system,
            messages=messages,  # type: ignore[arg-type]
            tools=tools or [],  # type: ignore[arg-type]
        )
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


def default_model_config() -> ModelConfig:
    return ModelConfig(
        baseline_model=os.environ.get("CORDON_BASELINE_MODEL", "claude-sonnet-5"),
        planner_model=os.environ.get("CORDON_PLANNER_MODEL", "claude-sonnet-5"),
        quarantine_model=os.environ.get("CORDON_QUARANTINE_MODEL", "claude-haiku-4-5-20251001"),
        token_budget=int(os.environ.get("CORDON_TOKEN_BUDGET", "200000")),
    )
