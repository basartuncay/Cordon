"""Shared fake LLM clients for offline tests. No network, no API key."""

from __future__ import annotations

from dataclasses import dataclass

from cordon.llm import LLMResponse, LLMUsage


@dataclass
class ScriptedTurn:
    text: str | None
    tool_calls: list[dict]


class FakeLLMClient:
    """Replays a fixed script of turns instead of calling a real API."""

    model = "fake-model"

    def __init__(self, script: list[ScriptedTurn]) -> None:
        self._script = list(script)
        self._call_count = 0

    def run(self, *, system, messages, tools=None):
        turn = self._script[self._call_count]
        self._call_count += 1
        return LLMResponse(
            text=turn.text,
            tool_calls=turn.tool_calls,
            stop_reason="tool_use" if turn.tool_calls else "end_turn",
            usage=LLMUsage(input_tokens=10, output_tokens=5),
        )


class ConstantLLMClient:
    """Answers immediately with no tool calls and fixed token usage per
    call, so multi-scenario token/cost accounting is exactly predictable."""

    model = "fake-model"

    def __init__(
        self, text: str = "ok", input_tokens: int = 100, output_tokens: int = 50
    ) -> None:
        self._text = text
        self._input_tokens = input_tokens
        self._output_tokens = output_tokens
        self.call_count = 0

    def run(self, *, system, messages, tools=None):
        self.call_count += 1
        return LLMResponse(
            text=self._text,
            tool_calls=[],
            stop_reason="end_turn",
            usage=LLMUsage(input_tokens=self._input_tokens, output_tokens=self._output_tokens),
        )


@dataclass
class RecordedCall:
    system: str
    messages: list[dict]
    tools: list[dict] | None


class TextScriptLLMClient:
    """Replays a fixed script of plain-text responses (no tool calls) and
    records every call made to .run(), so a test can assert what the
    caller actually sent — e.g. that the planner never grants itself real
    tool-calling capability (``tools`` should always be ``None``)."""

    model = "fake-model"

    def __init__(self, texts: list[str], input_tokens: int = 20, output_tokens: int = 10) -> None:
        self._texts = list(texts)
        self._call_count = 0
        self._input_tokens = input_tokens
        self._output_tokens = output_tokens
        self.calls: list[RecordedCall] = []

    def run(self, *, system, messages, tools=None):
        self.calls.append(RecordedCall(system=system, messages=list(messages), tools=tools))
        text = self._texts[self._call_count]
        self._call_count += 1
        return LLMResponse(
            text=text,
            tool_calls=[],
            stop_reason="end_turn",
            usage=LLMUsage(input_tokens=self._input_tokens, output_tokens=self._output_tokens),
        )
