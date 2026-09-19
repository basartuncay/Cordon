"""Disk-backed LLM response cache, keyed by model + the exact
system/messages/tools sent.

The point: B2 and B3 (and any re-run of the same scenario) issue *identical*
planner/quarantine calls for a given scenario+model — enforce_policy never
touches what gets sent to the LLM, only what the executor does with the
result. Caching those calls means a second baseline, or a second pass with
a different ConfirmDecider, costs nothing beyond the first real call.

Cache hits are flagged via ``LLMResponse.from_cache`` so callers that
accumulate spend (planner.make_plan, quarantine.extract, the B0/B1 tool
loops) can skip counting a hit's tokens — cache hits never count toward
cost, and are reported separately (CacheStats hits/misses).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from cordon.llm import LLMClient, LLMResponse, LLMUsage

CACHE_DIR = Path(__file__).parent / ".cache"


def _cache_key(model: str, system: str, messages: list[dict[str, Any]], tools: Any) -> str:
    payload = json.dumps(
        {"model": model, "system": system, "messages": messages, "tools": tools},
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


class CachingLLMClient:
    """Wraps any LLMClient with a disk cache under `cache_dir`."""

    def __init__(self, inner: LLMClient, cache_dir: Path = CACHE_DIR) -> None:
        self._inner = inner
        self.model = inner.model
        self._cache_dir = Path(cache_dir)
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self.hits = 0
        self.misses = 0

    def run(
        self,
        *,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> LLMResponse:
        key = _cache_key(self.model, system, messages, tools)
        path = self._cache_dir / f"{key}.json"

        if path.is_file():
            self.hits += 1
            data = json.loads(path.read_text())
            return LLMResponse(
                text=data["text"],
                tool_calls=data["tool_calls"],
                stop_reason=data["stop_reason"],
                usage=LLMUsage(**data["usage"]),
                from_cache=True,
            )

        self.misses += 1
        response = self._inner.run(system=system, messages=messages, tools=tools)
        path.write_text(
            json.dumps(
                {
                    "text": response.text,
                    "tool_calls": response.tool_calls,
                    "stop_reason": response.stop_reason,
                    "usage": {
                        "input_tokens": response.usage.input_tokens,
                        "output_tokens": response.usage.output_tokens,
                    },
                }
            )
        )
        return response
