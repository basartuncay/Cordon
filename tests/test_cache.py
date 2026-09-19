"""Tests for evals.cache.CachingLLMClient — a disk-backed cache keyed by
model + the exact system/messages/tools sent, so identical LLM calls (e.g.
B2 and B3's planner/quarantine calls for the same scenario) never cost
twice. No real API calls: wraps a counting fake inner client.
"""

from __future__ import annotations

from cordon.llm import LLMResponse, LLMUsage
from evals.cache import CachingLLMClient


class CountingLLMClient:
    """Returns a fixed response per distinct input; counts real calls."""

    def __init__(self, model: str = "fake-model") -> None:
        self.model = model
        self.call_count = 0

    def run(self, *, system, messages, tools=None):
        self.call_count += 1
        return LLMResponse(
            text=f"response #{self.call_count}",
            tool_calls=[],
            stop_reason="end_turn",
            usage=LLMUsage(input_tokens=100, output_tokens=50),
        )


def test_first_call_is_a_cache_miss(tmp_path):
    inner = CountingLLMClient()
    client = CachingLLMClient(inner, cache_dir=tmp_path)

    response = client.run(system="s", messages=[{"role": "user", "content": "hi"}])

    assert inner.call_count == 1
    assert response.from_cache is False
    assert client.hits == 0
    assert client.misses == 1


def test_identical_second_call_is_a_cache_hit_and_skips_the_inner_client(tmp_path):
    inner = CountingLLMClient()
    client = CachingLLMClient(inner, cache_dir=tmp_path)

    first = client.run(system="s", messages=[{"role": "user", "content": "hi"}])
    second = client.run(system="s", messages=[{"role": "user", "content": "hi"}])

    assert inner.call_count == 1  # inner never called a second time
    assert second.from_cache is True
    assert second.text == first.text
    assert second.usage.input_tokens == first.usage.input_tokens
    assert client.hits == 1
    assert client.misses == 1


def test_different_messages_are_a_cache_miss(tmp_path):
    inner = CountingLLMClient()
    client = CachingLLMClient(inner, cache_dir=tmp_path)

    client.run(system="s", messages=[{"role": "user", "content": "hi"}])
    client.run(system="s", messages=[{"role": "user", "content": "bye"}])

    assert inner.call_count == 2
    assert client.hits == 0
    assert client.misses == 2


def test_different_model_is_a_cache_miss_even_with_identical_messages(tmp_path):
    inner_a = CountingLLMClient(model="model-a")
    inner_b = CountingLLMClient(model="model-b")
    client_a = CachingLLMClient(inner_a, cache_dir=tmp_path)
    client_b = CachingLLMClient(inner_b, cache_dir=tmp_path)

    client_a.run(system="s", messages=[{"role": "user", "content": "hi"}])
    client_b.run(system="s", messages=[{"role": "user", "content": "hi"}])

    assert inner_a.call_count == 1
    assert inner_b.call_count == 1


def test_tools_argument_is_part_of_the_cache_key(tmp_path):
    inner = CountingLLMClient()
    client = CachingLLMClient(inner, cache_dir=tmp_path)

    client.run(system="s", messages=[{"role": "user", "content": "hi"}], tools=None)
    client.run(
        system="s",
        messages=[{"role": "user", "content": "hi"}],
        tools=[{"name": "list_emails"}],
    )

    assert inner.call_count == 2


def test_two_separate_client_instances_share_the_same_disk_cache(tmp_path):
    """This is the whole point: B2 and B3 (separate CachingLLMClient
    instances wrapping separate AnthropicClient instances) share a cache
    hit for the identical planner/quarantine call of the same scenario."""
    inner1 = CountingLLMClient()
    inner2 = CountingLLMClient()
    client1 = CachingLLMClient(inner1, cache_dir=tmp_path)
    client2 = CachingLLMClient(inner2, cache_dir=tmp_path)

    client1.run(system="s", messages=[{"role": "user", "content": "hi"}])
    response = client2.run(system="s", messages=[{"role": "user", "content": "hi"}])

    assert inner2.call_count == 0
    assert response.from_cache is True


def test_model_attribute_is_exposed_and_matches_the_inner_client(tmp_path):
    inner = CountingLLMClient(model="claude-haiku-4-5-20251001")
    client = CachingLLMClient(inner, cache_dir=tmp_path)
    assert client.model == "claude-haiku-4-5-20251001"


def test_cache_creates_the_directory_if_missing(tmp_path):
    cache_dir = tmp_path / "nested" / ".cache"
    inner = CountingLLMClient()
    client = CachingLLMClient(inner, cache_dir=cache_dir)

    client.run(system="s", messages=[{"role": "user", "content": "hi"}])

    assert cache_dir.is_dir()
    assert any(cache_dir.iterdir())
