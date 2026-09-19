"""Planner tests, all against a scripted text LLM client — no network,
no API key. The planner is privileged: it must never see tool output, and
it must retry only on Plan *validation* failure, never for any other
reason (there's nothing else it could retry on, since it never reads
anything untrusted in the first place).
"""

from __future__ import annotations

import json

import pytest

from cordon.llm import CacheStats, LLMUsage
from cordon.planner import MAX_RETRIES, PlannerError, make_plan
from tests.fakes import TextScriptLLMClient

VALID_PLAN_JSON = json.dumps(
    {
        "steps": [
            {"step_id": "s1", "tool": "list_emails", "args": {}},
        ]
    }
)


def test_make_plan_succeeds_on_first_valid_response():
    llm = TextScriptLLMClient([VALID_PLAN_JSON])
    plan = make_plan("Summarize my inbox.", llm)
    assert len(plan.steps) == 1
    assert plan.steps[0].tool == "list_emails"
    assert len(llm.calls) == 1


def test_make_plan_accepts_a_fenced_code_block():
    fenced = f"```json\n{VALID_PLAN_JSON}\n```"
    llm = TextScriptLLMClient([fenced])
    plan = make_plan("Summarize my inbox.", llm)
    assert len(plan.steps) == 1


def test_make_plan_retries_on_malformed_json_then_succeeds():
    llm = TextScriptLLMClient(["not json at all", VALID_PLAN_JSON])
    plan = make_plan("Summarize my inbox.", llm)
    assert len(plan.steps) == 1
    assert len(llm.calls) == 2


def test_make_plan_retries_on_schema_validation_error_then_succeeds():
    invalid = json.dumps({"steps": [{"step_id": "s1", "tool": "not_a_real_tool", "args": {}}]})
    llm = TextScriptLLMClient([invalid, VALID_PLAN_JSON])
    plan = make_plan("Summarize my inbox.", llm)
    assert len(plan.steps) == 1
    assert len(llm.calls) == 2


def test_make_plan_raises_after_exceeding_max_retries():
    bad = "still not json"
    llm = TextScriptLLMClient([bad] * (MAX_RETRIES + 1))
    with pytest.raises(PlannerError):
        make_plan("Summarize my inbox.", llm)
    assert len(llm.calls) == MAX_RETRIES + 1


def test_make_plan_retries_at_most_twice():
    """MAX_RETRIES=2 means at most 3 attempts total; a 4th never happens."""
    llm = TextScriptLLMClient(["bad"] * 10)
    with pytest.raises(PlannerError):
        make_plan("Summarize my inbox.", llm)
    assert len(llm.calls) == 3


def test_make_plan_never_grants_the_planner_real_tool_use():
    """The planner describes tool schemas in its prompt text but must
    never be given actual function-calling capability — it only ever
    emits a plan as JSON text, never a live tool_use block."""
    llm = TextScriptLLMClient([VALID_PLAN_JSON])
    make_plan("Summarize my inbox.", llm)
    assert llm.calls[0].tools is None


def test_make_plan_only_ever_sends_the_user_request_and_validation_feedback():
    """The planner's messages must never contain anything except the
    user's own request and (on retry) feedback about a validation error —
    never tool output, since it has none to begin with."""
    invalid = json.dumps({"steps": [{"step_id": "s1", "tool": "nope", "args": {}}]})
    llm = TextScriptLLMClient([invalid, VALID_PLAN_JSON])
    make_plan("Summarize my inbox please.", llm)

    first_call_messages = llm.calls[0].messages
    assert first_call_messages == [{"role": "user", "content": "Summarize my inbox please."}]

    second_call_messages = llm.calls[1].messages
    # everything beyond the first message is the model's own bad output
    # plus our feedback about *why* it failed validation — nothing else.
    assert second_call_messages[0] == {"role": "user", "content": "Summarize my inbox please."}
    for msg in second_call_messages[1:]:
        assert msg["role"] in ("assistant", "user")


def test_make_plan_error_after_retries_mentions_the_last_validation_error():
    invalid = json.dumps({"steps": [{"step_id": "s1", "tool": "nope", "args": {}}]})
    llm = TextScriptLLMClient([invalid] * (MAX_RETRIES + 1))
    with pytest.raises(PlannerError, match="unknown tool"):
        make_plan("Summarize my inbox.", llm)


def test_make_plan_records_a_cache_miss_and_counts_its_tokens():
    llm = TextScriptLLMClient([VALID_PLAN_JSON], from_cache=[False])
    usage = LLMUsage()
    stats = CacheStats()
    make_plan("Summarize my inbox.", llm, usage=usage, cache_stats=stats)
    assert stats.misses == 1
    assert stats.hits == 0
    assert usage.input_tokens == 20
    assert usage.output_tokens == 10


def test_make_plan_records_a_cache_hit_and_does_not_count_its_tokens():
    llm = TextScriptLLMClient([VALID_PLAN_JSON], from_cache=[True])
    usage = LLMUsage()
    stats = CacheStats()
    make_plan("Summarize my inbox.", llm, usage=usage, cache_stats=stats)
    assert stats.hits == 1
    assert stats.misses == 0
    assert usage.input_tokens == 0
    assert usage.output_tokens == 0


def test_make_plan_without_cache_stats_still_works_normally():
    llm = TextScriptLLMClient([VALID_PLAN_JSON], from_cache=[True])
    plan = make_plan("Summarize my inbox.", llm)
    assert len(plan.steps) == 1
