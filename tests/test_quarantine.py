"""Quarantine extraction tests, all against a scripted text LLM client —
no network, no API key. The quarantine LLM has no tools and must produce
output that validates against a caller-supplied schema (enum, date, id, or
a length-bounded string); anything that doesn't validate is rejected
outright rather than silently passed through.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from cordon.llm import CacheStats, LLMUsage
from cordon.quarantine import ExtractionSchema, QuarantineError, extract
from tests.fakes import TextScriptLLMClient


def test_extract_email_kind_accepts_a_well_formed_address():
    llm = TextScriptLLMClient(["attacker@evil.example"])
    schema = ExtractionSchema(kind="email")
    value = extract("some untrusted text", schema, "extract the address", llm)
    assert value == "attacker@evil.example"


def test_extract_email_kind_rejects_a_non_address():
    llm = TextScriptLLMClient(["this is not an email"])
    schema = ExtractionSchema(kind="email")
    with pytest.raises(QuarantineError):
        extract("some untrusted text", schema, "extract the address", llm)


def test_extract_date_kind_accepts_a_bare_date_and_normalizes_to_midnight():
    llm = TextScriptLLMClient(["2026-03-05"])
    schema = ExtractionSchema(kind="date")
    value = extract("meet me on March 5th", schema, "extract the date", llm)
    assert value == datetime(2026, 3, 5).isoformat()


def test_extract_date_kind_accepts_a_full_datetime_with_time_of_day():
    """Calendar start/end need time-of-day, not just a date — this is
    exactly what a real model extracts from 'moved to 2026-01-10T20:00:00'
    style text, and create_event's start/end args need the time to
    survive the round trip."""
    llm = TextScriptLLMClient(["2026-01-10T20:00:00"])
    schema = ExtractionSchema(kind="date")
    value = extract("the meeting moved to 2026-01-10T20:00:00", schema, "extract it", llm)
    assert value == datetime(2026, 1, 10, 20, 0, 0).isoformat()


def test_extract_date_kind_rejects_non_date_text():
    llm = TextScriptLLMClient(["sometime soon"])
    schema = ExtractionSchema(kind="date")
    with pytest.raises(QuarantineError):
        extract("meet me sometime soon", schema, "extract the date", llm)


def test_extract_id_kind_accepts_alphanumeric_id():
    llm = TextScriptLLMClient(["evt-4471"])
    schema = ExtractionSchema(kind="id")
    value = extract("event id evt-4471", schema, "extract the id", llm)
    assert value == "evt-4471"


def test_extract_id_kind_rejects_id_with_disallowed_characters():
    llm = TextScriptLLMClient(["evt 4471; drop table"])
    schema = ExtractionSchema(kind="id")
    with pytest.raises(QuarantineError):
        extract("id text", schema, "extract the id", llm)


def test_extract_enum_kind_accepts_one_of_the_listed_values():
    llm = TextScriptLLMClient(["urgent"])
    schema = ExtractionSchema(kind="enum", enum_values=["low", "normal", "urgent"])
    value = extract("this is urgent!!", schema, "extract the priority", llm)
    assert value == "urgent"


def test_extract_enum_kind_rejects_a_value_outside_the_enum():
    llm = TextScriptLLMClient(["catastrophic"])
    schema = ExtractionSchema(kind="enum", enum_values=["low", "normal", "urgent"])
    with pytest.raises(QuarantineError):
        extract("this is catastrophic!!", schema, "extract the priority", llm)


def test_extract_enum_schema_without_values_is_a_programming_error():
    with pytest.raises(ValueError, match="enum_values"):
        ExtractionSchema(kind="enum")


def test_extract_text_kind_enforces_max_length():
    llm = TextScriptLLMClient(["x" * 500])
    schema = ExtractionSchema(kind="text", max_length=50)
    with pytest.raises(QuarantineError):
        extract("long text", schema, "extract a short summary", llm)


def test_extract_text_kind_accepts_short_enough_text():
    llm = TextScriptLLMClient(["a short summary"])
    schema = ExtractionSchema(kind="text", max_length=50)
    value = extract("some text", schema, "summarize", llm)
    assert value == "a short summary"


def test_extract_raises_when_llm_finds_nothing():
    llm = TextScriptLLMClient(["NONE"])
    schema = ExtractionSchema(kind="email")
    with pytest.raises(QuarantineError, match="no matching value"):
        extract("no address here", schema, "extract the address", llm)


def test_extract_never_grants_the_quarantine_llm_tool_use():
    llm = TextScriptLLMClient(["attacker@evil.example"])
    schema = ExtractionSchema(kind="email")
    extract("text", schema, "extract the address", llm)
    assert llm.calls[0].tools is None


def test_extract_accumulates_usage_into_a_shared_accumulator():
    llm = TextScriptLLMClient(["a@b.example", "c@d.example"], input_tokens=15, output_tokens=5)
    schema = ExtractionSchema(kind="email")
    usage = LLMUsage()
    extract("text", schema, "extract", llm, usage=usage)
    extract("text2", schema, "extract", llm, usage=usage)
    assert usage.input_tokens == 30
    assert usage.output_tokens == 10


def test_extract_records_a_cache_miss_and_counts_its_tokens():
    llm = TextScriptLLMClient(["a@b.example"], input_tokens=15, output_tokens=5, from_cache=[False])
    usage = LLMUsage()
    stats = CacheStats()
    extract("text", ExtractionSchema(kind="email"), "extract", llm, usage=usage, cache_stats=stats)
    assert stats.misses == 1
    assert stats.hits == 0
    assert usage.input_tokens == 15
    assert usage.output_tokens == 5


def test_extract_records_a_cache_hit_and_does_not_count_its_tokens():
    llm = TextScriptLLMClient(["a@b.example"], input_tokens=15, output_tokens=5, from_cache=[True])
    usage = LLMUsage()
    stats = CacheStats()
    extract("text", ExtractionSchema(kind="email"), "extract", llm, usage=usage, cache_stats=stats)
    assert stats.hits == 1
    assert stats.misses == 0
    assert usage.input_tokens == 0
    assert usage.output_tokens == 0
