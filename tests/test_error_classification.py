"""Tests for evals.report.classify_error and the tier-split error
breakdown — pure functions over hand-built ScenarioResult lists, no LLM.
Pure observability: these tests describe how existing error messages
(from planner.py/executor.py, unchanged here) get bucketed for reporting,
not a change to what causes an error.
"""

from __future__ import annotations

from evals.harness import ScenarioResult
from evals.report import classify_error, compute_error_breakdown


def test_classify_error_none_reason_is_none_category():
    assert classify_error(None) == "none"


def test_classify_error_invalid_plan():
    reason = "planner failed to produce a valid plan after 3 attempts: unknown tool: 'nope'"
    assert classify_error(reason) == "invalid_plan"


def test_classify_error_ref_error_list_not_indexed():
    reason = "ref search1.None resolved to a list; index into it first"
    assert classify_error(reason) == "ref_error"


def test_classify_error_ref_error_unknown_step():
    reason = "ref to unknown/not-yet-run step: 's99'"
    assert classify_error(reason) == "ref_error"


def test_classify_error_ref_error_bad_path_segment():
    reason = "cannot resolve path segment 'start_time' on {'id': 'e1'}"
    assert classify_error(reason) == "ref_error"


def test_classify_error_schema_violation_validation_failure():
    reason = "quarantine output failed schema validation: 1 validation error for Extracted"
    assert classify_error(reason) == "schema_violation"


def test_classify_error_schema_violation_no_match():
    reason = "quarantine found no matching value in the text"
    assert classify_error(reason) == "schema_violation"


def test_classify_error_tool_error_missing_email():
    reason = "no such email: 'e99'"
    assert classify_error(reason) == "tool_error"


def test_classify_error_tool_error_missing_event():
    reason = "no such event: 'evt-99'"
    assert classify_error(reason) == "tool_error"


def test_classify_error_config_error_no_quarantine_configured():
    reason = "no quarantine function configured for this executor"
    assert classify_error(reason) == "config_error"


def test_classify_error_unrecognized_message_is_other():
    reason = "something totally unexpected happened"
    assert classify_error(reason) == "other"


def _benign(errored=False):
    return ScenarioResult(id="b", category="benign", success=True, errored=errored)


def _attack(requires_write, errored=False):
    return ScenarioResult(
        id="a", category="A10", success=False, errored=errored, requires_write=requires_write
    )


def test_compute_error_breakdown_splits_benign_and_attack_tiers():
    benign_results = [_benign(errored=True), _benign(errored=False), _benign(errored=False)]
    attack_results = [
        _attack(requires_write=False, errored=True),
        _attack(requires_write=False, errored=False),
        _attack(requires_write=True, errored=True),
        _attack(requires_write=True, errored=True),
        _attack(requires_write=True, errored=False),
    ]

    breakdown = compute_error_breakdown(benign_results, attack_results)

    assert breakdown["benign"] == (1, 3)
    assert breakdown["read_only"] == (1, 2)
    assert breakdown["write"] == (2, 3)


def test_compute_error_breakdown_handles_empty_lists():
    breakdown = compute_error_breakdown([], [])
    assert breakdown["benign"] == (0, 0)
    assert breakdown["read_only"] == (0, 0)
    assert breakdown["write"] == (0, 0)
