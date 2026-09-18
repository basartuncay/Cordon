"""Tests for the tiered/error-aware metric computations in report.py:
read-only vs write-tier ASR, errored-scenario separation, and utility-
under-attack. Pure functions over hand-built ScenarioResult lists — no
LLM, no corpus.
"""

from __future__ import annotations

from evals.harness import ScenarioResult
from evals.report import (
    compute_asr_tiers,
    compute_benign_utility,
    compute_utility_under_attack,
)


def benign(success=True, errored=False):
    return ScenarioResult(id="b", category="benign", success=success, errored=errored)


def attack(requires_write, success, errored=False, legit_outcome_success=None):
    return ScenarioResult(
        id="a",
        category="A10",
        success=success,
        errored=errored,
        requires_write=requires_write,
        legit_outcome_success=legit_outcome_success,
    )


def test_compute_benign_utility_excludes_errored_from_denominator():
    results = [benign(True), benign(False), benign(True, errored=True)]
    ci, errored_count, total = compute_benign_utility(results)
    assert errored_count == 1
    assert total == 3
    assert ci.n == 2  # errored one excluded
    assert ci.successes == 1


def test_compute_benign_utility_all_errored_gives_zero_n():
    results = [benign(True, errored=True)]
    ci, errored_count, total = compute_benign_utility(results)
    assert errored_count == 1
    assert ci.n == 0


def test_compute_asr_tiers_splits_read_only_from_write():
    results = [
        attack(requires_write=False, success=True),
        attack(requires_write=False, success=False),
        attack(requires_write=True, success=True),
        attack(requires_write=True, success=False),
        attack(requires_write=True, success=False),
    ]
    read_ci, write_ci, errored_count, total = compute_asr_tiers(results)
    assert read_ci.n == 2
    assert read_ci.successes == 1
    assert write_ci.n == 3
    assert write_ci.successes == 1
    assert errored_count == 0
    assert total == 5


def test_compute_asr_tiers_excludes_errored_scenarios():
    results = [
        attack(requires_write=True, success=True),
        attack(requires_write=True, success=False, errored=True),
    ]
    read_ci, write_ci, errored_count, total = compute_asr_tiers(results)
    assert write_ci.n == 1
    assert write_ci.successes == 1
    assert errored_count == 1
    assert total == 2


def test_compute_utility_under_attack_only_counts_scenarios_with_legit_outcome():
    results = [
        attack(requires_write=True, success=False, legit_outcome_success=True),
        attack(requires_write=True, success=False, legit_outcome_success=False),
        attack(requires_write=False, success=False, legit_outcome_success=None),  # not measured
    ]
    ci = compute_utility_under_attack(results)
    assert ci.n == 2
    assert ci.successes == 1


def test_compute_utility_under_attack_excludes_errored():
    results = [
        attack(requires_write=True, success=False, legit_outcome_success=True, errored=True),
        attack(requires_write=True, success=False, legit_outcome_success=True),
    ]
    ci = compute_utility_under_attack(results)
    assert ci.n == 1


def test_compute_utility_under_attack_empty_when_no_scenario_defines_it():
    results = [attack(requires_write=True, success=False)]
    ci = compute_utility_under_attack(results)
    assert ci.n == 0
