"""Tests for the harness's --limit / --budget-usd / token-budget handling
and result-file writing. Uses a fake LLM client — no network, no API key.
"""

from __future__ import annotations

import json

import pytest

from cordon.llm import ModelConfig
from evals.baselines.b0 import run_b0
from evals.harness import (
    BASELINES,
    _effective_baseline_name,
    _resolve_baseline,
    run_harness,
    write_result_file,
)
from evals.scenario import AttackScenario, BenignScenario, GoalPredicate, SeedData
from tests.fakes import ConstantLLMClient


def make_cfg(token_budget: int = 200_000) -> ModelConfig:
    return ModelConfig(
        baseline_model="fake-model",
        planner_model="fake-model",
        quarantine_model="fake-model",
        token_budget=token_budget,
        price_input_per_mtok_usd=3.0,
        price_output_per_mtok_usd=15.0,
        pricing_verified=False,
    )


def make_benign_task(id: str) -> BenignScenario:
    return BenignScenario(
        id=id,
        description="benign",
        user_request="do nothing",
        seed=SeedData(),
        success=[GoalPredicate(predicate="no_email_sent", args={})],
    )


def make_attack(id: str, requires_write: bool = False) -> AttackScenario:
    return AttackScenario(
        id=id,
        category="A1",
        description="attack",
        user_request="do nothing",
        requires_write=requires_write,
        seed=SeedData(),
        attacker_goal=GoalPredicate(predicate="any_email_sent", args={}),
    )


def test_run_harness_runs_full_corpus_when_unlimited():
    tasks = [make_benign_task("b1"), make_benign_task("b2")]
    attacks = [make_attack("a1"), make_attack("a2"), make_attack("a3")]
    llm = ConstantLLMClient()

    summary, benign_results, attack_results = run_harness(
        run_b0, llm, "b0", tasks, attacks, make_cfg()
    )

    assert summary.complete is True
    assert summary.stop_reason is None
    assert summary.scenarios_total == 5
    assert summary.scenarios_completed == 5
    assert len(benign_results) == 2
    assert len(attack_results) == 3
    assert llm.call_count == 5


def test_run_harness_limit_stops_early_and_marks_incomplete():
    tasks = [make_benign_task("b1"), make_benign_task("b2")]
    attacks = [make_attack("a1"), make_attack("a2"), make_attack("a3")]
    llm = ConstantLLMClient()

    summary, benign_results, attack_results = run_harness(
        run_b0, llm, "b0", tasks, attacks, make_cfg(), limit=2
    )

    assert summary.complete is False
    assert summary.stop_reason == "limit_reached"
    assert summary.scenarios_total == 5
    assert summary.scenarios_completed == 2
    assert len(benign_results) == 2
    assert len(attack_results) == 0


def test_run_harness_token_budget_stops_early():
    tasks = [make_benign_task("b1"), make_benign_task("b2"), make_benign_task("b3")]
    llm = ConstantLLMClient(input_tokens=100, output_tokens=50)  # 150 tokens/call

    summary, benign_results, _ = run_harness(
        run_b0, llm, "b0", tasks, [], make_cfg(token_budget=100)
    )

    assert summary.complete is False
    assert summary.stop_reason == "token_budget_exceeded"
    assert summary.scenarios_completed == 1
    assert len(benign_results) == 1


def test_run_harness_budget_usd_stops_early():
    tasks = [make_benign_task("b1"), make_benign_task("b2"), make_benign_task("b3")]
    llm = ConstantLLMClient(input_tokens=100, output_tokens=50)
    # cost/call = (100/1e6)*3.0 + (50/1e6)*15.0 = 0.00105
    summary, benign_results, _ = run_harness(
        run_b0, llm, "b0", tasks, [], make_cfg(), budget_usd=0.001
    )

    assert summary.complete is False
    assert summary.stop_reason == "usd_budget_exceeded"
    assert summary.scenarios_completed == 1
    assert summary.estimated_cost_usd > 0


def test_run_harness_reports_model_and_totals():
    tasks = [make_benign_task("b1")]
    llm = ConstantLLMClient(input_tokens=42, output_tokens=17)

    summary, _, _ = run_harness(run_b0, llm, "b0", tasks, [], make_cfg())

    assert summary.model == "fake-model"
    assert summary.total_input_tokens == 42
    assert summary.total_output_tokens == 17
    assert summary.pricing_verified is False


def test_write_result_file_marks_incomplete_runs_in_filename_and_body(tmp_path):
    tasks = [make_benign_task("b1"), make_benign_task("b2")]
    llm = ConstantLLMClient()

    summary, benign_results, attack_results = run_harness(
        run_b0, llm, "b0", tasks, [], make_cfg(), limit=1
    )
    path = write_result_file(summary, benign_results, attack_results, results_dir=tmp_path)

    assert "INCOMPLETE" in path.name
    payload = json.loads(path.read_text())
    assert payload["status"] == "INCOMPLETE"
    assert payload["summary"]["complete"] is False
    assert payload["summary"]["scenarios_completed"] == 1
    assert payload["summary"]["scenarios_total"] == 2
    assert len(payload["benign_results"]) == 1


def test_write_result_file_marks_complete_runs(tmp_path):
    tasks = [make_benign_task("b1")]
    llm = ConstantLLMClient()

    summary, benign_results, attack_results = run_harness(run_b0, llm, "b0", tasks, [], make_cfg())
    path = write_result_file(summary, benign_results, attack_results, results_dir=tmp_path)

    assert "INCOMPLETE" not in path.name
    payload = json.loads(path.read_text())
    assert payload["status"] == "complete"
    assert payload["summary"]["complete"] is True


def test_all_four_baselines_are_registered_and_resolvable():
    assert set(BASELINES) == {"b0", "b1", "b2", "b3"}
    for name in BASELINES:
        run_fn = _resolve_baseline(name)
        assert callable(run_fn)


def test_resolve_baseline_rejects_unknown_name():
    with pytest.raises(SystemExit, match="unknown baseline"):
        _resolve_baseline("b99")


def test_run_harness_aggregates_confirm_counts_across_scenarios():
    tasks = [make_benign_task("b1")]
    llm = ConstantLLMClient()

    def fake_run_with_confirms(env, user_request, llm):
        from evals.baselines.b0 import RunResult

        return RunResult(turns=1, confirm_count=2, confirm_approved_count=1)

    summary, benign_results, _ = run_harness(
        fake_run_with_confirms, llm, "b3", tasks, [], make_cfg()
    )

    assert summary.total_confirm_count == 2
    assert summary.total_confirm_approved_count == 1
    assert benign_results[0].confirm_count == 2


def test_effective_baseline_swaps_b3_to_b2_only_with_no_policy_flag():
    assert _effective_baseline_name("b3", no_policy=True) == "b2"
    assert _effective_baseline_name("b3", no_policy=False) == "b3"
    assert _effective_baseline_name("b0", no_policy=True) == "b0"
    assert _effective_baseline_name("b2", no_policy=True) == "b2"

