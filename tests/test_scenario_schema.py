"""Tests for the scenario schema itself (evals/scenario.py) — the
requires_write classification, optional legit_outcome list on attacks, and
BenignScenario.success accepting either a single predicate (old corpus
files) or a list (new compound-answer files). No LLM calls.
"""

from __future__ import annotations

from evals.scenario import AttackScenario, BenignScenario, GoalPredicate, SeedData


def test_attack_scenario_requires_write_is_required():
    scenario = AttackScenario(
        id="x",
        category="A1",
        description="d",
        user_request="r",
        requires_write=False,
        seed=SeedData(),
        attacker_goal=GoalPredicate(predicate="any_email_sent", args={}),
    )
    assert scenario.requires_write is False


def test_attack_scenario_legit_outcome_defaults_to_empty_list():
    scenario = AttackScenario(
        id="x",
        category="A1",
        description="d",
        user_request="r",
        requires_write=True,
        seed=SeedData(),
        attacker_goal=GoalPredicate(predicate="any_email_sent", args={}),
    )
    assert scenario.legit_outcome == []


def test_attack_scenario_legit_outcome_accepts_a_list_of_predicates():
    scenario = AttackScenario(
        id="x",
        category="A10",
        description="d",
        user_request="r",
        requires_write=True,
        seed=SeedData(),
        attacker_goal=GoalPredicate(predicate="any_email_sent", args={}),
        legit_outcome=[GoalPredicate(predicate="no_email_sent", args={})],
    )
    assert len(scenario.legit_outcome) == 1


def test_benign_scenario_success_normalizes_a_single_dict_to_a_one_item_list():
    scenario = BenignScenario.model_validate(
        {
            "id": "x",
            "description": "d",
            "user_request": "r",
            "seed": {},
            "success": {"predicate": "no_email_sent", "args": {}},
        }
    )
    assert scenario.success == [GoalPredicate(predicate="no_email_sent", args={})]


def test_benign_scenario_success_accepts_a_list_directly():
    scenario = BenignScenario.model_validate(
        {
            "id": "x",
            "description": "d",
            "user_request": "r",
            "seed": {},
            "success": [
                {"predicate": "no_email_sent", "args": {}},
                {"predicate": "final_text_contains_all", "args": {"markers": ["hi"]}},
            ],
        }
    )
    assert len(scenario.success) == 2
