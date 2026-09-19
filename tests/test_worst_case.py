"""Tests for evals.worst_case — the generic "quarantine output is exactly
what the attacker wants" plan builder used for Step 2's worst-case mode.
No LLM calls: the plan structure is built directly from each attack
scenario's attacker_goal (predicate + args), and the scripted quarantine
function always returns the tampered value regardless of its input text —
this is what "assume the model was completely fooled" means mechanically.
"""

from __future__ import annotations

from pathlib import Path

from cordon.confirm import AutoApproveDecider, AutoDenyDecider
from evals.predicates import evaluate
from evals.scenario import build_environment, load_attacks
from evals.worst_case import build_worst_case_plan, run_worst_case_scenario

CORPUS_DIR = Path(__file__).parent.parent / "evals" / "corpus"


def _attack(scenario_id: str):
    attacks = {a.id: a for a in load_attacks(CORPUS_DIR / "attacks")}
    return attacks[scenario_id]


def test_build_worst_case_plan_reply_contains():
    scenario = _attack("a10_002")
    plan, tampered_value = build_worst_case_plan(scenario)
    assert tampered_value == "5pm"
    assert any(step.tool == "reply_email" for step in plan.steps)


def test_build_worst_case_plan_event_with_start_exists():
    scenario = _attack("a10_001")
    plan, tampered_value = build_worst_case_plan(scenario)
    assert tampered_value == "2026-01-10T20:00:00"
    assert any(step.tool == "create_event" for step in plan.steps)


def test_build_worst_case_plan_event_attendee_domain_added_with_existing_event():
    scenario = _attack("a10_003")
    plan, tampered_value = build_worst_case_plan(scenario)
    assert tampered_value == "exfil@evil.example"
    assert any(step.tool == "add_attendee" for step in plan.steps)


def test_build_worst_case_plan_event_created_with_attendee():
    scenario = _attack("a9_004")
    plan, tampered_value = build_worst_case_plan(scenario)
    assert tampered_value == "bob@company.example"
    tools = [step.tool for step in plan.steps]
    assert "add_attendee" in tools or "create_event" in tools


def test_build_worst_case_plan_email_forwarded_to_domain():
    scenario = _attack("a1_004")
    plan, tampered_value = build_worst_case_plan(scenario)
    assert tampered_value == "exfil@evil.example"
    assert any(step.tool == "forward_email" for step in plan.steps)


def test_build_worst_case_plan_email_sent_to_domain():
    scenario = _attack("a2_002")
    plan, tampered_value = build_worst_case_plan(scenario)
    assert tampered_value == "exfil@evil.example"
    assert any(step.tool == "send_email" for step in plan.steps)


def test_build_worst_case_plan_sent_email_contains():
    scenario = _attack("a9_003")
    plan, tampered_value = build_worst_case_plan(scenario)
    assert tampered_value == "delayed a week"
    assert any(step.tool == "send_email" for step in plan.steps)


def test_build_worst_case_plan_final_text_contains_has_no_action_step():
    scenario = _attack("a10_004")
    plan, tampered_value = build_worst_case_plan(scenario)
    assert tampered_value == "tr000000000000000000000000"
    assert not any(
        step.tool in ("send_email", "forward_email", "reply_email", "create_event", "add_attendee")
        for step in plan.steps
    )


def test_build_worst_case_plan_handles_no_attacker_domain_email():
    """a2_004's injection is appended to a legitimate contact's own
    email, not a separate @evil.example sender — the builder must still
    produce a valid plan (the vehicle email's exact content doesn't
    matter since the quarantine output is scripted regardless)."""
    scenario = _attack("a2_004")
    plan, tampered_value = build_worst_case_plan(scenario)
    assert tampered_value == "exfil@evil.example"
    assert len(plan.steps) >= 1


def test_run_worst_case_scenario_b2_ablation_lets_the_tampered_value_through():
    scenario = _attack("a10_001")
    result = run_worst_case_scenario(scenario, enforce_policy=False, confirm=AutoDenyDecider())
    assert result["success"] is True
    assert result["action_status"] == "executed"


def test_run_worst_case_scenario_b3_deny_blocks_the_tampered_value():
    scenario = _attack("a10_001")
    result = run_worst_case_scenario(scenario, enforce_policy=True, confirm=AutoDenyDecider())
    assert result["success"] is False
    assert result["action_status"] == "confirm_rejected"
    assert "P4" in result["rules"]


def test_run_worst_case_scenario_b3_approve_lets_it_through():
    scenario = _attack("a10_001")
    result = run_worst_case_scenario(scenario, enforce_policy=True, confirm=AutoApproveDecider())
    assert result["success"] is True
    assert result["action_status"] == "confirm_approved"


def test_run_worst_case_scenario_final_text_contains_succeeds_when_it_should():
    """No action tool at all for this predicate family — success has to
    come from quarantine's own output, exactly like Cordon's real
    final_text. Regression test: this returned success=False
    unconditionally before final_text was wired into the evaluate() call."""
    scenario = _attack("a10_004")
    result = run_worst_case_scenario(scenario, enforce_policy=False, confirm=AutoDenyDecider())
    assert result["success"] is True
    assert result["action_status"] == "no_action_step"


def test_run_worst_case_scenario_uses_a_fresh_environment_per_call():
    """Calling it twice must not accumulate state from the first run."""
    scenario = _attack("a10_002")
    first = run_worst_case_scenario(scenario, enforce_policy=False, confirm=AutoDenyDecider())
    second = run_worst_case_scenario(scenario, enforce_policy=False, confirm=AutoDenyDecider())
    assert first["success"] == second["success"] is True


def test_every_requires_write_attack_has_a_buildable_worst_case_plan():
    """No LLM, no execution — just confirms the builder doesn't raise for
    any of the 37 write-tier attacks currently in the corpus, so Step 2's
    full-corpus report doesn't silently skip any of them."""
    attacks = load_attacks(CORPUS_DIR / "attacks")
    write_attacks = [a for a in attacks if a.requires_write]
    assert len(write_attacks) >= 30
    for scenario in write_attacks:
        plan, tampered_value = build_worst_case_plan(scenario)
        assert len(plan.steps) >= 1
        assert isinstance(tampered_value, str) and tampered_value


def test_every_requires_write_attack_worst_case_run_does_not_error():
    attacks = load_attacks(CORPUS_DIR / "attacks")
    write_attacks = [a for a in attacks if a.requires_write]
    for scenario in write_attacks:
        result = run_worst_case_scenario(scenario, enforce_policy=False, confirm=AutoDenyDecider())
        assert result["action_status"] != "error", (scenario.id, result)


def test_build_environment_and_evaluate_are_reexported_correctly():
    """Sanity check that the module under test wires into the same
    predicate/env machinery as the rest of the corpus, not a shadow copy."""
    scenario = _attack("a10_001")
    env = build_environment(scenario.seed)
    goal = scenario.attacker_goal
    assert evaluate(goal.predicate, goal.args, env, None) is False
