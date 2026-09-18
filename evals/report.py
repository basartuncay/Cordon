"""Prints the benign-utility / ASR report for a harness run.

An incomplete run (stopped early by --limit, --budget-usd, or the token
budget) is always flagged loudly here — never presented as if it covered the
full corpus.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from evals.metrics import wilson_interval

if TYPE_CHECKING:
    from evals.harness import RunSummary, ScenarioResult


def print_report(
    summary: RunSummary,
    benign_results: list[ScenarioResult],
    attack_results: list[ScenarioResult],
) -> None:
    benign_successes = sum(1 for r in benign_results if r.success)
    attack_successes = sum(1 for r in attack_results if r.success)

    print(f"=== Cordon eval report: baseline={summary.baseline} model={summary.model} ===\n")

    if not summary.complete:
        print(
            f"*** INCOMPLETE RUN: {summary.scenarios_completed}/{summary.scenarios_total} "
            f"scenarios completed (stopped: {summary.stop_reason}) ***\n"
            "*** Numbers below cover only the completed scenarios, not the full corpus. ***\n"
        )

    print("Benign utility (task completed as requested):")
    print(f"  {wilson_interval(benign_successes, len(benign_results))}\n")

    print("Attack success rate (attacker goal predicate true):")
    print(f"  {wilson_interval(attack_successes, len(attack_results))}\n")

    if attack_results:
        print("Attack success rate by category:")
        by_category: dict[str, list[bool]] = {}
        for r in attack_results:
            by_category.setdefault(r.category, []).append(r.success)
        for category in sorted(by_category):
            outcomes = by_category[category]
            successes = sum(outcomes)
            print(f"  {category}: {wilson_interval(successes, len(outcomes))}")
        print()

    all_results = benign_results + attack_results
    total_tool_calls = sum(len(r.tool_calls) for r in all_results)

    print(
        f"Scenarios completed: {summary.scenarios_completed}/{summary.scenarios_total} "
        f"({len(benign_results)} benign, {len(attack_results)} attack)"
    )
    total_tokens = summary.total_input_tokens + summary.total_output_tokens
    print(f"Model: {summary.model}")
    print(f"Total tool calls: {total_tool_calls}")
    print(f"Total tokens: {total_tokens} (input+output)")
    pricing_note = "" if summary.pricing_verified else "  [UNVERIFIED PRICING — rough estimate]"
    print(f"Estimated cost: ${summary.estimated_cost_usd:.4f}{pricing_note}")
    if summary.total_confirm_count:
        print(
            f"Confirmation prompts: {summary.total_confirm_count} "
            f"({summary.total_confirm_approved_count} approved, "
            f"{summary.total_confirm_count - summary.total_confirm_approved_count} rejected)"
        )
    elif summary.baseline in ("b2", "b3"):
        print("Confirmation prompts: 0")
