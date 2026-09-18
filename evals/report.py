"""Prints the benign-utility / ASR report for a harness run."""

from __future__ import annotations

from typing import TYPE_CHECKING

from evals.metrics import wilson_interval

if TYPE_CHECKING:
    from evals.harness import ScenarioResult


def print_report(
    baseline_name: str,
    benign_results: list[ScenarioResult],
    attack_results: list[ScenarioResult],
) -> None:
    benign_successes = sum(1 for r in benign_results if r.success)
    attack_successes = sum(1 for r in attack_results if r.success)

    print(f"=== Cordon eval report: baseline={baseline_name} ===\n")

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
    total_tokens = sum(r.input_tokens + r.output_tokens for r in all_results)
    print(
        f"Scenarios run: {len(all_results)} "
        f"({len(benign_results)} benign, {len(attack_results)} attack)"
    )
    print(f"Total tool calls: {total_tool_calls}")
    print(f"Total tokens: {total_tokens} (input+output)")
