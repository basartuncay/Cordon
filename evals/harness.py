"""Eval harness: runs a baseline against the attack/benign corpus and
reports benign utility + attack success rate, computed deterministically
from final mock-env state (never LLM-judged).
"""

from __future__ import annotations

import argparse
import importlib
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from cordon.llm import AnthropicClient, LLMClient, default_model_config
from evals.predicates import evaluate
from evals.report import print_report
from evals.scenario import (
    AttackScenario,
    BenignScenario,
    build_environment,
    load_attacks,
    load_benign_tasks,
)

CORPUS_DIR = Path(__file__).parent / "corpus"

BASELINES = {
    "b0": "evals.baselines.b0:run_b0",
}


@dataclass
class ScenarioResult:
    id: str
    category: str
    success: bool
    tool_calls: list[tuple[str, dict]] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0


def _resolve_baseline(name: str):
    if name not in BASELINES:
        raise SystemExit(f"unknown baseline {name!r}; choices: {sorted(BASELINES)}")
    module_name, func_name = BASELINES[name].split(":")
    module = importlib.import_module(module_name)
    return getattr(module, func_name)


def run_scenario(
    run_fn, llm: LLMClient, scenario: AttackScenario | BenignScenario
) -> ScenarioResult:
    env = build_environment(scenario.seed)
    result = run_fn(env, scenario.user_request, llm)

    if isinstance(scenario, AttackScenario):
        goal, category = scenario.attacker_goal, scenario.category
    else:
        goal, category = scenario.success, "benign"

    success = evaluate(goal.predicate, goal.args, env, result.final_text)
    return ScenarioResult(
        id=scenario.id,
        category=category,
        success=success,
        tool_calls=result.tool_calls,
        input_tokens=result.input_tokens,
        output_tokens=result.output_tokens,
    )


def run_corpus(
    run_fn,
    llm: LLMClient,
    scenarios: Sequence[AttackScenario | BenignScenario],
    token_budget: int,
    tokens_used: int,
) -> tuple[list[ScenarioResult], int]:
    results: list[ScenarioResult] = []
    for scenario in scenarios:
        if tokens_used >= token_budget:
            print(
                f"warning: token budget ({token_budget}) reached; "
                f"stopping early after {len(results)}/{len(scenarios)} scenarios",
                file=sys.stderr,
            )
            break
        result = run_scenario(run_fn, llm, scenario)
        tokens_used += result.input_tokens + result.output_tokens
        results.append(result)
    return results, tokens_used


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a Cordon baseline against the corpus.")
    parser.add_argument("--baseline", default="b0", choices=sorted(BASELINES))
    parser.add_argument("--corpus-dir", default=str(CORPUS_DIR))
    args = parser.parse_args(argv)

    run_fn = _resolve_baseline(args.baseline)
    cfg = default_model_config()

    try:
        llm = AnthropicClient(model=cfg.baseline_model)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    corpus_dir = Path(args.corpus_dir)
    tasks = load_benign_tasks(corpus_dir / "tasks")
    attacks = load_attacks(corpus_dir / "attacks")

    tokens_used = 0
    benign_results, tokens_used = run_corpus(run_fn, llm, tasks, cfg.token_budget, tokens_used)
    attack_results, tokens_used = run_corpus(run_fn, llm, attacks, cfg.token_budget, tokens_used)

    print_report(args.baseline, benign_results, attack_results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
