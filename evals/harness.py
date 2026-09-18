"""Eval harness: runs a baseline against the attack/benign corpus and
reports benign utility + attack success rate, computed deterministically
from final mock-env state (never LLM-judged).

Every run also writes a JSON result file under evals/results/ (gitignored)
carrying the same numbers as the printed report, so a partial run can be
inspected later. A run stopped early by --limit, --budget-usd, or the
CORDON_TOKEN_BUDGET env var is always marked incomplete — never reported as
if it were a full corpus run.
"""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from cordon.llm import (
    AnthropicClient,
    LLMClient,
    ModelConfig,
    default_model_config,
    estimate_cost_usd,
)
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
RESULTS_DIR = Path(__file__).parent / "results"

BASELINES = {
    "b0": "evals.baselines.b0:run_b0",
}

StopReason = Literal["limit_reached", "token_budget_exceeded", "usd_budget_exceeded"] | None


@dataclass
class ScenarioResult:
    id: str
    category: str
    success: bool
    tool_calls: list[tuple[str, dict]] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class RunSummary:
    baseline: str
    model: str
    started_at: str
    scenarios_total: int
    scenarios_completed: int
    complete: bool
    stop_reason: StopReason
    total_input_tokens: int
    total_output_tokens: int
    estimated_cost_usd: float
    pricing_verified: bool


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


def run_harness(
    run_fn,
    llm: LLMClient,
    baseline_name: str,
    tasks: Sequence[BenignScenario],
    attacks: Sequence[AttackScenario],
    cfg: ModelConfig,
    limit: int | None = None,
    budget_usd: float | None = None,
) -> tuple[RunSummary, list[ScenarioResult], list[ScenarioResult]]:
    started_at = datetime.now(UTC).isoformat()

    ordered: list[tuple[str, AttackScenario | BenignScenario]] = [
        ("benign", t) for t in tasks
    ] + [("attack", a) for a in attacks]
    scenarios_total = len(ordered)

    benign_results: list[ScenarioResult] = []
    attack_results: list[ScenarioResult] = []
    tokens_used = 0
    cost_so_far = 0.0
    stop_reason: StopReason = None

    for i, (kind, scenario) in enumerate(ordered):
        if limit is not None and i >= limit:
            stop_reason = "limit_reached"
            break
        if tokens_used >= cfg.token_budget:
            stop_reason = "token_budget_exceeded"
            break
        if budget_usd is not None and cost_so_far >= budget_usd:
            stop_reason = "usd_budget_exceeded"
            break

        result = run_scenario(run_fn, llm, scenario)
        tokens_used += result.input_tokens + result.output_tokens
        cost_so_far += estimate_cost_usd(result.input_tokens, result.output_tokens, cfg)
        (benign_results if kind == "benign" else attack_results).append(result)

    scenarios_completed = len(benign_results) + len(attack_results)
    complete = scenarios_completed == scenarios_total

    summary = RunSummary(
        baseline=baseline_name,
        model=llm.model,
        started_at=started_at,
        scenarios_total=scenarios_total,
        scenarios_completed=scenarios_completed,
        complete=complete,
        stop_reason=stop_reason,
        total_input_tokens=sum(
            r.input_tokens for r in benign_results + attack_results
        ),
        total_output_tokens=sum(
            r.output_tokens for r in benign_results + attack_results
        ),
        estimated_cost_usd=cost_so_far,
        pricing_verified=cfg.pricing_verified,
    )
    return summary, benign_results, attack_results


def write_result_file(
    summary: RunSummary,
    benign_results: list[ScenarioResult],
    attack_results: list[ScenarioResult],
    results_dir: Path = RESULTS_DIR,
) -> Path:
    results_dir.mkdir(parents=True, exist_ok=True)
    stamp = summary.started_at.replace(":", "-")
    status = "complete" if summary.complete else "INCOMPLETE"
    path = results_dir / f"{summary.baseline}_{stamp}_{status}.json"
    payload = {
        "summary": asdict(summary),
        "status": status,
        "benign_results": [asdict(r) for r in benign_results],
        "attack_results": [asdict(r) for r in attack_results],
    }
    path.write_text(json.dumps(payload, indent=2, default=str))
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a Cordon baseline against the corpus.")
    parser.add_argument("--baseline", default="b0", choices=sorted(BASELINES))
    parser.add_argument("--corpus-dir", default=str(CORPUS_DIR))
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="run only the first N scenarios (benign then attack)",
    )
    parser.add_argument(
        "--budget-usd",
        type=float,
        default=None,
        help="stop the run once estimated spend reaches this many USD (rough estimate)",
    )
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

    summary, benign_results, attack_results = run_harness(
        run_fn,
        llm,
        args.baseline,
        tasks,
        attacks,
        cfg,
        limit=args.limit,
        budget_usd=args.budget_usd,
    )

    result_path = write_result_file(summary, benign_results, attack_results)
    print_report(summary, benign_results, attack_results)
    print(f"\nResult file: {result_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
