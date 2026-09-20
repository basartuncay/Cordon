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
from evals.cache import CachingLLMClient
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
    "b1": "evals.baselines.b1:run_b1",
    "b2": "evals.baselines.cordon_runner:run_b2",
    "b3": "evals.baselines.cordon_runner:run_b3",
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
    confirm_count: int = 0
    confirm_approved_count: int = 0
    # None for benign scenarios (the read-only/write tiering is an attack-
    # only concept: it measures how much of the policy engine's job is
    # even reachable for a given attack's underlying user task).
    requires_write: bool | None = None
    # True if this scenario's run hit an executor "error" outcome or a
    # planning failure — excluded from ASR/utility ratios so a crash never
    # silently counts as either "attack blocked" or "task failed".
    errored: bool = False
    # The raw error message when errored is True — see
    # evals.report.classify_error to bucket it into a category.
    error_reason: str | None = None
    # True if this scenario's run stopped because a ref indexed into an
    # empty search/list result (nothing to act on — not a bug, so it's
    # excluded from ASR/utility ratios like errored, but counted
    # separately in the report rather than folded into the error rate).
    safe_abort_empty_result: bool = False
    # None unless the scenario defines legit_outcome (data-flow attacks,
    # category A10): whether the *correct*, untampered action happened.
    legit_outcome_success: bool | None = None
    # Every side-effecting call the policy engine actually evaluated,
    # regardless of the verdict — distinct from confirm_count, which only
    # counts calls that specifically landed on CONFIRM.
    policy_evaluated_count: int = 0
    # Disk-cache hits/misses for this scenario's LLM calls. A hit never
    # counts toward input_tokens/output_tokens/cost.
    cache_hits: int = 0
    cache_misses: int = 0


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
    total_confirm_count: int = 0
    total_confirm_approved_count: int = 0
    total_errored_count: int = 0
    total_safe_abort_count: int = 0
    total_policy_evaluated_count: int = 0
    # What the config specified for each role, regardless of whether this
    # baseline actually has separate roles (B0/B1 only ever use `model`;
    # B2/B3 currently default to a single shared client too — see
    # cordon_runner's planner_llm/quarantine_llm params for the plumbing
    # that would let them differ).
    planner_model: str = ""
    quarantine_model: str = ""
    total_cache_hits: int = 0
    total_cache_misses: int = 0
    # "main" for the default 80-scenario corpus; the --corpus-dir
    # directory's own name otherwise (e.g. "holdout"). Recorded here, and
    # used by main() to route a non-main corpus's result file into its
    # own results_dir subdirectory, so it can never land in the same
    # place as — or be glob-matched together with — a main-corpus run.
    corpus_name: str = "main"


def _resolve_baseline(name: str):
    if name not in BASELINES:
        raise SystemExit(f"unknown baseline {name!r}; choices: {sorted(BASELINES)}")
    module_name, func_name = BASELINES[name].split(":")
    module = importlib.import_module(module_name)
    return getattr(module, func_name)


def _corpus_name(corpus_dir: Path) -> str:
    """Returns "main" for the default corpus dir, the directory's own
    name otherwise. Never inspects contents — a purely path-based label."""
    return "main" if corpus_dir.resolve() == CORPUS_DIR.resolve() else corpus_dir.name


def _effective_baseline_name(baseline: str, no_policy: bool) -> str:
    """--no-policy only ever affects b3 (it becomes the b2 ablation);
    every other baseline is unaffected since only b2/b3 have a policy
    engine to switch off in the first place."""
    return "b2" if (no_policy and baseline == "b3") else baseline


def run_scenario(
    run_fn, llm: LLMClient, scenario: AttackScenario | BenignScenario
) -> ScenarioResult:
    env = build_environment(scenario.seed)
    result = run_fn(env, scenario.user_request, llm)

    legit_outcome_success = None
    if isinstance(scenario, AttackScenario):
        category = scenario.category
        requires_write = scenario.requires_write
        success = evaluate(
            scenario.attacker_goal.predicate, scenario.attacker_goal.args, env, result.final_text
        )
        if scenario.legit_outcome:
            legit_outcome_success = all(
                evaluate(p.predicate, p.args, env, result.final_text)
                for p in scenario.legit_outcome
            )
    else:
        category = "benign"
        requires_write = None
        success = all(
            evaluate(p.predicate, p.args, env, result.final_text) for p in scenario.success
        )

    return ScenarioResult(
        id=scenario.id,
        category=category,
        success=success,
        tool_calls=result.tool_calls,
        input_tokens=result.input_tokens,
        output_tokens=result.output_tokens,
        confirm_count=result.confirm_count,
        confirm_approved_count=result.confirm_approved_count,
        requires_write=requires_write,
        errored=result.errored,
        error_reason=result.error_reason,
        safe_abort_empty_result=result.safe_abort_empty_result,
        legit_outcome_success=legit_outcome_success,
        policy_evaluated_count=result.policy_evaluated_count,
        cache_hits=result.cache_hits,
        cache_misses=result.cache_misses,
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
    corpus_name: str = "main",
) -> tuple[RunSummary, list[ScenarioResult], list[ScenarioResult]]:
    started_at = datetime.now(UTC).isoformat()

    ordered: list[tuple[str, AttackScenario | BenignScenario]] = [("benign", t) for t in tasks] + [
        ("attack", a) for a in attacks
    ]
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
        total_input_tokens=sum(r.input_tokens for r in benign_results + attack_results),
        total_output_tokens=sum(r.output_tokens for r in benign_results + attack_results),
        estimated_cost_usd=cost_so_far,
        pricing_verified=cfg.pricing_verified,
        total_confirm_count=sum(r.confirm_count for r in benign_results + attack_results),
        total_confirm_approved_count=sum(
            r.confirm_approved_count for r in benign_results + attack_results
        ),
        total_errored_count=sum(1 for r in benign_results + attack_results if r.errored),
        total_safe_abort_count=sum(
            1 for r in benign_results + attack_results if r.safe_abort_empty_result
        ),
        total_policy_evaluated_count=sum(
            r.policy_evaluated_count for r in benign_results + attack_results
        ),
        planner_model=cfg.planner_model,
        quarantine_model=cfg.quarantine_model,
        total_cache_hits=sum(r.cache_hits for r in benign_results + attack_results),
        total_cache_misses=sum(r.cache_misses for r in benign_results + attack_results),
        corpus_name=corpus_name,
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
    parser.add_argument(
        "--no-policy",
        action="store_true",
        help="for --baseline b3, run without policy enforcement (equivalent to b2)",
    )
    args = parser.parse_args(argv)

    effective_baseline = _effective_baseline_name(args.baseline, args.no_policy)
    run_fn = _resolve_baseline(effective_baseline)
    cfg = default_model_config()

    try:
        llm: LLMClient = CachingLLMClient(AnthropicClient(model=cfg.baseline_model))
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    corpus_dir = Path(args.corpus_dir)
    corpus_name = _corpus_name(corpus_dir)
    tasks = load_benign_tasks(corpus_dir / "tasks")
    attacks = load_attacks(corpus_dir / "attacks")

    summary, benign_results, attack_results = run_harness(
        run_fn,
        llm,
        effective_baseline,
        tasks,
        attacks,
        cfg,
        limit=args.limit,
        budget_usd=args.budget_usd,
        corpus_name=corpus_name,
    )

    # A non-main corpus (e.g. holdout) writes into its own results_dir
    # subdirectory, never evals/results/ directly — so its result files
    # can never land alongside, or be glob-matched together with, a
    # main-corpus run's.
    results_dir = RESULTS_DIR if corpus_name == "main" else RESULTS_DIR / corpus_name
    result_path = write_result_file(
        summary, benign_results, attack_results, results_dir=results_dir
    )
    print_report(summary, benign_results, attack_results)
    print(f"\nResult file: {result_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
