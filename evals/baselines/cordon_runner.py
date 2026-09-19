"""B2 (Cordon without the policy engine — ablation) and B3 (Cordon full).

Both drive the same planner -> quarantine -> executor pipeline; whether
policy verdicts are actually enforced is the only difference. Same
``(env, user_request, llm) -> RunResult`` interface as B0/B1 by default,
using ONE llm client for both the planner and quarantine roles, so every
baseline plugs into the harness identically. ``_run_cordon`` additionally
accepts separate ``planner_llm``/``quarantine_llm`` for callers that want
different models per role (e.g. a stronger planner, a cheap quarantine
model) — run_b2/run_b3's public signature stays the one-client default.
"""

from __future__ import annotations

import os

from cordon.confirm import AutoApproveDecider, AutoDenyDecider, ConfirmDecider, ConfirmLog
from cordon.env import Environment
from cordon.executor import ExecutionResult, Executor
from cordon.llm import CacheStats, LLMClient, LLMUsage
from cordon.plan import QUARANTINE_TOOL, TEMPLATE_TOOL
from cordon.planner import PlannerError, make_plan
from cordon.policy import SIDE_EFFECT_TOOLS, PolicyConfig
from cordon.provenance import Tainted
from cordon.quarantine import extract as quarantine_extract
from evals.baselines.b0 import RunResult


def _status_line(exec_result: ExecutionResult) -> str:
    """A deterministic, template-built status line derived only from step
    outcomes/counts — never from anything read out of the mock env. This
    is structural, not an oversight: Cordon has no "summarize what you
    read in your own words" turn that could echo attacker-authored
    phrasing back to the user, which is exactly B0/B1's A7 (poisoned-
    summary) vulnerability.
    """
    executed = sum(1 for o in exec_result.outcomes if o.status == "executed")
    approved = sum(1 for o in exec_result.outcomes if o.status == "confirm_approved")
    rejected = sum(1 for o in exec_result.outcomes if o.status == "confirm_rejected")
    denied = sum(1 for o in exec_result.outcomes if o.status == "denied")
    errored = sum(1 for o in exec_result.outcomes if o.status == "error")
    parts = [f"Plan executed: {len(exec_result.outcomes)} step(s)."]
    allowed = executed + approved
    allowed_note = f"{allowed} allowed"
    if approved:
        allowed_note += f" ({approved} after confirmation)"
    parts.append(allowed_note)
    if rejected:
        parts.append(f"{rejected} rejected at confirmation")
    if denied:
        parts.append(f"{denied} denied by policy/budget")
    if errored:
        parts.append(f"{errored} failed to execute")
    return ", ".join(parts) + "."


def _extracted_content_lines(exec_result: ExecutionResult) -> list[str]:
    """The only path untrusted text has to the user: an explicit
    quarantine/template step's output, always labeled with its own
    provenance and never fed back into any decision — this function runs
    only after the plan has already finished executing."""
    lines = []
    for o in exec_result.outcomes:
        if o.tool not in (QUARANTINE_TOOL, TEMPLATE_TOOL) or o.status != "executed":
            continue
        tainted = exec_result.step_outputs.get(o.step_id)
        trust = tainted.provenance.trust if isinstance(tainted, Tainted) else "unknown"
        lines.append(f"[derived from untrusted content, trust={trust}] {o.result}")
    return lines


def _final_text(exec_result: ExecutionResult) -> str:
    lines = [_status_line(exec_result), *_extracted_content_lines(exec_result)]
    return "\n".join(lines)


def _default_confirm_decider() -> ConfirmDecider:
    """CORDON_CONFIRM_MODE=approve for the worst-case (blind rubber-stamp)
    eval mode; anything else (including unset) is the defense-favoring
    "deny" default — nothing risky ever gets approved. Has no observable
    effect on B2, which never reaches a CONFIRM decision in the first
    place (enforce_policy=False skips evaluate_call entirely)."""
    mode = os.environ.get("CORDON_CONFIRM_MODE", "deny").strip().lower()
    return AutoApproveDecider() if mode == "approve" else AutoDenyDecider()


def _run_cordon(
    env: Environment,
    user_request: str,
    llm: LLMClient,
    *,
    enforce_policy: bool,
    confirm: ConfirmDecider | None = None,
    planner_llm: LLMClient | None = None,
    quarantine_llm: LLMClient | None = None,
) -> RunResult:
    planner_llm = planner_llm or llm
    quarantine_llm = quarantine_llm or llm
    usage = LLMUsage()
    cache_stats = CacheStats()
    confirm = confirm or _default_confirm_decider()
    confirm_log = ConfirmLog()

    try:
        plan = make_plan(user_request, planner_llm, usage=usage, cache_stats=cache_stats)
    except PlannerError:
        return RunResult(
            turns=0,
            final_text="Planning failed; no actions were taken.",
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            errored=True,
            cache_hits=cache_stats.hits,
            cache_misses=cache_stats.misses,
        )

    def quarantine_fn(text: str, schema, instruction: str) -> str:
        return quarantine_extract(
            text, schema, instruction, quarantine_llm, usage=usage, cache_stats=cache_stats
        )

    cfg = PolicyConfig(contacts_allowlist=set(env.mailbox.contacts))
    executor = Executor(
        env,
        cfg,
        confirm=confirm,
        quarantine=quarantine_fn,
        confirm_log=confirm_log,
        enforce_policy=enforce_policy,
    )
    exec_result = executor.run(plan)

    tool_calls = [
        (o.tool, o.args)
        for o in exec_result.outcomes
        if o.status in ("executed", "confirm_approved")
        and o.tool not in (QUARANTINE_TOOL, TEMPLATE_TOOL)
    ]
    errored = any(o.status == "error" for o in exec_result.outcomes)
    policy_evaluated_count = (
        sum(1 for o in exec_result.outcomes if o.tool in SIDE_EFFECT_TOOLS)
        if enforce_policy
        else 0
    )

    return RunResult(
        turns=len(plan.steps),
        tool_calls=tool_calls,
        final_text=_final_text(exec_result),
        input_tokens=usage.input_tokens,
        output_tokens=usage.output_tokens,
        confirm_count=confirm_log.confirm_count,
        confirm_approved_count=confirm_log.approved_count,
        errored=errored,
        policy_evaluated_count=policy_evaluated_count,
        cache_hits=cache_stats.hits,
        cache_misses=cache_stats.misses,
    )


def run_b2(env: Environment, user_request: str, llm: LLMClient) -> RunResult:
    """Cordon without the policy engine (ablation)."""
    return _run_cordon(env, user_request, llm, enforce_policy=False)


def run_b3(env: Environment, user_request: str, llm: LLMClient) -> RunResult:
    """Cordon full."""
    return _run_cordon(env, user_request, llm, enforce_policy=True)
