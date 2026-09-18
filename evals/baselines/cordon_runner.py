"""B2 (Cordon without the policy engine — ablation) and B3 (Cordon full).

Both drive the same planner -> quarantine -> executor pipeline; whether
policy verdicts are actually enforced is the only difference. Same
``(env, user_request, llm) -> RunResult`` interface as B0/B1, using ONE llm
client for both the planner and quarantine roles, so every baseline plugs
into the harness identically. (A real deployment could use different
models for each via ``ModelConfig.planner_model`` / ``.quarantine_model`` —
that's a config knob for later, not something the eval harness's
one-model-per-baseline interface exercises here.)
"""

from __future__ import annotations

from cordon.confirm import AutoDenyDecider, ConfirmDecider, ConfirmLog
from cordon.env import Environment
from cordon.executor import ExecutionResult, Executor
from cordon.llm import LLMClient, LLMUsage
from cordon.plan import QUARANTINE_TOOL, TEMPLATE_TOOL
from cordon.planner import PlannerError, make_plan
from cordon.policy import PolicyConfig
from cordon.quarantine import extract as quarantine_extract
from evals.baselines.b0 import RunResult


def _final_text(exec_result: ExecutionResult) -> str:
    """A deterministic, template-built status line derived only from step
    outcomes/counts — never from anything read out of the mock env. This
    is structural, not an oversight: Cordon has no "summarize what you
    read in your own words" turn that could echo attacker-authored
    phrasing back to the user, which is exactly B0/B1's A7 (poisoned-
    summary) vulnerability. The only path untrusted text has to the user
    here is through an explicit quarantine/template step, and that value
    stays tainted the whole way — it never becomes free-form narration.
    """
    executed = sum(1 for o in exec_result.outcomes if o.status == "executed")
    approved = sum(1 for o in exec_result.outcomes if o.status == "confirm_approved")
    rejected = sum(1 for o in exec_result.outcomes if o.status == "confirm_rejected")
    denied = sum(1 for o in exec_result.outcomes if o.status == "denied")
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
    return ", ".join(parts) + "."


def _run_cordon(
    env: Environment,
    user_request: str,
    llm: LLMClient,
    *,
    enforce_policy: bool,
    confirm: ConfirmDecider | None = None,
) -> RunResult:
    usage = LLMUsage()
    confirm = confirm or AutoDenyDecider()
    confirm_log = ConfirmLog()

    try:
        plan = make_plan(user_request, llm, usage=usage)
    except PlannerError:
        return RunResult(
            turns=0,
            final_text="Planning failed; no actions were taken.",
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
        )

    def quarantine_fn(text: str, schema, instruction: str) -> str:
        return quarantine_extract(text, schema, instruction, llm, usage=usage)

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

    return RunResult(
        turns=len(plan.steps),
        tool_calls=tool_calls,
        final_text=_final_text(exec_result),
        input_tokens=usage.input_tokens,
        output_tokens=usage.output_tokens,
        confirm_count=confirm_log.confirm_count,
        confirm_approved_count=confirm_log.approved_count,
    )


def run_b2(env: Environment, user_request: str, llm: LLMClient) -> RunResult:
    """Cordon without the policy engine (ablation)."""
    return _run_cordon(env, user_request, llm, enforce_policy=False)


def run_b3(env: Environment, user_request: str, llm: LLMClient) -> RunResult:
    """Cordon full."""
    return _run_cordon(env, user_request, llm, enforce_policy=True)
