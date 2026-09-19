"""Privileged planner.

Sees only the trusted user request and the tool schemas — never a tool's
output. It emits a single JSON plan up front, which is what keeps control
flow fixed before any untrusted data is read. Retries (at most
``MAX_RETRIES`` of them) happen *only* in response to the emitted plan
failing to parse/validate — never for any other reason, since the planner
never reads anything untrusted in the first place.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import ValidationError

from cordon.llm import CacheStats, LLMClient, LLMUsage
from cordon.plan import Plan
from cordon.tools.dispatch import TOOL_SCHEMAS

MAX_RETRIES = 2

SYSTEM_PROMPT_TEMPLATE = """You are the planner for an email/calendar assistant. You are given \
the user's request and a list of available tools. Emit a single JSON object describing a Plan:

{{"steps": [{{"step_id": "...", "tool": "...", "args": {{...}}}}, ...]}}

Rules:
- You will NEVER see the output of any tool. Plan every step you need up front.
- Each arg value must be one of:
  - {{"kind": "literal", "value": <any JSON value>}} for values that come directly \
from the user's request
  - {{"kind": "ref", "step_id": "<id>", "path": "<dotted path, or empty for the whole value>"}} \
to reference an earlier step's output
  - {{"kind": "list", "items": [<arg value>, ...]}} for a list built from a mix of literals/refs
- step_id values must be unique. A ref may only point to a step_id that appears earlier \
in the plan.
- To use an address/date/id extracted from an email or event body, first read it, then add a \
{{"tool": "quarantine_extract", "args": {{"input": {{"kind": "ref", ...}}, \
"schema": {{"kind": "email|date|id|enum|text", ...}}, "instruction": "..."}}}} step to pull out \
the specific value you need, then ref that step's output.
- To build message text from a mix of your own words and extracted values, use a \
{{"tool": "template", "args": {{"parts": {{"kind": "list", "items": [...]}}}}}} step.
- Output ONLY the JSON object, no other text, no markdown fences.

Available tools:
{tool_schemas}
"""


class PlannerError(RuntimeError):
    pass


def _build_system_prompt() -> str:
    return SYSTEM_PROMPT_TEMPLATE.format(tool_schemas=json.dumps(TOOL_SCHEMAS, indent=2))


def _extract_json(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[len("json") :]
        text = text.strip()
    return json.loads(text)


def make_plan(
    user_request: str,
    llm: LLMClient,
    usage: LLMUsage | None = None,
    cache_stats: CacheStats | None = None,
) -> Plan:
    """Runs the planner LLM and returns a validated Plan, retrying up to
    MAX_RETRIES times but only in response to a parse/validation failure.

    If ``usage`` is given, token counts across every attempt are added to
    it in place — except for a cache hit's tokens, which are never billed
    (a caller that needs cost accounting passes its own accumulator;
    callers that don't care can ignore the parameter). If ``cache_stats``
    is given, every attempt increments its hits or misses.
    """
    system = _build_system_prompt()
    messages: list[dict[str, Any]] = [{"role": "user", "content": user_request}]
    if usage is None:
        usage = LLMUsage()

    last_error: Exception = PlannerError("planner produced no output")
    for _attempt in range(MAX_RETRIES + 1):
        response = llm.run(system=system, messages=messages, tools=None)
        if cache_stats is not None:
            if response.from_cache:
                cache_stats.hits += 1
            else:
                cache_stats.misses += 1
        if not response.from_cache:
            usage.input_tokens += response.usage.input_tokens
            usage.output_tokens += response.usage.output_tokens

        if not response.text:
            last_error = PlannerError("planner returned no text")
            messages.append({"role": "assistant", "content": "(no text)"})
            messages.append(
                {"role": "user", "content": "Your response had no text. Output the JSON plan."}
            )
            continue

        try:
            raw = _extract_json(response.text)
            return Plan.model_validate(raw)
        except (json.JSONDecodeError, ValidationError) as exc:
            last_error = exc
            messages.append({"role": "assistant", "content": response.text})
            messages.append(
                {
                    "role": "user",
                    "content": (
                        f"That plan failed validation: {exc}\n"
                        "Fix it and output ONLY the corrected JSON plan."
                    ),
                }
            )
            continue

    raise PlannerError(
        f"planner failed to produce a valid plan after {MAX_RETRIES + 1} attempts: {last_error}"
    ) from last_error
