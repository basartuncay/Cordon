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
- IMPORTANT — list-returning tools: list_emails, search_emails, and list_events each return a \
LIST of records, not a single record. A ref path into one of them MUST start with a numeric \
index, e.g. "0.id" or "0.sender" for the first result, "1.body" for the second. A bare empty \
path ("") on a list-returning step is only valid when the *next* step also expects a list \
(e.g. a `template`/`quarantine_extract` step never accepts a whole list as "input" — index into \
one specific item first). If you don't know which index has what you need, prefer get_email/\
get_event with a literal id when you already know it, or plan to inspect index 0 for the common \
single-result case.
- Email records have EXACTLY these fields: id, thread_id, sender, sender_trust, to, subject, \
body, sensitivity, received_at. There is no "start_time"/"end_time"/"date" field on an email — \
if a meeting time, address, or any other specific value is only mentioned in an email's free \
text (subject/body), you MUST extract it with quarantine_extract, never ref a made-up field name.
- Calendar event records have EXACTLY these fields: id, title, start, end, organizer, attendees, \
description, location.
- To use an address/date/id extracted from an email or event body, first read it, then add a \
quarantine_extract step to pull out the specific value you need, then ref that step's output. \
Its "schema" arg is a LITERAL wrapping an object with fields kind (one of email/date/id/enum/\
text — NOT one of literal/ref/list), enum_values, and max_length. Full example: \
{{"step_id": "extract1", "tool": "quarantine_extract", "args": {{"input": {{"kind": "ref", \
"step_id": "s1", "path": "body"}}, "schema": {{"kind": "literal", "value": {{"kind": "email", \
"max_length": 100}}}}, "instruction": {{"kind": "literal", "value": "extract the address"}}}}}}. \
Note "schema"'s own value has a nested "kind" too (email/date/id/enum/text) — do not confuse it \
with the outer arg-value "kind" (which must still be "literal" here).
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


# ExtractionSchema's own "kind" field (email/date/id/enum/text) collides
# closely enough with ArgValue's "kind" discriminator (literal/ref/list)
# that a real model sometimes emits a quarantine_extract step's "schema"
# arg unwrapped, e.g. {"schema": {"kind": "email"}} instead of the correct
# {"schema": {"kind": "literal", "value": {"kind": "email"}}}. Tolerating
# it here is cheaper than burning a retry (or exhausting all of them) on a
# mistake the model makes for a structural reason, not a careless one.
_EXTRACTION_SCHEMA_KINDS = {"email", "date", "id", "enum", "text"}


def _normalize_unwrapped_quarantine_schemas(raw: dict[str, Any]) -> dict[str, Any]:
    steps = raw.get("steps")
    if not isinstance(steps, list):
        return raw
    for step in steps:
        if not isinstance(step, dict) or step.get("tool") != "quarantine_extract":
            continue
        args = step.get("args")
        if not isinstance(args, dict):
            continue
        schema = args.get("schema")
        if isinstance(schema, dict) and schema.get("kind") in _EXTRACTION_SCHEMA_KINDS:
            args["schema"] = {"kind": "literal", "value": schema}
    return raw


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
            raw = _normalize_unwrapped_quarantine_schemas(raw)
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
