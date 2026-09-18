"""Typed plan DSL.

The planner emits one of these before any untrusted data is read; the
executor then runs it step by step and never calls back into the planner.
An argument is either a literal (trusted — authored by the planner from the
user's own request) or a ref to an earlier step's output, which, for a read
tool, will be tainted at execution time. Refs may only point to steps that
already ran, which is what makes "the plan can't be altered after untrusted
data is read" (P5) a structural property of this DSL rather than something
checked at runtime.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from cordon.tools.dispatch import TOOL_SCHEMAS

KNOWN_TOOLS = {schema["name"] for schema in TOOL_SCHEMAS}

# Pseudo-tool: routed to the quarantine extraction function instead of
# call_tool. Its one arg ("input") must resolve to a single Tainted value;
# the executor re-wraps the extracted output with that same provenance —
# quarantine can narrow a value's shape but never launder its trust.
QUARANTINE_TOOL = "quarantine_extract"

# Pseudo-tool: string-joins a "parts" ListArg of literals/refs. Lets the
# planner build message text out of pieces it will only see the shape of
# (never the untrusted content) — the executor concatenates the resolved
# values and tags the result with Tainted.combine() of every part, so the
# result is exactly as trusted/sensitive as its least-trusted, most-
# sensitive ingredient.
TEMPLATE_TOOL = "template"


class LiteralArg(BaseModel):
    kind: Literal["literal"] = "literal"
    value: Any


class RefArg(BaseModel):
    kind: Literal["ref"] = "ref"
    step_id: str
    path: str = ""


class ListArg(BaseModel):
    kind: Literal["list"] = "list"
    items: list[ArgValue]


ArgValue = Annotated[LiteralArg | RefArg | ListArg, Field(discriminator="kind")]
ListArg.model_rebuild()


class PlanStep(BaseModel):
    step_id: str
    tool: str
    args: dict[str, ArgValue] = Field(default_factory=dict)

    @field_validator("tool")
    @classmethod
    def _tool_must_be_known(cls, v: str) -> str:
        if v not in KNOWN_TOOLS and v not in (QUARANTINE_TOOL, TEMPLATE_TOOL):
            raise ValueError(f"unknown tool: {v!r}")
        return v


class Plan(BaseModel):
    steps: list[PlanStep]

    @model_validator(mode="after")
    def _validate_refs(self) -> Plan:
        seen: set[str] = set()
        for step in self.steps:
            if step.step_id in seen:
                raise ValueError(f"duplicate step_id: {step.step_id!r}")
            for arg in step.args.values():
                _check_arg_refs(arg, seen, step.step_id)
            seen.add(step.step_id)
        return self


def _check_arg_refs(
    arg: LiteralArg | RefArg | ListArg, seen: set[str], current_step_id: str
) -> None:
    if isinstance(arg, RefArg):
        if arg.step_id == current_step_id:
            raise ValueError(f"step {current_step_id!r} cannot reference itself")
        if arg.step_id not in seen:
            raise ValueError(
                f"step {current_step_id!r} references {arg.step_id!r}, which has not run "
                "yet (refs may only point to earlier steps)"
            )
    elif isinstance(arg, ListArg):
        for item in arg.items:
            _check_arg_refs(item, seen, current_step_id)
