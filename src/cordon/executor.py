"""Executes a validated Plan against a mock Environment, enforcing the
policy engine on every side-effecting call.

Every read-tool result is wrapped as ``Tainted`` using the sender-trust /
sensitivity ground truth already present on the mock env's Email/
CalendarEvent records (see ``cordon.tools.base``). A quarantine callback may
be supplied to transform untrusted extracted text (e.g. "pull the sender's
requested address out of this email body") — its output is re-wrapped with
the *same* provenance as its input, so quarantine can narrow a value's
shape but never launder its trust.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from cordon.confirm import AutoDenyDecider, ConfirmDecider, ConfirmLog, ConfirmRequest
from cordon.env import Environment
from cordon.plan import QUARANTINE_TOOL, TEMPLATE_TOOL, ListArg, LiteralArg, Plan, PlanStep, RefArg
from cordon.policy import (
    CALENDAR_CLASS_TOOLS,
    DESTRUCTIVE_TOOLS,
    EMAIL_TOOLS,
    Decision,
    PolicyConfig,
    PolicyState,
    evaluate_call,
)
from cordon.provenance import LITERAL_PROVENANCE, Provenance, Sensitivity, Tainted, TrustLevel
from cordon.quarantine import ExtractionSchema
from cordon.tools.dispatch import call_tool

READ_TOOLS = {"list_emails", "get_email", "search_emails", "list_events", "get_event"}

RECIPIENT_ARG_NAMES: dict[str, str] = {"send_email": "to", "forward_email": "to"}
# Every text-bearing arg P2 (exfiltration) must inspect, per tool. forward_email
# additionally carries the *original* email's subject/body — see
# _extract_contents, since that's what actually gets forwarded, not just `note`.
CONTENT_ARG_NAMES: dict[str, list[str]] = {
    "send_email": ["subject", "body"],
    "forward_email": ["note"],
    "reply_email": ["body"],
    "create_event": ["title", "description", "location"],
    "update_event": ["title", "description", "location"],
}
CALENDAR_FIELD_ARG_NAMES: dict[str, list[str]] = {
    "create_event": ["attendees", "location", "description"],
    "update_event": ["attendees", "location", "description"],
    "add_attendee": ["attendee"],
}
# Attendees double as P2's "recipients" for calendar tools — anyone invited
# can read the title/description/location, which is the calendar analog of
# an email recipient for exfiltration purposes (but NOT for P1: P1 is
# email-specific per CLAUDE.md, calendar attendee provenance is P4's job).
CALENDAR_ATTENDEE_ARG_NAMES: dict[str, str] = {
    "create_event": "attendees",
    "update_event": "attendees",
    "add_attendee": "attendee",
}

QuarantineFn = Callable[[str, ExtractionSchema, str], str]  # (text, schema, instruction) -> value


def _summarize_value(value: Any) -> str:
    if isinstance(value, Tainted):
        prov = value.provenance
        return f"{value.value!r} (trust={prov.trust}, sensitivity={prov.sensitivity})"
    if isinstance(value, list):
        return "[" + ", ".join(_summarize_value(v) for v in value) + "]"
    return repr(value)


@dataclass
class StepOutcome:
    step_id: str
    tool: str
    status: str  # "executed" | "confirm_approved" | "confirm_rejected" | "denied"
    rules: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    result: Any = None


@dataclass
class ExecutionResult:
    outcomes: list[StepOutcome] = field(default_factory=list)
    step_outputs: dict[str, Any] = field(default_factory=dict)


def _tainted_email(raw: dict[str, Any]) -> Tainted[dict[str, Any]]:
    return Tainted(
        raw,
        Provenance(
            source_id=f"email:{raw['id']}",
            trust=TrustLevel(raw["sender_trust"]),
            sensitivity=Sensitivity(raw["sensitivity"]),
        ),
    )


def _tainted_event(raw: dict[str, Any]) -> Tainted[dict[str, Any]]:
    # Calendar events in the mock env carry no per-record trust field the
    # way emails do (they're the user's own calendar, not attacker mail).
    # P4 governs writes derived from untrusted *email* data; reads here are
    # CONTACT-trust/PRIVATE by default and aren't the interesting attack
    # surface.
    prov = Provenance(
        source_id=f"event:{raw['id']}", trust=TrustLevel.CONTACT, sensitivity=Sensitivity.PRIVATE
    )
    return Tainted(raw, prov)


def _wrap_read_result(tool: str, raw: Any) -> Any:
    if tool == "get_email":
        return _tainted_email(raw)
    if tool == "get_event":
        return _tainted_event(raw)
    if tool in ("list_emails", "search_emails"):
        return [_tainted_email(item) for item in raw]
    if tool == "list_events":
        return [_tainted_event(item) for item in raw]
    raise ValueError(f"unsupported read tool: {tool}")


def _resolve_ref(step_outputs: dict[str, Any], step_id: str, path: str) -> Tainted[Any]:
    if step_id not in step_outputs:
        raise KeyError(f"ref to unknown/not-yet-run step: {step_id!r}")
    current: Any = step_outputs[step_id]
    parts = path.split(".") if path else []
    for part in parts:
        if isinstance(current, list):
            current = current[int(part)]
        elif isinstance(current, Tainted):
            base = current.value
            field_value = base[part] if isinstance(base, dict) else getattr(base, part)
            current = Tainted(field_value, current.provenance)
        else:
            raise TypeError(f"cannot resolve path segment {part!r} on {current!r}")
    if isinstance(current, list):
        raise TypeError(f"ref {step_id}.{path} resolved to a list; index into it first")
    return current


def _resolve_value(step_outputs: dict[str, Any], arg: LiteralArg | RefArg | ListArg) -> Any:
    if isinstance(arg, LiteralArg):
        if isinstance(arg.value, list):
            return [Tainted(v, LITERAL_PROVENANCE) for v in arg.value]
        return Tainted(arg.value, LITERAL_PROVENANCE)
    if isinstance(arg, RefArg):
        return _resolve_ref(step_outputs, arg.step_id, arg.path)
    if isinstance(arg, ListArg):
        return [_resolve_value(step_outputs, item) for item in arg.items]
    raise TypeError(f"unsupported arg type: {arg!r}")


def _unwrap(value: Any) -> Any:
    if isinstance(value, Tainted):
        return value.value
    if isinstance(value, list):
        return [_unwrap(v) for v in value]
    return value


class Executor:
    def __init__(
        self,
        env: Environment,
        policy_cfg: PolicyConfig,
        confirm: ConfirmDecider | None = None,
        quarantine: QuarantineFn | None = None,
        confirm_log: ConfirmLog | None = None,
    ) -> None:
        self.env = env
        self.policy_cfg = policy_cfg
        self._confirm = confirm or AutoDenyDecider()
        self._quarantine = quarantine
        self._confirm_log = confirm_log
        self._policy_state = PolicyState()

    def run(self, plan: Plan) -> ExecutionResult:
        result = ExecutionResult()
        for step in plan.steps:
            result.outcomes.append(self._run_step(step, result))
        return result

    def _run_step(self, step: PlanStep, exec_result: ExecutionResult) -> StepOutcome:
        if step.tool == QUARANTINE_TOOL:
            return self._run_quarantine_step(step, exec_result)
        if step.tool == TEMPLATE_TOOL:
            return self._run_template_step(step, exec_result)

        tainted_args: dict[str, Any] = {
            name: _resolve_value(exec_result.step_outputs, arg) for name, arg in step.args.items()
        }
        plain_args = {name: _unwrap(v) for name, v in tainted_args.items()}

        if step.tool in READ_TOOLS:
            raw = call_tool(self.env, step.tool, plain_args)
            exec_result.step_outputs[step.step_id] = _wrap_read_result(step.tool, raw)
            return StepOutcome(step_id=step.step_id, tool=step.tool, status="executed", result=raw)

        recipients = self._extract_recipients(step.tool, plain_args, tainted_args)
        contents = self._extract_contents(step.tool, plain_args, tainted_args)
        calendar_fields = self._extract_calendar_fields(step.tool, tainted_args)
        calendar_recipients = self._extract_calendar_recipients(step.tool, tainted_args)

        verdict = evaluate_call(
            step.tool,
            recipients=recipients,
            contents=contents,
            calendar_recipients=calendar_recipients,
            calendar_fields=calendar_fields,
            cfg=self.policy_cfg,
            state=self._policy_state,
        )

        if verdict.decision == Decision.DENY:
            return StepOutcome(step.step_id, step.tool, "denied", verdict.rules, verdict.reasons)

        if verdict.decision == Decision.CONFIRM:
            request = ConfirmRequest(
                tool=step.tool,
                step_id=step.step_id,
                rules=verdict.rules,
                reasons=verdict.reasons,
                argument_summary={name: _summarize_value(v) for name, v in tainted_args.items()},
            )
            approved = self._confirm.decide(request)
            if self._confirm_log is not None:
                self._confirm_log.record(request, approved)
            if not approved:
                return StepOutcome(
                    step.step_id, step.tool, "confirm_rejected", verdict.rules, verdict.reasons
                )

        raw = call_tool(self.env, step.tool, plain_args)
        self._policy_state.side_effect_count += 1
        if step.tool in EMAIL_TOOLS:
            self._policy_state.email_count += 1
        if step.tool in CALENDAR_CLASS_TOOLS:
            self._policy_state.calendar_count += 1
        if step.tool in DESTRUCTIVE_TOOLS:
            self._policy_state.destructive_count += 1
        exec_result.step_outputs[step.step_id] = Tainted(raw, LITERAL_PROVENANCE)
        status = "confirm_approved" if verdict.decision == Decision.CONFIRM else "executed"
        return StepOutcome(
            step.step_id, step.tool, status, verdict.rules, verdict.reasons, result=raw
        )

    def _run_quarantine_step(self, step: PlanStep, exec_result: ExecutionResult) -> StepOutcome:
        if self._quarantine is None:
            raise RuntimeError("no quarantine function configured for this executor")
        tainted_input = _resolve_value(exec_result.step_outputs, step.args["input"])
        if not isinstance(tainted_input, Tainted):
            raise TypeError("quarantine_extract requires its 'input' arg to resolve to a scalar")

        schema_dict = self._resolve_plain(exec_result, step.args.get("schema")) or {"kind": "text"}
        schema = ExtractionSchema.model_validate(schema_dict)
        instruction = self._resolve_plain(
            exec_result, step.args.get("instruction")
        ) or "Extract the relevant value."

        extracted = self._quarantine(str(tainted_input.value), schema, instruction)
        # Same provenance as the input: quarantine can reshape/validate a
        # value but must never elevate its trust or clear its sensitivity.
        tainted_output = Tainted(extracted, tainted_input.provenance)
        exec_result.step_outputs[step.step_id] = tainted_output
        return StepOutcome(step.step_id, step.tool, "executed", result=extracted)

    def _resolve_plain(self, exec_result: ExecutionResult, arg: Any) -> Any:
        if arg is None:
            return None
        resolved = _resolve_value(exec_result.step_outputs, arg)
        return _unwrap(resolved)

    def _run_template_step(self, step: PlanStep, exec_result: ExecutionResult) -> StepOutcome:
        parts_arg = step.args.get("parts")
        if not isinstance(parts_arg, ListArg):
            raise TypeError("template requires a 'parts' ListArg")
        resolved = [_resolve_value(exec_result.step_outputs, item) for item in parts_arg.items]
        for r in resolved:
            if not isinstance(r, Tainted):
                raise TypeError("template 'parts' items must each resolve to a scalar")
        text = "".join(str(r.value) for r in resolved)
        provenance = Tainted.combine(*resolved) if resolved else LITERAL_PROVENANCE
        tainted_output = Tainted(text, provenance)
        exec_result.step_outputs[step.step_id] = tainted_output
        return StepOutcome(step.step_id, step.tool, "executed", result=text)

    def _extract_recipients(
        self, tool: str, plain_args: dict[str, Any], tainted_args: dict[str, Any]
    ) -> list[Tainted[str]]:
        arg_name = RECIPIENT_ARG_NAMES.get(tool)
        if arg_name is not None:
            value = tainted_args.get(arg_name, [])
            return value if isinstance(value, list) else [value]
        if tool == "reply_email":
            original = self.env.mailbox.get_email(plain_args["email_id"])
            prov = Provenance(
                source_id=f"email:{original.id}",
                trust=original.sender_trust,
                sensitivity=original.sensitivity,
            )
            return [Tainted(original.sender, prov)]
        return []

    def _extract_contents(
        self, tool: str, plain_args: dict[str, Any], tainted_args: dict[str, Any]
    ) -> list[Tainted[Any]]:
        contents: list[Tainted[Any]] = []
        for name in CONTENT_ARG_NAMES.get(tool, []):
            value = tainted_args.get(name)
            if isinstance(value, Tainted):
                contents.append(value)
        if tool == "forward_email":
            # The actual outgoing message is the original subject/body plus
            # the note, not just the note — P2 must see all of it.
            original = self.env.mailbox.get_email(plain_args["email_id"])
            prov = Provenance(
                source_id=f"email:{original.id}",
                trust=original.sender_trust,
                sensitivity=original.sensitivity,
            )
            contents.append(Tainted(original.subject, prov))
            contents.append(Tainted(original.body, prov))
        return contents

    def _extract_calendar_fields(
        self, tool: str, tainted_args: dict[str, Any]
    ) -> list[Tainted[Any]]:
        fields: list[Tainted[Any]] = []
        for name in CALENDAR_FIELD_ARG_NAMES.get(tool, []):
            value = tainted_args.get(name)
            if value is None:
                continue
            if isinstance(value, list):
                fields.extend(value)
            else:
                fields.append(value)
        return fields

    def _extract_calendar_recipients(
        self, tool: str, tainted_args: dict[str, Any]
    ) -> list[Tainted[str]]:
        arg_name = CALENDAR_ATTENDEE_ARG_NAMES.get(tool)
        if arg_name is None:
            return []
        value = tainted_args.get(arg_name)
        if value is None:
            return []
        return value if isinstance(value, list) else [value]
