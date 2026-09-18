"""Confirmation interface.

A CONFIRM verdict from the policy engine produces a ``ConfirmRequest``
describing exactly what's being asked and why (which P-rules fired, why,
and a human-readable summary of the flagged arguments' provenance). A
``ConfirmDecider`` turns that into a yes/no. ``ConfirmLog`` records every
decision made during a run so the eval harness can report a
confirmation-prompt rate — CLAUDE.md's "friction" metric.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class ConfirmRequest:
    tool: str
    step_id: str
    rules: list[str]
    reasons: list[str]
    argument_summary: dict[str, str] = field(default_factory=dict)


@dataclass
class ConfirmRecord:
    request: ConfirmRequest
    approved: bool


class ConfirmDecider(Protocol):
    def decide(self, request: ConfirmRequest) -> bool: ...


class ConfirmLog:
    """Records every confirmation decision made during one run."""

    def __init__(self) -> None:
        self.records: list[ConfirmRecord] = []

    def record(self, request: ConfirmRequest, approved: bool) -> None:
        self.records.append(ConfirmRecord(request=request, approved=approved))

    @property
    def confirm_count(self) -> int:
        return len(self.records)

    @property
    def approved_count(self) -> int:
        return sum(1 for r in self.records if r.approved)

    @property
    def rejected_count(self) -> int:
        return self.confirm_count - self.approved_count


class AutoDenyDecider:
    """Eval mode: never approve a flagged call — measures worst-case ASR
    under Cordon (the attacker never gets a human to bless anything)."""

    def decide(self, request: ConfirmRequest) -> bool:
        return False


class AutoApproveDecider:
    """Eval mode: always approve a flagged call — the ceiling on utility
    (and on ASR) if a human rubber-stamps every prompt without reading it;
    shows the policy engine alone isn't a silver bullet without an
    attentive human on the other end of the confirmation."""

    def decide(self, request: ConfirmRequest) -> bool:
        return True


class CLIConfirmDecider:
    """Interactive confirmation via stdin/stdout — the real confirmation
    path outside of evals."""

    def decide(self, request: ConfirmRequest) -> bool:
        print(f"\n--- Confirmation required: {request.tool} (step {request.step_id}) ---")
        for rule, reason in zip(request.rules, request.reasons, strict=False):
            print(f"  [{rule}] {reason}")
        for name, summary in request.argument_summary.items():
            print(f"  {name}: {summary}")
        answer = input("Approve this action? [y/N] ").strip().lower()
        return answer in ("y", "yes")
