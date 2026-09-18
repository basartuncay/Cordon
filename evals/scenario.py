"""Load attack/benign-task YAML files from evals/corpus into typed scenarios."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator

from cordon.env import Environment
from cordon.tools.base import CalendarEvent, Email
from cordon.tools.mock_calendar import MockCalendar
from cordon.tools.mock_mail import MockMailbox


class SeedData(BaseModel):
    contacts: list[str] = Field(default_factory=list)
    emails: list[Email] = Field(default_factory=list)
    events: list[CalendarEvent] = Field(default_factory=list)


class GoalPredicate(BaseModel):
    predicate: str
    args: dict[str, Any] = Field(default_factory=dict)


class AttackScenario(BaseModel):
    id: str
    category: str
    description: str
    user_request: str
    # Does the user's OWN (legitimate) task require a write-type action
    # (reply/forward/create/delete/add_attendee) or a determinate answer
    # hinging on a specific value, as opposed to an open-ended read/
    # summary/"anything urgent?" ask? Required (no default) so every
    # scenario is explicitly classified — this is what lets the report
    # split ASR into a "read-only" tier (measures planner isolation alone)
    # vs a "write" tier (measures the policy engine's actual contribution).
    requires_write: bool
    seed: SeedData
    attacker_goal: GoalPredicate
    # For data-flow attacks only (category A10): the correct outcome using
    # the *untampered* value, checked separately from attacker_goal so
    # "utility under attack" can be measured without conflating it with
    # attack success. Empty (the default) means this scenario doesn't
    # measure utility-under-attack.
    legit_outcome: list[GoalPredicate] = Field(default_factory=list)
    notes: str = ""


class BenignScenario(BaseModel):
    id: str
    description: str
    user_request: str
    seed: SeedData
    success: list[GoalPredicate]
    notes: str = ""

    @field_validator("success", mode="before")
    @classmethod
    def _normalize_success(cls, v: Any) -> Any:
        if isinstance(v, dict):
            return [v]
        return v


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open() as f:
        return yaml.safe_load(f)


def load_attacks(directory: Path) -> list[AttackScenario]:
    return [AttackScenario.model_validate(_load_yaml(p)) for p in sorted(directory.glob("*.yaml"))]


def load_benign_tasks(directory: Path) -> list[BenignScenario]:
    return [BenignScenario.model_validate(_load_yaml(p)) for p in sorted(directory.glob("*.yaml"))]


def build_environment(seed: SeedData) -> Environment:
    return Environment(
        mailbox=MockMailbox(inbox=list(seed.emails), contacts=list(seed.contacts)),
        calendar=MockCalendar(events=list(seed.events)),
    )
