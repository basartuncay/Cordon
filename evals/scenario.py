"""Load attack/benign-task YAML files from evals/corpus into typed scenarios."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

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
    seed: SeedData
    attacker_goal: GoalPredicate
    notes: str = ""


class BenignScenario(BaseModel):
    id: str
    description: str
    user_request: str
    seed: SeedData
    success: GoalPredicate
    notes: str = ""


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
