"""Typed records for the mock mailbox/calendar environment.

``sender_trust``/``sensitivity`` are ground truth the mock env assigns at
seed time; the executor (M2) reads them to build each value's real
``Provenance`` when it wraps a read-tool result as ``Tainted``. The enums
themselves live in ``cordon.provenance`` and are re-exported here so
existing imports keep working.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from cordon.provenance import Sensitivity, TrustLevel

__all__ = ["CalendarEvent", "Email", "Sensitivity", "TrustLevel"]


class Email(BaseModel):
    id: str
    thread_id: str
    sender: str
    sender_trust: TrustLevel = TrustLevel.UNKNOWN
    to: list[str]
    subject: str
    body: str
    sensitivity: Sensitivity = Sensitivity.PRIVATE
    received_at: datetime


class CalendarEvent(BaseModel):
    id: str
    title: str
    start: datetime
    end: datetime
    organizer: str = "me@user.example"
    attendees: list[str] = Field(default_factory=list)
    description: str = ""
    location: str = ""
