"""Typed records for the mock mailbox/calendar environment.

Provenance fields here (``sender_trust``, ``sensitivity``) are placeholders
for the real taint-tracking that lands in M2 (``provenance.py``). For M1
they exist so the attack corpus can express "this content came from an
untrusted sender" without the policy engine yet acting on it.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class TrustLevel(StrEnum):
    USER = "user"
    CONTACT = "contact"
    UNKNOWN = "unknown"


class Sensitivity(StrEnum):
    PUBLIC = "public"
    PRIVATE = "private"


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
