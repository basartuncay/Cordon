"""A scenario's mock environment: one mailbox + one calendar."""

from __future__ import annotations

from dataclasses import dataclass

from cordon.tools.mock_calendar import MockCalendar
from cordon.tools.mock_mail import MockMailbox


@dataclass
class Environment:
    mailbox: MockMailbox
    calendar: MockCalendar
