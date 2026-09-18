"""In-memory mock calendar. No real Google Calendar access."""

from __future__ import annotations

import itertools
from typing import Any

from cordon.tools.base import CalendarEvent


class MockCalendar:
    def __init__(self, events: list[CalendarEvent] | None = None) -> None:
        self.events: dict[str, CalendarEvent] = {e.id: e for e in (events or [])}
        self.deleted: list[str] = []
        self._id_counter = itertools.count(1)

    # -- read tools -----------------------------------------------------
    def list_events(self) -> list[CalendarEvent]:
        return sorted(self.events.values(), key=lambda e: e.start)

    def get_event(self, event_id: str) -> CalendarEvent:
        if event_id not in self.events:
            raise KeyError(f"no such event: {event_id}")
        return self.events[event_id]

    # -- write tools ------------------------------------------------------
    def create_event(
        self,
        title: str,
        start: Any,
        end: Any,
        attendees: list[str] | None = None,
        description: str = "",
        location: str = "",
    ) -> str:
        event_id = f"evt-{next(self._id_counter)}"
        self.events[event_id] = CalendarEvent(
            id=event_id,
            title=title,
            start=start,
            end=end,
            attendees=attendees or [],
            description=description,
            location=location,
        )
        return event_id

    def update_event(self, event_id: str, **changes: Any) -> None:
        current = self.get_event(event_id).model_dump()
        current.update({k: v for k, v in changes.items() if v is not None})
        self.events[event_id] = CalendarEvent.model_validate(current)

    def add_attendee(self, event_id: str, attendee: str) -> None:
        event = self.get_event(event_id)
        if attendee not in event.attendees:
            event.attendees.append(attendee)

    def delete_event(self, event_id: str) -> None:
        self.get_event(event_id)
        del self.events[event_id]
        self.deleted.append(event_id)
