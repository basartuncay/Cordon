import pytest

from cordon.tools.base import CalendarEvent
from cordon.tools.mock_calendar import MockCalendar


def make_event(id="evt1", title="Sync", attendees=None):
    return CalendarEvent(
        id=id,
        title=title,
        start="2026-01-06T10:00:00",
        end="2026-01-06T11:00:00",
        attendees=attendees or [],
    )


def test_create_event_assigns_id_and_parses_datetimes():
    calendar = MockCalendar()
    event_id = calendar.create_event(
        title="Kickoff", start="2026-01-06T11:00:00", end="2026-01-06T12:00:00"
    )
    event = calendar.get_event(event_id)
    assert event.title == "Kickoff"
    assert event.start.hour == 11


def test_get_event_missing_raises():
    calendar = MockCalendar()
    with pytest.raises(KeyError):
        calendar.get_event("nope")


def test_add_attendee_is_idempotent():
    calendar = MockCalendar(events=[make_event()])
    calendar.add_attendee("evt1", "bob@company.example")
    calendar.add_attendee("evt1", "bob@company.example")
    assert calendar.get_event("evt1").attendees == ["bob@company.example"]


def test_delete_event_removes_and_logs():
    calendar = MockCalendar(events=[make_event()])
    calendar.delete_event("evt1")
    assert "evt1" not in calendar.events
    assert calendar.deleted == ["evt1"]
    with pytest.raises(KeyError):
        calendar.delete_event("evt1")


def test_update_event_coerces_and_preserves_untouched_fields():
    calendar = MockCalendar(events=[make_event(attendees=["alice@company.example"])])
    calendar.update_event("evt1", title="Renamed sync", start="2026-01-06T12:00:00")
    updated = calendar.get_event("evt1")
    assert updated.title == "Renamed sync"
    assert updated.start.hour == 12
    assert updated.attendees == ["alice@company.example"]


def test_list_events_sorted_by_start():
    later = make_event(id="evt-later")
    earlier = make_event(id="evt-earlier")
    later.start = later.start.replace(year=2027)
    calendar = MockCalendar(events=[later, earlier])
    assert [e.id for e in calendar.list_events()] == ["evt-earlier", "evt-later"]
