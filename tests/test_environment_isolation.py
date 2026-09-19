"""Regression test: build_environment() must hand back a fully independent
copy each time, never sharing the underlying Email/CalendarEvent objects
with the SeedData (or with a previous call's environment). Without this,
mutating one call's environment (e.g. add_attendee) silently corrupts every
later call built from the same scenario object — exactly the bug that made
an early worst-case aggregate report look like the policy engine wasn't
blocking attendee-tampering attacks it actually was blocking.
"""

from __future__ import annotations

from cordon.tools.base import CalendarEvent, Email
from evals.scenario import SeedData, build_environment


def _seed_with_event():
    return SeedData(
        events=[
            CalendarEvent(
                id="evt1",
                title="Sync",
                start="2026-01-06T10:00:00",
                end="2026-01-06T11:00:00",
                attendees=["alice@company.example"],
            )
        ]
    )


def _seed_with_email():
    return SeedData(
        emails=[
            Email(
                id="e1",
                thread_id="t1",
                sender="bob@company.example",
                to=["me@user.example"],
                subject="hi",
                body="hello",
                received_at="2026-01-05T09:00:00",
            )
        ]
    )


def test_mutating_one_environment_does_not_affect_a_second_build_from_the_same_seed():
    seed = _seed_with_event()

    first_env = build_environment(seed)
    first_env.calendar.add_attendee("evt1", "attacker@evil.example")
    assert "attacker@evil.example" in first_env.calendar.get_event("evt1").attendees

    second_env = build_environment(seed)
    assert "attacker@evil.example" not in second_env.calendar.get_event("evt1").attendees
    assert second_env.calendar.get_event("evt1").attendees == ["alice@company.example"]


def test_mutating_one_environment_does_not_affect_the_seed_itself():
    seed = _seed_with_event()
    env = build_environment(seed)
    env.calendar.add_attendee("evt1", "attacker@evil.example")
    assert seed.events[0].attendees == ["alice@company.example"]


def test_deleting_an_event_in_one_environment_does_not_affect_a_second_build():
    seed = _seed_with_event()

    first_env = build_environment(seed)
    first_env.calendar.delete_event("evt1")
    assert "evt1" not in first_env.calendar.events

    second_env = build_environment(seed)
    assert "evt1" in second_env.calendar.events


def test_sending_mail_in_one_environment_does_not_affect_a_second_build():
    seed = _seed_with_email()

    first_env = build_environment(seed)
    first_env.mailbox.reply_email("e1", "sure")
    assert len(first_env.mailbox.sent) == 1

    second_env = build_environment(seed)
    assert len(second_env.mailbox.sent) == 0


def test_calling_build_environment_many_times_never_accumulates_state():
    seed = _seed_with_event()
    for _ in range(5):
        env = build_environment(seed)
        env.calendar.add_attendee("evt1", "attacker@evil.example")
        assert len(env.calendar.get_event("evt1").attendees) == 2
