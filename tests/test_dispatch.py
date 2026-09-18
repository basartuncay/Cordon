"""Tests for cordon.tools.dispatch.call_tool — the shared dispatch layer
every baseline (B0/B1 directly, B2/B3 via the executor's read-tool path)
routes through, so a fix here benefits all four identically rather than
needing to be duplicated per baseline.
"""

from __future__ import annotations

from cordon.env import Environment
from cordon.tools.base import Email
from cordon.tools.dispatch import call_tool
from cordon.tools.mock_calendar import MockCalendar
from cordon.tools.mock_mail import MockMailbox


def test_search_emails_by_sender_name_is_fair_across_every_baseline():
    """B0/B1 call search_emails through call_tool directly in their tool
    loop; B2/B3's executor calls the exact same call_tool for its
    READ_TOOLS path. There is only one search_emails implementation to
    fix, so no baseline can end up with a different (better or worse)
    search behavior than another."""
    env = Environment(
        mailbox=MockMailbox(
            inbox=[
                Email(
                    id="e1",
                    thread_id="t1",
                    sender="alice@company.example",
                    to=["me@user.example"],
                    subject="Lunch Friday?",
                    body="Are we still on for lunch Friday at noon?",
                    received_at="2026-01-05T09:00:00",
                )
            ]
        ),
        calendar=MockCalendar(),
    )

    results = call_tool(env, "search_emails", {"query": "Alice"})

    assert len(results) == 1
    assert results[0]["id"] == "e1"
