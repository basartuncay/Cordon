"""In-memory mock mailbox.

No network calls, no real Gmail access. All write-tool effects land in
``sent`` (a plain list of dicts) so the eval harness can check attacker-goal
and task-success predicates deterministically from final state, without an
LLM judge.
"""

from __future__ import annotations

import itertools
from typing import Any

from cordon.tools.base import Email


class MockMailbox:
    def __init__(
        self,
        inbox: list[Email] | None = None,
        contacts: list[str] | None = None,
    ) -> None:
        self.inbox: dict[str, Email] = {e.id: e for e in (inbox or [])}
        self.contacts: set[str] = set(contacts or [])
        self.sent: list[dict[str, Any]] = []
        self._id_counter = itertools.count(1)

    # -- read tools -----------------------------------------------------
    def list_emails(self) -> list[Email]:
        return sorted(self.inbox.values(), key=lambda e: e.received_at)

    def get_email(self, email_id: str) -> Email:
        if email_id not in self.inbox:
            raise KeyError(f"no such email: {email_id}")
        return self.inbox[email_id]

    def search_emails(self, query: str) -> list[Email]:
        q = query.lower()
        return [
            e
            for e in self.inbox.values()
            if q in e.subject.lower() or q in e.body.lower() or q in e.sender.lower()
        ]

    # -- write tools ------------------------------------------------------
    def send_email(self, to: list[str], subject: str, body: str) -> str:
        msg_id = f"sent-{next(self._id_counter)}"
        self.sent.append(
            {"id": msg_id, "kind": "send", "to": list(to), "subject": subject, "body": body}
        )
        return msg_id

    def forward_email(self, email_id: str, to: list[str], note: str = "") -> str:
        original = self.get_email(email_id)
        msg_id = f"sent-{next(self._id_counter)}"
        body = f"{note}\n\n{original.body}" if note else original.body
        self.sent.append(
            {
                "id": msg_id,
                "kind": "forward",
                "to": list(to),
                "subject": f"Fwd: {original.subject}",
                "body": body,
                "original_id": email_id,
            }
        )
        return msg_id

    def reply_email(self, email_id: str, body: str) -> str:
        original = self.get_email(email_id)
        msg_id = f"sent-{next(self._id_counter)}"
        self.sent.append(
            {
                "id": msg_id,
                "kind": "reply",
                "to": [original.sender],
                "subject": f"Re: {original.subject}",
                "body": body,
                "original_id": email_id,
            }
        )
        return msg_id
