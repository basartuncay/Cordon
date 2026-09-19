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

# Gmail-style single-word operators search_emails understands, mapped to
# the Email field(s) they search. Anything not matching one of these
# prefixes is treated as free text, matched (like the plain query below)
# against subject/body/sender. Real Gmail supports quoting a multi-word
# operator value and many more operators (has:, is:, after:, ...) — this
# mock only covers what CLAUDE.md's corpus actually needs.
_QUERY_OPERATORS = ("from", "to", "subject")


def _split_query(query: str) -> tuple[dict[str, list[str]], list[str]]:
    """Splits a query into {"from": [...], "to": [...], "subject": [...]}
    (each a list of lowercased terms — multiple terms for the same
    operator are ANDed) plus a list of free-text terms. Operator values
    are single words, same as Gmail without quotes."""
    operator_terms: dict[str, list[str]] = {op: [] for op in _QUERY_OPERATORS}
    free_terms: list[str] = []
    for token in query.split():
        low = token.lower()
        for op in _QUERY_OPERATORS:
            prefix = f"{op}:"
            if low.startswith(prefix):
                value = low[len(prefix) :]
                if value:
                    operator_terms[op].append(value)
                break
        else:
            free_terms.append(low)
    return operator_terms, free_terms


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
        """Gmail-style search: from:/to:/subject: operators (case-
        insensitive, single-word values) plus free text, all substring-
        matched (never tokenized/stemmed — a mock, not a real search
        index). Free text matches subject/body/sender, same as before
        operators existed. Multiple terms (same operator or not) are all
        required (AND), matching Gmail's default query semantics."""
        operator_terms, free_terms = _split_query(query)

        def matches(e: Email) -> bool:
            sender = e.sender.lower()
            if any(t not in sender for t in operator_terms["from"]):
                return False
            to_lower = [addr.lower() for addr in e.to]
            if any(not any(t in addr for addr in to_lower) for t in operator_terms["to"]):
                return False
            subject = e.subject.lower()
            if any(t not in subject for t in operator_terms["subject"]):
                return False
            if free_terms:
                haystack = f"{e.subject} {e.body} {e.sender}".lower()
                if any(t not in haystack for t in free_terms):
                    return False
            return True

        return [e for e in self.inbox.values() if matches(e)]

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
