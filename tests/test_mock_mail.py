from datetime import datetime

import pytest

from cordon.tools.base import Email, TrustLevel
from cordon.tools.mock_mail import MockMailbox


def make_email(id="e1", sender="alice@company.example", trust=TrustLevel.CONTACT, body="hello"):
    return Email(
        id=id,
        thread_id=f"t-{id}",
        sender=sender,
        sender_trust=trust,
        to=["me@user.example"],
        subject="subject",
        body=body,
        received_at=datetime(2026, 1, 5, 9, 0, 0),
    )


def test_list_emails_sorted_by_received_at():
    later = make_email(id="e-later", body="later")
    earlier = make_email(id="e-earlier", body="earlier")
    later.received_at = datetime(2026, 1, 6)
    earlier.received_at = datetime(2026, 1, 4)
    mailbox = MockMailbox(inbox=[later, earlier])
    assert [e.id for e in mailbox.list_emails()] == ["e-earlier", "e-later"]


def test_get_email_missing_raises():
    mailbox = MockMailbox(inbox=[make_email()])
    with pytest.raises(KeyError):
        mailbox.get_email("nope")


def test_search_emails_matches_subject_and_body():
    mailbox = MockMailbox(inbox=[make_email(body="the quarterly report is attached")])
    assert len(mailbox.search_emails("quarterly")) == 1
    assert len(mailbox.search_emails("nonexistent")) == 0


def test_send_email_records_kind_send():
    mailbox = MockMailbox()
    msg_id = mailbox.send_email(to=["bob@company.example"], subject="hi", body="body")
    assert len(mailbox.sent) == 1
    sent = mailbox.sent[0]
    assert sent["id"] == msg_id
    assert sent["kind"] == "send"
    assert sent["to"] == ["bob@company.example"]


def test_forward_email_includes_original_id_and_body():
    original = make_email(id="e1", body="original body")
    mailbox = MockMailbox(inbox=[original])
    mailbox.forward_email("e1", to=["carol@partner.example"], note="fyi")
    sent = mailbox.sent[0]
    assert sent["kind"] == "forward"
    assert sent["original_id"] == "e1"
    assert sent["to"] == ["carol@partner.example"]
    assert "original body" in sent["body"]
    assert "fyi" in sent["body"]


def test_reply_email_targets_original_sender():
    original = make_email(id="e1", sender="alice@company.example")
    mailbox = MockMailbox(inbox=[original])
    mailbox.reply_email("e1", body="sure, works for me")
    sent = mailbox.sent[0]
    assert sent["kind"] == "reply"
    assert sent["to"] == ["alice@company.example"]
    assert sent["original_id"] == "e1"
