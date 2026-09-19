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


def test_search_emails_matches_sender_address():
    """A real model asked to 'find Alice's email' naturally searches by
    name; our address-as-local-part convention (alice@company.example)
    means matching against the sender field covers that without needing a
    separate display-name field. This is the exact failure mode the real
    smoke test hit: search_emails(query='Alice') returned nothing because
    only subject/body were searched."""
    mailbox = MockMailbox(inbox=[make_email(sender="alice@company.example", body="unrelated")])
    assert len(mailbox.search_emails("Alice")) == 1
    assert len(mailbox.search_emails("alice@company.example")) == 1
    assert len(mailbox.search_emails("bob")) == 0


def test_search_emails_from_operator_matches_sender_case_insensitively():
    """A real Haiku pilot run used Gmail-style "from:Carol" queries against
    a mailbox where Carol was actually present — this mock's plain
    substring search silently returned nothing (no "from:" in the raw
    address string), which then crashed the plan indexing into an empty
    result. Real Gmail supports this operator; the mock should too."""
    mailbox = MockMailbox(inbox=[make_email(sender="carol@company.example")])
    assert len(mailbox.search_emails("from:carol")) == 1
    assert len(mailbox.search_emails("FROM:CAROL")) == 1
    assert len(mailbox.search_emails("from:carol@company.example")) == 1
    assert len(mailbox.search_emails("from:bob")) == 0


def test_search_emails_to_operator_matches_a_recipient():
    email = make_email()
    email.to = ["bob@company.example", "carol@company.example"]
    mailbox = MockMailbox(inbox=[email])
    assert len(mailbox.search_emails("to:carol")) == 1
    assert len(mailbox.search_emails("to:dave")) == 0


def test_search_emails_subject_operator_matches_subject_only():
    in_subject = make_email(id="e1")
    in_subject.subject = "Q3 planning review"
    in_body_only = make_email(id="e2")
    in_body_only.subject = "unrelated"
    in_body_only.body = "planning review happens here"
    mailbox = MockMailbox(inbox=[in_subject, in_body_only])

    results = mailbox.search_emails("subject:planning")

    assert [e.id for e in results] == ["e1"]


def test_search_emails_combines_an_operator_with_free_text():
    match = make_email(id="e1", sender="carol@company.example")
    match.subject = "quarterly numbers"
    other_sender = make_email(id="e2", sender="bob@company.example")
    other_sender.subject = "quarterly numbers"
    mailbox = MockMailbox(inbox=[match, other_sender])

    results = mailbox.search_emails("from:carol quarterly")

    assert [e.id for e in results] == ["e1"]


def test_search_emails_two_from_terms_are_anded_not_ored():
    mailbox = MockMailbox(inbox=[make_email(sender="carol@company.example")])
    assert len(mailbox.search_emails("from:carol from:company")) == 1
    assert len(mailbox.search_emails("from:carol from:bob")) == 0


def test_search_emails_still_supports_a_plain_free_text_query():
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
