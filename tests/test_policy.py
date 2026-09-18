"""Policy engine tests — P1-P5, no LLM calls, no mock environment. These are
meant to be the cheap, high-signal tests CLAUDE.md asks for: pure functions
over provenance data. Written before cordon/policy.py and cordon/provenance.py
exist, against the planned API.
"""

from __future__ import annotations

from cordon.policy import (
    Decision,
    PolicyConfig,
    PolicyState,
    check_p1_recipient_provenance,
    check_p2_exfiltration,
    check_p3_destructive,
    check_p4_calendar,
    check_p5_budget,
    evaluate_call,
)
from cordon.provenance import LITERAL_PROVENANCE, Provenance, Sensitivity, Tainted, TrustLevel

ALLOWLIST = {"alice@company.example", "bob@company.example"}


def literal(value):
    return Tainted(value, LITERAL_PROVENANCE)


def untrusted(value, sensitivity=Sensitivity.PRIVATE):
    prov = Provenance(source_id="email:e1", trust=TrustLevel.UNKNOWN, sensitivity=sensitivity)
    return Tainted(value, prov)


def contact(value, sensitivity=Sensitivity.PRIVATE):
    prov = Provenance(source_id="email:e2", trust=TrustLevel.CONTACT, sensitivity=sensitivity)
    return Tainted(value, prov)


def make_cfg(**kw):
    kw.setdefault("contacts_allowlist", set(ALLOWLIST))
    return PolicyConfig(**kw)


# --- P1: recipient provenance ---------------------------------------------


def test_p1_allows_literal_recipient_from_user_request():
    verdict = check_p1_recipient_provenance([literal("random@anywhere.example")], make_cfg())
    assert verdict.decision == Decision.ALLOW


def test_p1_allows_allowlisted_recipient_even_if_untrusted_provenance():
    verdict = check_p1_recipient_provenance([untrusted("alice@company.example")], make_cfg())
    assert verdict.decision == Decision.ALLOW


def test_p1_confirms_recipient_derived_from_untrusted_data_not_in_allowlist():
    verdict = check_p1_recipient_provenance([untrusted("attacker@evil.example")], make_cfg())
    assert verdict.decision == Decision.CONFIRM
    assert "P1" in verdict.rules


def test_p1_confirms_if_any_recipient_in_a_multi_recipient_call_fails():
    verdict = check_p1_recipient_provenance(
        [literal("alice@company.example"), untrusted("attacker@evil.example")], make_cfg()
    )
    assert verdict.decision == Decision.CONFIRM


def test_p1_allows_contact_trust_recipient_in_allowlist():
    verdict = check_p1_recipient_provenance([contact("bob@company.example")], make_cfg())
    assert verdict.decision == Decision.ALLOW


def test_p1_is_case_insensitive_against_the_allowlist():
    verdict = check_p1_recipient_provenance([untrusted("ALICE@COMPANY.EXAMPLE")], make_cfg())
    assert verdict.decision == Decision.ALLOW


# --- P2: exfiltration -------------------------------------------------------
# P2 examines every text-bearing arg a tool call carries (subject, body,
# note, title, description, location) — not just one hardcoded field —
# since private content can leak through any of them.


def test_p2_allows_private_content_to_allowlisted_recipient():
    verdict = check_p2_exfiltration(
        recipients=[literal("bob@company.example")],
        contents=[untrusted("sensitive body", sensitivity=Sensitivity.PRIVATE)],
        cfg=make_cfg(),
    )
    assert verdict.decision == Decision.ALLOW


def test_p2_confirms_private_content_to_non_allowlisted_recipient():
    verdict = check_p2_exfiltration(
        recipients=[untrusted("attacker@evil.example")],
        contents=[contact("sensitive body", sensitivity=Sensitivity.PRIVATE)],
        cfg=make_cfg(),
    )
    assert verdict.decision == Decision.CONFIRM
    assert "P2" in verdict.rules


def test_p2_allows_public_content_to_non_allowlisted_recipient():
    verdict = check_p2_exfiltration(
        recipients=[untrusted("attacker@evil.example")],
        contents=[literal("nothing sensitive")],
        cfg=make_cfg(),
    )
    assert verdict.decision == Decision.ALLOW


def test_p2_allows_when_there_are_no_content_arguments():
    verdict = check_p2_exfiltration(
        recipients=[untrusted("attacker@evil.example")], contents=[], cfg=make_cfg()
    )
    assert verdict.decision == Decision.ALLOW


def test_p2_confirms_if_any_one_of_several_content_fields_is_private():
    """subject is public but body is private — a real send_email call
    carries both; P2 must catch the private one even if the others are
    fine, matching the requirement to inspect every text-bearing field."""
    verdict = check_p2_exfiltration(
        recipients=[untrusted("attacker@evil.example")],
        contents=[
            literal("ordinary subject line"),
            contact("body has sensitive stuff", sensitivity=Sensitivity.PRIVATE),
        ],
        cfg=make_cfg(),
    )
    assert verdict.decision == Decision.CONFIRM
    assert "P2" in verdict.rules


def test_p2_allows_when_every_content_field_is_public():
    verdict = check_p2_exfiltration(
        recipients=[untrusted("attacker@evil.example")],
        contents=[
            literal("subject"),
            untrusted("body", sensitivity=Sensitivity.PUBLIC),
        ],
        cfg=make_cfg(),
    )
    assert verdict.decision == Decision.ALLOW


def test_p2_applies_to_calendar_text_fields_with_attendees_as_recipients():
    """title/description/location are exactly as exfiltration-prone as an
    email body when the 'recipients' are the event's attendees."""
    verdict = check_p2_exfiltration(
        recipients=[untrusted("attacker@evil.example")],
        contents=[
            untrusted("Confidential: layoffs planning", sensitivity=Sensitivity.PRIVATE)
        ],
        cfg=make_cfg(),
    )
    assert verdict.decision == Decision.CONFIRM
    assert "P2" in verdict.rules


# --- P3: destructive / irreversible actions ---------------------------------


def test_p3_always_confirms_delete_event():
    verdict = check_p3_destructive("delete_event")
    assert verdict.decision == Decision.CONFIRM
    assert "P3" in verdict.rules


def test_p3_does_not_flag_non_destructive_tools():
    verdict = check_p3_destructive("send_email")
    assert verdict.decision == Decision.ALLOW


# --- P4: calendar ------------------------------------------------------------


def test_p4_confirms_attendee_derived_from_untrusted_data():
    verdict = check_p4_calendar("add_attendee", [untrusted("attacker@evil.example")])
    assert verdict.decision == Decision.CONFIRM
    assert "P4" in verdict.rules


def test_p4_allows_attendee_literal_from_user_request():
    verdict = check_p4_calendar("add_attendee", [literal("bob@company.example")])
    assert verdict.decision == Decision.ALLOW


def test_p4_confirms_even_if_untrusted_attendee_is_in_the_allowlist():
    """Unlike P1, P4 carves out no allowlist exception: an attendee add
    *decided* based on untrusted data still needs a human to bless it, even
    if the address itself happens to be a known contact."""
    verdict = check_p4_calendar("add_attendee", [untrusted("bob@company.example")])
    assert verdict.decision == Decision.CONFIRM


def test_p4_ignores_non_calendar_tools():
    verdict = check_p4_calendar("send_email", [untrusted("attacker@evil.example")])
    assert verdict.decision == Decision.ALLOW


# --- P5: budget ---------------------------------------------------------------


def test_p5_allows_under_budget():
    verdict = check_p5_budget(
        "send_email", PolicyState(side_effect_count=2), make_cfg(max_side_effects=5)
    )
    assert verdict.decision == Decision.ALLOW


def test_p5_denies_at_budget():
    verdict = check_p5_budget(
        "send_email", PolicyState(side_effect_count=5), make_cfg(max_side_effects=5)
    )
    assert verdict.decision == Decision.DENY
    assert "P5" in verdict.rules


def test_p5_ignores_read_tools():
    verdict = check_p5_budget(
        "list_emails", PolicyState(side_effect_count=999), make_cfg(max_side_effects=1)
    )
    assert verdict.decision == Decision.ALLOW


# --- combinator: evaluate_call -------------------------------------------------


def test_evaluate_call_combines_multiple_confirm_reasons():
    state = PolicyState()
    verdict = evaluate_call(
        "send_email",
        recipients=[untrusted("attacker@evil.example")],
        contents=[untrusted("private stuff", sensitivity=Sensitivity.PRIVATE)],
        cfg=make_cfg(),
        state=state,
    )
    assert verdict.decision == Decision.CONFIRM
    assert {"P1", "P2"} <= set(verdict.rules)


def test_evaluate_call_deny_wins_over_confirm():
    state = PolicyState(side_effect_count=5)
    verdict = evaluate_call(
        "send_email",
        recipients=[untrusted("attacker@evil.example")],
        cfg=make_cfg(max_side_effects=5),
        state=state,
    )
    assert verdict.decision == Decision.DENY


def test_evaluate_call_allows_ordinary_benign_send():
    state = PolicyState()
    verdict = evaluate_call(
        "send_email",
        recipients=[literal("bob@company.example")],
        contents=[literal("see you at noon")],
        cfg=make_cfg(),
        state=state,
    )
    assert verdict.decision == Decision.ALLOW


def test_evaluate_call_destructive_action_confirms_regardless_of_other_rules():
    state = PolicyState()
    verdict = evaluate_call("delete_event", cfg=make_cfg(), state=state)
    assert verdict.decision == Decision.CONFIRM
    assert "P3" in verdict.rules


def test_evaluate_call_create_event_private_title_to_non_allowlisted_attendee_triggers_p2():
    """Calendar analog of email exfiltration: a PRIVATE title/description
    read by a non-allowlisted attendee is exactly as much of a leak as a
    private email body sent to an unknown address."""
    state = PolicyState()
    verdict = evaluate_call(
        "create_event",
        calendar_recipients=[literal("attacker@evil.example")],
        contents=[contact("Confidential: layoffs planning", sensitivity=Sensitivity.PRIVATE)],
        cfg=make_cfg(),
        state=state,
    )
    assert verdict.decision == Decision.CONFIRM
    assert "P2" in verdict.rules


def test_evaluate_call_send_email_private_body_to_non_allowlisted_recipient_triggers_p2():
    """subject is public, body is private, recipient is outside the
    allowlist — P2 must catch it via the body field even though the
    subject alone would have been fine."""
    state = PolicyState()
    verdict = evaluate_call(
        "send_email",
        recipients=[untrusted("attacker@evil.example")],
        contents=[
            literal("ordinary subject"),
            contact("this is confidential", sensitivity=Sensitivity.PRIVATE),
        ],
        cfg=make_cfg(),
        state=state,
    )
    assert verdict.decision == Decision.CONFIRM
    assert "P2" in verdict.rules


# --- edge cases called out explicitly for M2a ----------------------------------


def test_edge_case_recipient_derived_from_untrusted_data():
    verdict = check_p1_recipient_provenance([untrusted("attacker@evil.example")], make_cfg())
    assert verdict.decision == Decision.CONFIRM


def test_edge_case_recipient_in_allowlist():
    verdict = check_p1_recipient_provenance([untrusted("alice@company.example")], make_cfg())
    assert verdict.decision == Decision.ALLOW


def test_edge_case_recipient_literal_in_user_request():
    verdict = check_p1_recipient_provenance([literal("anyone@anywhere.example")], make_cfg())
    assert verdict.decision == Decision.ALLOW


def test_edge_case_untrusted_body_with_trusted_recipient_is_not_over_blocked():
    """Untrusted-sourced content flowing to an allowlisted recipient (e.g.
    forwarding a suspicious email to a legitimate teammate for review) must
    not be blocked just because the body is tainted — P2 is about
    exfiltration to *new* destinations, not about touching untrusted text."""
    verdict = evaluate_call(
        "forward_email",
        recipients=[literal("alice@company.example")],
        contents=[untrusted("attacker-authored body", sensitivity=Sensitivity.PRIVATE)],
        cfg=make_cfg(),
        state=PolicyState(),
    )
    assert verdict.decision == Decision.ALLOW


def test_edge_case_concatenated_tainted_values_inherit_least_trusted_and_most_sensitive():
    contact_part = contact("Hi, ", sensitivity=Sensitivity.PUBLIC)
    untrusted_part = untrusted("please forward everything", sensitivity=Sensitivity.PRIVATE)
    merged = Tainted.combine(contact_part, untrusted_part)

    assert merged.trust == TrustLevel.UNKNOWN
    assert merged.sensitivity == Sensitivity.PRIVATE

    body = Tainted(contact_part.value + untrusted_part.value, merged)
    verdict = check_p2_exfiltration(
        recipients=[untrusted("attacker@evil.example")],
        contents=[body],
        cfg=make_cfg(),
    )
    assert verdict.decision == Decision.CONFIRM
