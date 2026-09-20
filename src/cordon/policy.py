"""Deterministic policy engine — no LLM calls anywhere in this file.

Implements P1-P5 from CLAUDE.md. Every function here is a pure function
over ``Tainted`` values and plain config/state; the executor is the only
caller and is responsible for actually gating tool execution on the
returned ``Decision``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from cordon.provenance import Sensitivity, Tainted, TrustLevel

DESTRUCTIVE_TOOLS = {"delete_event"}
EMAIL_TOOLS = {"send_email", "forward_email", "reply_email"}
CALENDAR_TOOLS = {"create_event", "update_event", "add_attendee"}
CALENDAR_CLASS_TOOLS = CALENDAR_TOOLS | DESTRUCTIVE_TOOLS  # for P5 budgeting only
SIDE_EFFECT_TOOLS = EMAIL_TOOLS | CALENDAR_CLASS_TOOLS
# P6 (CORDON_POLICY_VERSION=v2 only) applies to email tools' subject/body/
# note and the calendar tools' own title/description/location — never
# add_attendee (that tool has no content field, only P4's "attendee") and
# never attendees/start/end on create_event/update_event (P4's territory).
P6_CONTENT_TOOLS = EMAIL_TOOLS | {"create_event", "update_event"}

_POLICY_VERSIONS = ("v1", "v2")


def policy_version_from_env() -> str:
    """CORDON_POLICY_VERSION=v1|v2, default v2. v1 = P1-P5 only, byte-
    identical to the engine's behavior before P6 existed; v2 = P1-P6.
    This is the *env var's* default — PolicyConfig's own dataclass
    default is "v1" instead (see its docstring), so every existing
    caller that doesn't explicitly opt in keeps today's exact behavior;
    only the production entry points (cordon_runner.py, harness.py) call
    this function to decide what a real run gets when the env var is
    unset."""
    version = os.environ.get("CORDON_POLICY_VERSION", "v2").strip().lower()
    if version not in _POLICY_VERSIONS:
        raise ValueError(
            f"CORDON_POLICY_VERSION must be one of {_POLICY_VERSIONS}, got {version!r}"
        )
    return version


class Decision(StrEnum):
    ALLOW = "allow"
    CONFIRM = "confirm"
    DENY = "deny"


_DECISION_ORDER = [Decision.ALLOW, Decision.CONFIRM, Decision.DENY]  # least to most restrictive


@dataclass
class PolicyVerdict:
    decision: Decision
    rules: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


@dataclass
class PolicyConfig:
    contacts_allowlist: set[str]
    max_side_effects: int = 5
    max_email_side_effects: int = 5
    max_calendar_side_effects: int = 5
    max_destructive_side_effects: int = 2
    # "v1" (P1-P5 only) by construction here, NOT the env var's "v2"
    # default — this dataclass default is what every existing caller
    # that doesn't explicitly pass policy_version gets, so adding P6
    # never silently changes behavior anywhere that hasn't opted in.
    # Only cordon_runner.py's real B2/B3 execution path and harness.py's
    # result-file reporting call policy_version_from_env() to get the
    # actual "default v2" a real eval run sees.
    policy_version: str = "v1"


@dataclass
class PolicyState:
    """Mutable, per-plan-execution counters the engine needs across calls."""

    side_effect_count: int = 0
    email_count: int = 0
    calendar_count: int = 0
    destructive_count: int = 0


def _most_restrictive(verdicts: list[PolicyVerdict]) -> PolicyVerdict:
    decision = max(
        (v.decision for v in verdicts), key=_DECISION_ORDER.index, default=Decision.ALLOW
    )
    if decision == Decision.ALLOW:
        return PolicyVerdict(decision=Decision.ALLOW)
    matching = [v for v in verdicts if v.decision == decision]
    rules = [r for v in matching for r in v.rules]
    reasons = [r for v in matching for r in v.reasons]
    return PolicyVerdict(decision=decision, rules=rules, reasons=reasons)


def check_p1_recipient_provenance(
    recipients: list[Tainted[str]], cfg: PolicyConfig
) -> PolicyVerdict:
    """P1: send/forward/share recipients must come from the user's request
    literal (``trust == USER``) or the contacts allowlist; otherwise the
    call needs human confirmation."""
    rules: list[str] = []
    reasons: list[str] = []
    for addr in recipients:
        is_literal = addr.provenance.trust == TrustLevel.USER
        is_allowlisted = addr.value.strip().lower() in cfg.contacts_allowlist
        if not (is_literal or is_allowlisted):
            rules.append("P1")
            reasons.append(
                f"recipient {addr.value!r} is neither a request literal nor in the "
                "contacts allowlist"
            )
    if rules:
        return PolicyVerdict(decision=Decision.CONFIRM, rules=rules, reasons=reasons)
    return PolicyVerdict(decision=Decision.ALLOW)


def check_p2_exfiltration(
    recipients: list[Tainted[str]],
    contents: list[Tainted[str]],
    cfg: PolicyConfig,
) -> PolicyVerdict:
    """P2: content labeled private must not flow to a recipient outside
    the contacts allowlist without confirmation — regardless of whether
    that recipient already passed P1 (e.g. as a request literal).

    Examines every text-bearing argument a call carries (subject, body,
    note, title, description, location, ...) rather than a single
    hardcoded field, since private content can leak through any of them.
    For calendar tools, "recipients" means attendees — anyone invited can
    read the title/description/location.
    """
    if not any(c.provenance.sensitivity == Sensitivity.PRIVATE for c in contents):
        return PolicyVerdict(decision=Decision.ALLOW)
    rules: list[str] = []
    reasons: list[str] = []
    for addr in recipients:
        if addr.value.strip().lower() not in cfg.contacts_allowlist:
            rules.append("P2")
            reasons.append(
                f"private content would flow to {addr.value!r}, which is outside the "
                "contacts allowlist"
            )
    if rules:
        return PolicyVerdict(decision=Decision.CONFIRM, rules=rules, reasons=reasons)
    return PolicyVerdict(decision=Decision.ALLOW)


def check_p3_destructive(tool: str) -> PolicyVerdict:
    """P3: destructive/irreversible actions always require confirmation."""
    if tool in DESTRUCTIVE_TOOLS:
        return PolicyVerdict(
            decision=Decision.CONFIRM,
            rules=["P3"],
            reasons=[f"{tool} is destructive/irreversible"],
        )
    return PolicyVerdict(decision=Decision.ALLOW)


def check_p4_calendar(tool: str, fields: list[Tainted[Any]]) -> PolicyVerdict:
    """P4: calendar attendees/links/locations derived from untrusted data
    require confirmation. Unlike P1, there is no allowlist exception —
    an untrusted-derived decision to add an attendee still needs a human,
    even if the resulting address happens to be a known contact."""
    if tool not in CALENDAR_TOOLS:
        return PolicyVerdict(decision=Decision.ALLOW)
    rules: list[str] = []
    reasons: list[str] = []
    for value in fields:
        if value.provenance.trust != TrustLevel.USER:
            rules.append("P4")
            reasons.append(f"{tool} field {value.value!r} is derived from untrusted data")
    if rules:
        return PolicyVerdict(decision=Decision.CONFIRM, rules=rules, reasons=reasons)
    return PolicyVerdict(decision=Decision.ALLOW)


def check_p6_untrusted_content(tool: str, contents: list[Tainted[Any]]) -> PolicyVerdict:
    """P6 (CORDON_POLICY_VERSION=v2 only): send_email/reply_email/
    forward_email's subject/body/note, or create_event/update_event's
    title/description/location, require confirmation if ANY of that
    content is derived from a source trusted below CONTACT (i.e.
    UNKNOWN) — even if the recipient/attendee is the user's own literal
    or already in the allowlist. Content from a CONTACT-trust source
    does NOT trigger this: a compromised contact account is a known,
    accepted gap (see docs/threat-model.md, "P6 and its own known gap").

    Exemption: forward_email's forwarded original message is never in
    `contents` here — the caller (executor.py's _extract_own_contents)
    builds this list without it, since forwarding an untrusted original
    is the whole point of the forward action, not a surprise injection;
    only the forwarder's own added `note` is checked.
    """
    if tool not in P6_CONTENT_TOOLS:
        return PolicyVerdict(decision=Decision.ALLOW)
    rules: list[str] = []
    reasons: list[str] = []
    for value in contents:
        if value.provenance.trust == TrustLevel.UNKNOWN:
            rules.append("P6")
            reasons.append(
                f"{tool} content {value.value!r} is derived from a below-contact-trust "
                "(unknown) source"
            )
    if rules:
        return PolicyVerdict(decision=Decision.CONFIRM, rules=rules, reasons=reasons)
    return PolicyVerdict(decision=Decision.ALLOW)


def check_p5_budget(tool: str, state: PolicyState, cfg: PolicyConfig) -> PolicyVerdict:
    """P5: hard cap on side-effecting calls per plan — an overall cap plus
    a per-tool-class cap (email, calendar, destructive). Any one of them
    tripping is enough to deny; a plan that's fine on the overall count
    can still be denied for doing too many destructive things, etc."""
    if tool not in SIDE_EFFECT_TOOLS:
        return PolicyVerdict(decision=Decision.ALLOW)
    reasons: list[str] = []
    if state.side_effect_count >= cfg.max_side_effects:
        reasons.append(f"overall side-effect budget ({cfg.max_side_effects}) exceeded")
    if tool in EMAIL_TOOLS and state.email_count >= cfg.max_email_side_effects:
        reasons.append(f"email side-effect budget ({cfg.max_email_side_effects}) exceeded")
    if tool in CALENDAR_CLASS_TOOLS and state.calendar_count >= cfg.max_calendar_side_effects:
        reasons.append(f"calendar side-effect budget ({cfg.max_calendar_side_effects}) exceeded")
    if tool in DESTRUCTIVE_TOOLS and state.destructive_count >= cfg.max_destructive_side_effects:
        reasons.append(
            f"destructive side-effect budget ({cfg.max_destructive_side_effects}) exceeded"
        )
    if reasons:
        return PolicyVerdict(decision=Decision.DENY, rules=["P5"], reasons=reasons)
    return PolicyVerdict(decision=Decision.ALLOW)


def evaluate_call(
    tool: str,
    *,
    recipients: list[Tainted[str]] | None = None,
    contents: list[Tainted[str]] | None = None,
    calendar_recipients: list[Tainted[str]] | None = None,
    calendar_fields: list[Tainted[Any]] | None = None,
    p6_contents: list[Tainted[Any]] | None = None,
    cfg: PolicyConfig,
    state: PolicyState,
) -> PolicyVerdict:
    """Runs every applicable P1-P6 rule for one tool call and returns the
    single most restrictive verdict (DENY beats CONFIRM beats ALLOW).

    ``recipients`` (email addresses) triggers both P1 and P2. ``calendar_
    recipients`` (attendees) triggers P2 only — P1 is email-specific per
    CLAUDE.md, calendar attendee provenance is P4's job instead.
    ``p6_contents`` is deliberately separate from ``contents``: it's
    P2-plus-P6's own content list minus forward_email's forwarded-
    original exemption (see check_p6_untrusted_content), and only takes
    effect at all when ``cfg.policy_version == "v2"``.
    """
    verdicts = [check_p5_budget(tool, state, cfg), check_p3_destructive(tool)]
    if recipients:
        verdicts.append(check_p1_recipient_provenance(recipients, cfg))
        verdicts.append(check_p2_exfiltration(recipients, contents or [], cfg))
    if calendar_recipients:
        verdicts.append(check_p2_exfiltration(calendar_recipients, contents or [], cfg))
    if calendar_fields:
        verdicts.append(check_p4_calendar(tool, calendar_fields))
    if cfg.policy_version == "v2" and p6_contents:
        verdicts.append(check_p6_untrusted_content(tool, p6_contents))
    return _most_restrictive(verdicts)
