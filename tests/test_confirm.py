"""Tests for the confirmation interface: request/log bookkeeping and the
two eval-mode deciders (auto-deny/auto-approve), plus the interactive CLI
decider with input/output faked. No LLM calls anywhere here.
"""

from __future__ import annotations

from cordon.confirm import (
    AutoApproveDecider,
    AutoDenyDecider,
    CLIConfirmDecider,
    ConfirmLog,
    ConfirmRequest,
)


def make_request(**overrides):
    defaults = dict(
        tool="forward_email",
        step_id="s3",
        rules=["P1"],
        reasons=["recipient 'attacker@evil.example' is not in the allowlist"],
        argument_summary={"to": "['attacker@evil.example'] (trust=unknown)"},
    )
    defaults.update(overrides)
    return ConfirmRequest(**defaults)


def test_auto_deny_decider_always_returns_false():
    decider = AutoDenyDecider()
    assert decider.decide(make_request()) is False
    assert decider.decide(make_request(tool="delete_event")) is False


def test_auto_approve_decider_always_returns_true():
    decider = AutoApproveDecider()
    assert decider.decide(make_request()) is True


def test_confirm_log_records_every_decision():
    log = ConfirmLog()
    log.record(make_request(step_id="s1"), approved=False)
    log.record(make_request(step_id="s2"), approved=True)
    log.record(make_request(step_id="s3"), approved=False)

    assert log.confirm_count == 3
    assert log.approved_count == 1
    assert log.rejected_count == 2
    assert [r.request.step_id for r in log.records] == ["s1", "s2", "s3"]


def test_confirm_log_starts_empty():
    log = ConfirmLog()
    assert log.confirm_count == 0
    assert log.approved_count == 0
    assert log.rejected_count == 0


def test_cli_confirm_decider_approves_on_yes(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda _prompt="": "y")
    decider = CLIConfirmDecider()
    approved = decider.decide(make_request())
    assert approved is True
    out = capsys.readouterr().out
    assert "forward_email" in out
    assert "P1" in out


def test_cli_confirm_decider_denies_on_anything_else(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _prompt="": "")
    decider = CLIConfirmDecider()
    assert decider.decide(make_request()) is False

    monkeypatch.setattr("builtins.input", lambda _prompt="": "n")
    assert decider.decide(make_request()) is False

    monkeypatch.setattr("builtins.input", lambda _prompt="": "nah")
    assert decider.decide(make_request()) is False


def test_cli_confirm_decider_prints_argument_summary(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda _prompt="": "n")
    decider = CLIConfirmDecider()
    decider.decide(make_request())
    out = capsys.readouterr().out
    assert "to:" in out
    assert "attacker@evil.example" in out
