import pytest
from pydantic import ValidationError

from cordon.plan import TEMPLATE_TOOL, ListArg, LiteralArg, Plan, PlanStep, RefArg


def test_valid_plan_with_literal_and_ref_args():
    plan = Plan(
        steps=[
            PlanStep(step_id="s1", tool="list_emails", args={}),
            PlanStep(
                step_id="s2",
                tool="reply_email",
                args={
                    "email_id": RefArg(step_id="s1", path="0.id"),
                    "body": LiteralArg(value="sure, works for me"),
                },
            ),
        ]
    )
    assert len(plan.steps) == 2


def test_unknown_tool_is_rejected():
    with pytest.raises(ValidationError, match="unknown tool"):
        PlanStep(step_id="s1", tool="delete_everything", args={})


def test_duplicate_step_id_is_rejected():
    with pytest.raises(ValidationError, match="duplicate step_id"):
        Plan(
            steps=[
                PlanStep(step_id="s1", tool="list_emails", args={}),
                PlanStep(step_id="s1", tool="list_events", args={}),
            ]
        )


def test_ref_to_unknown_step_is_rejected():
    with pytest.raises(ValidationError, match="has not run yet"):
        Plan(
            steps=[
                PlanStep(
                    step_id="s1",
                    tool="reply_email",
                    args={
                        "email_id": RefArg(step_id="s99", path="id"),
                        "body": LiteralArg(value="hi"),
                    },
                ),
            ]
        )


def test_ref_to_a_later_step_is_rejected():
    with pytest.raises(ValidationError, match="has not run yet"):
        Plan(
            steps=[
                PlanStep(
                    step_id="s1",
                    tool="reply_email",
                    args={
                        "email_id": RefArg(step_id="s2", path="id"),
                        "body": LiteralArg(value="hi"),
                    },
                ),
                PlanStep(step_id="s2", tool="list_emails", args={}),
            ]
        )


def test_self_reference_is_rejected():
    with pytest.raises(ValidationError, match="cannot reference itself"):
        Plan(
            steps=[
                PlanStep(
                    step_id="s1",
                    tool="reply_email",
                    args={
                        "email_id": RefArg(step_id="s1", path="id"),
                        "body": LiteralArg(value="hi"),
                    },
                ),
            ]
        )


def test_ref_nested_inside_list_arg_is_validated():
    with pytest.raises(ValidationError, match="has not run yet"):
        Plan(
            steps=[
                PlanStep(
                    step_id="s1",
                    tool="send_email",
                    args={
                        "to": ListArg(items=[RefArg(step_id="s2", path="sender")]),
                        "subject": LiteralArg(value="hi"),
                        "body": LiteralArg(value="hi"),
                    },
                ),
            ]
        )


def test_valid_plan_with_list_arg_of_mixed_literal_and_ref():
    plan = Plan(
        steps=[
            PlanStep(step_id="s1", tool="get_email", args={"email_id": LiteralArg(value="e1")}),
            PlanStep(
                step_id="s2",
                tool="send_email",
                args={
                    "to": ListArg(
                        items=[
                            LiteralArg(value="alice@company.example"),
                            RefArg(step_id="s1", path="sender"),
                        ]
                    ),
                    "subject": LiteralArg(value="hi"),
                    "body": LiteralArg(value="hi"),
                },
            ),
        ]
    )
    assert len(plan.steps) == 2


def test_template_step_with_mixed_literal_and_ref_parts_is_valid():
    plan = Plan(
        steps=[
            PlanStep(step_id="s1", tool="get_email", args={"email_id": LiteralArg(value="e1")}),
            PlanStep(
                step_id="s2",
                tool=TEMPLATE_TOOL,
                args={
                    "parts": ListArg(
                        items=[
                            LiteralArg(value="Hi "),
                            RefArg(step_id="s1", path="sender"),
                            LiteralArg(value=", thanks!"),
                        ]
                    )
                },
            ),
        ]
    )
    assert len(plan.steps) == 2


def test_template_step_ref_to_a_later_step_is_rejected():
    with pytest.raises(ValidationError, match="has not run yet"):
        Plan(
            steps=[
                PlanStep(
                    step_id="s1",
                    tool=TEMPLATE_TOOL,
                    args={"parts": ListArg(items=[RefArg(step_id="s2", path="sender")])},
                ),
                PlanStep(step_id="s2", tool="get_email", args={"email_id": LiteralArg(value="e1")}),
            ]
        )
