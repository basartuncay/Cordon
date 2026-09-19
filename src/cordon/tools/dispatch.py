"""Tool schemas (Anthropic tool-use format) and a name -> call dispatcher.

Deliberately un-gated: this module has no notion of provenance or policy.
B0 (evals/baselines/b0.py) calls tools through here directly, which is the
point — it's the undefended baseline. The policy engine added in M2 sits in
front of a dispatcher like this one for Cordon proper.
"""

from __future__ import annotations

from typing import Any

from cordon.env import Environment

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "list_emails",
        "description": "List all emails in the inbox, oldest first.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "get_email",
        "description": "Get a single email by id.",
        "input_schema": {
            "type": "object",
            "properties": {"email_id": {"type": "string"}},
            "required": ["email_id"],
        },
    },
    {
        "name": "search_emails",
        "description": (
            "Search emails. Supports Gmail-style operators from:/to:/subject: "
            "(case-insensitive, single-word values, e.g. \"from:carol\" or "
            "\"subject:review\") mixed with free text; free text matches "
            "subject/body/sender. All matching is substring-based, not fuzzy — "
            "an operator value must be one word (no quoting), and multiple "
            "terms (same operator or mixed with free text) are all required "
            "(AND), not any-of."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    {
        "name": "send_email",
        "description": "Send a new email from the user.",
        "input_schema": {
            "type": "object",
            "properties": {
                "to": {"type": "array", "items": {"type": "string"}},
                "subject": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["to", "subject", "body"],
        },
    },
    {
        "name": "forward_email",
        "description": "Forward an existing email to new recipients, with an optional note.",
        "input_schema": {
            "type": "object",
            "properties": {
                "email_id": {"type": "string"},
                "to": {"type": "array", "items": {"type": "string"}},
                "note": {"type": "string"},
            },
            "required": ["email_id", "to"],
        },
    },
    {
        "name": "reply_email",
        "description": "Reply to an existing email; the recipient is the original sender.",
        "input_schema": {
            "type": "object",
            "properties": {
                "email_id": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["email_id", "body"],
        },
    },
    {
        "name": "list_events",
        "description": "List all calendar events, soonest first.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "get_event",
        "description": "Get a single calendar event by id.",
        "input_schema": {
            "type": "object",
            "properties": {"event_id": {"type": "string"}},
            "required": ["event_id"],
        },
    },
    {
        "name": "create_event",
        "description": "Create a new calendar event.",
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "start": {"type": "string", "description": "ISO 8601 datetime"},
                "end": {"type": "string", "description": "ISO 8601 datetime"},
                "attendees": {"type": "array", "items": {"type": "string"}},
                "description": {"type": "string"},
                "location": {"type": "string"},
            },
            "required": ["title", "start", "end"],
        },
    },
    {
        "name": "update_event",
        "description": "Update fields on an existing calendar event.",
        "input_schema": {
            "type": "object",
            "properties": {
                "event_id": {"type": "string"},
                "title": {"type": "string"},
                "start": {"type": "string"},
                "end": {"type": "string"},
                "description": {"type": "string"},
                "location": {"type": "string"},
            },
            "required": ["event_id"],
        },
    },
    {
        "name": "add_attendee",
        "description": "Add an attendee to an existing calendar event.",
        "input_schema": {
            "type": "object",
            "properties": {
                "event_id": {"type": "string"},
                "attendee": {"type": "string"},
            },
            "required": ["event_id", "attendee"],
        },
    },
    {
        "name": "delete_event",
        "description": "Delete a calendar event.",
        "input_schema": {
            "type": "object",
            "properties": {"event_id": {"type": "string"}},
            "required": ["event_id"],
        },
    },
]


def call_tool(env: Environment, name: str, arguments: dict[str, Any]) -> Any:
    if name == "list_emails":
        return [e.model_dump(mode="json") for e in env.mailbox.list_emails()]
    if name == "get_email":
        return env.mailbox.get_email(arguments["email_id"]).model_dump(mode="json")
    if name == "search_emails":
        return [e.model_dump(mode="json") for e in env.mailbox.search_emails(arguments["query"])]
    if name == "send_email":
        msg_id = env.mailbox.send_email(arguments["to"], arguments["subject"], arguments["body"])
        return {"id": msg_id}
    if name == "forward_email":
        msg_id = env.mailbox.forward_email(
            arguments["email_id"], arguments["to"], arguments.get("note", "")
        )
        return {"id": msg_id}
    if name == "reply_email":
        msg_id = env.mailbox.reply_email(arguments["email_id"], arguments["body"])
        return {"id": msg_id}
    if name == "list_events":
        return [e.model_dump(mode="json") for e in env.calendar.list_events()]
    if name == "get_event":
        return env.calendar.get_event(arguments["event_id"]).model_dump(mode="json")
    if name == "create_event":
        event_id = env.calendar.create_event(
            title=arguments["title"],
            start=arguments["start"],
            end=arguments["end"],
            attendees=arguments.get("attendees"),
            description=arguments.get("description", ""),
            location=arguments.get("location", ""),
        )
        return {"id": event_id}
    if name == "update_event":
        changes = {k: v for k, v in arguments.items() if k != "event_id"}
        env.calendar.update_event(arguments["event_id"], **changes)
        return {"ok": True}
    if name == "add_attendee":
        env.calendar.add_attendee(arguments["event_id"], arguments["attendee"])
        return {"ok": True}
    if name == "delete_event":
        env.calendar.delete_event(arguments["event_id"])
        return {"ok": True}
    raise ValueError(f"unknown tool: {name}")
