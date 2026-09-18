"""Quarantined extraction LLM.

No tools, no memory of the plan — it only ever sees one blob of untrusted
text plus a schema describing exactly what shape of value to pull out of
it (an enum, a date, an id, or a length-bounded string). Whatever it
returns must validate against that schema or the extraction is rejected
outright; the caller (the executor) re-wraps whatever comes out with the
*same* provenance as the untrusted input, so even a well-formed extraction
never becomes more trusted than its source.
"""

from __future__ import annotations

from datetime import date
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, ValidationError, create_model, model_validator

from cordon.llm import LLMClient, LLMUsage

SYSTEM_PROMPT = (
    "You extract exactly one specific value from a piece of text. You have "
    "no tools. Respond with ONLY the extracted value as plain text, nothing "
    "else — no explanation, no punctuation around it. If the value "
    "described is not present in the text, respond with exactly: NONE"
)

_EMAIL_PATTERN = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
_ID_PATTERN = r"^[A-Za-z0-9_.:-]+$"


class ExtractionSchema(BaseModel):
    kind: Literal["email", "date", "id", "enum", "text"]
    enum_values: list[str] | None = None
    max_length: int = 200

    @model_validator(mode="after")
    def _enum_requires_values(self) -> ExtractionSchema:
        if self.kind == "enum" and not self.enum_values:
            raise ValueError("enum schema requires enum_values")
        return self


class QuarantineError(RuntimeError):
    pass


def _validator_model(schema: ExtractionSchema) -> type[BaseModel]:
    if schema.kind == "email":
        field = Field(pattern=_EMAIL_PATTERN, max_length=schema.max_length)
        return create_model("Extracted", value=(str, field))
    if schema.kind == "date":
        return create_model("Extracted", value=(date, ...))
    if schema.kind == "id":
        field = Field(pattern=_ID_PATTERN, max_length=schema.max_length)
        return create_model("Extracted", value=(str, field))
    if schema.kind == "enum":
        assert schema.enum_values  # noqa: S101 - guaranteed by ExtractionSchema's own validator
        dynamic_enum = Enum("ExtractedEnum", {v: v for v in schema.enum_values})  # type: ignore[misc]
        return create_model("Extracted", value=(dynamic_enum, ...))
    if schema.kind == "text":
        field = Field(max_length=schema.max_length)
        return create_model("Extracted", value=(str, field))
    raise ValueError(f"unknown schema kind: {schema.kind}")  # pragma: no cover - kind is Literal


def _stringify(value: object) -> str:
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Enum):
        return str(value.value)
    return str(value)


def extract(
    text: str,
    schema: ExtractionSchema,
    instruction: str,
    llm: LLMClient,
    usage: LLMUsage | None = None,
) -> str:
    """Runs the quarantine LLM once and validates its output against
    `schema`. Raises QuarantineError if the output doesn't validate — the
    caller must not use anything from a rejected extraction."""
    prompt = f"{instruction}\n\n---\n{text}\n---"
    response = llm.run(
        system=SYSTEM_PROMPT, messages=[{"role": "user", "content": prompt}], tools=None
    )
    if usage is not None:
        usage.input_tokens += response.usage.input_tokens
        usage.output_tokens += response.usage.output_tokens

    raw = (response.text or "").strip()
    if raw == "NONE":
        raise QuarantineError("quarantine found no matching value in the text")

    model = _validator_model(schema)
    try:
        validated = model(value=raw)
    except ValidationError as exc:
        raise QuarantineError(f"quarantine output failed schema validation: {exc}") from exc
    return _stringify(validated.value)  # type: ignore[attr-defined]
