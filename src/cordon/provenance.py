"""Provenance tracking.

Every value read from an untrusted tool is wrapped as ``Tainted[T]`` with a
``Provenance`` record (where it came from, how much to trust it, how
sensitive it is). Application code should carry ``Tainted`` values around
and only project out ``.value`` at the last possible moment — in practice,
inside the executor, right before a tool call actually runs. The policy
engine (policy.py) is what reads ``.provenance`` to make decisions.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

_TRUST_ORDER = ["user", "contact", "unknown"]  # most to least trusted, left to right


class TrustLevel(StrEnum):
    USER = "user"
    CONTACT = "contact"
    UNKNOWN = "unknown"


class Sensitivity(StrEnum):
    PUBLIC = "public"
    PRIVATE = "private"


def _least_trusted(a: TrustLevel, b: TrustLevel) -> TrustLevel:
    return a if _TRUST_ORDER.index(a) >= _TRUST_ORDER.index(b) else b


@dataclass(frozen=True)
class Provenance:
    source_id: str
    trust: TrustLevel
    sensitivity: Sensitivity = Sensitivity.PRIVATE

    def merge(self, other: Provenance) -> Provenance:
        """Provenance for a value built by combining this one with another
        (e.g. string concatenation): trust degrades to the less-trusted of
        the two inputs, sensitivity escalates to private if either side is.
        """
        sensitivity = (
            Sensitivity.PRIVATE
            if Sensitivity.PRIVATE in (self.sensitivity, other.sensitivity)
            else Sensitivity.PUBLIC
        )
        return Provenance(
            source_id=f"{self.source_id}+{other.source_id}",
            trust=_least_trusted(self.trust, other.trust),
            sensitivity=sensitivity,
        )


LITERAL_PROVENANCE = Provenance(
    source_id="user_request", trust=TrustLevel.USER, sensitivity=Sensitivity.PUBLIC
)


@dataclass(frozen=True)
class Tainted[T]:
    value: T
    provenance: Provenance

    def map(self, fn: Any) -> Tainted[Any]:
        """Apply a pure function to the underlying value, preserving
        provenance (e.g. to project a field out of a tainted dict)."""
        return Tainted(fn(self.value), self.provenance)

    @staticmethod
    def combine(*items: Tainted[Any]) -> Provenance:
        """Provenance for a value derived from multiple tainted inputs at
        once (e.g. string concatenation) — merges all of them."""
        if not items:
            raise ValueError("combine() needs at least one Tainted value")
        result = items[0].provenance
        for item in items[1:]:
            result = result.merge(item.provenance)
        return result
