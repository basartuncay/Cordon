"""Validates evals/corpus/holdout/attacks/*.yaml against AttackScenario's
own schema (the exact pydantic model the harness loads with — see
evals/scenario.py) plus the holdout-specific authoring rules documented in
evals/corpus/holdout/GUIDE.md. Read-only: never modifies corpus content,
never calls an LLM.

Run via `make holdout-check` or `uv run python -m evals.holdout_check`.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml
from pydantic import ValidationError

from evals.scenario import AttackScenario

HOLDOUT_DIR = Path(__file__).parent / "corpus" / "holdout"
ATTACKS_DIR = HOLDOUT_DIR / "attacks"

_TURKISH_CHARS = re.compile(r"[çğıöşüÇĞİÖŞÜ]")
_GERMAN_MARKERS = re.compile(
    r"\b(und|nicht|für|bitte|können|müssen|der|die|das|ist|sehr|dringend)\b", re.IGNORECASE
)

# GUIDE.md's rules: at least 1 write-tier scenario per this many total, and
# at least this many scenarios (absolute count) must be Turkish/German.
MIN_WRITE_RATIO = 8
MIN_NON_ENGLISH = 4


def _looks_non_english(scenario: AttackScenario) -> bool:
    """Heuristic only (no structured language field on AttackScenario, and
    this script must not change that schema) — Turkish diacritics or
    common German function words anywhere in the scenario's own text
    (never its notes-about-itself, though those get scanned too, which
    only makes the heuristic more permissive, never less)."""
    text = " ".join(
        [scenario.user_request, scenario.description, scenario.notes]
        + [e.subject for e in scenario.seed.emails]
        + [e.body for e in scenario.seed.emails]
    )
    return bool(_TURKISH_CHARS.search(text) or _GERMAN_MARKERS.search(text))


def _domain(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower()


def _addresses(scenario: AttackScenario) -> list[str]:
    addrs = list(scenario.seed.contacts)
    for e in scenario.seed.emails:
        addrs.append(e.sender)
        addrs.extend(e.to)
    for ev in scenario.seed.events:
        addrs.append(ev.organizer)
        addrs.extend(ev.attendees)
    return addrs


def check_file(path: Path) -> tuple[AttackScenario | None, list[str]]:
    """Loads and validates a single holdout scenario file. Returns
    (scenario, errors); scenario is None if it didn't even parse or
    validate against AttackScenario's schema. Errors are plain messages —
    the caller adds the filename prefix, since this function doesn't know
    where it's being run from."""
    errors: list[str] = []
    try:
        raw = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        return None, [f"invalid YAML: {exc}"]

    try:
        scenario = AttackScenario.model_validate(raw)
    except ValidationError as exc:
        return None, [f"schema validation failed: {exc}"]

    if scenario.category != "H":
        errors.append(f'category must be "H", got {scenario.category!r}')
    if not re.fullmatch(r"h_\d{3,}", scenario.id):
        errors.append(f"id must match h_NNN (e.g. h_001), got {scenario.id!r}")
    for addr in _addresses(scenario):
        if "@" in addr and not _domain(addr).endswith(".example"):
            errors.append(f"non-.example domain: {addr!r}")
    for e in scenario.seed.emails:
        if e.sender_trust == "unknown" and e.sensitivity != "public":
            errors.append(
                f"email {e.id!r} is from an untrusted sender but "
                f'sensitivity={e.sensitivity!r} (must be "public")'
            )

    return scenario, errors


def run_check(attacks_dir: Path) -> tuple[bool, list[str]]:
    """Validates every *.yaml in attacks_dir. Returns (had_errors, lines)
    — lines are ready to print in order, filename-prefixed where a line
    is about one specific file. An empty/missing directory is reported,
    never treated as an error — there's nothing to check yet, which is
    the expected state right after this scaffolding is added."""
    if not attacks_dir.is_dir():
        return False, [f"{attacks_dir} does not exist yet — nothing to check."]

    files = sorted(attacks_dir.glob("*.yaml"))
    if not files:
        return False, [f"0 holdout scenarios found in {attacks_dir} — nothing to check yet."]

    lines: list[str] = []
    had_errors = False
    scenarios: list[AttackScenario] = []
    seen_ids: dict[str, str] = {}

    for path in files:
        scenario, errors = check_file(path)
        if scenario is not None:
            if scenario.id in seen_ids:
                errors.append(f"duplicate id {scenario.id!r} (also in {seen_ids[scenario.id]})")
            else:
                seen_ids[scenario.id] = path.name
            scenarios.append(scenario)
        for err in errors:
            lines.append(f"{path.name}: {err}")
            had_errors = True

    total = len(scenarios)
    if total:
        write_count = sum(1 for s in scenarios if s.requires_write)
        min_write = -(-total // MIN_WRITE_RATIO)  # ceil(total / MIN_WRITE_RATIO)
        if write_count < min_write:
            lines.append(
                f"aggregate: only {write_count}/{total} scenarios require a write action; "
                f"need at least {min_write} (>= 1 in every {MIN_WRITE_RATIO})"
            )
            had_errors = True

        non_english_count = sum(1 for s in scenarios if _looks_non_english(s))
        if non_english_count < MIN_NON_ENGLISH:
            lines.append(
                f"aggregate: only {non_english_count}/{total} scenarios look Turkish/German "
                f"(heuristic text scan); need at least {MIN_NON_ENGLISH}"
            )
            had_errors = True

        if not had_errors:
            lines.append(
                f"{total} holdout scenario(s) OK: {write_count} write-tier, "
                f"{non_english_count} non-English (heuristic)."
            )

    return had_errors, lines


def main() -> int:
    had_errors, lines = run_check(ATTACKS_DIR)
    for line in lines:
        print(line)
    return 1 if had_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
