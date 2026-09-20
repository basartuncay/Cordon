"""Generalized, LLM-free validator for a corpus directory laid out like
evals/corpus/<name>/{tasks,attacks}/*.yaml (the same shape --corpus-dir
expects — see evals/harness.py). A sibling to evals/holdout_check.py,
which stays holdout-specific (category "H", the write-ratio and non-English
aggregate rules, and the unknown-sender/public-sensitivity rule, all
from evals/corpus/holdout/GUIDE.md's authoring conventions) and is left
untouched. This one checks only what's a hard schema/domain requirement
for any corpus: schema validity, *.example domains, and id
format/uniqueness — deliberately NOT the sensitivity convention, since a
corpus's spec can legitimately mark an unknown-sender email `private`
(e.g. p6cost's p_006, transcribed verbatim from its source spec) without
that being an authoring mistake. Read-only: never modifies corpus
content, never calls an LLM.

Run via `make corpus-check DIR=evals/corpus/p6cost` or
`uv run python -m evals.corpus_check evals/corpus/p6cost`.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml
from pydantic import ValidationError

from evals.scenario import AttackScenario, BenignScenario

_ID_RE = re.compile(r"^[a-z][a-z0-9]*_\d{3,}$")


def _domain(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower()


def _addresses(scenario: AttackScenario | BenignScenario) -> list[str]:
    addrs = list(scenario.seed.contacts)
    for e in scenario.seed.emails:
        addrs.append(e.sender)
        addrs.extend(e.to)
    for ev in scenario.seed.events:
        addrs.append(ev.organizer)
        addrs.extend(ev.attendees)
    return addrs


def _check_common(scenario: AttackScenario | BenignScenario) -> list[str]:
    errors: list[str] = []
    if not _ID_RE.match(scenario.id):
        errors.append(f"id must match <prefix>_NNN (e.g. p_001), got {scenario.id!r}")
    for addr in _addresses(scenario):
        if "@" in addr and not _domain(addr).endswith(".example"):
            errors.append(f"non-.example domain: {addr!r}")
    return errors


def check_task_file(path: Path) -> tuple[BenignScenario | None, list[str]]:
    try:
        raw = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        return None, [f"invalid YAML: {exc}"]
    try:
        scenario = BenignScenario.model_validate(raw)
    except ValidationError as exc:
        return None, [f"schema validation failed: {exc}"]
    return scenario, _check_common(scenario)


def check_attack_file(path: Path) -> tuple[AttackScenario | None, list[str]]:
    try:
        raw = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        return None, [f"invalid YAML: {exc}"]
    try:
        scenario = AttackScenario.model_validate(raw)
    except ValidationError as exc:
        return None, [f"schema validation failed: {exc}"]
    errors = _check_common(scenario)
    if not scenario.category:
        errors.append("category must not be empty")
    return scenario, errors


def run_check(corpus_dir: Path) -> tuple[bool, list[str]]:
    """Validates every *.yaml under corpus_dir/tasks (BenignScenario) and
    corpus_dir/attacks (AttackScenario). Returns (had_errors, lines).
    A directory with neither tasks/ nor attacks/ present (or both empty)
    is reported, never treated as an error."""
    tasks_dir = corpus_dir / "tasks"
    attacks_dir = corpus_dir / "attacks"

    if not tasks_dir.is_dir() and not attacks_dir.is_dir():
        return False, [f"{corpus_dir} has no tasks/ or attacks/ subdirectory — nothing to check."]

    lines: list[str] = []
    had_errors = False
    seen_ids: dict[str, str] = {}
    task_count = 0
    attack_count = 0

    if tasks_dir.is_dir():
        for path in sorted(tasks_dir.glob("*.yaml")):
            task, errors = check_task_file(path)
            if task is not None:
                if task.id in seen_ids:
                    errors.append(f"duplicate id {task.id!r} (also in {seen_ids[task.id]})")
                else:
                    seen_ids[task.id] = path.name
                task_count += 1
            for err in errors:
                lines.append(f"{path.name}: {err}")
                had_errors = True

    if attacks_dir.is_dir():
        for path in sorted(attacks_dir.glob("*.yaml")):
            attack, errors = check_attack_file(path)
            if attack is not None:
                if attack.id in seen_ids:
                    errors.append(f"duplicate id {attack.id!r} (also in {seen_ids[attack.id]})")
                else:
                    seen_ids[attack.id] = path.name
                attack_count += 1
            for err in errors:
                lines.append(f"{path.name}: {err}")
                had_errors = True

    if task_count == 0 and attack_count == 0:
        lines.append(f"0 scenarios found under {corpus_dir} — nothing to check yet.")
    elif not had_errors:
        lines.append(f"{corpus_dir}: {task_count} task(s), {attack_count} attack(s) OK.")

    return had_errors, lines


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: uv run python -m evals.corpus_check <corpus-dir>", file=sys.stderr)
        return 2
    had_errors, lines = run_check(Path(args[0]))
    for line in lines:
        print(line)
    return 1 if had_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
