"""Corpus integrity checks. No LLM calls — these validate the YAML corpus
against its pydantic schema and CLAUDE.md's M1 acceptance thresholds
(>=30 attacks, >=15 benign tasks).
"""

from pathlib import Path

from cordon.env import Environment
from evals.predicates import evaluate
from evals.scenario import build_environment, load_attacks, load_benign_tasks

CORPUS_DIR = Path(__file__).parent.parent / "evals" / "corpus"

ATTACK_CATEGORIES = {"A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8"}


def test_attack_corpus_has_at_least_30_entries():
    attacks = load_attacks(CORPUS_DIR / "attacks")
    assert len(attacks) >= 30


def test_benign_corpus_has_at_least_15_entries():
    tasks = load_benign_tasks(CORPUS_DIR / "tasks")
    assert len(tasks) >= 15


def test_attack_ids_are_unique():
    attacks = load_attacks(CORPUS_DIR / "attacks")
    ids = [a.id for a in attacks]
    assert len(ids) == len(set(ids))


def test_benign_task_ids_are_unique():
    tasks = load_benign_tasks(CORPUS_DIR / "tasks")
    ids = [t.id for t in tasks]
    assert len(ids) == len(set(ids))


def test_every_attack_category_is_known():
    attacks = load_attacks(CORPUS_DIR / "attacks")
    for a in attacks:
        assert a.category in ATTACK_CATEGORIES, f"{a.id} has unrecognized category {a.category!r}"


def test_every_attack_has_at_least_one_category_represented():
    attacks = load_attacks(CORPUS_DIR / "attacks")
    seen = {a.category for a in attacks}
    assert seen == ATTACK_CATEGORIES


def test_attack_seeds_only_use_reserved_or_company_example_domains():
    attacks = load_attacks(CORPUS_DIR / "attacks")
    for a in attacks:
        for e in a.seed.emails:
            domain = e.sender.rsplit("@", 1)[-1]
            assert domain.endswith(".example"), f"{a.id} uses a non-reserved domain: {domain}"


def test_every_attack_goal_predicate_resolves_on_its_own_fresh_environment():
    attacks = load_attacks(CORPUS_DIR / "attacks")
    for a in attacks:
        env: Environment = build_environment(a.seed)
        result = evaluate(a.attacker_goal.predicate, a.attacker_goal.args, env, None)
        assert result is False, (
            f"{a.id}: attacker goal is already true on the seed environment before any "
            "agent action ran — the predicate or seed data needs fixing"
        )


def test_every_benign_success_predicate_resolves_on_its_own_fresh_environment():
    tasks = load_benign_tasks(CORPUS_DIR / "tasks")
    for t in tasks:
        env: Environment = build_environment(t.seed)
        # Some benign success predicates (e.g. no_email_sent) are trivially true
        # on a fresh env; we only assert here that evaluation doesn't raise.
        evaluate(t.success.predicate, t.success.args, env, None)
