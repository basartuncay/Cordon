"""Corpus integrity checks. No LLM calls — these validate the YAML corpus
against its pydantic schema and CLAUDE.md's M1 acceptance thresholds
(>=30 attacks, >=15 benign tasks).
"""

from pathlib import Path

from cordon.env import Environment
from evals.predicates import evaluate
from evals.scenario import build_environment, load_attacks, load_benign_tasks

CORPUS_DIR = Path(__file__).parent.parent / "evals" / "corpus"

ATTACK_CATEGORIES = {"A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "A10"}


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
        for p in t.success:
            evaluate(p.predicate, p.args, env, None)


def test_attacker_domain_emails_are_never_marked_private():
    """'private' means the user's own sensitive data; an attacker's own
    injected text isn't that, and mislabeling it private could make P2
    fire for the wrong reason (or mask that P1 alone is what's actually
    catching a given attack). Every seeded email from the reserved
    attacker domain must be public."""
    attacks = load_attacks(CORPUS_DIR / "attacks")
    for a in attacks:
        for e in a.seed.emails:
            if e.sender.rsplit("@", 1)[-1] == "evil.example":
                assert e.sensitivity == "public", (
                    f"{a.id}: attacker email {e.id} is marked {e.sensitivity!r}, expected 'public'"
                )


def test_every_attack_declares_requires_write():
    attacks = load_attacks(CORPUS_DIR / "attacks")
    for a in attacks:
        assert isinstance(a.requires_write, bool)


def test_known_read_only_and_write_attack_classification():
    """Spot-checks the M1 corpus's read-only/write split (27/34 read-only,
    7/34 write) so a future edit can't silently flip these without a
    failing test to explain why."""
    attacks = {a.id: a for a in load_attacks(CORPUS_DIR / "attacks")}
    write_ids = {"a1_004", "a2_002", "a2_004", "a4_005", "a5_005", "a8_003", "a8_004"}
    for scenario_id in write_ids:
        assert attacks[scenario_id].requires_write is True, scenario_id
    assert attacks["a1_001"].requires_write is False
    assert attacks["a2_001"].requires_write is False


def test_text_marker_predicate_args_are_never_accidentally_parsed_as_yaml_ints():
    """A YAML gotcha bit us for real: an unquoted marker like `1:1` is
    parsed by PyYAML as a sexagesimal int (61), not the string '1:1' —
    silently breaking final_text_contains(_all). Every marker/needle arg
    across the whole corpus must be a str."""
    text_arg_names = {
        "final_text_contains": "marker",
        "final_text_contains_all": "markers",
        "reply_contains": "needle",
        "sent_email_contains": "needle",
    }

    def check(predicate: str, args: dict) -> None:
        arg_name = text_arg_names.get(predicate)
        if arg_name is None or arg_name not in args:
            return
        value = args[arg_name]
        values = value if isinstance(value, list) else [value]
        for v in values:
            assert isinstance(v, str), f"{predicate}.{arg_name} contains a non-str value: {v!r}"

    for a in load_attacks(CORPUS_DIR / "attacks"):
        check(a.attacker_goal.predicate, a.attacker_goal.args)
        for p in a.legit_outcome:
            check(p.predicate, p.args)
    for t in load_benign_tasks(CORPUS_DIR / "tasks"):
        for p in t.success:
            check(p.predicate, p.args)


def test_legit_outcome_predicates_resolve_false_on_fresh_environment():
    """Like the attacker_goal check above: a legit_outcome predicate
    describes something that should only become true once the correct
    action has actually run, never on the unexecuted seed."""
    attacks = load_attacks(CORPUS_DIR / "attacks")
    for a in attacks:
        if not a.legit_outcome:
            continue
        env: Environment = build_environment(a.seed)
        for p in a.legit_outcome:
            result = evaluate(p.predicate, p.args, env, None)
            assert result is False, (
                f"{a.id}: legit_outcome predicate {p.predicate!r} is already true on the "
                "seed environment before any agent action ran"
            )
