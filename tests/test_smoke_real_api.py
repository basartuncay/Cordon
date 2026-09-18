"""One real-API smoke test: 2 benign tasks + 2 attacks against B3 (full
Cordon), capped at an estimated $0.30 spend via --budget-usd.

Every other test in this repo runs against a scripted LLM client. This is
the only one that calls a real model, and it's automatically skipped if no
ANTHROPIC_API_KEY is available — checked only after the code's own .env
loader has run, so a key can come from either the shell or .env. Nothing
here ever reads the key's value into a variable this test prints, logs, or
returns; AnthropicClient itself already redacts it from any error message
(see test_llm.py).

Costs real money, so it's marked `smoke_real_api` and excluded from a plain
`pytest`/`pytest -q` run (see pyproject.toml's addopts) even when a key is
present. Run it explicitly with:

    uv run pytest -m smoke_real_api -s tests/test_smoke_real_api.py
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from cordon.dotenv import load_dotenv
from cordon.llm import AnthropicClient, default_model_config
from evals.baselines.cordon_runner import run_b3
from evals.harness import run_harness, write_result_file
from evals.scenario import load_attacks, load_benign_tasks

CORPUS_DIR = Path(__file__).parent.parent / "evals" / "corpus"

load_dotenv()
_HAS_KEY = bool(os.environ.get("ANTHROPIC_API_KEY"))

pytestmark = [
    pytest.mark.smoke_real_api,
    pytest.mark.skipif(
        not _HAS_KEY,
        reason="ANTHROPIC_API_KEY not set (checked after loading .env); skipping smoke test",
    ),
]


def test_b3_real_api_smoke_two_benign_two_attacks():
    cfg = default_model_config()
    llm = AnthropicClient(model=cfg.baseline_model)

    all_tasks = load_benign_tasks(CORPUS_DIR / "tasks")
    all_attacks = load_attacks(CORPUS_DIR / "attacks")
    tasks = [t for t in all_tasks if t.id in ("benign_001", "benign_003")]
    attacks = [a for a in all_attacks if a.id in ("a2_001", "a3_001")]
    assert len(tasks) == 2, "expected corpus IDs benign_001/benign_003 to still exist"
    assert len(attacks) == 2, "expected corpus IDs a2_001/a3_001 to still exist"

    summary, benign_results, attack_results = run_harness(
        run_b3, llm, "b3", tasks, attacks, cfg, budget_usd=0.30
    )
    result_path = write_result_file(summary, benign_results, attack_results)

    assert summary.estimated_cost_usd <= 0.30 + 1e-9

    benign_successes = sum(1 for r in benign_results if r.success)
    attack_successes = sum(1 for r in attack_results if r.success)
    total_tokens = summary.total_input_tokens + summary.total_output_tokens
    print(
        f"\n[smoke] model={summary.model} complete={summary.complete} "
        f"scenarios={summary.scenarios_completed}/{summary.scenarios_total} "
        f"benign_utility={benign_successes}/{len(benign_results)} "
        f"attack_success={attack_successes}/{len(attack_results)} "
        f"tokens={total_tokens} cost=${summary.estimated_cost_usd:.4f} "
        f"confirms={summary.total_confirm_count} "
        f"result_file={result_path}"
    )
