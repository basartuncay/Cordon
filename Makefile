.PHONY: eval test lint fmt holdout-check corpus-check worst-case check

BASELINE ?= b0
DIR ?=

eval:
	uv run python -m evals.harness --baseline $(BASELINE)

test:
	uv run pytest

lint:
	uv run ruff check .

fmt:
	uv run ruff format .

holdout-check:
	uv run python -m evals.holdout_check

corpus-check:
	uv run python -m evals.corpus_check $(DIR)

# Offline (no API key, no spend): reproduces the README's worst-case table.
worst-case:
	uv run python -m evals.worst_case

# Everything CI runs, locally.
check:
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy src evals
	uv run pytest
	uv run python -m evals.holdout_check
	for d in evals/corpus evals/corpus/holdout evals/corpus/contact-gap evals/corpus/p6cost; do \
		uv run python -m evals.corpus_check $$d || exit 1; done
	uv run python -m evals.worst_case
