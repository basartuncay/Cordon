.PHONY: eval test lint fmt holdout-check corpus-check

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
