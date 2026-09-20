.PHONY: eval test lint fmt holdout-check

BASELINE ?= b0

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
