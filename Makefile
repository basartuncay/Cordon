.PHONY: eval test lint fmt

BASELINE ?= b0

eval:
	uv run python -m evals.harness --baseline $(BASELINE)

test:
	uv run pytest

lint:
	uv run ruff check .

fmt:
	uv run ruff format .
