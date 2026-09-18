"""Minimal .env loader — no external dependency.

Reads KEY=VALUE lines from a .env file into ``os.environ``, without
overwriting a variable that's already set in the real environment (so an
explicit ``export`` always wins over the file). This module only ever
writes into ``os.environ``; it never returns, logs, or prints a value it
loads — callers that need a secret read it back out of ``os.environ``
themselves, at the point they need it.
"""

from __future__ import annotations

import os
from pathlib import Path


def load_dotenv(path: str | Path = ".env") -> None:
    p = Path(path)
    if not p.is_file():
        return
    for raw_line in p.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value
