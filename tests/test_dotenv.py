"""Tests for the minimal .env loader. Uses only dummy values written to a
temp file — never touches the real .env or any real secret.
"""

from __future__ import annotations

import os

from cordon.dotenv import load_dotenv


def test_load_dotenv_sets_unset_variables(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("FOO_TEST_VAR=hello\nBAR_TEST_VAR=world\n")
    monkeypatch.delenv("FOO_TEST_VAR", raising=False)
    monkeypatch.delenv("BAR_TEST_VAR", raising=False)

    load_dotenv(env_file)

    assert os.environ["FOO_TEST_VAR"] == "hello"
    assert os.environ["BAR_TEST_VAR"] == "world"


def test_load_dotenv_never_overwrites_an_already_set_variable(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("FOO_TEST_VAR=from_file\n")
    monkeypatch.setenv("FOO_TEST_VAR", "from_shell")

    load_dotenv(env_file)

    assert os.environ["FOO_TEST_VAR"] == "from_shell"


def test_load_dotenv_skips_comments_and_blank_lines(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("# a comment\n\nFOO_TEST_VAR=value\n  # indented comment\n")
    monkeypatch.delenv("FOO_TEST_VAR", raising=False)

    load_dotenv(env_file)

    assert os.environ["FOO_TEST_VAR"] == "value"


def test_load_dotenv_strips_quotes(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text('FOO_TEST_VAR="quoted value"\n')
    monkeypatch.delenv("FOO_TEST_VAR", raising=False)

    load_dotenv(env_file)

    assert os.environ["FOO_TEST_VAR"] == "quoted value"


def test_load_dotenv_is_a_noop_when_file_is_missing(tmp_path):
    missing = tmp_path / "does_not_exist.env"
    load_dotenv(missing)  # must not raise
