# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Fixture loading helpers.

Deliberately stdlib-only and frappe-free so the parser suite runs with no site
and no database — see the module docstring in `server/ssh/parser.py` for why
that matters, and for the exact command (it must be the bench's python 3.14).
"""

from __future__ import annotations

import json
import os

FIXTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def fixture_path(name: str) -> str:
	return os.path.join(FIXTURE_DIR, name)


def read_lines(name: str, skip_comments: bool = True) -> list[str]:
	"""Return the meaningful lines of a `.log` fixture.

	Blank lines and `#` comments are dropped by default because they are
	commentary for the reader, not log records. `skip_comments=False` is used by
	the prefix tests, which need to prove the parser skips them rather than
	raising.
	"""
	with open(fixture_path(name), encoding="utf-8") as fh:
		lines = [line.rstrip("\n") for line in fh]
	if not skip_comments:
		return lines
	return [line for line in lines if line.strip() and not line.lstrip().startswith("#")]


def read_journal(name: str = "journal_auth.jsonl") -> list[dict]:
	with open(fixture_path(name), encoding="utf-8") as fh:
		return [json.loads(line) for line in fh if line.strip()]
