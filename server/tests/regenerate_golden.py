# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Regenerate `fixtures/expected_events.json`.

Run from the app root AFTER deliberately changing parser behaviour:

    python3 -m server.tests.regenerate_golden

Then READ THE DIFF before committing. The whole value of the golden file is
that an unintended change shows up as a diff you have to consciously accept;
regenerating it reflexively to make a red test go green throws that away.
"""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass

from server.ssh.parser import parse_log_line
from server.tests._support import fixture_path, read_lines


def build() -> list[dict]:
	rows = []
	for raw in read_lines("auth_rfc3339.log"):
		event = parse_log_line(raw)
		if event is None:
			continue
		row = {"kind": type(event).__name__}
		row.update({k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in asdict(event).items()})
		rows.append(row)
	return rows


def main() -> None:
	assert is_dataclass, "parser events must stay dataclasses for asdict() to work"
	rows = build()
	path = fixture_path("expected_events.json")
	with open(path, "w", encoding="utf-8") as fh:
		json.dump(rows, fh, indent=1, sort_keys=True)
		fh.write("\n")
	print(f"wrote {len(rows)} events to {path}")


if __name__ == "__main__":
	main()
