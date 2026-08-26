# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""No DocType ships a section with nothing in it.

`Server Settings` had one. The whole Bench Management block —
`allow_app_install`, `bench_root`, `bench_executable`, the install timeout and
the git SSH command — had drifted to the END of `field_order`, so the section
header rendered empty and its five fields appeared under "Security
Monitoring", which is where nobody would look for the bench root.

`field_order` is what frappe lays a form out by; the `fields` array is only a
bag of definitions. They can disagree silently, and a JSON round-trip is
enough to make them.
"""

from __future__ import annotations

import json
import pathlib
import unittest

BREAKS = ("Section Break", "Tab Break")


def _doctypes():
	root = pathlib.Path(__file__).resolve().parents[1] / "server" / "doctype"
	for path in sorted(root.glob("*/*.json")):
		schema = json.loads(path.read_text())
		if "field_order" in schema and "fields" in schema:
			yield path.name, schema


class EverySectionHasSomethingInIt(unittest.TestCase):
	def test_no_section_is_empty(self):
		empty = []
		for name, schema in _doctypes():
			kinds = {f["fieldname"]: f["fieldtype"] for f in schema["fields"]}
			current, count = None, 0
			for fieldname in schema["field_order"] + ["__end__"]:
				kind = kinds.get(fieldname)
				if kind in BREAKS or fieldname == "__end__":
					if current and count == 0:
						empty.append(f"{name}:{current}")
					current, count = fieldname, 0
				elif kind and kind != "Column Break":
					count += 1
		self.assertEqual(empty, [], f"sections with no fields under them: {empty}")

	def test_the_two_lists_hold_the_same_names(self):
		# A field in `fields` but missing from `field_order` is appended to the
		# end of the form by frappe, which is how the bench block ended up
		# under the security section.
		for name, schema in _doctypes():
			declared = {f["fieldname"] for f in schema["fields"]}
			ordered = set(schema["field_order"])
			self.assertEqual(declared - ordered, set(), f"{name}: in fields, not in field_order")
			self.assertEqual(ordered - declared, set(), f"{name}: in field_order, not in fields")


class TheKillSwitchShipsOn(unittest.TestCase):
	"""Off by default made every fresh install refuse its own first job.

	It is still the kill switch and still checked by every path that spawns a
	process — including ones another server calls, which is where "off" turned
	into "the remote refused the credentials". A default of on means the app
	works when installed; turning it off remains a deliberate act.
	"""

	def test_allow_app_install_defaults_to_on(self):
		path = (
			pathlib.Path(__file__).resolve().parents[1]
			/ "server" / "doctype" / "server_settings" / "server_settings.json"
		)
		schema = json.loads(path.read_text())
		field = next(f for f in schema["fields"] if f["fieldname"] == "allow_app_install")
		self.assertEqual(field.get("default"), "1")


if __name__ == "__main__":
	unittest.main()
