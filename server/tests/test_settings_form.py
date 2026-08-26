# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Every setting, editable, without a route to leaking one.

The SPA used to expose exactly one switch, and the reasoning was written down:
everything else lived on the Desk form "where each field carries the long
description explaining what it does — a toggle in a dashboard has no room for
that". The descriptions run to 450 characters. The answer was not to keep the
settings elsewhere; it was to give the descriptions somewhere to go.
"""

from __future__ import annotations

import inspect
import pathlib
import unittest

import frappe

from server import api


class NothingSecretIsServed(unittest.TestCase):
	def setUp(self):
		if not frappe.db:
			self.skipTest("needs a site")

	def test_a_password_field_reports_only_that_one_exists(self):
		form = api.server_settings_form()
		secrets = [
			field
			for group in form["groups"]
			for field in group["fields"]
			if field["fieldtype"] == "Password"
		]
		self.assertTrue(secrets, "there are Password fields; this test is worthless without them")
		for field in secrets:
			self.assertEqual(field["value"], "")
			self.assertIn("has_value", field)


class WhatSaveAccepts(unittest.TestCase):
	def test_it_refuses_anything_the_doctype_does_not_declare(self):
		source = inspect.getsource(api.save_server_settings)
		self.assertIn("editable.get(name)", source)
		self.assertIn("if not field:", source)

	def test_a_read_only_field_is_not_editable(self):
		# `detected_log_source` is written by the probe. A form that could set
		# it would let somebody state a source the machine does not have.
		source = inspect.getsource(api.save_server_settings)
		self.assertIn("not field.read_only", source)

	def test_a_blank_password_keeps_the_stored_one(self):
		# The form is never given the value, so blank is what it always sends
		# for a secret nobody retyped. Treating that as "clear it" would wipe
		# the watchdog token every time anything else on the page was saved.
		source = inspect.getsource(api.save_server_settings)
		self.assertIn('if not (value or "").strip():', source)
		self.assertIn("continue", source)

	def test_the_cache_is_cleared(self):
		# Settings are read through a cached document on every scheduled tick.
		self.assertIn("frappe.clear_cache()", inspect.getsource(api.save_server_settings))


class TheFormComesFromTheDocType(unittest.TestCase):
	def test_it_is_built_from_meta_not_from_a_list(self):
		# A hand-kept list drifts: a field added to the DocType would simply
		# not appear, and the only sign would be somebody wondering where the
		# thing they read about went.
		self.assertIn('frappe.get_meta("Server Settings")', inspect.getsource(api.server_settings_form))


class TheDescriptionsHaveSomewhereToGo(unittest.TestCase):
	def test_the_page_shows_them_on_demand(self):
		view = (
			pathlib.Path(__file__).resolve().parents[2] / "serving" / "src" / "views" / "Settings.vue"
		).read_text()
		self.assertIn("hovered === field.fieldname", view)
		self.assertIn("pinned === field.fieldname", view)

	def test_the_groups_are_tabs(self):
		view = (
			pathlib.Path(__file__).resolve().parents[2] / "serving" / "src" / "views" / "Settings.vue"
		).read_text()
		self.assertIn("group.key === active", view)

	def test_they_really_are_too_long_to_inline(self):
		if not frappe.db:
			self.skipTest("needs a site")
		longest = max(
			len(field["description"])
			for group in api.server_settings_form()["groups"]
			for field in group["fields"]
		)
		self.assertGreater(longest, 200)


if __name__ == "__main__":
	unittest.main()
