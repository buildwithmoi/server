# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""What the dashboard has to know before it says "nothing has arrived".

That sentence has two completely different causes and they rendered
identically: a quiet machine, or a reader that cannot open a single file. On
the first server this app was installed on it was the second — the bench user
was not in `adm` — and the install script said so once, in a terminal, while
the dashboard went on reporting zeros and offering a button that is refused
outside developer mode.
"""

from __future__ import annotations

import unittest

import frappe

from server import dashboard


class CollectionSurface(unittest.TestCase):
	def setUp(self):
		if not frappe.db:
			self.skipTest("needs a site")

	def test_it_reports_every_key_the_banner_branches_on(self):
		surface = dashboard.collection_surface()
		for key in (
			"user",
			"journal_readable",
			"auth_log_readable",
			"auth_log_path",
			"detected_source",
			"explanation",
			"scheduler_paused",
			"developer_mode",
		):
			self.assertIn(key, surface, f"the banner reads {key} and would render 'undefined' without it")

	def test_it_names_the_user_the_fix_is_about(self):
		# The fix is `usermod -aG adm <user>`, and the operator reading the page
		# is not necessarily the one who created the account.
		self.assertTrue(dashboard.collection_surface()["user"])

	def test_it_is_included_in_the_health_payload(self):
		self.assertIn("collection", dashboard.get_health())

	def test_it_never_raises(self):
		# It runs on the landing page of a monitoring app. A probe that throws
		# takes down the page that would have explained why.
		try:
			dashboard.collection_surface()
		except Exception as exc:  # noqa: BLE001
			self.fail(f"collection_surface raised {exc!r}")


if __name__ == "__main__":
	unittest.main()
