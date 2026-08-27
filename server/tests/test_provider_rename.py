# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Renaming a credential has to be a rename.

`Domain Provider` autonames `field:provider_name`, so the docname IS the name.
Assigning the field on an existing document and saving does nothing at all —
frappe puts the old value back, silently, and a refresh shows exactly what was
there before. Somebody trying to fix a credential called "Hostinger" that was
in fact talking to GoDaddy did it three times and concluded the app was
ignoring them.
"""

from __future__ import annotations

import inspect
import unittest

import frappe

from server import api


class Renaming(unittest.TestCase):
	def setUp(self):
		if not frappe.db:
			self.skipTest("needs a site")
		self._clean()

	def tearDown(self):
		if frappe.db:
			self._clean()

	def _clean(self):
		for name in frappe.get_all(
			"Domain Provider", filters={"provider_name": ["like", "renametest-%"]}, pluck="name"
		):
			frappe.delete_doc("Domain Provider", name, force=True)
		frappe.db.commit()

	def test_the_document_actually_moves(self):
		made = api.save_domain_provider(
			provider_name="renametest-one", provider="GoDaddy", api_token="a-secret"
		)
		moved = api.save_domain_provider(
			provider_name="renametest-two", provider="GoDaddy", name=made["name"]
		)
		self.assertEqual(moved["name"], "renametest-two")
		self.assertFalse(frappe.db.exists("Domain Provider", "renametest-one"))

	def test_the_token_survives_it(self):
		# The secret lives in `__Auth` against the DOCNAME. A rename that left
		# it behind would read as "no token stored", which is indistinguishable
		# from never having had one — and the fix somebody reaches for is to
		# paste the token in again, which is how this was reported.
		made = api.save_domain_provider(
			provider_name="renametest-one", provider="GoDaddy", api_token="a-secret"
		)
		moved = api.save_domain_provider(
			provider_name="renametest-two", provider="GoDaddy", name=made["name"]
		)
		self.assertTrue(moved["has_token"])
		self.assertEqual(
			frappe.utils.password.get_decrypted_password(
				"Domain Provider", "renametest-two", "api_token", raise_exception=False
			),
			"a-secret",
		)

	def test_a_name_already_taken_is_refused_rather_than_merged(self):
		api.save_domain_provider(provider_name="renametest-one", provider="GoDaddy", api_token="a")
		second = api.save_domain_provider(
			provider_name="renametest-two", provider="GoDaddy", api_token="b"
		)
		with self.assertRaises(frappe.ValidationError):
			api.save_domain_provider(
				provider_name="renametest-one", provider="GoDaddy", name=second["name"]
			)

	def test_saving_without_changing_the_name_does_not_rename(self):
		made = api.save_domain_provider(
			provider_name="renametest-one", provider="GoDaddy", api_token="a-secret"
		)
		again = api.save_domain_provider(
			provider_name="renametest-one", provider="Hostinger", name=made["name"]
		)
		self.assertEqual(again["name"], "renametest-one")
		self.assertTrue(again["has_token"])


class NotAskedIsNotAVerdict(unittest.TestCase):
	""""No domains on that credential" was a statement that nobody had asked.

	The domain list is whatever the last check found, and a credential nobody
	has checked has none — which read as a judgement about the token, with
	nothing on the page to check it with.
	"""

	def test_the_page_offers_to_check(self):
		import pathlib

		view = (
			pathlib.Path(__file__).resolve().parents[2] / "serving" / "src" / "views" / "DnsRecords.vue"
		).read_text()
		self.assertIn("verifyDomainProviderResource", view)
		self.assertIn("has not been checked yet", view)

	def test_it_separates_no_token_from_a_failed_check(self):
		import pathlib

		view = (
			pathlib.Path(__file__).resolve().parents[2] / "serving" / "src" / "views" / "DnsRecords.vue"
		).read_text()
		self.assertIn("verify_error", view)
		self.assertIn("No token is stored", view)


class TheRenameIsInTheCode(unittest.TestCase):
	def test_it_calls_rename_doc(self):
		self.assertIn("frappe.rename_doc(", inspect.getsource(api.save_domain_provider))


if __name__ == "__main__":
	unittest.main()
