# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Regression guard: the site's default country must never leak onto a record.

Frappe's `Document._set_defaults()` copies `frappe.new_doc()` defaults over any
empty field on insert, and `new_doc` fills a Link->Country field with the
session's default country. For a business document that is a convenience; on an
audit log it is a falsification — every SSH login would silently claim to come
from whatever country the site was configured with, and the "traffic by country"
chart would show one enormous slice hiding the real attack origins.

This needs a site and a database, so unlike the parser suite it only runs under
    bench --site <site> run-tests --app server
and skips cleanly otherwise.
"""

from __future__ import annotations

import unittest

try:
	import frappe

	_HAS_SITE = bool(getattr(frappe.local, "site", None))
except Exception:  # pragma: no cover - frappe absent entirely
	frappe = None
	_HAS_SITE = False


@unittest.skipUnless(_HAS_SITE, "requires a frappe site")
class TestDefaultCountryDoesNotLeak(unittest.TestCase):
	def setUp(self):
		# Set a global default so the test is meaningful even on a site that has
		# none configured — otherwise it would pass for the wrong reason.
		self._previous = frappe.defaults.get_global_default("country")
		frappe.defaults.set_global_default("country", "Ghana")
		self.addCleanup(self._restore)

	def _restore(self):
		if self._previous:
			frappe.defaults.set_global_default("country", self._previous)
		else:
			frappe.defaults.clear_default("country", parenttype="__default")
		frappe.db.rollback()
		frappe.clear_cache()

	def test_the_default_is_actually_set(self):
		"""Guard the guard: if no default is configured the other tests prove nothing."""
		self.assertEqual(frappe.defaults.get_user_default("Country"), "Ghana")

	def test_auth_event_country_is_not_a_link(self):
		"""A Data field cannot inherit a Link default — that is why it is Data."""
		meta = frappe.get_meta("SSH Auth Event")
		field = meta.get_field("country")
		self.assertEqual(
			field.fieldtype,
			"Data",
			"country must stay Data; as a Link it inherits the site's default country",
		)

	def test_auth_event_insert_leaves_country_empty(self):
		event = frappe.get_doc(
			{
				"doctype": "SSH Auth Event",
				"event_time": frappe.utils.now_datetime(),
				"event_type": "Failed",
				"outcome": "Failure",
				"raw_message": "Failed password for root from 1.2.3.4 port 1 ssh2",
				"dedup_hash": "test_default_country_auth",
			}
		)
		event.insert(ignore_permissions=True)
		self.assertIsNone(
			frappe.db.get_value("SSH Auth Event", event.name, "country"),
			"an event with no resolved country must stay empty, not inherit the site default",
		)

	def test_pending_ip_does_not_inherit_a_country(self):
		ip = frappe.get_doc(
			{"doctype": "IP Address Info", "ip_address": "203.0.113.201", "status": "Pending"}
		)
		ip.insert(ignore_permissions=True)
		self.assertIsNone(frappe.db.get_value("IP Address Info", ip.name, "country"))

	def test_private_ip_does_not_inherit_a_country(self):
		ip = frappe.get_doc({"doctype": "IP Address Info", "ip_address": "10.11.12.13", "status": "Private"})
		ip.insert(ignore_permissions=True)
		self.assertIsNone(frappe.db.get_value("IP Address Info", ip.name, "country"))

	def test_resolved_ip_keeps_the_country_it_was_given(self):
		"""The guard must not clobber a country the resolver actually found."""
		ip = frappe.get_doc(
			{
				"doctype": "IP Address Info",
				"ip_address": "203.0.113.202",
				"status": "Resolved",
				"country": "Germany",
				"country_code": "DE",
			}
		)
		ip.insert(ignore_permissions=True)
		self.assertEqual(frappe.db.get_value("IP Address Info", ip.name, "country"), "Germany")


if __name__ == "__main__":
	unittest.main()
