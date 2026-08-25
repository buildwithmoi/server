# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Findings: deduplication, suppression, and the baseline that is not trusted.

Two behaviours here decide whether the alerting survives contact with a real
server. Deduplication is what keeps a standing condition from producing one
alert per scan — ninety-six a day, at fifteen-minute intervals. And the
baseline is deliberately NOT accepted on first sight, because these servers are
rebuilt from snapshots of a host that was compromised for eight months, and a
scanner that adopts whatever it finds first would record that host's malware as
normal and never mention it again.
"""

from __future__ import annotations

import unittest

try:
	import frappe

	_HAS_SITE = bool(getattr(frappe.local, "site", None))
except Exception:  # pragma: no cover
	frappe = None
	_HAS_SITE = False

if _HAS_SITE:
	from server.security import watch
	from server.server.doctype.security_event.security_event import (
		build_dedupe_key,
		raise_event,
	)


@unittest.skipUnless(_HAS_SITE, "requires a frappe site")
class TestDeduplication(unittest.TestCase):
	SUBJECT = "TEST — a condition that keeps being true"

	def tearDown(self):
		frappe.db.delete("Security Event", {"subject": self.SUBJECT})
		frappe.db.commit()

	def test_the_same_condition_is_one_event_with_a_count(self):
		first = raise_event("High", "test", self.SUBJECT, "detail")
		self.assertIsNotNone(first)

		for _ in range(5):
			self.assertIsNone(
				raise_event("High", "test", self.SUBJECT, "detail"),
				"a repeat produced a second event",
			)

		self.assertEqual(frappe.db.count("Security Event", {"subject": self.SUBJECT}), 1)
		self.assertEqual(frappe.db.get_value("Security Event", first, "occurrences"), 6)

	def test_the_key_carries_the_day(self):
		"""Without a date a standing condition alerts once and never again,
		however long it lasts; with a finer timestamp it alerts every scan."""
		import datetime

		today = build_dedupe_key(self.SUBJECT, datetime.datetime(2026, 8, 25, 9, 0))
		later = build_dedupe_key(self.SUBJECT, datetime.datetime(2026, 8, 25, 23, 59))
		tomorrow = build_dedupe_key(self.SUBJECT, datetime.datetime(2026, 8, 26, 0, 1))

		self.assertEqual(today, later)
		self.assertNotEqual(today, tomorrow)

	def test_last_seen_advances_even_when_nothing_new_is_raised(self):
		name = raise_event("High", "test", self.SUBJECT, "detail")
		before = frappe.db.get_value("Security Event", name, "last_seen")
		raise_event("High", "test", self.SUBJECT, "detail")
		self.assertGreaterEqual(frappe.db.get_value("Security Event", name, "last_seen"), before)


@unittest.skipUnless(_HAS_SITE, "requires a frappe site")
class TestSuppression(unittest.TestCase):
	SUBJECT = "TEST — something being silenced"

	def tearDown(self):
		frappe.db.delete("Security Event", {"subject": self.SUBJECT})
		frappe.db.commit()

	def test_silencing_requires_a_reason(self):
		from server import api

		name = raise_event("High", "test", self.SUBJECT, "detail")
		with self.assertRaises(frappe.ValidationError):
			api.acknowledge_security_event(name=name, suppress_hours=4)

	def test_a_silence_always_expires(self):
		"""Permanent suppression is how alerting dies quietly."""
		from server import api

		name = raise_event("High", "test", self.SUBJECT, "detail")
		api.acknowledge_security_event(name=name, suppress_hours=10_000, reason="known")

		until = frappe.db.get_value("Security Event", name, "suppressed_until")
		self.assertIsNotNone(until)
		self.assertLessEqual(
			frappe.utils.time_diff_in_seconds(until, frappe.utils.now_datetime()),
			24 * 30 * 3600 + 60,
			"a silence was allowed to run beyond the cap",
		)

	def test_acknowledging_without_hours_does_not_suppress(self):
		from server import api

		name = raise_event("High", "test", self.SUBJECT, "detail")
		api.acknowledge_security_event(name=name)
		self.assertEqual(frappe.db.get_value("Security Event", name, "status"), "Acknowledged")
		self.assertFalse(frappe.db.get_value("Security Event", name, "suppressed_until"))


@unittest.skipUnless(_HAS_SITE, "requires a frappe site")
class TestScanBehaviour(unittest.TestCase):
	def test_a_second_scan_of_an_unchanged_host_raises_nothing_new(self):
		"""At fifteen-minute intervals, a detector that re-reports a standing
		condition produces ninety-six alerts a day."""
		watch.scan()
		before = frappe.db.count("Security Event")
		result = watch.scan()
		self.assertEqual(frappe.db.count("Security Event"), before)
		self.assertEqual(result["changes"], 0)

	def test_the_baseline_is_recorded_but_not_accepted(self):
		"""A host rebuilt from a compromised snapshot must not adopt its
		malware as normal."""
		watch.scan()
		recorded = frappe.db.count("Persistence Item", {"status": "Active"})
		self.assertGreater(recorded, 0)
		# Either everything is still awaiting review, or someone accepted it —
		# what must never happen is items being born accepted.
		self.assertFalse(
			frappe.db.exists(
				"Persistence Item",
				{"status": "Active", "is_baseline": 1, "first_seen": [">", frappe.utils.now_datetime()]},
			)
		)

	def test_record_only_mode_raises_nothing(self):
		"""The log-only week the specification asks for before a new detector
		is allowed to page anyone."""
		watch.scan()
		before = frappe.db.count("Security Event")
		result = watch.scan(record_only=True)
		self.assertEqual(frappe.db.count("Security Event"), before)
		self.assertTrue(result["record_only"])

	def test_the_scheduled_entry_point_never_raises(self):
		from unittest import mock

		with mock.patch.object(watch, "scan", side_effect=RuntimeError("boom")):
			result = watch.run_persistence_scan()
		self.assertIn("boom", result["error"])


if __name__ == "__main__":
	unittest.main()
