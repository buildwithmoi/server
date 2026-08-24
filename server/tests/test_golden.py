# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Golden-output test for the full RFC3339 fixture.

The rule-level tests above say "this body means that". This one says "and
nothing else changed" — it is the net that catches a regex tweak fixing one
variant while quietly breaking another. When it fails, read the diff before
reaching for `python3 -m server.tests.regenerate_golden`.
"""

from __future__ import annotations

import json
import unittest

from server.tests._support import fixture_path
from server.tests.regenerate_golden import build


class TestGoldenEvents(unittest.TestCase):
	def setUp(self):
		with open(fixture_path("expected_events.json"), encoding="utf-8") as fh:
			self.expected = json.load(fh)
		self.actual = build()

	def test_event_count_is_unchanged(self):
		self.assertEqual(
			len(self.actual),
			len(self.expected),
			"the fixture produced a different number of events — a rule started or stopped matching",
		)

	def test_every_event_matches_field_for_field(self):
		for index, (actual, expected) in enumerate(zip(self.actual, self.expected, strict=True)):
			with self.subTest(index=index, raw=expected.get("raw_message")):
				self.assertEqual(actual, expected)


class TestGoldenCoverage(unittest.TestCase):
	"""Guard rails on the fixture itself, so it cannot quietly shrink."""

	def setUp(self):
		self.rows = build()

	def test_both_event_kinds_are_represented(self):
		kinds = {row["kind"] for row in self.rows}
		self.assertEqual(kinds, {"AuthEvent", "SudoEvent"})

	def test_all_event_types_have_at_least_one_example(self):
		from server.ssh import parser

		covered = {row["event_type"] for row in self.rows if row["kind"] == "AuthEvent"}
		expected = {
			parser.EVENT_ACCEPTED,
			parser.EVENT_FAILED,
			parser.EVENT_INVALID_USER,
			parser.EVENT_SESSION_OPENED,
			parser.EVENT_SESSION_CLOSED,
			parser.EVENT_DISCONNECTED,
			parser.EVENT_REFUSED,
			parser.EVENT_PROTOCOL_ERROR,
			parser.EVENT_OTHER,
		}
		self.assertEqual(expected - covered, set(), "an event type has no fixture example")

	def test_all_sudo_statuses_have_at_least_one_example(self):
		from server.ssh import parser

		covered = {row["status"] for row in self.rows if row["kind"] == "SudoEvent"}
		self.assertEqual(
			{parser.SUDO_EXECUTED, parser.SUDO_DENIED, parser.SUDO_AUTH_FAILURE} - covered,
			set(),
		)

	def test_no_successful_login_lost_its_source_ip(self):
		"""A successful login with no IP is useless for the whole point of this app."""
		for row in self.rows:
			if row["kind"] == "AuthEvent" and row["outcome"] == "Success":
				self.assertIsNotNone(row["source_ip"], f"no source_ip: {row['raw_message']!r}")

	def test_every_failure_keeps_an_ip_or_explains_why_not(self):
		"""Failures without an IP cannot be attributed, so they must be rare and known."""
		ipless = [
			row["raw_message"]
			for row in self.rows
			if row["kind"] == "AuthEvent" and row["outcome"] == "Failure" and not row["source_ip"]
		]
		# The only accepted case is the bare `Disconnecting: Too many …` form,
		# which genuinely carries no peer address in the message.
		for message in ipless:
			self.assertIn("Too many authentication failures", message, f"unattributable failure: {message!r}")


if __name__ == "__main__":
	unittest.main()
